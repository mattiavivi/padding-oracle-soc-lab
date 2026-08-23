"""
Lightweight SIEM Query Parser and Evaluator for Log Analysis.

Supports:
- Field comparisons: status = 404, status != 200, status >= 400, endpoint = /decrypt,
  latency_ms > 15, error_type = padding_error, src_ip = attacker
- Logical operators: AND, OR, NOT
- String matching (case-insensitive substring or equality)
- Aggregation conditions: COUNT > N, FAIL_RATE > F (evaluated over grouped IP sets)
"""

import re
from collections import defaultdict
from typing import Any, Callable


def _get_field(event: dict, field: str) -> Any:
    field = field.lower().strip()
    if field in ("status", "status_code", "code"):
        try:
            return int(event.get("status_code", 0))
        except (ValueError, TypeError):
            return 0
    if field in ("endpoint", "path", "url"):
        return str(event.get("endpoint", "")).lower()
    if field in ("ip", "src_ip", "source_ip", "client_ip", "client_id"):
        return str(event.get("src_ip", "")).lower()
    if field in ("latency", "latency_ms", "time"):
        val = event.get("latency_ms")
        try:
            return float(val) if val is not None else 0.0
        except (ValueError, TypeError):
            return 0.0
    if field in ("ciphertext_len", "len", "length"):
        val = event.get("ciphertext_len")
        try:
            return int(val) if val is not None else 0
        except (ValueError, TypeError):
            return 0
    if field in ("error", "error_type", "type"):
        return str(event.get("error_type", "")).lower()
    if field in ("service", "service_name"):
        return str(event.get("service", "")).lower()
    if field in ("mode", "victim_mode"):
        return str(event.get("mode", "")).lower()
    return event.get(field)


def _eval_comparison(field_val: Any, op: str, target_val: str) -> bool:
    target_val = target_val.strip().strip("'\"").lower()
    if field_val is None:
        return False

    # Numeric comparison
    if isinstance(field_val, (int, float)):
        try:
            num_target = float(target_val)
            num_field = float(field_val)
            if op in ("=", "=="):
                return num_field == num_target
            if op in ("!=", "<>"):
                return num_field != num_target
            if op == ">":
                return num_field > num_target
            if op == ">=":
                return num_field >= num_target
            if op == "<":
                return num_field < num_target
            if op == "<=":
                return num_field <= num_target
        except ValueError:
            pass

    # String comparison
    str_field = str(field_val).lower()
    if op in ("=", "=="):
        return str_field == target_val or target_val in str_field
    if op in ("!=", "<>"):
        return str_field != target_val and target_val not in str_field
    if op in ("contains", "like"):
        return target_val in str_field
    return False


def _split_clauses(query_str: str) -> list[tuple[str, str]]:
    """Splits query into (operator_prefix, clause_text) tokens respecting OR / AND."""
    tokens = re.split(r"\s+(AND|OR)\s+", query_str, flags=re.IGNORECASE)
    clauses = []
    current_op = "AND"
    for idx, token in enumerate(tokens):
        token = token.strip()
        if not token:
            continue
        if token.upper() in ("AND", "OR"):
            current_op = token.upper()
        else:
            clauses.append((current_op if idx > 0 else "START", token))
    return clauses


def evaluate_event_query(event: dict, query_str: str) -> bool:
    """Evaluates whether a single event matches a SIEM query string."""
    q = query_str.strip()
    if not q or q == "*":
        return True

    clauses = _split_clauses(q)
    if not clauses:
        return True

    result = True
    comp_regex = re.compile(r"^([a-zA-Z_]+)\s*(=|==|!=|<>|>=|<=|>|<|contains|like)\s*(.+)$", re.IGNORECASE)

    for op, clause in clauses:
        clause = clause.strip()
        is_not = False
        if clause.upper().startswith("NOT "):
            is_not = True
            clause = clause[4:].strip()

        # Skip aggregation clauses in single-event filter
        if re.match(r"^(COUNT|FAIL_RATE)\s*(>|<|>=|<=|=|==)", clause, re.IGNORECASE):
            continue

        match = comp_regex.match(clause)
        if match:
            field_name, comp_op, target_val = match.groups()
            field_val = _get_field(event, field_name)
            clause_result = _eval_comparison(field_val, comp_op, target_val)
        else:
            # Free text search across JSON string
            clause_result = clause.lower() in str(event).lower()

        if is_not:
            clause_result = not clause_result

        if op in ("START", "AND"):
            result = result and clause_result
        elif op == "OR":
            result = result or clause_result

    return result


def filter_and_aggregate_events(events: list[dict], query_str: str) -> dict:
    """Filters events by query and computes SIEM aggregation summary."""
    q = query_str.strip()
    
    # 1. Base Event Filtering
    matching_events = [e for e in events if evaluate_event_query(e, q)]

    # 2. Check for Aggregation constraints in query (e.g., COUNT > 10, FAIL_RATE > 0.8)
    count_match = re.search(r"COUNT\s*(>|>=|=|<|<=)\s*(\d+)", q, re.IGNORECASE)
    fail_match = re.search(r"FAIL_RATE\s*(>|>=|=|<|<=)\s*([0-9.]+)", q, re.IGNORECASE)

    # Group by IP for profiling
    per_ip = defaultdict(list)
    for e in matching_events:
        ip = str(e.get("src_ip", "unknown"))
        per_ip[ip].append(e)

    # Status distribution
    status_counts = defaultdict(int)
    for e in matching_events:
        sc = e.get("status_code")
        if sc is not None:
            status_counts[str(sc)] += 1

    # Endpoints distribution
    endpoint_counts = defaultdict(int)
    for e in matching_events:
        ep = e.get("endpoint")
        if ep:
            endpoint_counts[str(ep)] += 1

    ip_summaries = []
    for ip, ip_events in per_ip.items():
        total_reqs = len(ip_events)
        fails = sum(1 for x in ip_events if int(x.get("status_code", 0)) != 200)
        fail_rate = round(fails / total_reqs, 3) if total_reqs > 0 else 0.0
        padding_errors = sum(1 for x in ip_events if x.get("error_type") == "padding_error")
        lats = [float(x.get("latency_ms", 0.0)) for x in ip_events if x.get("latency_ms") is not None]
        avg_lat = round(sum(lats) / len(lats), 2) if lats else 0.0

        # Aggregation filter per IP if query has COUNT or FAIL_RATE
        keep_ip = True
        if count_match:
            op, val = count_match.groups()
            keep_ip = keep_ip and _eval_comparison(total_reqs, op, val)
        if fail_match:
            op, val = fail_match.groups()
            keep_ip = keep_ip and _eval_comparison(fail_rate, op, val)

        ip_summaries.append({
            "ip": ip,
            "total_requests": total_reqs,
            "failed_requests": fails,
            "fail_rate": fail_rate,
            "padding_errors": padding_errors,
            "avg_latency_ms": avg_lat,
            "matches_aggregation": keep_ip,
        })

    return {
        "query": query_str,
        "total_matched": len(matching_events),
        "events": matching_events,
        "status_distribution": dict(status_counts),
        "endpoint_distribution": dict(endpoint_counts),
        "ip_summaries": ip_summaries,
    }
