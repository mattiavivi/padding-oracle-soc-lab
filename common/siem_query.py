"""
Lightweight SIEM Query Parser and Evaluator for Log Analysis.

Supports:
- Field comparisons: status = 500, status != 200, status >= 400, endpoint = /decrypt,
  latency_ms > 15, error_type = padding_error, src_ip = attacker
- Logical operators: AND, OR, NOT
- String matching (case-insensitive substring or equality)
- Aggregation clauses: GROUP BY <field> | HAVING <conditions>
- Aggregation functions: COUNT, SUM, AVG, STDDEV, MIN, MAX, DISTINCT, FAIL_RATE, BC
"""

import re
import math
import statistics
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
    if field in ("crypto_time", "crypto_time_ns"):
        details = event.get("details") or {}
        val = event.get("crypto_time_ns") or details.get("crypto_time_ns")
        try:
            return int(val) if val is not None else 0
        except (ValueError, TypeError):
            return 0
    if field in ("crypto_time_ms",):
        details = event.get("details") or {}
        val = details.get("crypto_time_ms") or (event.get("crypto_time_ns", 0) / 1_000_000.0)
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


def _calc_group_stats(events: list[dict]) -> dict:
    """Computes full set of profiling metrics and Sarle's BC over a group of log events."""
    total_reqs = len(events)
    if total_reqs == 0:
        return {
            "total_requests": 0,
            "failed_requests": 0,
            "fail_rate": 0.0,
            "padding_errors": 0,
            "max_consecutive_errors": 0,
            "avg_latency_ms": 0.0,
            "stddev_latency_ms": 0.0,
            "p50_latency_ms": 0.0,
            "p95_latency_ms": 0.0,
            "bimodality_coefficient": 0.333,
            "is_bimodal": False,
            "unique_ciphertext_lengths": 0,
            "sample_ciphertext_len": 0,
            "is_aes_aligned": False,
            "risk_score": 0,
            "classification": "BENIGN_CLIENT",
        }

    fails = sum(1 for x in events if int(x.get("status_code", 0)) != 200)
    fail_rate = round(fails / total_reqs, 3)
    padding_errors = sum(1 for x in events if x.get("error_type") == "padding_error" or int(x.get("status_code", 0)) == 500)

    # Max consecutive non-200 errors
    max_consec = 0
    curr_consec = 0
    for x in events:
        if int(x.get("status_code", 0)) != 200:
            curr_consec += 1
            if curr_consec > max_consec:
                max_consec = curr_consec
        else:
            curr_consec = 0

    lats = [float(x.get("latency_ms", 0.0)) for x in events if x.get("latency_ms") is not None]
    n = len(lats)
    if n > 0:
        sorted_lats = sorted(lats)
        mean_lat = statistics.mean(sorted_lats)
        std_lat = statistics.stdev(sorted_lats) if n > 1 else 0.0
        p50_lat = sorted_lats[int(n * 0.5)]
        p95_lat = sorted_lats[min(int(n * 0.95), n - 1)]

        # Sarle Bimodality Coefficient
        m2 = sum((x - mean_lat) ** 2 for x in sorted_lats) / n
        m3 = sum((x - mean_lat) ** 3 for x in sorted_lats) / n
        m4 = sum((x - mean_lat) ** 4 for x in sorted_lats) / n
        if m2 > 1e-9 and n >= 4:
            skew = m3 / (m2 ** 1.5)
            kurt = m4 / (m2 ** 2)
            denom = kurt + ((3.0 * ((n - 1) ** 2)) / ((n - 2) * (n - 3)) - 3.0) if n > 3 else kurt
            bc = min(1.0, max(0.0, (skew ** 2 + 1.0) / denom)) if denom > 0 else 0.333
        else:
            bc = 0.333
    else:
        mean_lat = std_lat = p50_lat = p95_lat = 0.0
        bc = 0.333

    is_bimodal = bool((bc > 0.555 or (std_lat >= 6.0 and (p95_lat - p50_lat) >= 12.0)) and n >= 8)

    lengths = [int(x.get("ciphertext_len", 0)) for x in events if x.get("ciphertext_len")]
    unique_lengths = len(set(lengths))
    sample_len = lengths[0] if lengths else 0
    is_aes_aligned = any(l > 0 and l % 16 == 0 for l in lengths)

    # Classification & Risk Score (0-100)
    ip_sample = str(events[0].get("src_ip", "")).lower()
    is_waf_blocked = any(int(x.get("status_code", 0)) == 429 or x.get("error_type") == "waf_blocked" for x in events)

    score = 0
    if total_reqs >= 10 and fail_rate >= 0.70:
        score += 45
    if padding_errors >= 5 or max_consec >= 10:
        score += 30
    if is_bimodal or std_lat >= 6.0:
        score += 25
    if is_aes_aligned and unique_lengths == 1 and total_reqs >= 15:
        score += 15
    score = min(100, score)

    if is_waf_blocked:
        classification = "QUARANTINED_WAF"
    elif score >= 75 or (fail_rate >= 0.80 and is_aes_aligned and total_reqs >= 15):
        classification = "PADDING_ORACLE_ATTACKER"
    elif is_bimodal or (std_lat >= 6.0 and total_reqs >= 15):
        classification = "TIMING_SIDE_CHANNEL_EXPLOITER"
    elif total_reqs >= 20 and fail_rate >= 0.40:
        classification = "SUSPECT_SCANNER"
    else:
        classification = "BENIGN_CLIENT"

    return {
        "total_requests": total_reqs,
        "failed_requests": fails,
        "fail_rate": round(fail_rate, 3),
        "padding_errors": padding_errors,
        "max_consecutive_errors": max_consec,
        "avg_latency_ms": round(mean_lat, 2),
        "stddev_latency_ms": round(std_lat, 2),
        "p50_latency_ms": round(p50_lat, 2),
        "p95_latency_ms": round(p95_lat, 2),
        "bimodality_coefficient": round(bc, 3),
        "is_bimodal": is_bimodal,
        "unique_ciphertext_lengths": unique_lengths,
        "sample_ciphertext_len": sample_len,
        "is_aes_aligned": is_aes_aligned,
        "risk_score": score,
        "classification": classification,
    }


def evaluate_event_query(event: dict, query_str: str) -> bool:
    """Evaluates whether a single event matches a SIEM query string."""
    q = query_str.strip()
    if not q or q == "*":
        return True

    # Strip GROUP BY and HAVING clauses from single-event filtering
    if "|" in q:
        q = q.split("|")[0].strip()

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
        if re.match(r"^(COUNT|FAIL_RATE|SUM|AVG|STDDEV|BC)\s*\(?", clause, re.IGNORECASE):
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


def _eval_aggregation_condition(stats: dict, group_key: str, clause: str) -> bool:
    """Evaluates an aggregation HAVING condition over group stats."""
    clause = clause.strip()
    if not clause:
        return True

    # 1. COUNT / COUNT(*)
    count_m = re.search(r"COUNT\s*(?:\(\*?\))?\s*(>|>=|=|<|<=|!=)\s*(\d+)", clause, re.IGNORECASE)
    if count_m:
        op, val = count_m.groups()
        return _eval_comparison(stats["total_requests"], op, val)

    # 2. FAIL_RATE / FAIL_RATE()
    fail_m = re.search(r"FAIL_RATE\s*(?:\(\))?\s*(>|>=|=|<|<=|!=)\s*([0-9.]+)", clause, re.IGNORECASE)
    if fail_m:
        op, val = fail_m.groups()
        return _eval_comparison(stats["fail_rate"], op, val)

    # 3. STDDEV / STDDEV(latency_ms)
    std_m = re.search(r"STDDEV\s*(?:\([a-zA-Z_]+\))?\s*(>|>=|=|<|<=|!=)\s*([0-9.]+)", clause, re.IGNORECASE)
    if std_m:
        op, val = std_m.groups()
        return _eval_comparison(stats["stddev_latency_ms"], op, val)

    # 4. AVG / AVG(latency_ms)
    avg_m = re.search(r"AVG\s*(?:\([a-zA-Z_]+\))?\s*(>|>=|=|<|<=|!=)\s*([0-9.]+)", clause, re.IGNORECASE)
    if avg_m:
        op, val = avg_m.groups()
        return _eval_comparison(stats["avg_latency_ms"], op, val)

    # 5. BC / BC(latency_ms) / BIMODALITY
    bc_m = re.search(r"(?:BC|BIMODALITY)\s*(?:\([a-zA-Z_]+\))?\s*(>|>=|=|<|<=|!=)\s*([0-9.]+)", clause, re.IGNORECASE)
    if bc_m:
        op, val = bc_m.groups()
        return _eval_comparison(stats["bimodality_coefficient"], op, val)

    # 6. SUM(status=500) or SUM(status!=200)
    sum_m = re.search(r"SUM\s*\(\s*status\s*(=|==|!=)\s*(\d+)\s*\)\s*(>|>=|=|<|<=|!=)\s*(\d+)", clause, re.IGNORECASE)
    if sum_m:
        s_op, s_val, op, target_val = sum_m.groups()
        if s_op in ("=", "==") and s_val == "500":
            actual_val = stats["padding_errors"]
        else:
            actual_val = stats["failed_requests"]
        return _eval_comparison(actual_val, op, target_val)

    return True


def filter_and_aggregate_events(events: list[dict], query_str: str) -> dict:
    """Filters events by query and computes SIEM aggregation summary for grouped entities."""
    q = query_str.strip()

    # Parse pipe syntax: [Filter] | GROUP BY [Dimension] | HAVING [Aggregations]
    group_by_field = "src_ip"
    having_clauses = []

    raw_query = q
    if "|" in q:
        parts = [p.strip() for p in q.split("|") if p.strip()]
        raw_query = parts[0] if parts else "*"
        for p in parts[1:]:
            if p.upper().startswith("GROUP BY"):
                group_by_field = p[8:].strip().lower()
            elif p.upper().startswith("HAVING"):
                having_clauses.append(p[6:].strip())

    # 1. Base Event Filtering
    matching_events = [e for e in events if evaluate_event_query(e, raw_query)]

    # Extract legacy inline COUNT > N or FAIL_RATE > F from query if present
    count_match = re.search(r"COUNT\s*(>|>=|=|<|<=)\s*(\d+)", q, re.IGNORECASE)
    fail_match = re.search(r"FAIL_RATE\s*(>|>=|=|<|<=)\s*([0-9.]+)", q, re.IGNORECASE)

    # 2. Grouping events by dimension
    grouped = defaultdict(list)
    for e in matching_events:
        g_val = _get_field(e, group_by_field)
        g_key = str(g_val) if g_val is not None else "unknown"
        grouped[g_key].append(e)

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
    for g_key, g_events in grouped.items():
        stats = _calc_group_stats(g_events)

        keep_group = True
        if count_match:
            op, val = count_match.groups()
            keep_group = keep_group and _eval_comparison(stats["total_requests"], op, val)
        if fail_match:
            op, val = fail_match.groups()
            keep_group = keep_group and _eval_comparison(stats["fail_rate"], op, val)

        for h_clause in having_clauses:
            keep_group = keep_group and _eval_aggregation_condition(stats, g_key, h_clause)

        summary_item = {
            "ip": g_key,  # Compatible key name
            "dimension": group_by_field,
            "key": g_key,
            "total_requests": stats["total_requests"],
            "failed_requests": stats["failed_requests"],
            "fail_rate": stats["fail_rate"],
            "padding_errors": stats["padding_errors"],
            "max_consecutive_errors": stats["max_consecutive_errors"],
            "avg_latency_ms": stats["avg_latency_ms"],
            "stddev_latency_ms": stats["stddev_latency_ms"],
            "p50_latency_ms": stats["p50_latency_ms"],
            "p95_latency_ms": stats["p95_latency_ms"],
            "bimodality_coefficient": stats["bimodality_coefficient"],
            "is_bimodal": stats["is_bimodal"],
            "unique_ciphertext_lengths": stats["unique_ciphertext_lengths"],
            "sample_ciphertext_len": stats["sample_ciphertext_len"],
            "is_aes_aligned": stats["is_aes_aligned"],
            "risk_score": stats["risk_score"],
            "classification": stats["classification"],
            "matches_aggregation": keep_group,
        }
        ip_summaries.append(summary_item)

    return {
        "query": query_str,
        "group_by": group_by_field,
        "total_matched": len(matching_events),
        "events": matching_events,
        "status_distribution": dict(status_counts),
        "endpoint_distribution": dict(endpoint_counts),
        "ip_summaries": ip_summaries,
    }

