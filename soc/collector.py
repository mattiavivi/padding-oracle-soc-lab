import json
import math
import os
import sqlite3
import statistics
import threading
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from glob import glob

from flask import Flask, jsonify, request

from common.siem_query import evaluate_event_query, filter_and_aggregate_events

try:
    import requests
except ImportError:
    requests = None


app = Flask(__name__)
LOG_DIR = os.getenv("LOG_DIR", "/logs")
WINDOW_MINUTES = int(os.getenv("SOC_WINDOW_MINUTES", "0"))
ALERT_RULES_FILE = os.getenv(
    "ALERT_RULES_FILE",
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "control", "alert_rules.json"),
)
VICTIM_URL = os.getenv("VICTIM_URL", "http://victim:8080")
SOAR_ENABLED = os.getenv("SOAR_ENABLED", "true").lower() in ("true", "1", "yes")

MAX_MEMORY_LOGS = int(os.getenv("MAX_LOGS_MEMORY", "10000"))
_MEMORY_LOG_BUFFER: deque = deque(maxlen=MAX_MEMORY_LOGS)
_FILE_BYTE_OFFSETS: dict[str, int] = {}
_LOG_SYNC_LOCK = threading.Lock()
_DB_LOCK = threading.Lock()

# ---------------------------------------------------------------------------
# Embedded SQLite WAL Database Engine for SIEM & High-Performance Indexing
# ---------------------------------------------------------------------------
_DB_FILE = os.path.join(LOG_DIR, "siem_events.db") if os.path.exists(LOG_DIR) else ":memory:"


def _init_sqlite_db() -> sqlite3.Connection:
    try:
        if _DB_FILE != ":memory:":
            os.makedirs(os.path.dirname(_DB_FILE), exist_ok=True)
        conn = sqlite3.connect(_DB_FILE, timeout=10.0, check_same_thread=False)
        conn.execute("PRAGMA busy_timeout = 10000;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA temp_store = MEMORY;")
        conn.execute("PRAGMA journal_size_limit = 10485760;")
        conn.execute("PRAGMA wal_autocheckpoint = 500;")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                ts TEXT NOT NULL,
                ts_epoch REAL NOT NULL,
                service TEXT NOT NULL,
                event_type TEXT,
                scenario_id TEXT,
                src_ip TEXT NOT NULL,
                endpoint TEXT,
                status_code INTEGER,
                latency_ms REAL,
                crypto_time_ns INTEGER DEFAULT 0,
                ciphertext_len INTEGER DEFAULT 0,
                error_type TEXT,
                mode TEXT,
                raw_json TEXT NOT NULL
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts_epoch ON events(ts_epoch);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ip_ts ON events(src_ip, ts_epoch);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_service_endpoint ON events(service, endpoint, ts_epoch);")
        conn.commit()
        return conn
    except Exception:
        conn = sqlite3.connect(":memory:", check_same_thread=False)
        return conn


_DB_CONN = _init_sqlite_db()


def _ts_to_epoch(ts_str: str) -> float:
    try:
        dt = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
        return dt.timestamp()
    except Exception:
        return time.time()


_SQLITE_INSERT_COUNTER = 0


def _save_event_sqlite(ev: dict) -> None:
    global _SQLITE_INSERT_COUNTER
    try:
        ev_id = str(ev.get("event_id") or uuid.uuid4())
        ts = str(ev.get("ts") or datetime.now(timezone.utc).isoformat())
        ts_epoch = _ts_to_epoch(ts)
        service = str(ev.get("service", "unknown"))
        event_type = str(ev.get("event_type", ""))
        scenario_id = str(ev.get("scenario_id", "default"))
        src_ip = str(ev.get("src_ip", "unknown"))
        endpoint = str(ev.get("endpoint", ""))
        status_code = int(ev.get("status_code", 0)) if ev.get("status_code") is not None else None
        latency_ms = float(ev.get("latency_ms", 0.0)) if ev.get("latency_ms") is not None else None
        details = ev.get("details") or {}
        crypto_time_ns = int(ev.get("crypto_time_ns") or details.get("crypto_time_ns") or 0)
        ciphertext_len = int(ev.get("ciphertext_len", 0)) if ev.get("ciphertext_len") is not None else 0
        error_type = str(ev.get("error_type", ""))
        mode = str(ev.get("mode", ""))
        raw_json = json.dumps(ev, separators=(",", ":"))

        with _DB_LOCK:
            _DB_CONN.execute("""
                INSERT OR REPLACE INTO events (
                    id, ts, ts_epoch, service, event_type, scenario_id,
                    src_ip, endpoint, status_code, latency_ms, crypto_time_ns,
                    ciphertext_len, error_type, mode, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (ev_id, ts, ts_epoch, service, event_type, scenario_id,
                  src_ip, endpoint, status_code, latency_ms, crypto_time_ns,
                  ciphertext_len, error_type, mode, raw_json))
            _SQLITE_INSERT_COUNTER += 1
            if _SQLITE_INSERT_COUNTER >= 500:
                _SQLITE_INSERT_COUNTER = 0
                _DB_CONN.execute("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY ts_epoch DESC LIMIT 15000);")
                _DB_CONN.execute("PRAGMA wal_checkpoint(PASSIVE);")
            _DB_CONN.commit()
    except Exception:
        pass


def _trigger_soar_mitigation(ip: str, rule: str, reason: str, ttl_seconds: int = 120, endpoint: str | None = None) -> None:
    """SOAR Active Response: automatizza il blocco IP su Victim WAF in caso di exploit rilevato con isolamento endpoint."""
    if not SOAR_ENABLED or not ip or ip in ("unknown", "127.0.0.1", "localhost", "::1") or ip.startswith("benign"):
        return

    def _async_post():
        if requests is None:
            return
        try:
            payload = {
                "ip": ip,
                "reason": f"SOAR Auto-Mitigation: {rule} ({reason})",
                "ttl_seconds": ttl_seconds,
            }
            if endpoint and endpoint not in ("*", "/"):
                payload["endpoint"] = endpoint
            requests.post(
                f"{VICTIM_URL}/waf/block_ip",
                json=payload,
                timeout=1.5,
            )
        except Exception:
            pass

    threading.Thread(target=_async_post, daemon=True, name=f"SOAR-Block-{ip}").start()


def _default_siem_rules():
    return [
        {
            "id": "rule_error_flooding",
            "name": "AES-CBC Padding Oracle Exploit (Error Flooding)",
            "mitre": "T1110.001",
            "description": "Trigger: Fail Rate > 80% su errori espliciti (500/padding_error)",
            "endpoint": "/api/v1/crypto/decrypt",
            "enabled": True,
            "rule_type": "error_flooding",
            "min_events": 15,
            "fail_rate": 0.8,
        },
        {
            "id": "rule_timing_oracle",
            "name": "Cryptographic Timing Side-Channel Oracle Detected",
            "mitre": "T1595.002",
            "description": "Trigger: StdDev latenza > 6ms o Bimodalità Sarle > 0.555",
            "endpoint": "/api/v1/crypto/decrypt",
            "enabled": True,
            "rule_type": "timing_oracle",
            "timing_stddev": 6.0,
            "bimodality": 0.555,
        },
        {
            "id": "rule_byte_probing",
            "name": "Sequential CBC Block Byte-Probing Pattern",
            "mitre": "T1040",
            "description": "Trigger: Scansione sequenziale 16-byte blocks con errori consecutivi",
            "endpoint": "/api/v1/crypto/decrypt",
            "enabled": True,
            "rule_type": "byte_probing",
            "consecutive_errors": 12,
        },
        {
            "id": "rule_auth_bruteforce",
            "name": "Authentication Brute-Force & Credential Spraying",
            "mitre": "T1110.001",
            "description": "Trigger: Fail Rate > 80% su tentativi di autenticazione falliti (HTTP 401)",
            "endpoint": "/api/v1/auth/login",
            "enabled": True,
            "rule_type": "error_flooding",
            "min_events": 5,
            "fail_rate": 0.8,
        },
    ]


def _load_rules() -> dict:
    defaults = {
        "enabled": False,
        "rule_error_flooding_enabled": True,
        "rule_timing_oracle_enabled": True,
        "rule_byte_probing_enabled": True,
        "rule_auth_bruteforce_enabled": True,
        "min_events_per_ip": 25,
        "high_fail_rate_threshold": 0.85,
        "collector_window_minutes": 0,
        "timing_stddev_threshold_ms": 6.0,
        "timing_p95_p50_diff_threshold_ms": 12.0,
        "bimodality_threshold": 0.555,
        "min_timing_events_per_ip": 20,
        "block_probing_min_consecutive_errors": 15,
        "soar_auto_block": True,
        "soar_ban_ttl_seconds": 120,
        "window_seconds": 60,
        "rules": _default_siem_rules(),
    }
    try:
        if os.path.exists(ALERT_RULES_FILE):
            with open(ALERT_RULES_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    for k in defaults.keys():
                        if k in data:
                            defaults[k] = data[k]
                    if "rules" in data and isinstance(data["rules"], list):
                        defaults["rules"] = data["rules"]
    except Exception:
        pass
    return defaults


def _sync_collector_memory_logs() -> None:
    with _LOG_SYNC_LOCK:
        new_events = []
        for path in sorted(glob(os.path.join(LOG_DIR, "*.jsonl"))):
            last_offset = _FILE_BYTE_OFFSETS.get(path, 0)
            try:
                if not os.path.exists(path):
                    continue
                size = os.path.getsize(path)
                if size < last_offset:
                    last_offset = 0
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    f.seek(last_offset)
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            ev = json.loads(line)
                            new_events.append(ev)
                        except json.JSONDecodeError:
                            continue
                    _FILE_BYTE_OFFSETS[path] = f.tell()
            except Exception:
                continue
        if new_events:
            for ev in new_events:
                _MEMORY_LOG_BUFFER.append(ev)
                _save_event_sqlite(ev)


def _read_events(limit: int = 10000) -> list[dict]:
    _sync_collector_memory_logs()
    try:
        with _DB_LOCK:
            cursor = _DB_CONN.cursor()
            cursor.execute("SELECT raw_json FROM events ORDER BY ts_epoch DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            if rows:
                return [json.loads(row[0]) for row in reversed(rows)]
    except Exception:
        pass
    with _LOG_SYNC_LOCK:
        return list(_MEMORY_LOG_BUFFER)



def _windowed_events(events: list[dict], window_minutes: int) -> list[dict]:
    if window_minutes <= 0:
        return events
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
    filtered = []
    for e in events:
        ts = e.get("ts")
        if not isinstance(ts, str):
            continue
        try:
            ev_dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            continue
        if ev_dt >= cutoff:
            filtered.append(e)
    return filtered


def _calc_latency_stats(latencies: list[float]) -> dict:
    """Calcola statistiche avanzate di latenza inclusi momenti centrali (skewness, kurtosis),

    IQR (Interquartile Range) e il coefficiente di bimodalità di Sarle con correzione campionaria finita:
    BC = (skewness^2 + 1) / (kurtosis + 3*(n-1)^2 / ((n-2)*(n-3))).
    Un valore BC > 0.555 (o picchi bimodali con IQR elevato) indica la firma matematica di side-channel.
    """
    if not latencies:
        return {
            "count": 0,
            "mean": 0.0,
            "stddev": 0.0,
            "p50": 0.0,
            "p95": 0.0,
            "p95_p50_diff": 0.0,
            "iqr": 0.0,
            "min": 0.0,
            "max": 0.0,
            "skewness": 0.0,
            "kurtosis": 3.0,
            "bimodality_coefficient": 0.333,
            "is_bimodal": False,
        }
    n = len(latencies)
    sorted_lats = sorted(latencies)
    mean_val = statistics.mean(sorted_lats)
    std_val = statistics.stdev(sorted_lats) if n > 1 else 0.0
    p25_idx = int(n * 0.25)
    p50_idx = int(n * 0.50)
    p75_idx = min(int(n * 0.75), n - 1)
    p95_idx = min(int(n * 0.95), n - 1)
    p25_val = sorted_lats[p25_idx]
    p50_val = sorted_lats[p50_idx]
    p75_val = sorted_lats[p75_idx]
    p95_val = sorted_lats[p95_idx]
    iqr_val = round(p75_val - p25_val, 3)

    # Calcolo momenti centrali
    m2 = sum((x - mean_val) ** 2 for x in sorted_lats) / n
    m3 = sum((x - mean_val) ** 3 for x in sorted_lats) / n
    m4 = sum((x - mean_val) ** 4 for x in sorted_lats) / n

    if m2 > 1e-9 and n >= 4:
        skewness_val = m3 / (m2 ** 1.5)
        kurtosis_val = m4 / (m2 ** 2)  # Pearson's kurtosis (normale = 3.0)

        # Correzione di Sarle per finite samples:
        if n > 3:
            finite_sample_adj = (3.0 * ((n - 1) ** 2)) / ((n - 2) * (n - 3))
            denom = kurtosis_val + (finite_sample_adj - 3.0)
            if denom > 0:
                bimodality_coeff = min(1.0, max(0.0, (skewness_val ** 2 + 1.0) / denom))
            else:
                bimodality_coeff = 0.333
        else:
            bimodality_coeff = 0.333
    else:
        skewness_val = 0.0
        kurtosis_val = 3.0
        bimodality_coeff = 0.333

    is_bimodal_val = bool((bimodality_coeff > 0.555 or (std_val >= 6.0 and (p95_val - p50_val) >= 12.0)) and n >= 8)

    return {
        "count": n,
        "mean": round(mean_val, 2),
        "stddev": round(std_val, 2),
        "p50": round(p50_val, 2),
        "p95": round(p95_val, 2),
        "p95_p50_diff": round(p95_val - p50_val, 2),
        "iqr": iqr_val,
        "min": round(sorted_lats[0], 2),
        "max": round(sorted_lats[-1], 2),
        "skewness": round(skewness_val, 3),
        "kurtosis": round(kurtosis_val, 3),
        "bimodality_coefficient": round(bimodality_coeff, 3),
        "is_bimodal": is_bimodal_val,
    }


def _is_victim_telemetry(e: dict) -> bool:
    """Verifica se l'evento proviene dall'infrastruttura difensiva (vittima/server).
    Nel SIEM, le analisi forensi e gli allarmi devono basarsi sulla telemetria autoritativa del server,
    escludendo le tracce interne dei client (attacker/benign) per evitare duplicazioni dei conteggi."""
    svc = str(e.get("service", "") or "").lower()
    if svc == "victim":
        return True
    if svc in ("attacker", "benign"):
        return False
    etype = str(e.get("event_type", "") or "").lower()
    if etype.startswith("attack_") or etype.startswith("benign_"):
        return False
    return True


def _is_decrypt_event(e: dict) -> bool:
    endpoint = str(e.get("endpoint", "") or "").lower()
    event_type = str(e.get("event_type", "") or "").lower()
    # Align exactly with WAF scope on victim: decrypt endpoint only
    if endpoint in ("/decrypt", "/api/v1/crypto/decrypt") or "decrypt" in endpoint:
        return True
    if event_type in ("attack_probe", "attack_progress", "attack_blocked", "attack_recon"):
        return True
    return False


def _event_matches_endpoint(e: dict, target_ep: str | None) -> bool:
    if not target_ep or target_ep in ("*", "/"):
        return True
    target = str(target_ep).strip().lower()
    ep = str(e.get("endpoint", "") or "").strip().lower()

    if "decrypt" in target:
        if _is_decrypt_event(e):
            return True

    if not ep:
        return False
    return (target in ep) or (ep in target)



def _build_alerts(events: list[dict], custom_rules: dict | None = None) -> list[dict]:
    if custom_rules is not None:
        rules = _load_rules()
        rules.update(custom_rules)
        if "enabled" not in custom_rules:
            rules["enabled"] = True
    else:
        rules = _load_rules()

    alerts = []

    # Priority 1: Instant Inline WAF Drop Alert
    for e in events:
        if e.get("service") == "victim" and (e.get("status_code") == 429 or e.get("error_type") == "waf_blocked"):
            ip = str(e.get("src_ip", "unknown"))
            details = e.get("details", {}) if isinstance(e.get("details"), dict) else {}
            alerts.append(
                {
                    "alert_id": f"ALT-WAF-DROP-{e.get('scenario_id', 'live')}-{int(time.time()*1000)}",
                    "timestamp": e.get("ts", datetime.now(timezone.utc).isoformat()),
                    "rule": "waf_padding_oracle_blocked",
                    "severity": "critical",
                    "title": f"🚫 INLINE WAF BLOCK: IP {ip} dropped by Active WAF Defense",
                    "ip": ip,
                    "src_ip": ip,
                    "target": "victim",
                    "scenario_id": e.get("scenario_id", "default"),
                    "category": "PREVENTIVE_DEFENSE",
                    "confidence": 0.99,
                    "details": {
                        "reason": details.get("reason", "WAF Block Engaged"),
                        "queries_total": details.get("queries_total", 0),
                        "status_code": 429,
                        "action": "429_TOO_MANY_REQUESTS",
                    },
                    "evidence": {
                        "blocked_requests": details.get("queries_total", 1),
                        "action": "429_TOO_MANY_REQUESTS",
                        "reason": details.get("reason", "WAF Block Engaged"),
                    },
                    "recommended_action": "IP gia' isolato dal WAF inline. Mantieni blocco temporaneo o aggiorna ban TTL.",
                }
            )

    # Priority 2: Forensic correlation for attackers causing repeat WAF drops
    per_ip_waf = defaultdict(list)
    for e in events:
        if _is_victim_telemetry(e) and (e.get("status_code") == 429 or e.get("error_type") == "waf_blocked"):
            per_ip_waf[str(e.get("src_ip", "unknown"))].append(e)

    for ip, ip_waf_evs in per_ip_waf.items():
        if len(ip_waf_evs) >= 3:
            alerts.append(
                {
                    "alert_id": f"ALT-WAF-REPEAT-{ip.replace('.', '_')}-{int(time.time()*1000)}",
                    "severity": "high",
                    "title": f"🛡️ WAF HARDENING ALERT: Continuous probing blocked from {ip}",
                    "ip": ip,
                    "src_ip": ip,
                    "target": "victim",
                    "scenario_id": ip_waf_evs[0].get("scenario_id", "default"),
                    "category": "EXPLOIT_PREVENTION",
                    "confidence": 0.95,
                    "details": {
                        "dropped_requests": len(ip_waf_evs),
                        "action_taken": "INLINE_DROPPED_429",
                    },
                    "evidence": {
                        "blocked_requests": len(ip_waf_evs),
                        "action": "INLINE_DROPPED_429",
                    },
                    "recommended_action": "Mantieni quarantena IP o applica ban permanente L7",
                    "timestamp": ip_waf_evs[-1].get("ts", datetime.now(timezone.utc).isoformat()),
                }
            )

    # If detection rules are disabled, do not generate proactive detection alerts
    if not rules.get("enabled", False):
        return alerts

    victim_events = [e for e in events if _is_victim_telemetry(e)]

    # Regola 1: Error-rate Padding Oracle su victim-vuln (o errori espliciti status 500 / padding_error)
    r1_dict = next((r for r in rules.get("rules", []) if r.get("id") == "rule_error_flooding"), {})
    r1_enabled = rules.get("rule_error_flooding_enabled", True) and r1_dict.get("enabled", True)
    r1_ep = r1_dict.get("endpoint", "/api/v1/crypto/decrypt")
    r1_min = int(r1_dict.get("min_events", rules.get("min_events_per_ip", 15)))
    r1_fail = float(r1_dict.get("fail_rate", rules.get("high_fail_rate_threshold", 0.80)))

    if r1_enabled:
        r1_events = [e for e in victim_events if _event_matches_endpoint(e, r1_ep)]
        per_ip_r1 = defaultdict(list)
        for ev in r1_events:
            per_ip_r1[ev.get("src_ip", "unknown")].append(ev)

        for ip, items in per_ip_r1.items():
            total = len(items)
            if total < r1_min:
                continue
            failures = sum(1 for x in items if int(x.get("status_code", 0)) != 200)
            padding_err_count = sum(1 for x in items if x.get("error_type") == "padding_error")
            fail_rate = failures / total
            lengths = [int(x.get("ciphertext_len", 0)) for x in items if x.get("ciphertext_len")]
            unique_lengths = len(set(lengths))
            is_explicit_oracle = padding_err_count > 0 or any(x.get("status_code") == 500 for x in items)

            if fail_rate >= r1_fail and is_explicit_oracle:
                if rules.get("soar_auto_block", True):
                    _trigger_soar_mitigation(ip, "high_fail_rate_padding_oracle", "AES-CBC Padding Oracle Exploit", ttl_seconds=int(rules.get("soar_ban_ttl_seconds", 120)), endpoint=r1_ep)
                alerts.append(
                    {
                        "rule": "high_fail_rate_padding_oracle",
                        "title": "AES-CBC Padding Oracle Exploit (Error Flooding)",
                        "severity": "critical",
                        "ip": ip,
                        "src_ip": ip,
                        "endpoint": r1_ep,
                        "confidence": 0.98,
                        "mitre_technique": "T1110.001 - Brute Force (Padding Oracle)",
                        "evidence": {
                            "endpoint": r1_ep,
                            "total_requests": total,
                            "failed_requests": failures,
                            "fail_rate": round(fail_rate, 3),
                            "padding_errors": padding_err_count,
                            "unique_lengths": unique_lengths,
                            "block_aligned": any(l > 0 and l % 16 == 0 for l in lengths),
                            "soar_mitigation_active": bool(rules.get("soar_auto_block", True)),
                        },
                        "recommended_action": "Hot-Patch to victim-fixed o Blocca IP sorgente (SOAR Playbook)",
                        "timestamp": items[-1].get("ts", datetime.now(timezone.utc).isoformat()),
                    }
                )

    # Regola 2: Timing Side-Channel Oracle su victim-partial (status 403 generico ma latenza bimodale / dispersione temporale)
    r2_dict = next((r for r in rules.get("rules", []) if r.get("id") == "rule_timing_oracle"), {})
    r2_enabled = rules.get("rule_timing_oracle_enabled", True) and r2_dict.get("enabled", True)
    r2_ep = r2_dict.get("endpoint", "/api/v1/crypto/decrypt")
    stddev_thresh = float(rules.get("timing_stddev_threshold_ms", r2_dict.get("timing_stddev", 6.0)))
    p95_diff_thresh = float(rules.get("timing_p95_p50_diff_threshold_ms", 12.0))
    bimodal_thresh = float(rules.get("bimodality_threshold", r2_dict.get("bimodality", 0.555)))
    min_timing_events = int(rules.get("min_timing_events_per_ip", 20))

    if r2_enabled:
        r2_events = [e for e in victim_events if _event_matches_endpoint(e, r2_ep)]
        per_ip_r2 = defaultdict(list)
        for ev in r2_events:
            per_ip_r2[ev.get("src_ip", "unknown")].append(ev)

        for ip, items in per_ip_r2.items():
            total = len(items)
            if total < min_timing_events:
                continue
            latencies = [float(x.get("latency_ms", 0.0)) for x in items if x.get("latency_ms") is not None]
            lstats = _calc_latency_stats(latencies)
            is_timing_anomaly = (
                lstats["stddev"] >= stddev_thresh
                or lstats["p95_p50_diff"] >= p95_diff_thresh
                or (lstats["bimodality_coefficient"] >= bimodal_thresh and total >= min_timing_events)
            )
            if is_timing_anomaly:
                if rules.get("soar_auto_block", True) and (lstats["is_bimodal"] or lstats["stddev"] >= stddev_thresh):
                    _trigger_soar_mitigation(ip, "timing_side_channel_oracle", "Timing Side-Channel Oracle", ttl_seconds=int(rules.get("soar_ban_ttl_seconds", 120)), endpoint=r2_ep)
                alerts.append(
                    {
                        "rule": "timing_side_channel_oracle",
                        "title": "Cryptographic Timing Side-Channel Oracle Detected",
                        "severity": "high",
                        "ip": ip,
                        "src_ip": ip,
                        "endpoint": r2_ep,
                        "confidence": 0.96 if lstats["is_bimodal"] else 0.90,
                        "mitre_technique": "T1595.002 - Active Scanning (Side-Channel Timing Analysis)",
                        "evidence": {
                            "endpoint": r2_ep,
                            "sample_size": lstats["count"],
                            "latency_stddev_ms": lstats["stddev"],
                            "latency_mean_ms": lstats["mean"],
                            "p50_ms": lstats["p50"],
                            "p95_ms": lstats["p95"],
                            "p95_p50_diff_ms": lstats["p95_p50_diff"],
                            "bimodality_coefficient": lstats["bimodality_coefficient"],
                            "is_bimodal": lstats["is_bimodal"],
                            "skewness": lstats["skewness"],
                            "kurtosis": lstats["kurtosis"],
                            "soar_mitigation_active": bool(rules.get("soar_auto_block", True)),
                        },
                        "recommended_action": "Abilita mitigazione crittografica Encrypt-then-MAC (victim-fixed) o inietta tarpit jitter",
                        "timestamp": items[-1].get("ts", datetime.now(timezone.utc).isoformat()),
                    }
                )

    # Regola 3: Sequential Block Probing Signature (scansione byte-by-byte su blocchi multipli di 16 con fallimenti)
    r3_dict = next((r for r in rules.get("rules", []) if r.get("id") == "rule_byte_probing"), {})
    r3_enabled = rules.get("rule_byte_probing_enabled", True) and r3_dict.get("enabled", True)
    r3_ep = r3_dict.get("endpoint", "/api/v1/crypto/decrypt")
    consec_errors_thresh = int(rules.get("block_probing_min_consecutive_errors", r3_dict.get("consecutive_errors", 15)))

    if r3_enabled:
        r3_events = [e for e in victim_events if _event_matches_endpoint(e, r3_ep)]
        per_ip_r3 = defaultdict(list)
        for ev in r3_events:
            per_ip_r3[ev.get("src_ip", "unknown")].append(ev)

        for ip, items in per_ip_r3.items():
            total = len(items)
            if total < consec_errors_thresh:
                continue
            failures = sum(1 for x in items if int(x.get("status_code", 0)) != 200)
            fail_rate = failures / total
            lengths = [int(x.get("ciphertext_len", 0)) for x in items if x.get("ciphertext_len")]
            unique_lengths = len(set(lengths))
            if failures >= consec_errors_thresh and fail_rate >= 0.70 and unique_lengths == 1 and lengths and lengths[0] % 16 == 0:
                alerts.append(
                    {
                        "rule": "cbc_block_probing_signature",
                        "title": "Sequential CBC Block Byte-Probing Pattern",
                        "severity": "medium",
                        "ip": ip,
                        "src_ip": ip,
                        "endpoint": r3_ep,
                        "confidence": 0.85,
                        "mitre_technique": "T1040 - Network & Protocol Probing",
                        "evidence": {
                            "endpoint": r3_ep,
                            "consecutive_probes": failures,
                            "target_ciphertext_len": lengths[0],
                            "is_aes_block": True,
                        },
                        "recommended_action": "Monitora sessione e applica rate-limiting progressivo",
                        "timestamp": items[-1].get("ts", datetime.now(timezone.utc).isoformat()),
                    }
                )

    # Regola 4: Authentication Brute-Force & Credential Spraying su /api/v1/auth/login (HTTP 401/403)
    r4_dict = next((r for r in rules.get("rules", []) if r.get("id") == "rule_auth_bruteforce"), {})
    r4_enabled = rules.get("rule_auth_bruteforce_enabled", True) and r4_dict.get("enabled", True)
    r4_ep = r4_dict.get("endpoint", "/api/v1/auth/login")
    r4_min = int(r4_dict.get("min_events", 5))
    r4_fail = float(r4_dict.get("fail_rate", 0.80))

    if r4_enabled:
        r4_events = [e for e in victim_events if _event_matches_endpoint(e, r4_ep)]
        per_ip_r4 = defaultdict(list)
        for ev in r4_events:
            per_ip_r4[ev.get("src_ip", "unknown")].append(ev)

        for ip, items in per_ip_r4.items():
            total = len(items)
            if total < r4_min:
                continue
            failures = sum(1 for x in items if int(x.get("status_code", 0)) in (401, 403, 429) or int(x.get("status_code", 0)) >= 400)
            fail_rate = failures / total
            if fail_rate >= r4_fail:
                if rules.get("soar_auto_block", True):
                    _trigger_soar_mitigation(ip, "auth_bruteforce_detected", "Authentication Brute-Force Shield", ttl_seconds=int(rules.get("soar_ban_ttl_seconds", 120)), endpoint=r4_ep)
                alerts.append(
                    {
                        "rule": "auth_bruteforce_detected",
                        "title": "Authentication Brute-Force & Credential Spraying Detected",
                        "severity": "high",
                        "ip": ip,
                        "src_ip": ip,
                        "endpoint": r4_ep,
                        "confidence": 0.95,
                        "mitre_technique": "T1110.001 - Password Spraying & Brute Force",
                        "evidence": {
                            "endpoint": r4_ep,
                            "total_requests": total,
                            "failed_auth_requests": failures,
                            "fail_rate": round(fail_rate, 3),
                            "soar_mitigation_active": bool(rules.get("soar_auto_block", True)),
                        },
                        "recommended_action": f"Blocca endpoint {r4_ep} per l'IP aggressore (SOAR Scoped Quarantine)",
                        "timestamp": items[-1].get("ts", datetime.now(timezone.utc).isoformat()),
                    }
                )

    # Regole addizionali/personalizzate definite dall'utente
    for cr in rules.get("rules", []):
        cid = cr.get("id", "")
        if cid in ("rule_error_flooding", "rule_timing_oracle", "rule_byte_probing", "rule_auth_bruteforce"):
            continue
        if not cr.get("enabled", True):
            continue
        cr_ep = cr.get("endpoint", "*")
        c_min = int(cr.get("min_events", rules.get("min_events_per_ip", 10)))
        c_fail = float(cr["fail_rate"]) if ("fail_rate" in cr and cr["fail_rate"] is not None) else 0.0
        c_timing = float(cr["timing_stddev"]) if ("timing_stddev" in cr and cr["timing_stddev"] is not None) else 0.0
        c_bimod = float(cr["bimodality"]) if ("bimodality" in cr and cr["bimodality"] is not None) else 0.0

        cr_events = [e for e in victim_events if _event_matches_endpoint(e, cr_ep)]
        per_ip_cr = defaultdict(list)
        for ev in cr_events:
            per_ip_cr[ev.get("src_ip", "unknown")].append(ev)

        for ip, items in per_ip_cr.items():
            total = len(items)
            if total < c_min:
                continue
            failures = sum(1 for x in items if int(x.get("status_code", 0)) != 200)
            fail_rate = failures / total if total > 0 else 0.0
            latencies = [float(x.get("latency_ms", 0.0)) for x in items if x.get("latency_ms") is not None]
            lstats = _calc_latency_stats(latencies)

            conds = []
            if c_fail > 0:
                conds.append(fail_rate >= c_fail)
            if c_timing > 0:
                conds.append(lstats["stddev"] >= c_timing)
            if c_bimod > 0:
                conds.append(lstats["bimodality_coefficient"] >= c_bimod)

            matches = any(conds) if conds else (fail_rate >= float(rules.get("high_fail_rate_threshold", 0.75)))
            if matches:
                target_alert_ep = cr_ep if cr_ep and cr_ep != "*" else (items[-1].get("endpoint") or "*")
                if rules.get("soar_auto_block", True) and (fail_rate >= 0.80 or lstats["is_bimodal"]):
                    _trigger_soar_mitigation(ip, cid, cr.get("name", "Custom SIEM Alert"), ttl_seconds=int(rules.get("soar_ban_ttl_seconds", 120)), endpoint=target_alert_ep)
                alerts.append(
                    {
                        "rule": cid,
                        "title": cr.get("name", "Custom SIEM Detection Alert"),
                        "severity": cr.get("severity", "high"),
                        "ip": ip,
                        "src_ip": ip,
                        "endpoint": target_alert_ep,
                        "confidence": 0.90,
                        "mitre_technique": cr.get("mitre", "T1110 - Brute Force / Probing"),
                        "evidence": {
                            "endpoint": target_alert_ep,
                            "total_requests": total,
                            "failed_requests": failures,
                            "fail_rate": round(fail_rate, 3),
                            "latency_stddev_ms": lstats["stddev"],
                            "bimodality_coefficient": lstats["bimodality_coefficient"],
                            "is_bimodal": lstats["is_bimodal"],
                        },
                        "recommended_action": f"Analizza sorgente malevola e applica isolamento su {target_alert_ep}",
                        "timestamp": items[-1].get("ts", datetime.now(timezone.utc).isoformat()),
                    }
                )

    return alerts


def _compute_soc_kpis(events: list[dict], alerts: list[dict]) -> dict:
    """Calcola metriche formali SOC: TPR, FPR, MTTD e profiling del traffico."""
    attacker_events = [
        e for e in events
        if e.get("service") == "attacker" or str(e.get("event_type", "")).startswith("attack")
    ]
    victim_events = [e for e in events if e.get("service") == "victim"]

    decrypts_by_ip = defaultdict(list)
    for e in victim_events:
        if e.get("endpoint") in ("/decrypt", "/api/v1/crypto/decrypt"):
            decrypts_by_ip[str(e.get("src_ip", "unknown"))].append(e)

    benign_decrypts = []
    attacker_decrypts = []

    for ip, items in decrypts_by_ip.items():
        total = len(items)
        fails = sum(1 for x in items if int(x.get("status_code", 0)) != 200)
        rate = fails / total if total > 0 else 0.0
        if ip == "attacker" or "attacker" in ip or (total >= 10 and rate >= 0.60):
            attacker_decrypts.extend(items)
        else:
            benign_decrypts.extend(items)

    benign_total = len(benign_decrypts)
    benign_fails = sum(1 for e in benign_decrypts if int(e.get("status_code", 0)) != 200)
    benign_fail_rate = round(benign_fails / benign_total, 3) if benign_total > 0 else 0.0
    benign_lats = [float(e.get("latency_ms", 0.0)) for e in benign_decrypts if e.get("latency_ms") is not None]
    benign_stats = _calc_latency_stats(benign_lats)

    attacker_total = len(attacker_decrypts)
    attacker_fails = sum(1 for e in attacker_decrypts if int(e.get("status_code", 0)) != 200)
    attacker_fail_rate = round(attacker_fails / attacker_total, 3) if attacker_total > 0 else 0.0
    attacker_lats = [float(e.get("latency_ms", 0.0)) for e in attacker_decrypts if e.get("latency_ms") is not None]
    attacker_stats = _calc_latency_stats(attacker_lats)

    alerted_ips = {a.get("ip") or a.get("src_ip") for a in alerts if (a.get("ip") or a.get("src_ip"))}
    has_attacker_alert = len(alerted_ips) > 0
    has_benign_alert = False
    for ip, items in decrypts_by_ip.items():
        total = len(items)
        fails = sum(1 for x in items if int(x.get("status_code", 0)) != 200)
        rate = fails / total if total > 0 else 0.0
        if rate < 0.20 and ip in alerted_ips:
            has_benign_alert = True

    is_attack_present = len(attacker_events) > 0 or len(attacker_decrypts) >= 15

    tpr = 1.0 if has_attacker_alert else (1.0 if not is_attack_present else 0.0)
    fpr = 1.0 if has_benign_alert else 0.0

    # MTTD (Mean Time to Detect in seconds) - robust matching against windowed events
    mttd_seconds = None
    if attacker_events and alerts:
        try:
            sorted_attack = sorted(
                [e for e in attacker_events if e.get("ts")],
                key=lambda x: str(x.get("ts"))
            )
            if sorted_attack:
                first_attack_ts = datetime.fromisoformat(str(sorted_attack[0].get("ts")).replace("Z", "+00:00"))
                relevant_alerts = []
                for a in alerts:
                    a_ts_str = str(a.get("timestamp", ""))
                    if a_ts_str:
                        try:
                            a_dt = datetime.fromisoformat(a_ts_str.replace("Z", "+00:00"))
                            if a_dt >= first_attack_ts:
                                relevant_alerts.append(a_dt)
                        except ValueError:
                            pass
                if relevant_alerts:
                    first_alert_ts = min(relevant_alerts)
                    diff = (first_alert_ts - first_attack_ts).total_seconds()
                    if diff >= 0:
                        mttd_seconds = round(diff, 2)
        except Exception:
            mttd_seconds = None

    ip_table = []
    for ip, items in decrypts_by_ip.items():
        total = len(items)
        fails = sum(1 for x in items if int(x.get("status_code", 0)) != 200)
        rate = round(fails / total, 3) if total > 0 else 0.0
        lats = [float(x.get("latency_ms", 0.0)) for x in items if x.get("latency_ms") is not None]
        stats = _calc_latency_stats(lats)
        is_alerted = ip in alerted_ips
        ip_table.append({
            "ip": ip,
            "requests": total,
            "failed_requests": fails,
            "fail_rate": rate,
            "latency_p50_ms": stats.get("p50", 0.0),
            "latency_stddev_ms": stats.get("stddev", 0.0),
            "is_alerted": is_alerted,
            "evaluation": "Violazione Rilevata (Exploit)" if is_alerted else "Conforme alla Baseline",
        })

    return {
        "true_positive_rate": tpr,
        "false_positive_rate": fpr,
        "mttd_seconds": mttd_seconds,
        "is_attack_active": is_attack_present,
        "ip_telemetry_table": ip_table,
        "baseline_profile": {
            "benign_requests": benign_total,
            "benign_fail_rate": benign_fail_rate,
            "benign_latency_p50_ms": benign_stats["p50"],
            "benign_latency_mean_ms": benign_stats["mean"],
            "benign_latency_stddev_ms": benign_stats["stddev"],
            "benign_bimodality_coefficient": benign_stats["bimodality_coefficient"],
        },
        "attacker_profile": {
            "attacker_requests": attacker_total,
            "attacker_fail_rate": attacker_fail_rate,
            "attacker_latency_stddev_ms": attacker_stats["stddev"],
            "attacker_latency_p95_p50_diff_ms": attacker_stats["p95_p50_diff"],
            "attacker_bimodality_coefficient": attacker_stats["bimodality_coefficient"],
            "attacker_is_bimodal": attacker_stats["is_bimodal"],
        },
    }


def _generate_sigma_rule(rules: dict, query_str: str = "") -> str:
    rule_id = uuid.uuid4().hex[:8]
    date_str = datetime.now(timezone.utc).strftime('%Y/%m/%d')
    endpoint = rules.get("endpoint") or "/decrypt"
    status_filter = 500
    if query_str:
        if "endpoint" in query_str:
            for part in query_str.split("AND"):
                if "endpoint" in part and "=" in part:
                    endpoint = part.split("=")[-1].strip().strip('"').strip("'")
        if "status" in query_str:
            for part in query_str.split("AND"):
                if "status" in part and "=" in part:
                    try:
                        status_filter = int(part.split("=")[-1].strip())
                    except ValueError:
                        pass

    min_events = rules.get('min_events_per_ip', 15)
    fail_rate = rules.get('high_fail_rate_threshold', 0.80)
    timing_std = rules.get('timing_stddev_threshold_ms', 6.0)
    try:
        timeframe_sec = max(5, int(rules.get('window_seconds', rules.get('timeframe', 60))))
    except (ValueError, TypeError):
        timeframe_sec = 60

    return f"""title: AES-CBC Cryptographic Padding Oracle & Side-Channel Exploit
id: {rule_id}-cbc-oracle-detect
status: production
description: |
  Detects active cryptographic attacks against CBC ciphers (Padding Oracle and Timing Side-Channels)
  characterized by anomalous decryption error bursts or bimodal latency variance on AES block multiples.
references:
  - https://attack.mitre.org/techniques/T1110/001/
  - https://attack.mitre.org/techniques/T1595/002/
author: SOC Threat Hunting Team
date: {date_str}
tags:
  - attack.brute_force
  - attack.t1110.001
  - attack.reconnaissance
  - attack.t1595.002
logsource:
  category: webserver
  service: victim
detection:
  selection_endpoint:
    endpoint:
      - '{endpoint}'
  selection_status:
    status_code:
      - {status_filter}
  timeframe: {timeframe_sec}s
  condition_error_rate:
    selection_endpoint and selection_status and count() >= {min_events} by src_ip
    and failure_rate >= {fail_rate}
  condition_timing_leakage:
    selection_endpoint and count() >= {rules.get('min_timing_events_per_ip', 20)} by src_ip
    and latency_stddev >= {timing_std}
  condition: condition_error_rate or condition_timing_leakage
fields:
  - src_ip
  - endpoint
  - status_code
  - latency_ms
  - ciphertext_len
falsepositives:
  - Legitimate client key mismatch during bulk rotation
level: critical
"""


@app.route("/hunting/explore", methods=["GET", "POST"])
def hunting_explore():
    rules = _load_rules()
    data = request.get_json(force=True, silent=True) if request.is_json else {}
    window_minutes = int(request.args.get("window_minutes", data.get("window_minutes", rules.get("collector_window_minutes", 0))))
    query_str = str(data.get("query") or request.args.get("query") or "").strip()

    events = _windowed_events(_read_events(), window_minutes)
    victim_events = [e for e in events if _is_victim_telemetry(e)]
    attacker_ips = {
        str(e.get("src_ip", ""))
        for e in events
        if not _is_victim_telemetry(e) and (e.get("service") == "attacker" or str(e.get("event_type", "")).startswith("attack"))
    }
    
    if query_str and query_str != "*":
        scoped_events = [e for e in victim_events if evaluate_event_query(e, query_str)]
    else:
        scoped_events = victim_events

    per_ip = defaultdict(list)
    for e in scoped_events:
        ip = str(e.get("src_ip", "unknown"))
        per_ip[ip].append(e)

    ip_profiles = []
    for ip, items in per_ip.items():
        total_scope_reqs = len(items)
        failed_scope_reqs = sum(1 for x in items if int(x.get("status_code", 0)) != 200)
        scope_fail_rate = round(failed_scope_reqs / total_scope_reqs, 3) if total_scope_reqs > 0 else 0.0

        decrypt_items = [x for x in items if _is_decrypt_event(x)]
        total_decrypts = len(decrypt_items)
        failed_decrypts = sum(1 for x in decrypt_items if int(x.get("status_code", 0)) != 200)
        padding_errors = sum(1 for x in items if x.get("error_type") == "padding_error" or int(x.get("status_code", 0)) == 500)
        
        # Max consecutive non-200 errors nello scope
        max_consec = 0
        curr_consec = 0
        for x in items:
            if int(x.get("status_code", 0)) != 200:
                curr_consec += 1
                if curr_consec > max_consec:
                    max_consec = curr_consec
            else:
                curr_consec = 0

        lengths = [int(x.get("ciphertext_len", 0)) for x in items if x.get("ciphertext_len")]
        unique_lengths = len(set(lengths))
        latencies = [float(x.get("latency_ms", 0.0)) for x in items if x.get("latency_ms") is not None]
        lstats = _calc_latency_stats(latencies)
        
        is_waf_blocked = any(int(x.get("status_code", 0)) == 429 or x.get("error_type") == "waf_blocked" for x in items)
        endpoints_seen = sorted(list(set(str(x.get("endpoint", "")) for x in items if x.get("endpoint"))))

        # Calculate Risk Score (0-100)
        score = 0
        req_count = total_scope_reqs
        eff_fail_rate = scope_fail_rate
        if req_count >= 10 and eff_fail_rate >= 0.70:
            score += 45
        if padding_errors >= 5 or max_consec >= 10:
            score += 30
        if lstats["is_bimodal"] or lstats["stddev"] >= 6.0:
            score += 25
        if any(l > 0 and l % 16 == 0 for l in lengths) and unique_lengths == 1 and req_count >= 15:
            score += 15
        score = min(100, score)

        if is_waf_blocked:
            classification = "QUARANTINED_WAF"
        elif score >= 75 or (eff_fail_rate >= 0.80 and any(l > 0 and l % 16 == 0 for l in lengths) and req_count >= 15):
            classification = "PADDING_ORACLE_ATTACKER"
        elif lstats["is_bimodal"] or (lstats["stddev"] >= 6.0 and req_count >= 15):
            classification = "TIMING_SIDE_CHANNEL_EXPLOITER"
        elif req_count >= 20 and eff_fail_rate >= 0.40:
            classification = "SUSPECT_SCANNER"
        else:
            classification = "BENIGN_CLIENT"

        # Verifica se l'IP è noto come attaccante (storico o recente)
        is_attacker_origin = ip in attacker_ips or any(
            x.get("service") == "attacker"
            or str(x.get("event_type", "")).startswith("attack")
            or str(x.get("details", {}).get("client_role", "")) == "attacker"
            for x in items
        )
        # Rileva attività recente negli ultimi 15 secondi
        now_utc = datetime.now(timezone.utc)
        recent_cutoff = now_utc - timedelta(seconds=15)
        has_recent_activity = False
        for x in items:
            ts_str = x.get("ts")
            if ts_str:
                try:
                    ev_dt = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
                    if ev_dt >= recent_cutoff:
                        has_recent_activity = True
                        break
                except ValueError:
                    pass

        is_currently_active_attacker = is_attacker_origin and has_recent_activity

        ip_profiles.append({
            "ip": ip,
            "total_events": len(items),
            "total_requests": total_scope_reqs,
            "failed_requests": failed_scope_reqs,
            "decrypt_requests": total_decrypts,
            "failed_decrypts": failed_decrypts,
            "fail_rate": eff_fail_rate,
            "is_attacker_origin": is_attacker_origin,
            "is_currently_active_attacker": is_currently_active_attacker,
            "padding_errors": padding_errors,
            "max_consecutive_errors": max_consec,
            "unique_lengths": unique_lengths,
            "sample_ciphertext_len": lengths[0] if lengths else 0,
            "is_aes_aligned": any(l > 0 and l % 16 == 0 for l in lengths),
            "latency_stats": lstats,
            "risk_score": score,
            "classification": classification,
            "endpoints": endpoints_seen,
        })

    scope_endpoints = sorted(list({str(e.get("endpoint", "")) for e in scoped_events if e.get("endpoint")}))
    scope_stats = {
        "query": query_str or "*",
        "total_events": len(scoped_events),
        "total_requests": len(scoped_events),
        "failed_requests": sum(1 for e in scoped_events if int(e.get("status_code", 0)) != 200),
        "endpoints": scope_endpoints,
    }

    return jsonify({
        "ok": True,
        "window_minutes": window_minutes,
        "query": query_str,
        "total_events": len(scoped_events),
        "scope_stats": scope_stats,
        "ip_profiles": ip_profiles,
        "active_rules": rules,
    })


@app.route("/hunting/query", methods=["GET", "POST"])
def hunting_query():
    """Filtra i log grezzi secondo la query SIEM (Lucene/KQL-like) e restituisce aggregazioni."""
    data = request.get_json(force=True, silent=True) or {}
    query_str = data.get("query", request.args.get("query", ""))
    rules = _load_rules()
    window_minutes = int(data.get("window_minutes", request.args.get("window_minutes", rules.get("collector_window_minutes", 0))))
    events = _windowed_events(_read_events(), window_minutes)
    victim_events = [e for e in events if _is_victim_telemetry(e)]
    result = filter_and_aggregate_events(victim_events, query_str)
    result["ok"] = True
    result["window_minutes"] = window_minutes
    return jsonify(result)


@app.route("/hunting/backtest", methods=["GET", "POST"])
def hunting_backtest():
    """Esegue un backtesting live di una regola candidata sui log storici."""
    candidate_rules = _load_rules()
    data = request.get_json(force=True, silent=True) or {}
    candidate_rules.update({k: data[k] for k in candidate_rules if k in data})
    if "window_seconds" in data:
        try:
            candidate_rules["window_seconds"] = max(5, int(data["window_seconds"]))
        except (ValueError, TypeError):
            pass
    if "endpoint" in data:
        candidate_rules["endpoint"] = data["endpoint"]

    window_minutes = int(data.get("window_minutes", request.args.get("window_minutes", candidate_rules.get("collector_window_minutes", 0))))
    events = _windowed_events(_read_events(), window_minutes)
    victim_events = [e for e in events if _is_victim_telemetry(e)]
    
    rule_endpoint = str(candidate_rules.get("endpoint", "") or "").strip()
    if rule_endpoint and rule_endpoint not in ("*", "/"):
        target_events = [e for e in victim_events if _event_matches_endpoint(e, rule_endpoint)]
    elif rule_endpoint in ("*", "/"):
        target_events = victim_events
    else:
        target_events = [e for e in victim_events if _is_decrypt_event(e)]

    per_ip = defaultdict(list)
    for ev in target_events:
        per_ip[ev.get("src_ip", "unknown")].append(ev)

    intercepted_ips = set()
    evaluation_details = []

    for ip, items in per_ip.items():
        total = len(items)
        if total == 0:
            continue
        failures = sum(1 for x in items if int(x.get("status_code", 0)) != 200)
        fail_rate = failures / total
        latencies = [float(x.get("latency_ms", 0.0)) for x in items if x.get("latency_ms") is not None]
        lstats = _calc_latency_stats(latencies)

        min_reqs = int(candidate_rules.get("min_events_per_ip", 15))
        fail_thresh = float(candidate_rules.get("high_fail_rate_threshold", 0.80))
        stddev_thresh = float(candidate_rules.get("timing_stddev_threshold_ms", 6.0))
        bimodal_thresh = float(candidate_rules.get("bimodality_threshold", 0.555))

        triggered_reasons = []
        if total >= min_reqs and fail_rate >= fail_thresh:
            triggered_reasons.append(f"High Fail-Rate ({fail_rate*100:.1f}% >= {fail_thresh*100:.1f}%)")
        if total >= min_reqs and (lstats["stddev"] >= stddev_thresh or lstats["bimodality_coefficient"] >= bimodal_thresh):
            triggered_reasons.append(f"Timing Anomaly (stddev={lstats['stddev']}ms, BC={lstats['bimodality_coefficient']})")

        is_flagged = len(triggered_reasons) > 0
        if is_flagged:
            intercepted_ips.add(ip)

        evaluation_details.append({
            "ip": ip,
            "requests": total,
            "fail_rate": round(fail_rate, 3),
            "latency_stddev": lstats["stddev"],
            "bimodality_coeff": lstats["bimodality_coefficient"],
            "flagged": is_flagged,
            "reasons": triggered_reasons,
        })

    has_attacker_intercepted = any("attacker" in ip for ip in intercepted_ips)
    has_benign_intercepted = any(str(ip).startswith("benign") for ip in intercepted_ips)

    tpr = 1.0 if has_attacker_intercepted else (1.0 if not any("attacker" in str(e.get("src_ip","")) for e in target_events) else 0.0)
    fpr = 1.0 if has_benign_intercepted else 0.0

    sigma_rule_yaml = _generate_sigma_rule(candidate_rules, query_str=data.get("query", ""))

    return jsonify({
        "ok": True,
        "candidate_rules": candidate_rules,
        "evaluated_ips_count": len(per_ip),
        "intercepted_ips": list(intercepted_ips),
        "true_positive_rate": tpr,
        "false_positive_rate": fpr,
        "evaluation_details": evaluation_details,
        "sigma_rule_yaml": sigma_rule_yaml,
    })


@app.post("/api/v1/events")
@app.post("/events")
def ingest_event():
    """Endpoint di Ingestion diretta: inserisce l'evento in SQLite WAL, memory buffer e cold JSONL."""
    event = request.get_json(force=True, silent=True)
    if not isinstance(event, dict):
        return jsonify({"ok": False, "error": "Invalid JSON event body"}), 400

    event.setdefault("event_id", str(uuid.uuid4()))
    event.setdefault("ts", datetime.now(timezone.utc).isoformat())
    service_name = str(event.get("service", "unknown"))

    with _LOG_SYNC_LOCK:
        _MEMORY_LOG_BUFFER.append(event)

    _save_event_sqlite(event)

    # Append atomico a cold storage JSONL
    try:
        log_file = os.path.join(LOG_DIR, f"{service_name}.jsonl")
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, separators=(",", ":")) + "\n")
    except Exception:
        pass

    return jsonify({"ok": True, "event_id": event.get("event_id")}), 201


@app.get("/health")
def health():
    return jsonify({
        "status": "ok",
        "log_dir": LOG_DIR,
        "rules": _load_rules(),
        "storage": "sqlite_wal_and_jsonl",
        "soar_enabled": SOAR_ENABLED,
    })


@app.get("/metrics")
def metrics():
    rules = _load_rules()
    window_minutes = int(rules.get("collector_window_minutes", WINDOW_MINUTES))
    events = _windowed_events(_read_events(), window_minutes)
    by_service = defaultdict(int)
    for e in events:
        by_service[e.get("service", "unknown")] += 1
    
    alerts = _build_alerts(events)
    kpis = _compute_soc_kpis(events, alerts)

    return jsonify(
        {
            "window_minutes": window_minutes,
            "event_count": len(events),
            "events_by_service": dict(by_service),
            "alerts_count": len(alerts),
            "detection_kpis": kpis,
            "rules": rules,
        }
    )


@app.get("/alerts")
def alerts():
    rules = _load_rules()
    events = _windowed_events(_read_events(), int(rules.get("collector_window_minutes", WINDOW_MINUTES)))
    alerts_list = _build_alerts(events)
    kpis = _compute_soc_kpis(events, alerts_list)
    return jsonify({"alerts": alerts_list, "kpis": kpis, "rules": rules})


@app.get("/forensics/report")
def forensics_report():
    """Genera una struttura dati completa per il report forense d'esame."""
    rules = _load_rules()
    events = _windowed_events(_read_events(), int(rules.get("collector_window_minutes", WINDOW_MINUTES)))
    victim_events = [e for e in events if _is_victim_telemetry(e)]
    alerts_list = _build_alerts(victim_events)
    kpis = _compute_soc_kpis(events, alerts_list)
    
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_events_analyzed": len(victim_events),
            "total_alerts_generated": len(alerts_list),
            "mttd_seconds": kpis.get("mttd_seconds"),
            "true_positive_rate": kpis.get("true_positive_rate"),
            "false_positive_rate": kpis.get("false_positive_rate"),
        },
        "alerts": alerts_list,
        "kpis": kpis,
        "rules_applied": rules,
    }
    return jsonify(report)


@app.post("/logs/clear")
def logs_clear():
    with _LOG_SYNC_LOCK:
        _MEMORY_LOG_BUFFER.clear()
        _FILE_BYTE_OFFSETS.clear()
    with _DB_LOCK:
        try:
            _DB_CONN.execute("DELETE FROM events;")
            _DB_CONN.commit()
            _DB_CONN.execute("PRAGMA wal_checkpoint(TRUNCATE);")
            _DB_CONN.execute("VACUUM;")
        except Exception:
            pass

    log_dirs = [
        LOG_DIR,
        "/logs",
        "/app/runtime-logs",
        os.path.join(LAB_ROOT, "runtime-logs"),
    ]
    cleared_paths = set()
    for d in log_dirs:
        if os.path.exists(d):
            for path in sorted(glob(os.path.join(d, "*.jsonl"))):
                try:
                    p_res = os.path.realpath(path)
                except Exception:
                    p_res = path
                if p_res in cleared_paths:
                    continue
                cleared_paths.add(p_res)
                try:
                    with open(path, "w", encoding="utf-8") as f:
                        f.truncate(0)
                except Exception:
                    pass
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8090)



