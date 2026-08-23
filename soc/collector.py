import json
import math
import os
import statistics
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from glob import glob

from flask import Flask, jsonify, request

from common.siem_query import filter_and_aggregate_events


app = Flask(__name__)
LOG_DIR = os.getenv("LOG_DIR", "/logs")
WINDOW_MINUTES = int(os.getenv("SOC_WINDOW_MINUTES", "15"))
ALERT_RULES_FILE = os.getenv(
    "ALERT_RULES_FILE",
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "control", "alert_rules.json"),
)


def _load_rules() -> dict:
    defaults = {
        "enabled": False,
        "min_events_per_ip": 25,
        "high_fail_rate_threshold": 0.85,
        "collector_window_minutes": 15,
        "timing_stddev_threshold_ms": 6.0,
        "timing_p95_p50_diff_threshold_ms": 12.0,
        "bimodality_threshold": 0.555,
        "min_timing_events_per_ip": 20,
        "block_probing_min_consecutive_errors": 15,
    }
    try:
        if os.path.exists(ALERT_RULES_FILE):
            with open(ALERT_RULES_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    defaults.update({k: data[k] for k in defaults.keys() if k in data})
    except Exception:
        pass
    return defaults


def _read_events() -> list[dict]:
    events = []
    for path in sorted(glob(os.path.join(LOG_DIR, "*.jsonl"))):
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except Exception:
            continue
    return events


def _windowed_events(events: list[dict], window_minutes: int) -> list[dict]:
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
    """Calcola statistiche avanzate di latenza inclusi momenti centrali (skewness, kurtosis)

    e il coefficiente di bimodalità di Sarle (BC = (skewness^2 + 1) / kurtosis).
    Un valore BC > 0.555 indica una distribuzione bimodale/multimodale, firma matematica dei side-channel.
    """
    if not latencies:
        return {
            "count": 0,
            "mean": 0.0,
            "stddev": 0.0,
            "p50": 0.0,
            "p95": 0.0,
            "p95_p50_diff": 0.0,
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
    p50_idx = int(n * 0.50)
    p95_idx = min(int(n * 0.95), n - 1)
    p50_val = sorted_lats[p50_idx]
    p95_val = sorted_lats[p95_idx]

    # Calcolo momenti centrali per Skewness, Kurtosis e Sarle's Bimodality Coefficient
    m2 = sum((x - mean_val) ** 2 for x in sorted_lats) / n
    m3 = sum((x - mean_val) ** 3 for x in sorted_lats) / n
    m4 = sum((x - mean_val) ** 4 for x in sorted_lats) / n

    if m2 > 1e-9 and n >= 4:
        skewness_val = m3 / (m2 ** 1.5)
        kurtosis_val = m4 / (m2 ** 2)  # Pearson's kurtosis (normale = 3.0)
        if kurtosis_val > 0:
            bimodality_coeff = min(1.0, (skewness_val ** 2 + 1.0) / kurtosis_val)
        else:
            bimodality_coeff = 0.333
    else:
        skewness_val = 0.0
        kurtosis_val = 3.0
        bimodality_coeff = 0.333

    is_bimodal_val = bool(bimodality_coeff > 0.555 and n >= 8)

    return {
        "count": n,
        "mean": round(mean_val, 2),
        "stddev": round(std_val, 2),
        "p50": round(p50_val, 2),
        "p95": round(p95_val, 2),
        "p95_p50_diff": round(p95_val - p50_val, 2),
        "min": round(sorted_lats[0], 2),
        "max": round(sorted_lats[-1], 2),
        "skewness": round(skewness_val, 3),
        "kurtosis": round(kurtosis_val, 3),
        "bimodality_coefficient": round(bimodality_coeff, 3),
        "is_bimodal": is_bimodal_val,
    }


def _build_alerts(events: list[dict], custom_rules: dict | None = None) -> list[dict]:
    if custom_rules is not None:
        rules = _load_rules()
        rules.update(custom_rules)
        if "enabled" not in custom_rules:
            rules["enabled"] = True
    else:
        rules = _load_rules()

    alerts = []

    # WAF Preventive Block Events (always captured if present)
    waf_events = [
        e for e in events
        if e.get("service") == "victim" and (e.get("status_code") == 429 or e.get("error_type") == "waf_blocked")
    ]
    if waf_events:
        waf_ips = {e.get("src_ip", "unknown") for e in waf_events}
        for ip in sorted(waf_ips):
            ip_waf_evs = [e for e in waf_events if e.get("src_ip") == ip]
            alerts.append(
                {
                    "rule": "waf_padding_oracle_blocked",
                    "title": "🛡️ Inline WAF: Active Exploit Neutralized (HTTP 429)",
                    "severity": "critical",
                    "ip": ip,
                    "confidence": 1.0,
                    "mitre_technique": "T1110.001 - Brute Force (Mitigated by WAF)",
                    "evidence": {
                        "blocked_requests": len(ip_waf_evs),
                        "action": "HTTP 429 Preventive Drop before AES-CBC Decrypt Engine",
                        "attack_neutralized": True,
                    },
                    "recommended_action": "Mantieni quarantena IP o applica ban permanente L7",
                    "timestamp": ip_waf_evs[-1].get("ts", datetime.now(timezone.utc).isoformat()),
                }
            )

    # If detection rules are disabled, do not generate proactive detection alerts
    if not rules.get("enabled", False):
        return alerts

    per_ip = defaultdict(list)
    decrypt_events = [
        e for e in events if e.get("service") == "victim" and e.get("endpoint") == "/decrypt"
    ]
    for ev in decrypt_events:
        per_ip[ev.get("src_ip", "unknown")].append(ev)

    for ip, items in per_ip.items():
        total = len(items)
        if total == 0:
            continue

        failures = sum(1 for x in items if int(x.get("status_code", 0)) != 200)
        padding_err_count = sum(1 for x in items if x.get("error_type") == "padding_error")
        fail_rate = failures / total
        lengths = [int(x.get("ciphertext_len", 0)) for x in items if x.get("ciphertext_len")]
        unique_lengths = len(set(lengths))
        latencies = [float(x.get("latency_ms", 0.0)) for x in items if x.get("latency_ms") is not None]
        lstats = _calc_latency_stats(latencies)

        # Regola 1: Error-rate Padding Oracle su victim-vuln (o errori espliciti status 500 / padding_error)
        is_explicit_oracle = padding_err_count > 0 or any(x.get("status_code") == 500 for x in items)
        if total >= int(rules["min_events_per_ip"]) and fail_rate >= float(rules["high_fail_rate_threshold"]) and is_explicit_oracle:
            alerts.append(
                {
                    "rule": "high_fail_rate_padding_oracle",
                    "title": "AES-CBC Padding Oracle Exploit (Error Flooding)",
                    "severity": "critical",
                    "ip": ip,
                    "confidence": 0.98,
                    "mitre_technique": "T1110.001 - Brute Force (Padding Oracle)",
                    "evidence": {
                        "total_requests": total,
                        "failed_requests": failures,
                        "fail_rate": round(fail_rate, 3),
                        "padding_errors": padding_err_count,
                        "unique_lengths": unique_lengths,
                        "block_aligned": any(l > 0 and l % 16 == 0 for l in lengths),
                    },
                    "recommended_action": "Hot-Patch to victim-fixed o Blocca IP sorgente (SOAR Playbook)",
                    "timestamp": items[-1].get("ts", datetime.now(timezone.utc).isoformat()),
                }
            )

        # Regola 2: Timing Side-Channel Oracle su victim-partial (status 403 generico ma latenza bimodale / dispersione temporale)
        stddev_thresh = float(rules.get("timing_stddev_threshold_ms", 6.0))
        p95_diff_thresh = float(rules.get("timing_p95_p50_diff_threshold_ms", 12.0))
        bimodal_thresh = float(rules.get("bimodality_threshold", 0.555))
        min_timing_events = int(rules.get("min_timing_events_per_ip", 20))

        is_timing_anomaly = (
            lstats["stddev"] >= stddev_thresh
            or lstats["p95_p50_diff"] >= p95_diff_thresh
            or (lstats["bimodality_coefficient"] >= bimodal_thresh and total >= min_timing_events)
        )

        if total >= min_timing_events and is_timing_anomaly:
            alerts.append(
                {
                    "rule": "timing_side_channel_oracle",
                    "title": "Cryptographic Timing Side-Channel Oracle Detected",
                    "severity": "high",
                    "ip": ip,
                    "confidence": 0.96 if lstats["is_bimodal"] else 0.90,
                    "mitre_technique": "T1595.002 - Active Scanning (Side-Channel Timing Analysis)",
                    "evidence": {
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
                    },
                    "recommended_action": "Abilita mitigazione costante-tempo (victim-fixed) o inietta tarpit jitter",
                    "timestamp": items[-1].get("ts", datetime.now(timezone.utc).isoformat()),
                }
            )

        # Regola 3: Sequential Block Probing Signature (scansione byte-by-byte su blocchi multipli di 16 con fallimenti)
        consec_errors_thresh = int(rules.get("block_probing_min_consecutive_errors", 15))
        if failures >= consec_errors_thresh and fail_rate >= 0.70 and unique_lengths == 1 and lengths and lengths[0] % 16 == 0:
            alerts.append(
                {
                    "rule": "cbc_block_probing_signature",
                    "title": "Sequential CBC Block Byte-Probing Pattern",
                    "severity": "medium",
                    "ip": ip,
                    "confidence": 0.85,
                    "mitre_technique": "T1040 - Network & Protocol Probing",
                    "evidence": {
                        "consecutive_probes": failures,
                        "target_ciphertext_len": lengths[0],
                        "is_aes_block": True,
                    },
                    "recommended_action": "Monitora sessione e applica rate-limiting progressivo",
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

    # Baseline Benign Profile
    benign_decrypts = [e for e in victim_events if str(e.get("src_ip", "")).startswith("benign")]
    benign_total = len(benign_decrypts)
    benign_fails = sum(1 for e in benign_decrypts if int(e.get("status_code", 0)) != 200)
    benign_fail_rate = round(benign_fails / benign_total, 3) if benign_total > 0 else 0.0
    benign_lats = [float(e.get("latency_ms", 0.0)) for e in benign_decrypts if e.get("latency_ms") is not None]
    benign_stats = _calc_latency_stats(benign_lats)

    # Attacker Profile
    attacker_decrypts = [e for e in victim_events if str(e.get("src_ip", "")) == "attacker"]
    attacker_total = len(attacker_decrypts)
    attacker_fails = sum(1 for e in attacker_decrypts if int(e.get("status_code", 0)) != 200)
    attacker_fail_rate = round(attacker_fails / attacker_total, 3) if attacker_total > 0 else 0.0
    attacker_lats = [float(e.get("latency_ms", 0.0)) for e in attacker_decrypts if e.get("latency_ms") is not None]
    attacker_stats = _calc_latency_stats(attacker_lats)

    # Detection KPIs: TPR, FPR, MTTD
    alerted_ips = {a.get("ip") for a in alerts}
    has_attacker_alert = "attacker" in alerted_ips or any("attacker" in str(ip) for ip in alerted_ips)
    has_benign_alert = any(str(ip).startswith("benign") for ip in alerted_ips)

    is_attack_present = len(attacker_events) > 0 or len(attacker_decrypts) >= 20

    # True Positive Rate (TPR)
    if is_attack_present:
        tpr = 1.0 if has_attacker_alert else 0.0
    else:
        tpr = 1.0  # Nessun attacco presente, non mancato

    # False Positive Rate (FPR)
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

    return {
        "is_attack_active": is_attack_present,
        "true_positive_rate": tpr,
        "false_positive_rate": fpr,
        "mttd_seconds": mttd_seconds,
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


def _generate_sigma_rule(rules: dict) -> str:
    rule_id = uuid.uuid4().hex[:8]
    date_str = datetime.now(timezone.utc).strftime('%Y/%m/%d')
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
  category: application
  product: padding_oracle_victim
detection:
  selection_endpoint:
    endpoint: '/decrypt'
  selection_failures:
    status_code:
      - 400
      - 403
      - 500
  condition_error_rate:
    selection_endpoint and count() >= {rules.get('min_events_per_ip', 15)} by src_ip
    and failure_rate >= {rules.get('high_fail_rate_threshold', 0.80)}
  condition_timing_leakage:
    selection_endpoint and count() >= {rules.get('min_timing_events_per_ip', 20)} by src_ip
    and (latency_stddev >= {rules.get('timing_stddev_threshold_ms', 6.0)} or sarle_bimodality_coefficient >= {rules.get('bimodality_threshold', 0.555)})
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


@app.get("/hunting/explore")
def hunting_explore():
    """Aggrega i log grezzi per la vista Threat Hunting con profilazione approfondita."""
    rules = _load_rules()
    window_minutes = int(rules.get("collector_window_minutes", WINDOW_MINUTES))
    events = _windowed_events(_read_events(), window_minutes)
    
    per_ip = defaultdict(list)
    for e in events:
        ip = str(e.get("src_ip", "unknown"))
        per_ip[ip].append(e)

    ip_profiles = []
    for ip, items in per_ip.items():
        decrypt_items = [x for x in items if x.get("service") == "victim" and x.get("endpoint") == "/decrypt"]
        total_decrypts = len(decrypt_items)
        failed_decrypts = sum(1 for x in decrypt_items if int(x.get("status_code", 0)) != 200)
        fail_rate = round(failed_decrypts / total_decrypts, 3) if total_decrypts > 0 else 0.0
        
        lengths = [int(x.get("ciphertext_len", 0)) for x in decrypt_items if x.get("ciphertext_len")]
        unique_lengths = len(set(lengths))
        latencies = [float(x.get("latency_ms", 0.0)) for x in decrypt_items if x.get("latency_ms") is not None]
        lstats = _calc_latency_stats(latencies)
        
        is_attacker_signature = (
            (total_decrypts >= 10 and fail_rate >= 0.70 and (unique_lengths == 1 and lengths and lengths[0] % 16 == 0))
            or lstats["is_bimodal"]
            or (ip == "attacker" or "attacker" in ip)
        )
        
        ip_profiles.append({
            "ip": ip,
            "total_events": len(items),
            "decrypt_requests": total_decrypts,
            "failed_decrypts": failed_decrypts,
            "fail_rate": fail_rate,
            "unique_lengths": unique_lengths,
            "sample_ciphertext_len": lengths[0] if lengths else 0,
            "is_aes_aligned": any(l > 0 and l % 16 == 0 for l in lengths),
            "latency_stats": lstats,
            "classification": "SUSPECT_ATTACKER" if is_attacker_signature else "BENIGN_CLIENT",
        })

    return jsonify({
        "ok": True,
        "window_minutes": window_minutes,
        "total_events": len(events),
        "ip_profiles": ip_profiles,
        "active_rules": rules,
    })


@app.post("/hunting/query")
def hunting_query():
    """Filtra i log grezzi secondo la query SIEM (Lucene/KQL-like) e restituisce aggregazioni."""
    data = request.get_json(force=True, silent=True) or {}
    query_str = data.get("query", "")
    rules = _load_rules()
    window_minutes = int(data.get("window_minutes", rules.get("collector_window_minutes", WINDOW_MINUTES)))
    events = _windowed_events(_read_events(), window_minutes)
    result = filter_and_aggregate_events(events, query_str)
    result["ok"] = True
    result["window_minutes"] = window_minutes
    return jsonify(result)


@app.post("/hunting/backtest")
def hunting_backtest():
    """Esegue un backtesting live di una regola candidata sui log storici."""
    candidate_rules = _load_rules()
    data = request.get_json(force=True, silent=True) or {}
    candidate_rules.update({k: data[k] for k in candidate_rules if k in data})

    window_minutes = int(candidate_rules.get("collector_window_minutes", WINDOW_MINUTES))
    events = _windowed_events(_read_events(), window_minutes)
    
    per_ip = defaultdict(list)
    decrypt_events = [e for e in events if e.get("service") == "victim" and e.get("endpoint") == "/decrypt"]
    for ev in decrypt_events:
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

    tpr = 1.0 if has_attacker_intercepted else (1.0 if not any("attacker" in str(e.get("src_ip","")) for e in decrypt_events) else 0.0)
    fpr = 1.0 if has_benign_intercepted else 0.0

    sigma_rule_yaml = _generate_sigma_rule(candidate_rules)

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


@app.get("/health")
def health():
    return jsonify({"status": "ok", "log_dir": LOG_DIR, "rules": _load_rules()})


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
    alerts_list = _build_alerts(events)
    kpis = _compute_soc_kpis(events, alerts_list)
    
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_events_analyzed": len(events),
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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8090)



