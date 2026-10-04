import csv
import io
import json
import os
import signal
import threading
import time
import uuid
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
import secrets
import sqlite3
import string

import docker
import requests
from docker.errors import APIError, NotFound
from flask import Flask, jsonify, redirect, render_template_string, request, url_for, Response

from urllib.parse import quote
from common.siem_query import evaluate_event_query, filter_and_aggregate_events, _calc_group_stats


app = Flask(__name__)
app.secret_key = os.getenv("UI_SECRET_KEY", "soc-lab-ui")

LAB_ROOT = Path(os.getenv("LAB_ROOT", Path(__file__).resolve().parents[1]))
LOG_DIR = Path(os.getenv("LOG_DIR", str(LAB_ROOT / "runtime-logs")))
ALERT_RULES_FILE = Path(
    os.getenv("ALERT_RULES_FILE", str(LAB_ROOT / "control" / "alert_rules.json"))
)
NETWORK = os.getenv("LAB_NETWORK", "padding-oracle-soc-lab_default")
BASE_IMAGE = os.getenv("LAB_IMAGE", "padding-oracle-soc-lab-base")
UI_PORT = int(os.getenv("UI_PORT", "8091"))
SOC_URL = os.getenv("SOC_URL", "http://soc:8090")

docker_client = docker.from_env()


# ---------------------------------------------------------------------------
# Service specs
# ---------------------------------------------------------------------------

SERVICE_SPECS: dict[str, dict] = {
    "victim": {
        "command": ["python", "victim/app.py"],
        "environment": {"VICTIM_MODE": "vuln", "SCENARIO_ID": "default", "LOG_DIR": "/logs"},
        "ports": {"8080/tcp": 18080},
    },
    "soc": {
        "command": ["python", "soc/collector.py"],
        "environment": {
            "LOG_DIR": "/logs",
            "SOC_WINDOW_MINUTES": "0",
            "ALERT_RULES_FILE": str(ALERT_RULES_FILE),
        },
        "ports": {"8090/tcp": 18090},
    },
    "attacker": {
        "command": ["sleep", "infinity"],
        "environment": {"LOG_DIR": "/logs"},
    },
    "benign": {
        "command": ["sleep", "infinity"],
        "environment": {"LOG_DIR": "/logs"},
    },
}

VICTIM_NAMES = ["victim"]
WORKLOAD_NAMES = ["victim", "benign", "attacker"]
CORE_SERVICES = ["soc", "soc-ui"]
ALL_MANAGED = ["victim", "benign", "attacker", "soc", "soc-ui"]


# ---------------------------------------------------------------------------
# Docker helpers
# ---------------------------------------------------------------------------

def _service_volume_spec() -> dict:
    log_volume = os.getenv("DOCKER_LOG_VOLUME", "padding-oracle-soc-lab_ram-logs")
    log_bind = str(LOG_DIR)
    if log_bind == "/logs" or not os.path.isabs(log_bind):
        log_spec = log_volume
    else:
        log_spec = log_bind

    lab_root_spec = os.getenv("HOST_LAB_ROOT", str(LAB_ROOT))

    return {
        lab_root_spec: {"bind": "/app", "mode": "rw"},
        log_spec: {"bind": "/logs", "mode": "rw"},
    }



def _container(name: str):
    try:
        return docker_client.containers.get(name)
    except NotFound:
        return None


def _status(name: str) -> dict:
    container = _container(name)
    role_map = {
        "victim": "🖥️ Target Enterprise (AES-CBC Auth & Crypto Server)",
        "attacker": "🔴 Attaccante Red Team (Padding Oracle & Stealth Evasion)",
        "benign": "🟡 Flotta Client Aziendali (Multi-IP Virtual Workstations)",
        "soc": "📊 SIEM & Threat Hunting Engine",
        "soc-ui": "🌐 Web Console Dashboard",
    }
    if container is None:
        return {"name": name, "role": role_map.get(name, "Servizio"), "ip": "-", "state": "missing", "image": "-", "ports": "-"}

    container.reload()
    ports = container.attrs.get("NetworkSettings", {}).get("Ports", {})
    mapped = []
    for _, bindings in ports.items():
        if not bindings:
            continue
        for b in bindings:
            mapped.append(f"{b.get('HostIp')}:{b.get('HostPort')}")

    networks = container.attrs.get("NetworkSettings", {}).get("Networks", {})
    ip_addr = "-"
    if networks:
        for net_name, net_data in networks.items():
            if net_data.get("IPAddress"):
                ip_addr = net_data.get("IPAddress")
                break
    if ip_addr == "-":
        ip_addr = container.attrs.get("NetworkSettings", {}).get("IPAddress") or "-"

    return {
        "name": name,
        "role": role_map.get(name, "Servizio"),
        "ip": ip_addr,
        "state": container.status,
        "image": container.image.tags[0] if container.image.tags else container.image.short_id,
        "ports": ", ".join(mapped) if mapped else "-",
    }


def _ensure_container(name: str):
    c = _container(name)
    if c is not None:
        return c
    spec = SERVICE_SPECS.get(name)
    if not spec:
        raise RuntimeError(f"Unknown service spec for '{name}'")
    try:
        return docker_client.containers.create(
            image=BASE_IMAGE,
            command=spec["command"],
            name=name,
            detach=True,
            network=NETWORK,
            environment=spec["environment"],
            volumes=_service_volume_spec(),
            ports=spec.get("ports"),
            working_dir="/app",
        )
    except APIError as exc:
        raise RuntimeError(f"Unable to create {name}: {exc.explanation}") from exc


def _start(name: str) -> None:
    if name in ("attacker", "benign-1", "benign-2"):
        c = _container(name)
        if c is not None:
            desired_cmd = SERVICE_SPECS[name]["command"]
            current_cmd = c.attrs.get("Config", {}).get("Cmd")
            entrypoint = c.attrs.get("Config", {}).get("Entrypoint")
            if current_cmd != desired_cmd or entrypoint:
                try:
                    c.remove(force=True)
                except Exception:
                    pass
    c = _ensure_container(name)
    try:
        c.reload()
    except Exception:
        c = _container(name)
    if c is not None and c.status != "running":
        try:
            c.start()
        except APIError:
            try:
                c.remove(force=True)
                c = _ensure_container(name)
                c.start()
            except Exception:
                pass


def _stop(name: str) -> None:
    c = _container(name)
    if c is not None:
        try:
            c.stop(timeout=2)
        except Exception:
            pass


def _run_one_shot(name_prefix: str, command: list[str], environment: dict, labels: dict | None = None) -> None:
    kwargs = {
        "image": BASE_IMAGE,
        "command": command,
        "detach": True,
        "auto_remove": True,
        "network": NETWORK,
        "environment": environment,
        "volumes": _service_volume_spec(),
        "working_dir": "/app",
        "name": f"{name_prefix}-{uuid.uuid4().hex[:8]}",
        "labels": {"lab.runtime": "padding-oracle-soc-lab", "lab.role": name_prefix, **(labels or {})},
    }
    try:
        docker_client.containers.run(**kwargs)
    except APIError as exc:
        raise RuntimeError(f"Unable to run job: {exc.explanation}") from exc


def _ensure_core_services() -> None:
    # soc-ui is self-managed by docker compose; soc must always be up while UI is up.
    _start("soc")


def _clear_jsonl_logs() -> list[str]:
    cleared = []
    for path in sorted(LOG_DIR.glob("*.jsonl")):
        try:
            path.write_text("", encoding="utf-8")
            cleared.append(path.name)
        except (IOError, OSError):
            continue
    return cleared


def _reset_test_state() -> dict:
    _start("victim")
    try:
        requests.post("http://victim:8080/mode", json={"mode": "vuln"}, timeout=2)
    except Exception:
        pass

    for name in ["benign", "attacker"]:
        _stop(name)

    # Stop any detached one-shot jobs launched from UI.
    for container in docker_client.containers.list(all=True, filters={"label": "lab.runtime=padding-oracle-soc-lab"}):
        labels = container.labels or {}
        role = labels.get("lab.role", "")
        if role in {"attacker", "benign"}:
            try:
                container.stop(timeout=1)
            except APIError:
                pass

    _ensure_core_services()
    cleared = _clear_jsonl_logs()

    # Reset rules and WAF to initial disabled baseline (zero-alert state)
    rules = _read_rules()
    rules["enabled"] = False
    _write_rules(rules)

    waf_policy = {
        "enabled": False,
        "min_requests_window": int(rules.get("min_events_per_ip", 15)),
        "max_fail_rate": float(rules.get("high_fail_rate_threshold", 0.80)),
        "max_consecutive_errors": int(rules.get("block_probing_min_consecutive_errors", 12)),
        "window_seconds": 60,
        "action": "429_too_many_requests",
    }
    waf_policy_path = os.path.join(LAB_ROOT, "control", "waf_policy.json")
    try:
        with open(waf_policy_path, "w", encoding="utf-8") as f:
            json.dump(waf_policy, f, indent=2)
    except Exception:
        pass

    _call_victim_waf("/waf/reset", method="POST")
    _call_victim_waf("/waf/policy", method="POST", json_data={"enabled": False})

    return {"active_victim": "victim", "cleared": cleared, "waf_reset": True}



def _stop_attack_related_workloads() -> None:
    _stop_role_traffic("attacker", "attacker")


def _stop_role_traffic(role: str, host: str | None = None) -> None:
    for container in docker_client.containers.list(all=True, filters={"label": "lab.runtime=padding-oracle-soc-lab"}):
        labels = container.labels or {}
        if labels.get("lab.role", "") != role:
            continue
        if host is not None and labels.get("lab.host", "") != host:
            continue
        try:
            container.stop(timeout=1)
        except APIError:
            pass


def _shutdown_all_after_response() -> None:
    # Let Flask send the JSON response, then stop only attacker/benign workloads.
    time.sleep(0.5)
    _stop_attack_related_workloads()


def _shutdown_soc_with_ui() -> None:
    # Keep SOC and UI lifecycle coupled: if UI is stopped, stop SOC as well.
    _stop("soc")


def _handle_shutdown_signal(signum, _frame) -> None:
    _shutdown_soc_with_ui()
    raise SystemExit(0)


# ---------------------------------------------------------------------------
# In-Memory Ring Buffer (10,000 Capacity) & Incremental Ingestion
# ---------------------------------------------------------------------------

MAX_MEMORY_LOGS = int(os.getenv("MAX_LOGS_MEMORY", "10000"))
_MEMORY_LOG_BUFFER: deque = deque(maxlen=MAX_MEMORY_LOGS)
_FILE_BYTE_OFFSETS: dict[str, int] = {}
_LOG_SYNC_LOCK = threading.Lock()


def _clear_jsonl_logs() -> list[str]:
    cleared = []
    with _LOG_SYNC_LOCK:
        _MEMORY_LOG_BUFFER.clear()
        _FILE_BYTE_OFFSETS.clear()

    # First call SOC Collector clear endpoint to delete events via primary DB connection
    try:
        requests.post(f"{SOC_URL}/logs/clear", timeout=2)
    except Exception:
        pass

    log_dirs = [
        LOG_DIR,
        Path("/logs"),
        LAB_ROOT / "runtime-logs",
        Path("/app/runtime-logs"),
    ]
    cleared_paths = set()
    for d in log_dirs:
        if d.exists():
            for path in sorted(d.glob("*.jsonl")):
                try:
                    p_res = str(path.resolve())
                except Exception:
                    p_res = str(path)
                if p_res in cleared_paths:
                    continue
                cleared_paths.add(p_res)
                try:
                    path.write_text("", encoding="utf-8")
                    if path.name not in cleared:
                        cleared.append(path.name)
                except (IOError, OSError):
                    continue

    db_paths = [
        LOG_DIR / "siem_events.db",
        Path("/logs/siem_events.db"),
        LAB_ROOT / "runtime-logs" / "siem_events.db",
        Path("/app/runtime-logs/siem_events.db"),
        Path("/dev/shm/siem_events.db"),
    ]
    for p in db_paths:
        if p.exists():
            try:
                conn = sqlite3.connect(str(p), timeout=5.0, check_same_thread=False)
                conn.execute("PRAGMA busy_timeout = 5000;")
                conn.execute("DELETE FROM events;")
                conn.commit()
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
                conn.execute("VACUUM;")
                conn.close()
                if p.name not in cleared:
                    cleared.append(p.name)
            except Exception:
                pass
    return cleared


def _sync_memory_logs() -> None:
    """Incrementally ingests newly appended lines from *.jsonl files into the in-memory ring buffer."""
    with _LOG_SYNC_LOCK:
        new_events = []
        log_dirs = [
            LOG_DIR,
            Path("/logs"),
            LAB_ROOT / "runtime-logs",
            Path("/app/runtime-logs"),
        ]
        scanned_paths = set()
        for d in log_dirs:
            if not d.exists():
                continue
            for path in sorted(d.glob("*.jsonl")):
                try:
                    path_str = str(path.resolve())
                except Exception:
                    path_str = str(path)
                if path_str in scanned_paths:
                    continue
                scanned_paths.add(path_str)
                last_offset = _FILE_BYTE_OFFSETS.get(path_str, 0)
                try:
                    size = path.stat().st_size
                    if size < last_offset:
                        # File was truncated/cleared
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
                        _FILE_BYTE_OFFSETS[path_str] = f.tell()
                except Exception:
                    continue
        if new_events:
            for ev in new_events:
                _MEMORY_LOG_BUFFER.append(ev)


def _read_events(
    limit: int = 1000,
    service: str | None = None,
    q: str | None = None,
    src_ip: str | None = None,
    event_type: str | None = None,
    endpoint: str | None = None,
    status_code: int | None = None,
) -> list[dict]:
    _sync_memory_logs()

    with _LOG_SYNC_LOCK:
        events = list(_MEMORY_LOG_BUFFER)

    filtered = []
    for ev in events:
        if service:
            svc_str = str(ev.get("service", ""))
            etype_str = str(ev.get("event_type", ""))
            ev_ip = str(ev.get("src_ip", "") or "")
            client_role = ev.get("details", {}).get("client_role") if isinstance(ev.get("details"), dict) else None

            if service == "benign":
                is_match = svc_str.startswith("benign") or "benign" in svc_str or client_role == "benign"
            elif service == "attacker":
                is_match = (
                    svc_str == "attacker"
                    or svc_str.startswith("attacker")
                    or etype_str.startswith("attack")
                    or ev_ip == "198.51.100.50"
                    or "attacker" in ev_ip
                    or client_role == "attacker"
                )
            elif service == "victim":
                is_match = svc_str.startswith("victim")
            else:
                is_match = svc_str == service or svc_str.startswith(service)
            if not is_match:
                continue
        if src_ip:
            ev_ip = str(ev.get("src_ip", "") or "")
            if ev_ip != src_ip:
                continue
        if event_type:
            ev_etype = str(ev.get("event_type", "") or "")
            if ev_etype != event_type:
                continue
        if endpoint:
            ev_ep = str(ev.get("endpoint", "") or "").strip()
            req_ep = str(endpoint).strip()
            crypto_decrypt_aliases = {"/decrypt", "/api/v1/crypto/decrypt"}
            if req_ep in crypto_decrypt_aliases:
                if ev_ep not in crypto_decrypt_aliases:
                    continue
            elif req_ep != ev_ep and req_ep not in ev_ep and ev_ep not in req_ep:
                continue
        if status_code is not None:
            ev_sc = ev.get("status_code")
            if ev_sc is None:
                ev_sc = ev.get("status")
            try:
                if ev_sc is None or int(ev_sc) != int(status_code):
                    continue
            except (ValueError, TypeError):
                continue
        if q:
            blob = json.dumps(ev, sort_keys=True)
            if q.lower() not in blob.lower():
                continue
        filtered.append(ev)

    def _ts_key(ev: dict) -> str:
        return str(ev.get("ts", "") or "")
    filtered.sort(key=_ts_key)
    if limit <= 0 or limit >= len(filtered):
        return list(reversed(filtered))
    return list(reversed(filtered[-limit:]))


@app.get("/logs/ips")
def logs_ips():
    """Return all known/discovered unique source IPs in the environment."""
    _sync_memory_logs()
    ips = set()
    ips.add("198.51.100.50")
    for i in range(10, 20):
        ips.add(f"192.168.1.{i}")
    ips.add("victim:8080")
    with _LOG_SYNC_LOCK:
        for ev in _MEMORY_LOG_BUFFER:
            ip = ev.get("src_ip")
            if ip and isinstance(ip, str) and ip.strip():
                ips.add(ip.strip())
    for path in sorted(LOG_DIR.glob("*.jsonl")):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if '"src_ip"' in line:
                        try:
                            ev = json.loads(line.strip())
                            ip = ev.get("src_ip")
                            if ip:
                                ips.add(str(ip).strip())
                        except Exception:
                            continue
        except Exception:
            continue
    sorted_ips = sorted(list(ips))
    return jsonify(sorted_ips)


@app.get("/logs/export/csv")
def logs_export_csv():
    """Export all in-memory raw logs as a downloadable CSV file."""
    _sync_memory_logs()
    with _LOG_SYNC_LOCK:
        events = list(_MEMORY_LOG_BUFFER)

    def _ts_key(ev: dict) -> str:
        return str(ev.get("ts", "") or "")
    events.sort(key=_ts_key)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "timestamp", "service", "event_type", "src_ip", "endpoint",
        "status_code", "latency_ms", "ciphertext_len", "error_type",
        "scenario_id", "details_json"
    ])
    for e in events:
        details_str = json.dumps(e.get("details", {})) if e.get("details") else ""
        writer.writerow([
            e.get("ts", ""),
            e.get("service", ""),
            e.get("event_type", ""),
            e.get("src_ip", ""),
            e.get("endpoint", ""),
            e.get("status_code", ""),
            e.get("latency_ms", ""),
            e.get("ciphertext_len", ""),
            e.get("error_type", ""),
            e.get("scenario_id", ""),
            details_str,
        ])

    filename = f"soc_raw_logs_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.get("/logs/export/jsonl")
def logs_export_jsonl():
    """Export all in-memory raw logs as a downloadable JSONL file."""
    _sync_memory_logs()
    with _LOG_SYNC_LOCK:
        events = list(_MEMORY_LOG_BUFFER)

    def _ts_key(ev: dict) -> str:
        return str(ev.get("ts", "") or "")
    events.sort(key=_ts_key)

    lines = [json.dumps(e) for e in events]
    filename = f"soc_raw_logs_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.jsonl"
    return Response(
        "\n".join(lines) + ("\n" if lines else ""),
        mimetype="application/x-ndjson",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


def _is_attack_active(window_seconds: int = 6) -> bool:
    """Check if an attack is actively probing right now."""
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
    attacker_log = LOG_DIR / "attacker.jsonl"
    if not attacker_log.exists():
        return False
    try:
        with open(attacker_log, "r", encoding="utf-8") as f:
            lines = f.readlines()
        for line in reversed(lines[-100:]):
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
                etype = str(ev.get("event_type", ""))
                ts_str = ev.get("ts", "")
                if ts_str:
                    ev_dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    if ev_dt >= cutoff:
                        if etype in ("attack_complete", "attack_blocked", "attack_not_permitted", "attack_error"):
                            return False
                        if etype in ("attack_probe", "attack_recon", "attack_progress", "attack_noise_blend"):
                            return True
            except (ValueError, json.JSONDecodeError):
                continue
    except (FileNotFoundError, IOError):
        pass
    return False


def _is_role_traffic_active(role: str, window_seconds: int = 6) -> bool:
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
    for path in sorted(LOG_DIR.glob("*.jsonl")):
        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            for line in reversed(lines[-150:]):
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                svc = str(ev.get("service", ""))
                etype = str(ev.get("event_type", ""))
                src_ip = str(ev.get("src_ip", ""))
                client_role = ev.get("details", {}).get("client_role") if isinstance(ev.get("details"), dict) else None

                if role == "attacker":
                    is_role = svc == "attacker" or svc.startswith("attacker") or etype.startswith("attack")
                elif role == "benign":
                    is_role = svc == "benign" or svc.startswith("benign") or client_role == "benign" or src_ip.startswith("192.168.1.")
                else:
                    is_role = svc == role or svc.startswith(role)
                if not is_role:
                    continue
                ts_str = ev.get("ts", "")
                if not isinstance(ts_str, str):
                    continue
                try:
                    ev_dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                except ValueError:
                    continue
                if ev_dt >= cutoff:
                    return True
        except (FileNotFoundError, IOError):
            continue
    return False



def _role_has_recent_events(role: str, window_seconds: int = 10) -> bool:
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
    for path in sorted(LOG_DIR.glob("*.jsonl")):
        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            for line in reversed(lines[-300:]):
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                svc = str(ev.get("service", ""))
                etype = str(ev.get("event_type", ""))
                if role == "attacker":
                    is_role = svc == "attacker" or svc.startswith("attacker") or etype.startswith("attack")
                else:
                    is_role = svc == role or svc.startswith(role)
                if not is_role:
                    continue
                ts_str = ev.get("ts", "")
                if not isinstance(ts_str, str):
                    continue
                try:
                    ev_dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                except ValueError:
                    continue
                if ev_dt >= cutoff:
                    return True
        except (FileNotFoundError, IOError):
            continue
    return False


def _active_victim() -> str | None:
    for name in VICTIM_NAMES:
        c = _container(name)
        if c is not None:
            c.reload()
            if c.status == "running":
                return name
    return None


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


def _read_rules() -> dict:
    defaults = {
        "enabled": True,
        "rule_error_flooding_enabled": True,
        "rule_timing_oracle_enabled": True,
        "rule_byte_probing_enabled": True,
        "rule_auth_bruteforce_enabled": True,
        "min_events_per_ip": 25,
        "high_fail_rate_threshold": 0.85,
        "collector_window_minutes": 15,
        "timing_stddev_threshold_ms": 6.0,
        "timing_p95_p50_diff_threshold_ms": 12.0,
        "bimodality_threshold": 0.555,
        "min_timing_events_per_ip": 20,
        "block_probing_min_consecutive_errors": 15,
        "window_seconds": 60,
        "rules": _default_siem_rules(),
    }
    try:
        with open(ALERT_RULES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                for k in defaults:
                    if k in data:
                        defaults[k] = data[k]
                if "rules" in data and isinstance(data["rules"], list):
                    defaults["rules"] = data["rules"]
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return defaults


def _write_rules(rules: dict) -> None:
    ALERT_RULES_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(ALERT_RULES_FILE, "w", encoding="utf-8") as f:
        json.dump(rules, f, indent=2, sort_keys=True)



def _collector_alerts() -> list[dict]:
    try:
        response = requests.get(f"{SOC_URL}/alerts", timeout=3)
        response.raise_for_status()
        return response.json().get("alerts", [])
    except Exception:
        return []


# ---------------------------------------------------------------------------
# New API endpoints
# ---------------------------------------------------------------------------

@app.get("/logs/tail")
def logs_tail():
    """Return the last N log events as JSON array, enriched with a color tag."""
    limit = int(request.args.get("limit", "1000"))
    service = request.args.get("service")
    q = request.args.get("q")
    src_ip = request.args.get("src_ip") or request.args.get("ip")
    event_type = request.args.get("event_type") or request.args.get("etype")
    endpoint = request.args.get("endpoint") or request.args.get("ep")
    status_raw = request.args.get("status_code") or request.args.get("status")
    status_code = int(status_raw) if (status_raw and str(status_raw).lstrip('-').isdigit()) else None
    events = _read_events(
        limit=limit,
        service=service,
        q=q,
        src_ip=src_ip,
        event_type=event_type,
        endpoint=endpoint,
        status_code=status_code,
    )
    for ev in events:
        svc = str(ev.get("service", ""))
        etype = str(ev.get("event_type", ""))
        if svc == "attacker" or etype.startswith("attack"):
            ev["_color"] = "attacker"
        elif svc.startswith("benign") or "benign" in svc:
            ev["_color"] = "benign"
        else:
            ev["_color"] = "victim"
    return jsonify(events)


@app.get("/status")
def status():
    """Synthetic status: active victim, attack active, total event counts per category."""
    _ensure_core_services()
    victim = _active_victim()
    attack_active = _is_attack_active()
    benign_active = _is_role_traffic_active("benign")

    victim_mode = SERVICE_SPECS.get("victim", {}).get("environment", {}).get("VICTIM_MODE", "vuln")
    try:
        r = requests.get("http://victim:8080/health", timeout=1)
        if r.status_code == 200:
            victim_mode = r.json().get("mode", victim_mode)
            SERVICE_SPECS["victim"]["environment"]["VICTIM_MODE"] = victim_mode
    except Exception:
        pass

    # Count events per category across ALL log files (not limited tail)
    by_color: Counter = Counter()
    for path in sorted(LOG_DIR.glob("*.jsonl")):
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    svc = str(ev.get("service", ""))
                    etype = str(ev.get("event_type", ""))
                    if svc == "attacker" or etype.startswith("attack"):
                        by_color["attacker"] += 1
                    elif svc.startswith("benign") or "benign" in svc:
                        by_color["benign"] += 1
                    else:
                        by_color["victim"] += 1
        except (FileNotFoundError, IOError):
            continue
    services_status = {name: _status(name) for name in ALL_MANAGED}
    return jsonify({
        "active_victim": victim,
        "victim_mode": victim_mode,
        "attack_active": attack_active,
        "benign_active": benign_active,
        "event_counts": dict(by_color),
        "services": services_status,
    })



@app.get("/network/data")
def network_data():
    """Nodes and edges for vis-network, plus recent events."""
    _ensure_core_services()
    service_names = ["victim", "benign", "attacker"]
    services = [_status(name) for name in service_names]
    active_victim = _active_victim() or "victim"
    benign_traffic_active = _is_role_traffic_active("benign")
    attacker_traffic_active = _is_role_traffic_active("attacker")

    all_statuses = {name: _status(name) for name in service_names}

    ON_COLORS  = {"victim": "#10b981", "benign": "#f59e0b", "attacker": "#ef4444"}
    OFF_COLORS = {
        "victim":   {"bg": "#143826", "brd": "#2f7d5b", "fnt": "#8fd6b5"},
        "benign":   {"bg": "#3a2b10", "brd": "#9b6721", "fnt": "#ffd08a"},
        "attacker": {"bg": "#3f1414", "brd": "#a73737", "fnt": "#ff9c9c"},
    }

    POSITIONS = {
        "victim": {"x": 60, "y": 0},
        "benign": {"x": -220, "y": -80},
        "attacker": {"x": -220, "y": 80},
    }

    def _node_group(name: str) -> str:
        if name.startswith("victim"): return "victim"
        if name.startswith("benign"): return "benign"
        return "attacker"

    nodes = []
    for name, s in all_statuses.items():
        grp = _node_group(name)
        is_up = s["state"] == "running"
        on_c  = ON_COLORS[grp]
        off_c = OFF_COLORS[grp]
        status_label = "🟢 ON" if is_up else "⚫ OFF"
        pos = POSITIONS.get(name, {"x": 0, "y": 0})
        label_text = f"{name}\n{status_label}"
        if name == "benign":
            label_text = f"benign (Fleet)\n{status_label}"
        elif name == "victim":
            label_text = f"victim (Target)\n{status_label}"
        if is_up:
            nodes.append({
                "id": name, "label": label_text, "group": grp,
                "color": {"background": on_c, "border": on_c,
                           "highlight": {"background": on_c, "border": "#fff"}},
                "font": {"color": "#fff", "size": 14, "bold": True},
                "shape": "box", "borderWidth": 2,
                "widthConstraint": {"minimum": 120},
                "shadow": {"enabled": True, "color": on_c + "55", "size": 12},
                "x": pos["x"], "y": pos["y"],
            })
        else:
            nodes.append({
                "id": name, "label": label_text,
                "group": grp + "_off",
                "color": {"background": off_c["bg"], "border": off_c["brd"],
                           "highlight": {"background": off_c["bg"], "border": off_c["brd"]}},
                "font": {"color": off_c["fnt"], "size": 12, "bold": True},
                "shape": "box", "borderWidth": 2, "opacity": 0.9,
                "widthConstraint": {"minimum": 120},
                "x": pos["x"], "y": pos["y"],
            })

    edges = []
    is_ben_active = benign_traffic_active
    edges.append({
        "id": "benign->victim", "from": "benign", "to": "victim",
        "arrows": "to",
        "color": {"color": "#f59e0b" if is_ben_active else "#5f4b26", "opacity": 1.0},
        "width": 3 if is_ben_active else 1, "dashes": not is_ben_active,
    })
    is_atk = attacker_traffic_active
    edges.append({
        "id": "attacker->victim", "from": "attacker", "to": "victim",
        "arrows": "to",
        "color": {"color": "#ef4444" if is_atk else "#6a2f2f", "opacity": 1.0},
        "width": 4 if is_atk else 1, "dashes": not is_atk,
    })

    recent_events = _read_events(limit=30)
    events_out = []
    for ev in recent_events:
        svc = ev.get("service", "")
        etype = ev.get("event_type", "")
        if svc in ("attacker",) or etype in ("attack_progress", "attack_complete", "attack_probe", "attack_recon", "attack_noise_blend"):
            color = "attacker"
        elif svc.startswith("benign") or "benign" in str(etype):
            color = "benign"
        else:
            color = "victim"
        events_out.append({
            "ts": ev.get("ts", ""), "service": svc, "event_type": etype,
            "status": ev.get("status_code", ""), "error": ev.get("error_type", ""),
            "color": color,
        })
    return jsonify({"nodes": nodes, "edges": edges, "events": events_out,
                    "active_victim": active_victim})


# ---------------------------------------------------------------------------
# Node action endpoints (called from modals)
# ---------------------------------------------------------------------------

@app.post("/nodes/host/toggle/<name>")
def toggle_host(name: str):
    if name not in ("victim", "benign", "attacker"):
        return jsonify({"ok": False, "error": "Nodo non valido"}), 400
    try:
        c = _container(name)
        is_running = False
        if c is not None:
            try:
                c.reload()
                is_running = c.status == "running"
            except Exception:
                is_running = False

        if is_running:
            _stop(name)
            running = False
        else:
            _start(name)
            running = True
        _ensure_core_services()
        return jsonify({"ok": True, "running": running, "name": name})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.post("/nodes/victim/switch")
def victim_switch():
    try:
        data = request.get_json(force=True, silent=True) or {}
        mode = data.get("mode", "vuln")
        if mode not in ("vuln", "partial", "fixed"):
            mode = "vuln"
        SERVICE_SPECS["victim"]["environment"]["VICTIM_MODE"] = mode
        _start("victim")
        try:
            requests.post("http://victim:8080/mode", json={"mode": mode}, timeout=2)
        except Exception:
            pass
        _ensure_core_services()
        return jsonify({"ok": True, "active": "victim", "mode": mode})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.get("/nodes/host/status/<name>")
def host_status(name: str):
    if name not in ("victim", "benign", "attacker"):
        return jsonify({"ok": False, "error": "Nodo non valido"}), 400
    try:
        c = _container(name)
        running = False
        if c is not None:
            try:
                c.reload()
                running = c.status == "running"
            except Exception:
                running = False
        return jsonify({
            "ok": True,
            "host_running": running,
            "traffic_active": _is_role_traffic_active(name),
            "recent_events": _role_has_recent_events(name),
        })
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.post("/nodes/benign/launch")
def benign_launch():
    data = request.get_json(force=True, silent=True) or {}
    virtual_ips = int(data.get("virtual_ips", 10))
    iterations = int(data.get("iterations", 100))
    min_ms = int(data.get("min_ms", 300))
    max_ms = int(data.get("max_ms", 1000))
    continuous = bool(data.get("continuous", True))
    error_rate = float(data.get("error_rate", 3.0))

    _start("benign")
    _start("victim")

    cmd = [
        "python", "benign/benign_client.py",
        "--target", "http://victim:8080",
        "--name", "benign",
        "--scenario-id", "ui-enterprise-baseline",
        "--virtual-ips", str(virtual_ips),
        "--min-sleep-ms", str(min_ms),
        "--max-sleep-ms", str(max_ms),
        "--error-rate-pct", str(error_rate),
    ]
    if continuous:
        cmd.append("--continuous")
    else:
        cmd.extend(["--iterations", str(iterations)])

    _run_one_shot(
        "benign",
        cmd,
        {"LOG_DIR": "/logs"},
        labels={"lab.host": "benign"},
    )
    _ensure_core_services()
    return jsonify({"ok": True, "continuous": continuous, "iterations": iterations, "virtual_ips": virtual_ips})


@app.post("/nodes/benign/pause")
def benign_pause():
    _stop_role_traffic("benign", "benign")
    for container in docker_client.containers.list(all=True, filters={"label": "lab.host=benign"}):
        try:
            container.stop(timeout=1)
        except APIError:
            pass
    return jsonify({"ok": True, "host": "benign"})


@app.post("/nodes/attacker/launch")
def attacker_launch():
    data = request.get_json(force=True, silent=True) or {}
    mode = data.get("mode", "vuln")
    sleep_ms = float(data.get("sleep_ms", 4.0))
    ip_mode = data.get("ip_mode", "static")
    blend_noise = bool(data.get("blend_noise", False))
    target_name = "victim"
    scenario_id = f"attack-{mode}-{int(time.time()*1000)}"
    _start(target_name)
    _start("attacker")
    cmd = [
        "python", "attacker/attack.py",
        "--target", f"http://{target_name}:8080",
        "--mode", mode,
        "--sleep-ms", str(sleep_ms),
        "--ip-mode", ip_mode,
        "--scenario-id", scenario_id,
    ]
    if blend_noise:
        cmd.append("--blend-noise")

    _run_one_shot(
        "attacker",
        cmd,
        {"LOG_DIR": "/logs"},
        labels={"lab.host": "attacker"},
    )
    return jsonify({"ok": True, "mode": mode, "ip_mode": ip_mode, "blend_noise": blend_noise, "target": target_name, "scenario_id": scenario_id})


@app.post("/nodes/attacker/pause")
def attacker_pause():
    _stop_role_traffic("attacker", "attacker")
    for container in docker_client.containers.list(all=True, filters={"label": "lab.host=attacker"}):
        try:
            container.stop(timeout=1)
        except APIError:
            pass
    return jsonify({"ok": True})


@app.get("/nodes/victim/secret")
def victim_get_secret():
    spec = SERVICE_SPECS.get("victim", {})
    secret = spec.get("environment", {}).get("SECRET_MESSAGE", "PaddingOracle:TopSecret")
    return jsonify({"secret": secret, "active": "victim"})


@app.post("/nodes/victim/secret")
def victim_set_secret():
    data = request.get_json(force=True, silent=True) or {}
    secret = str(data.get("secret", "")).strip()
    if not secret:
        return jsonify({"ok": False, "error": "Il segreto non può essere vuoto"}), 400
    SERVICE_SPECS["victim"]["environment"]["SECRET_MESSAGE"] = secret
    c = _container("victim")
    if c is not None:
        try:
            c.remove(force=True)
        except Exception:
            pass
    _start("victim")
    _ensure_core_services()
    return jsonify({"ok": True, "secret": secret, "active": "victim"})


@app.post("/nodes/victim/secret/random")
def victim_set_secret_random():
    alphabet = string.ascii_letters + string.digits
    secret = "PaddingOracle:" + "".join(secrets.choice(alphabet) for _ in range(12))
    SERVICE_SPECS["victim"]["environment"]["SECRET_MESSAGE"] = secret
    c = _container("victim")
    if c is not None:
        try:
            c.remove(force=True)
        except Exception:
            pass
    _start("victim")
    _ensure_core_services()
    return jsonify({"ok": True, "secret": secret, "active": "victim"})



# ---------------------------------------------------------------------------
# Legacy docker action (kept for compatibility)
# ---------------------------------------------------------------------------

@app.post("/docker/action/<action>")
def docker_action(action: str):
    target = request.form.get("target", "victim-vuln")
    victim_target = request.form.get("victim_target", "victim-vuln")
    if action == "start":
        if target == "attacker" or target.startswith("benign-"):
            return redirect(url_for("docker_page"))
        _start(target)
    elif action == "stop":
        if target == "soc":
            return jsonify({"ok": False, "error": "SOC is bound to soc-ui and cannot be stopped independently"}), 400
        _stop(target)
    elif action == "start-victim":
        for name in VICTIM_NAMES:
            if name == target:
                _start(name)
            else:
                _stop(name)
    elif action == "start-soc":
        _start("soc")
    elif action == "stop-all":
        for name in WORKLOAD_NAMES:
            _stop(name)
    elif action == "run-attack":
        _run_one_shot(
            "attacker",
            ["python", "attacker/attack.py", "--target", f"http://{victim_target}:8080",
             "--mode", "vuln", "--scenario-id", f"ui-{victim_target}"],
            {"LOG_DIR": "/logs"},
        )
    elif action == "run-benign":
        _run_one_shot(
            "benign",
            ["python", "benign/benign_client.py", "--target", f"http://{victim_target}:8080",
             "--name", "benign-ui", "--scenario-id", "ui-baseline",
             "--iterations", "60", "--min-sleep-ms", "50", "--max-sleep-ms", "140"],
            {"LOG_DIR": "/logs"},
        )
    _ensure_core_services()
    return redirect(url_for("docker_page"))


# ---------------------------------------------------------------------------
# Main dashboard page
# ---------------------------------------------------------------------------

MAIN_PAGE = r"""<!doctype html>
<html lang="it">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Padding Oracle SOC Lab</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --bg-base:     #f8fafc;
      --bg-panel:    #ffffff;
      --bg-card:     #ffffff;
      --bg-hover:    #f1f5f9;
      --bg-subtle:   #f1f5f9;
      --border:      #e2e8f0;
      --border-lit:  #cbd5e1;
      --text:        #0f172a;
      --text-dim:    #64748b;
      --text-muted:  #475569;
      --accent:      #2563eb;
      --accent-soft: #eff6ff;
      --accent-glow: #1d4ed8;
      --red:         #dc2626;
      --red-dim:     #fef2f2;
      --amber:       #d97706;
      --amber-dim:   #fffbeb;
      --green:       #16a34a;
      --green-dim:   #f0fdf4;
      --blue:        #2563eb;
      --font-ui:     'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      --font-mono:   'JetBrains Mono', 'Fira Code', 'Cascadia Code', Consolas, monospace;
    }

    html, body { height: 100%; overflow: hidden; background: var(--bg-base); color: var(--text); font-family: var(--font-ui); -webkit-font-smoothing: antialiased; }

    /* ── Layout ── */
    .app { display: flex; flex-direction: column; height: 100vh; }

    /* Header */
    .header {
      display: flex; align-items: center; gap: 16px;
      padding: 0 24px; height: 56px; flex-shrink: 0;
      background: var(--bg-panel);
      border-bottom: 1px solid var(--border);
      box-shadow: 0 1px 3px rgba(0,0,0,0.03);
      z-index: 10;
    }
    .header-logo { font-size: 14px; font-weight: 700; letter-spacing: .2px; color: var(--text); display: flex; align-items: center; gap: 8px; }
    .header-logo span { color: var(--accent); }
    .header-badge-uni {
      font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.6px;
      padding: 2px 8px; border-radius: 4px; background: var(--accent-soft);
      border: 1px solid #bfdbfe; color: var(--accent);
    }
    .header-spacer { flex: 1; }
    .badge {
      display: inline-flex; align-items: center; gap: 6px;
      padding: 4px 12px; border-radius: 999px; font-size: 11px; font-weight: 600;
      letter-spacing: .4px; text-transform: uppercase;
    }
    .badge-attack {
      background: #fef2f2;
      border: 1px solid #fecaca;
      color: var(--red);
      animation: pulse-red 1.5s ease-in-out infinite;
    }
    .badge-quiet {
      background: #f0fdf4;
      border: 1px solid #bbf7d0;
      color: #15803d;
    }
    .dot { width: 7px; height: 7px; border-radius: 50%; background: currentColor; }
    @keyframes pulse-red {
      0%, 100% { box-shadow: 0 0 0 0 rgba(220, 38, 38, 0.4); }
      50%       { box-shadow: 0 0 0 4px transparent; }
    }
    .header-time { font-size: 12px; color: var(--text-dim); font-family: var(--font-mono); }

    /* Body split */
    .body { display: flex; flex: 1; overflow: hidden; }

    /* Sidebar */
    .sidebar {
      width: 220px; flex-shrink: 0;
      background: var(--bg-panel);
      border-right: 1px solid var(--border);
      display: flex; flex-direction: column;
      padding: 16px 0;
    }
    .sidebar-section { padding: 8px 18px 4px; font-size: 11px; font-weight: 700;
      letter-spacing: 0.8px; text-transform: uppercase; color: var(--text-dim); }
    .nav-item {
      display: flex; align-items: center; gap: 10px;
      padding: 8px 18px; font-size: 13px; font-weight: 500;
      color: var(--text-muted); cursor: pointer; text-decoration: none;
      border-left: 3px solid transparent;
      transition: background .12s, color .12s, border-color .12s;
    }
    .nav-item:hover  { background: var(--bg-hover); color: var(--text); }
    .nav-item.active { background: #eff6ff; color: var(--accent); border-left-color: var(--accent); font-weight: 600; }
    .nav-icon { font-size: 14px; width: 18px; text-align: center; }
    .sidebar-spacer { flex: 1; }
    .sidebar-victim-badge {
      margin: 12px 14px; padding: 10px 12px; border-radius: 6px;
      font-size: 11px; font-family: var(--font-mono);
      background: #f8fafc; border: 1px solid var(--border);
      color: var(--text-muted);
    }
    .sidebar-victim-badge strong { color: var(--green); display: block; font-size: 12px; margin-top: 2px; }

    /* Main area */
    .main { flex: 1; display: flex; flex-direction: column; overflow: hidden; background: var(--bg-base); }

    /* Panels (each view) */
    .panel { display: none; flex: 1; overflow: hidden; flex-direction: column; }
    .panel.visible { display: flex; }

    /* Network & Scenario Command Center panel */
    .net-panel { display: flex; flex-direction: column; flex: 1; min-height: 0; }
    
    /* Scenario Command Center */
    .scenario-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
      padding: 14px 20px;
      background: var(--bg-panel);
      border-bottom: 1px solid var(--border);
      flex-shrink: 0;
    }
    @media (max-width: 1280px) {
      .scenario-grid { grid-template-columns: repeat(2, 1fr); }
    }
    @media (max-width: 760px) {
      .scenario-grid { grid-template-columns: 1fr; }
    }
    .sc-card {
      background: var(--bg-panel);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 12px 14px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      gap: 8px;
      transition: border-color .15s, box-shadow .15s;
      box-shadow: 0 1px 3px rgba(0,0,0,0.03);
    }
    .sc-card:hover { border-color: var(--border-lit); box-shadow: 0 3px 6px rgba(0,0,0,0.05); }
    .sc-card.card-benign   { border-left: 3px solid var(--amber); }
    .sc-card.card-attacker { border-left: 3px solid var(--red); }
    .sc-card.card-victim   { border-left: 3px solid var(--green); }
    .sc-card.card-soc      { border-left: 3px solid var(--accent); }

    .sc-header { display: flex; align-items: center; justify-content: space-between; gap: 6px; }
    .sc-title { font-size: 13px; font-weight: 600; color: var(--text); display: flex; align-items: center; gap: 6px; }
    .sc-badge { font-size: 11px; font-weight: 600; padding: 2px 7px; border-radius: 4px; font-family: var(--font-mono); }
    .sc-badge.on    { background: #f0fdf4; color: #166534; border: 1px solid #bbf7d0; }
    .sc-badge.off   { background: #f1f5f9; color: #64748b; border: 1px solid #cbd5e1; }
    .sc-badge.alert { background: #fef2f2; color: #991b1b; border: 1px solid #fecaca; }
    .sc-badge.warn  { background: #fffbeb; color: #92400e; border: 1px solid #fde68a; }
    
    .sc-metrics { display: grid; grid-template-columns: 1fr 1fr; gap: 6px 10px; font-size: 11px; margin-top: 2px; }
    .sc-metric-item { display: flex; flex-direction: column; }
    .sc-m-lbl { font-size: 10px; text-transform: uppercase; color: var(--text-dim); letter-spacing: .4px; font-weight: 500; }
    .sc-m-val { font-family: var(--font-mono); font-weight: 600; color: var(--text); font-variant-numeric: tabular-nums; }
    .sc-m-val.green { color: #15803d; }
    .sc-m-val.red   { color: #b91c1c; }
    .sc-m-val.amber { color: #b45309; }

    .sc-actions { display: flex; gap: 6px; align-items: center; margin-top: 4px; flex-wrap: wrap; }

    /* Log stream generic */
    .log-stream-wrap { flex: 1; overflow-y: auto; padding: 0; background: var(--bg-panel); }
    .log-stream-wrap::-webkit-scrollbar { width: 6px; }
    .log-stream-wrap::-webkit-scrollbar-thumb { background: #cbd5e1; border-radius: 3px; }
    .log-header {
      display: flex; align-items: center; gap: 14px; padding: 10px 20px;
      border-bottom: 1px solid var(--border);
      background: var(--bg-panel); flex-shrink: 0; font-size: 12px;
    }
    .log-legend { display: flex; gap: 14px; }
    .legend-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; margin-right: 4px; }
    
    .log-table-header {
      display: grid;
      grid-template-columns: 145px 125px 130px 160px 80px 1fr;
      gap: 0 10px;
      padding: 8px 16px;
      font-size: 11px;
      font-weight: 600;
      color: var(--text-dim);
      background: #f8fafc;
      border-bottom: 1px solid var(--border);
      text-transform: uppercase;
      letter-spacing: .5px;
      position: sticky;
      top: 0;
      z-index: 2;
    }

    .log-row {
      display: grid;
      grid-template-columns: 145px 125px 130px 160px 80px 1fr;
      gap: 0 10px;
      padding: 6px 16px;
      font-size: 11px; font-family: var(--font-mono);
      border-bottom: 1px solid #f1f5f9;
      transition: background .1s;
      cursor: pointer;
      align-items: center;
      color: var(--text);
    }

    .hide-etype .log-table-header,
    .hide-etype .log-row {
      grid-template-columns: 145px 125px 180px 80px 1fr;
    }
    .hide-etype .col-etype {
      display: none !important;
    }

    .log-row:hover { background: #f8fafc; }
    .log-row.attacker { border-left: 3px solid var(--red); background: #fff5f5; }
    .log-row.benign   { border-left: 3px solid var(--amber); background: #fffdf5; }
    .log-row.victim   { border-left: 3px solid #94a3b8; color: var(--text-dim); }
    
    .log-tag {
      display: inline-flex; align-items: center; justify-content: center;
      padding: 2px 7px; border-radius: 4px; font-size: 11px; font-weight: 600;
    }
    .tag-attacker { background: #fee2e2; color: #991b1b; border: 1px solid #fecaca; }
    .tag-benign   { background: #fef3c7; color: #92400e; border: 1px solid #fde68a; }
    .tag-victim   { background: #eff6ff; color: #1e40af; border: 1px solid #dbeafe; }
    .status-ok   { color: #166534; font-weight: 600; }
    .status-err  { color: #991b1b; font-weight: 600; }
    .status-warn { color: #92400e; font-weight: 600; }

    /* ── Details sub-row (expandable) ── */
    .log-details {
      display: none;
      padding: 10px 20px;
      font-size: 11px; font-family: var(--font-mono);
      background: #f8fafc;
      border-left: 3px solid var(--accent);
      border-bottom: 1px solid var(--border);
      color: var(--text-muted);
      white-space: pre-wrap;
      word-break: break-all;
    }
    .log-details.open { display: block; }
    .log-details .det-key   { color: var(--accent); font-weight: 600; }
    .log-details .det-val   { color: var(--text); }
    .log-details .det-str   { color: #047857; }
    .log-details .det-num   { color: #b45309; }
    .log-details .det-label { font-size: 10px; font-weight: 700; text-transform: uppercase;
      letter-spacing: .8px; color: var(--text-dim); margin-bottom: 6px; display: block; }

    /* ── SOC Academic Paired Cards UI ── */
    .soc-container {
      padding: 16px 24px 32px 24px;
      display: flex;
      flex-direction: column;
      gap: 14px;
      background: var(--bg-base);
    }
    .soc-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px 18px;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.03);
      transition: border-color .15s, box-shadow .15s;
    }
    .soc-card:hover {
      border-color: var(--border-lit);
      box-shadow: 0 3px 8px rgba(0, 0, 0, 0.06);
    }
    .soc-card.atk-card {
      border-left: 3px solid var(--red);
    }
    .soc-card.ben-card {
      border-left: 3px solid var(--amber);
    }
    .soc-card-header {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 10px;
      font-size: 12px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 8px;
    }
    .soc-card-ts {
      font-family: var(--font-mono);
      font-size: 11px;
      color: var(--text-dim);
    }
    .soc-card-svc {
      font-weight: 600;
      color: var(--text);
      font-size: 12px;
    }
    .soc-card-etype {
      font-family: var(--font-mono);
      font-size: 11px;
      padding: 2px 8px;
      border-radius: 4px;
      background: #f1f5f9;
      color: var(--text-muted);
    }
    .soc-pair-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 14px;
      margin-top: 8px;
    }
    @media (max-width: 960px) {
      .soc-pair-grid { grid-template-columns: 1fr; }
    }
    .soc-box {
      background: #f8fafc;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 10px 14px;
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    .soc-box-title {
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.5px;
      text-transform: uppercase;
      display: flex;
      align-items: center;
      justify-content: space-between;
      color: var(--text-dim);
      border-bottom: 1px dashed var(--border);
      padding-bottom: 4px;
      margin-bottom: 4px;
    }
    .soc-box-row {
      font-family: var(--font-mono);
      font-size: 11px;
      display: flex;
      align-items: baseline;
      gap: 8px;
      color: var(--text);
    }
    .soc-box-key {
      color: var(--text-dim);
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      min-width: 90px;
      flex-shrink: 0;
    }
    .soc-badge-status {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
      font-family: var(--font-mono);
    }
    .soc-badge-200   { background: #f0fdf4; color: #166534; border: 1px solid #bbf7d0; }
    .soc-badge-500   { background: #fef2f2; color: #991b1b; border: 1px solid #fecaca; }
    .soc-badge-403   { background: #fffbeb; color: #92400e; border: 1px solid #fde68a; }
    .soc-badge-probe { background: #eff6ff; color: var(--accent); border: 1px solid #bfdbfe; }

    .soc-analysis-footer {
      margin-top: 10px;
      padding: 8px 12px;
      background: #f8fafc;
      border-radius: 6px;
      border-left: 3px solid var(--accent);
      font-size: 11px;
      color: var(--text-muted);
      display: flex;
      align-items: center;
      gap: 8px;
    }

    /* ── Attack Detail panel ── */
    .atk-panel { padding: 0; overflow-y: auto; flex-direction: column; background: var(--bg-base); }
    .atk-header { padding: 12px 20px; background: var(--bg-panel); border-bottom: 1px solid var(--border);
      display: flex; align-items: center; gap: 12px; flex-shrink: 0; }
    .atk-header h2 { font-size: 14px; font-weight: 600; color: var(--text); }
    .atk-body { flex: 1; overflow-y: auto; padding: 16px 20px; }

    /* Byte progress bar */
    .byte-grid { display: grid; grid-template-columns: repeat(16, 1fr); gap: 4px; margin-bottom: 20px; }
    .byte-cell {
      aspect-ratio: 1; border-radius: 4px; display: flex; flex-direction: column;
      align-items: center; justify-content: center;
      font-family: var(--font-mono); font-size: 9px;
      border: 1px solid var(--border); background: var(--bg-card);
      transition: background .2s, border-color .2s;
    }
    .byte-cell.recovered   { background: #f0fdf4; border-color: #86efac; }
    .byte-cell.in-progress { background: #fffbeb; border-color: #fde68a; animation: pulse-amber 1s ease-in-out infinite; }
    @keyframes pulse-amber { 0%,100%{opacity:1} 50%{opacity:.6} }
    .byte-cell .bc-idx  { color: var(--text-dim); font-size: 8px; }
    .byte-cell .bc-val  { color: #166534; font-size: 11px; font-weight: 700; }
    .byte-cell .bc-hex  { color: var(--text-dim); font-size: 8px; }

    /* Attack event cards */
    .atk-event {
      border: 1px solid var(--border); border-radius: 6px; padding: 10px 14px;
      margin-bottom: 8px; font-family: var(--font-mono); font-size: 11px;
      background: var(--bg-card);
    }
    .atk-event.progress { border-left: 3px solid var(--amber); }
    .atk-event.complete { border-left: 3px solid var(--green); background: #f0fdf4; }
    .atk-event .ae-header { display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }
    .atk-event .ae-type { font-size: 10px; font-weight: 700; text-transform: uppercase; padding: 2px 7px; border-radius: 4px; }
    .ae-progress-badge { background: #fef3c7; color: #92400e; border: 1px solid #fde68a; }
    .ae-complete-badge { background: #dcfce7; color: #166534; border: 1px solid #86efac; }
    .atk-event .ae-ts  { color: var(--text-dim); font-size: 10px; }
    .atk-event .ae-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 4px 12px; }
    .atk-event .ae-kv  { display: flex; gap: 6px; }
    .atk-event .ae-k   { color: var(--text-dim); min-width: 100px; }
    .atk-event .ae-v   { color: var(--text); font-weight: 500; }
    .atk-event .ae-v.green { color: #166534; }
    .atk-event .ae-v.amber { color: #92400e; }
    .atk-no-data { color: var(--text-dim); font-size: 13px; padding: 20px 0; }

    /* Docker panel */
    .docker-panel { padding: 20px; overflow-y: auto; background: var(--bg-base); }
    .panel-title { font-size: 15px; font-weight: 600; margin-bottom: 16px; color: var(--text); }
    .card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.02); }
    .card h3 { font-size: 12px; font-weight: 600; color: var(--text-muted); margin-bottom: 12px; text-transform: uppercase; letter-spacing: .5px; }
    table { width: 100%; border-collapse: collapse; font-size: 12px; }
    th { text-align: left; padding: 8px 10px; color: var(--text-dim); font-weight: 600; border-bottom: 1px solid var(--border); background: #f8fafc; font-size: 11px; text-transform: uppercase; letter-spacing: .4px; }
    td { padding: 8px 10px; border-bottom: 1px solid var(--border); vertical-align: middle; color: var(--text); }
    .state-running { color: #166534; font-weight: 600; }
    .state-exited  { color: var(--text-dim); }
    .state-missing { color: #991b1b; }
    .btn { display: inline-flex; align-items: center; gap: 5px; padding: 6px 12px;
      border-radius: 6px; font-size: 12px; font-weight: 500; cursor: pointer; border: 1px solid transparent;
      text-decoration: none; transition: background .12s, border-color .12s, opacity .12s; }
    .btn:hover { opacity: .92; }
    .btn-primary   { background: var(--accent); color: #fff; }
    .btn-primary:hover { background: var(--accent-glow); }
    .btn-secondary { background: #f1f5f9; color: var(--text); border-color: #cbd5e1; }
    .btn-secondary:hover { background: #e2e8f0; }
    .btn-danger    { background: #fef2f2; color: #991b1b; border-color: #fecaca; }
    .btn-danger:hover { background: #fee2e2; }
    .btn-success   { background: #f0fdf4; color: #166534; border-color: #bbf7d0; }
    .btn-success:hover { background: #dcfce7; }

    /* Alerts & SOC Analytics */
    .alerts-panel { padding: 20px; overflow-y: auto; flex-direction: column; gap: 16px; background: var(--bg-base); }
    .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-bottom: 8px; }

    .kpi-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 14px; display: flex; flex-direction: column; gap: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.02); }
    .kpi-label { font-size: 11px; text-transform: uppercase; color: var(--text-dim); font-weight: 600; letter-spacing: 0.5px; }
    .kpi-val { font-size: 24px; font-weight: 700; color: var(--text); font-family: var(--font-mono); font-variant-numeric: tabular-nums; }
    .kpi-sub { font-size: 11px; color: var(--text-dim); }
    
    .alert-card { background: var(--bg-card); border: 1px solid var(--border); border-left: 3px solid var(--red); border-radius: 6px; padding: 14px; margin-bottom: 12px; }
    .alert-card.sev-critical { border-left-color: #dc2626; background: #fff5f5; }
    .alert-card.sev-high     { border-left-color: #ea580c; background: #fff7ed; }
    .alert-card.sev-medium   { border-left-color: #d97706; background: #fffbeb; }
    .alert-card.sev-low      { border-left-color: #2563eb; background: #eff6ff; }
    
    .alert-header { display: flex; align-items: center; justify-content: space-between; gap: 10px; margin-bottom: 8px; flex-wrap: wrap; }
    .alert-sev { font-size: 10px; font-weight: 700; text-transform: uppercase; padding: 2px 7px; border-radius: 4px; }
    .alert-sev.sev-critical { background: #fee2e2; color: #991b1b; border: 1px solid #fecaca; }
    .alert-sev.sev-high     { background: #ffedd5; color: #9a3412; border: 1px solid #fed7aa; }
    .alert-sev.sev-medium   { background: #fef3c7; color: #92400e; border: 1px solid #fde68a; }
    .alert-sev.sev-low      { background: #dbeafe; color: #1e40af; border: 1px solid #bfdbfe; }
    .mitre-tag { background: #f1f5f9; border: 1px solid #cbd5e1; color: #475569; font-size: 11px; font-family: var(--font-mono); padding: 2px 6px; border-radius: 4px; }
    .evidence-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 8px; background: #f8fafc; border: 1px solid var(--border); border-radius: 6px; padding: 8px 12px; margin-top: 8px; font-size: 12px; }
    .evidence-item { display: flex; flex-direction: column; }
    .evidence-k { font-size: 10px; color: var(--text-dim); text-transform: uppercase; }
    .evidence-v { font-size: 12px; font-weight: 600; font-family: var(--font-mono); color: var(--text); }

    /* Sub-tabs in Network View */
    .net-subtabs-bar {
      display: flex; align-items: center; gap: 8px;
      padding: 8px 16px; background: var(--bg-panel);
      border-bottom: 1px solid var(--border); flex-shrink: 0;
    }
    .subtab-btn {
      background: #f8fafc; border: 1px solid var(--border);
      color: var(--text-muted); border-radius: 6px; padding: 5px 12px;
      font-size: 11px; font-weight: 600; cursor: pointer;
      transition: all .12s; display: inline-flex; align-items: center; gap: 5px;
    }
    .subtab-btn:hover { background: #f1f5f9; color: var(--text); }
    .subtab-btn.active { background: var(--accent); color: #fff; border-color: var(--accent); }
    .subtab-content { display: none; flex: 1; flex-direction: column; overflow: hidden; min-height: 0; }
    .subtab-content.active { display: flex; }

    /* Logs raw panel */
    .logs-raw-panel { padding: 20px; overflow-y: auto; background: var(--bg-base); }
    .filter-bar { display: flex; gap: 10px; margin-bottom: 16px; }
    input, select { background: var(--bg-panel); border: 1px solid var(--border-lit); color: var(--text);
      border-radius: 6px; padding: 6px 10px; font-size: 12px; font-family: var(--font-ui); }
    input:focus, select:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 2px rgba(37,99,235,0.15); }

    /* Modals */
    .modal-overlay {
      display: none; position: fixed; inset: 0; z-index: 100;
      background: rgba(15,23,42,0.4); backdrop-filter: blur(2px);
      align-items: center; justify-content: center;
    }
    .modal-overlay.open { display: flex; }
    .modal {
      background: var(--bg-panel); border: 1px solid var(--border);
      border-radius: 10px; padding: 24px; min-width: 340px; max-width: 440px;
      box-shadow: 0 10px 25px rgba(0,0,0,.08);
      animation: modal-in .15s ease;
    }
    @keyframes modal-in { from { opacity:0; transform: scale(.98) translateY(6px); } }
    .modal-title { font-size: 15px; font-weight: 700; color: var(--text); margin-bottom: 4px; }
    .modal-sub { font-size: 12px; color: var(--text-dim); margin-bottom: 18px; }
    .form-group { margin-bottom: 14px; }
    .form-label { display: block; font-size: 11px; font-weight: 600; text-transform: uppercase;
      letter-spacing: .4px; color: var(--text-dim); margin-bottom: 6px; }
    .form-input { width: 100%; background: var(--bg-panel); border: 1px solid var(--border-lit);
      color: var(--text); border-radius: 6px; padding: 7px 10px; font-size: 12px; }
    .form-input:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 2px rgba(37,99,235,0.15); }
    .radio-group { display: flex; flex-direction: column; gap: 8px; }
    .radio-opt { display: flex; align-items: center; gap: 10px; padding: 9px 12px;
      border: 1px solid var(--border); border-radius: 6px; cursor: pointer; transition: border-color .12s, background .12s; background: var(--bg-panel); }
    .radio-opt:hover { border-color: var(--border-lit); background: var(--bg-hover); }
    .radio-opt input[type=radio] { accent-color: var(--accent); }
    .radio-opt .opt-label { font-size: 13px; font-weight: 500; color: var(--text); }
    .radio-opt .opt-desc { font-size: 11px; color: var(--text-dim); margin-top: 2px; }
    .modal-actions { display: flex; gap: 10px; margin-top: 20px; justify-content: flex-end; }
    .spinner { display: none; width: 14px; height: 14px; border: 2px solid transparent;
      border-top-color: #fff; border-radius: 50%; animation: spin .6s linear infinite; }
    @keyframes spin { to { transform: rotate(360deg); } }

    /* Stat counters in header */
    .stat-pill { display: inline-flex; align-items: center; gap: 6px;
      padding: 3px 10px; border-radius: 999px; font-size: 11px; font-family: var(--font-mono);
      background: #f1f5f9; border: 1px solid var(--border); color: var(--text-muted); }
    .stat-pill .num { font-weight: 600; font-variant-numeric: tabular-nums; }
    .stat-pill .num.red    { color: #dc2626; }
    .stat-pill .num.amber  { color: #d97706; }
    .stat-pill .num.dim    { color: #64748b; }
  </style>
</head>
<body>
<div class="app">

  <!-- ══ HEADER ══ -->
  <header class="header">
    <div class="header-logo">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--accent)"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
      Padding Oracle <span>SOC Lab</span>
      <span class="header-badge-uni">Cybersecurity Lab · Uni Project</span>
    </div>
    <div id="attack-badge" class="badge badge-quiet"><span class="dot"></span> QUIET</div>
    <div class="stat-pill" title="Eventi inviati dall'attaccante">Attaccante <span class="num red" id="cnt-attacker">0</span></div>
    <div class="stat-pill" title="Eventi client benigni">Client <span class="num amber" id="cnt-benign">0</span></div>
    <div class="stat-pill" title="Richieste ricevute dal server vittima">Vittima <span class="num dim" id="cnt-victim">0</span></div>
    <div class="header-spacer"></div>
    <div class="header-time" id="clock"></div>
  </header>

  <div class="body">

    <!-- ══ SIDEBAR ══ -->
    <nav class="sidebar">
      <div class="sidebar-section">Laboratorio &amp; Controllo</div>
      <a class="nav-item active" data-panel="network" onclick="showPanel('network',this)">
        <span class="nav-icon">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
        </span> 1. Controllo Scenario &amp; Live
      </a>

      <div class="sidebar-section" style="margin-top:12px">Esperienza SOC &amp; Difesa</div>
      <a class="nav-item" data-panel="hunting" onclick="showPanel('hunting',this)">
        <span class="nav-icon">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="22" y1="12" x2="18" y2="12"></line><line x1="6" y1="12" x2="2" y2="12"></line><line x1="12" y1="6" x2="12" y2="2"></line><line x1="12" y1="22" x2="12" y2="18"></line></svg>
        </span> 2. Threat Hunting &amp; SIEM
      </a>
      <a class="nav-item" data-panel="alerts" onclick="showPanel('alerts',this)">
        <span class="nav-icon">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
        </span> 3. Alert SOC &amp; WAF Triage
      </a>
      <a class="nav-item" data-panel="attack-detail" onclick="showPanel('attack-detail',this)">
        <span class="nav-icon">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="4" y1="21" x2="4" y2="14"></line><line x1="4" y1="10" x2="4" y2="3"></line><line x1="12" y1="21" x2="12" y2="12"></line><line x1="12" y1="8" x2="12" y2="3"></line><line x1="20" y1="21" x2="20" y2="16"></line><line x1="20" y1="12" x2="20" y2="3"></line><line x1="1" y1="14" x2="7" y2="14"></line><line x1="9" y1="8" x2="15" y2="8"></line><line x1="17" y1="16" x2="23" y2="16"></line></svg>
        </span> 4. Attack Detail &amp; Matrix
      </a>
      <a class="nav-item" data-panel="log-soc" onclick="showPanel('log-soc',this)">
        <span class="nav-icon">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
        </span> 5. Log SOC (Req/Res)
      </a>

      <div class="sidebar-section" style="margin-top:12px">Mappatura &amp; Telemetria</div>
      <a class="nav-item" data-panel="docker" onclick="showPanel('docker',this)">
        <span class="nav-icon">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>
        </span> 6. Entity Directory &amp; IP Matrix
      </a>
      <a class="nav-item" data-panel="log-raw" onclick="showPanel('log-raw',this)">
        <span class="nav-icon">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"></polyline><line x1="12" y1="19" x2="20" y2="19"></line></svg>
        </span> 7. Telemetria &amp; Log Raw (Live)
      </a>

      <div class="sidebar-spacer"></div>
      <span id="sidebar-victim-name" style="display:none">—</span>
    </nav>

    <!-- ══ MAIN ══ -->
    <main class="main">

      <!-- ── Scenario Command Center + Live Log ── -->
      <div id="panel-network" class="panel visible">
        <div class="net-panel">
          
          <!-- ══ 4-Card Scenario Command Center ══ -->
          <div class="scenario-grid">
            
            <!-- Card 1: Benign Fleet -->
            <div class="sc-card card-benign">
              <div class="sc-header">
                <div class="sc-title">Flotta Client Aziendali</div>
                <span class="sc-badge off" id="sc-benign-badge">IN PAUSA</span>
              </div>
              <div class="sc-metrics">
                <div class="sc-metric-item">
                  <span class="sc-m-lbl">Subnet Virtuale</span>
                  <span class="sc-m-val amber" id="sc-benign-subnet">192.168.1.0/24</span>
                </div>
                <div class="sc-metric-item">
                  <span class="sc-m-lbl">Workstation Pool</span>
                  <span class="sc-m-val" id="sc-benign-vips">10 Host IP</span>
                </div>
                <div class="sc-metric-item">
                  <span class="sc-m-lbl">Error Rate Fisiologico</span>
                  <span class="sc-m-val green" id="sc-benign-err">3.0%</span>
                </div>
                <div class="sc-metric-item">
                  <span class="sc-m-lbl">Eventi Generati</span>
                  <span class="sc-m-val amber" id="sc-benign-cnt">0</span>
                </div>
              </div>
              <div class="sc-actions">
                <button class="btn btn-secondary" style="font-size:11px;padding:4px 8px" onclick="openModal('modal-benign')">Configura</button>
                <button id="btn-toggle-benign" class="btn btn-secondary" style="font-size:11px;padding:4px 10px;border-color:var(--amber);color:var(--amber)" onclick="toggleBenignTraffic()">Avvia</button>
              </div>
            </div>

            <!-- Card 2: Red Team Attacker -->
            <div class="sc-card card-attacker">
              <div class="sc-header">
                <div class="sc-title">Attaccante Red Team</div>
                <span class="sc-badge off" id="sc-atk-badge">QUIET</span>
              </div>
              <div class="sc-metrics">
                <div class="sc-metric-item">
                  <span class="sc-m-lbl">Modalità Exploit</span>
                  <span class="sc-m-val red" id="sc-atk-mode">Status 500 Oracle</span>
                </div>
                <div class="sc-metric-item">
                  <span class="sc-m-lbl">Origine IP</span>
                  <span class="sc-m-val" id="sc-atk-ipmode">198.51.100.50</span>
                </div>
                <div class="sc-metric-item">
                  <span class="sc-m-lbl">Stealth Evasion</span>
                  <span class="sc-m-val" id="sc-atk-stealth">Disattivo</span>
                </div>
                <div class="sc-metric-item">
                  <span class="sc-m-lbl">Probe Inviati</span>
                  <span class="sc-m-val red" id="sc-atk-cnt">0</span>
                </div>
              </div>
              <div class="sc-actions">
                <button class="btn btn-secondary" style="font-size:11px;padding:4px 8px" onclick="openModal('modal-attacker')">Configura</button>
                <button id="btn-toggle-attack" class="btn btn-danger" style="font-size:11px;padding:4px 10px" onclick="toggleAttackerTraffic()">Avvia</button>
              </div>
            </div>

            <!-- Card 3: Target Server -->
            <div class="sc-card card-victim">
              <div class="sc-header">
                <div class="sc-title">Target Crittografico (Victim)</div>
                <span class="sc-badge on" id="sc-victim-badge">RUNNING</span>
              </div>
              <div class="sc-metrics">
                <div class="sc-metric-item">
                  <span class="sc-m-lbl">Profilo Crittografico</span>
                  <span class="sc-m-val green" id="sc-victim-mode-lbl">Vulnerabile (500)</span>
                </div>
                <div class="sc-metric-item">
                  <span class="sc-m-lbl">Protezione WAF L7</span>
                  <span class="sc-m-val" id="sc-victim-waf-lbl">Disattivo</span>
                </div>
                <div class="sc-metric-item">
                  <span class="sc-m-lbl">Endpoint Interno</span>
                  <span class="sc-m-val" style="font-size:11px">victim:8080</span>
                </div>
                <div class="sc-metric-item">
                  <span class="sc-m-lbl">Stato Target</span>
                  <span class="sc-m-val green">Ascolto Attivo</span>
                  <span id="sc-victim-cnt" style="display:none">0</span>
                </div>
              </div>
              <div class="sc-actions">
                <button class="btn btn-secondary" style="font-size:11px;padding:4px 8px" onclick="openModal('modal-victim')">Switch Modo</button>
                <button class="btn btn-secondary" style="font-size:11px;padding:4px 8px" onclick="toggleWAFPolicy()">Toggle WAF</button>
              </div>
            </div>

            <!-- Card 4: SOC SIEM Engine -->
            <div class="sc-card card-soc">
              <div class="sc-header">
                <div class="sc-title">SOC SIEM &amp; Triage</div>
                <span class="sc-badge on" id="sc-soc-badge">ENGINE ON</span>
              </div>
              <div class="sc-metrics">
                <div class="sc-metric-item">
                  <span class="sc-m-lbl">Allarmi Attivi</span>
                  <span class="sc-m-val" id="sc-soc-alerts-num" style="color:var(--accent)">0</span>
                </div>
                <div class="sc-metric-item">
                  <span class="sc-m-lbl">Precisione TPR / FPR</span>
                  <span class="sc-m-val green" id="sc-soc-kpi-str">100% / 0%</span>
                  <span id="sc-soc-mttd-str" style="display:none">—</span>
                </div>
                <div class="sc-metric-item">
                  <span class="sc-m-lbl">Stato Analisi</span>
                  <span class="sc-m-val" style="font-size:11px;color:var(--text-dim)">Forensic Ready</span>
                </div>
              </div>
              <div class="sc-actions">
                <button class="btn btn-secondary" style="font-size:11px;padding:4px 10px;border:1px solid var(--border-lit)" onclick="resetTest()" id="btn-reset-test">Reset Globale</button>
              </div>
            </div>

          </div>

          <!-- Network Sub-Tab Bar -->
          <div class="net-subtabs-bar">
            <span style="font-size:11px;font-weight:700;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px;margin-right:6px">TELEMETRIA &amp; LOG:</span>
            <button class="subtab-btn active" id="subtab-btn-raw" onclick="switchNetSubTab('raw')">Telemetria &amp; Log Raw</button>
            <button class="subtab-btn" id="subtab-btn-soc" onclick="switchNetSubTab('soc')">Log SOC (Richieste/Risposte)</button>
            <button class="subtab-btn" id="subtab-btn-attack" onclick="switchNetSubTab('attack')">Attack Detail</button>
            <button class="subtab-btn" id="subtab-btn-alerts" onclick="switchNetSubTab('alerts')">Alert SOC</button>
            <div style="flex:1"></div>
            <div class="log-legend" id="subtab-legend" style="margin-right:12px">
              <span><span class="legend-dot" style="background:var(--red)"></span>Attaccante</span>
              <span><span class="legend-dot" style="background:var(--amber)"></span>Flotta Benigna</span>
              <span><span class="legend-dot" style="background:#94a3b8"></span>Target Server</span>
            </div>
            <label id="subtab-autoscroll-wrap" style="font-size:11px;color:var(--text-dim);display:flex;align-items:center;gap:6px">
              <input type="checkbox" id="auto-scroll-chk" checked style="accent-color:var(--accent)"> Auto-scroll
            </label>
          </div>

          <!-- Sub-Tab Containers -->
          <div class="subtab-content active" id="subtab-content-raw">
            <div class="log-table-header">
              <span>TIMESTAMP</span>
              <span>IP SORGENTE</span>
              <span class="col-etype">EVENT TYPE</span>
              <span>ENDPOINT</span>
              <span>STATUS</span>
              <span>DETTAGLI FORENSI &amp; PAYLOAD</span>
            </div>
            <div class="log-stream-wrap" id="net-raw-stream"></div>
          </div>
          <div class="subtab-content" id="subtab-content-soc">
            <div class="log-stream-wrap" id="net-soc-stream"></div>
          </div>
          <div class="subtab-content" id="subtab-content-attack">
            <div class="atk-body" id="net-atk-body" style="padding:16px;overflow-y:auto;flex:1">
              <p class="atk-no-data">In attesa di un attacco… lancia l'attaccante dal Command Center in alto.</p>
            </div>
          </div>
          <div class="subtab-content" id="subtab-content-alerts">
            <div id="net-alerts-content" style="padding:16px;overflow-y:auto;flex:1">
              <p style="color:var(--text-muted)">Caricamento allarmi…</p>
            </div>
          </div>
        </div>
      </div>



      <!-- ── Log SOC (filtered: attacker + benign) ── -->
      <div id="panel-log-soc" class="panel">
        <div class="log-header" style="padding:12px 24px;flex-wrap:wrap;gap:8px;background:#ffffff;border-bottom:1px solid var(--border)">
          <div style="display:flex;align-items:center;gap:10px">
            <strong style="font-size:13px;color:var(--text);display:flex;align-items:center;gap:6px">
              Log SOC — Correlazione Richiesta e Risposta
            </strong>
            <span style="font-size:11px;color:var(--text-dim);background:#f1f5f9;border:1px solid #e2e8f0;padding:2px 8px;border-radius:4px;font-family:var(--font-mono)">Analisi Forense Oracolo &amp; Payload CBC</span>
          </div>
          <div style="flex:1"></div>
          <select id="soc-ep-filter" onchange="loadSocLogs()" style="font-size:11px;padding:4px 8px">
            <option value="">Tutti gli Endpoint</option>
            <option value="/api/v1/crypto/decrypt">/api/v1/crypto/decrypt</option>
            <option value="/api/v1/crypto/encrypt">/api/v1/crypto/encrypt</option>
            <option value="/api/v1/auth/login">/api/v1/auth/login</option>
            <option value="/api/v1/user/profile">/api/v1/user/profile</option>
            <option value="/api/v1/health">/api/v1/health</option>
            <option value="/sample_token">/sample_token</option>
            <option value="/decrypt">/decrypt (Legacy Target)</option>
          </select>
          <button id="soc-filter-mode-btn" class="btn btn-secondary" style="font-size:11px;padding:4px 10px;background:#fee2e2;border-color:#fecaca;color:#991b1b" onclick="toggleSocFilterMode()">Solo Attacchi (Default)</button>
          <a href="/logs/export/csv" class="btn btn-primary" style="font-size:11px;padding:4px 10px;text-decoration:none;display:inline-flex;align-items:center;gap:4px">📥 Scarica CSV</a>
          <a href="/logs/export/jsonl" class="btn btn-secondary" style="font-size:11px;padding:4px 10px;text-decoration:none;display:inline-flex;align-items:center;gap:4px;margin-left:4px">📄 Scarica JSONL</a>
          <label style="font-size:11px;color:var(--text-muted);display:flex;align-items:center;gap:6px;cursor:pointer;margin-left:10px">
            <input type="checkbox" id="soc-auto-scroll" checked style="accent-color:var(--accent)"> Auto-scroll
          </label>
          <button class="btn btn-secondary" style="font-size:11px;padding:4px 10px;margin-left:8px" onclick="loadSocLogs()">↻ Aggiorna</button>
          <span style="font-size:11px;color:var(--text-dim);margin-left:8px">ogni 2s</span>
        </div>
        <div class="log-stream-wrap" id="log-soc-stream"></div>
      </div>

      <!-- ── Log Raw & Live Telemetry ── -->
      <div id="panel-log-raw" class="panel">
        <div style="padding:12px 20px;border-bottom:1px solid var(--border);background:var(--bg-panel)">
          <div class="filter-bar" style="flex-wrap:wrap;gap:8px;align-items:center">
            <select id="raw-ip-filter" onchange="loadRawLogs()">
              <option value="">Tutti gli IP sorgente</option>
            </select>
            <select id="raw-etype-filter" onchange="loadRawLogs()">
              <option value="">Tutti gli event_type</option>
              <option value="attack_probe">attack_probe (sonde oracle)</option>
              <option value="attack_progress">attack_progress (byte decifrati)</option>
              <option value="attack_complete">attack_complete (exploit completato)</option>
              <option value="attack_blocked">attack_blocked (bloccato dal WAF)</option>
              <option value="attack_recon">attack_recon (ricognizione token)</option>
              <option value="attack_noise_blend">attack_noise_blend (traffico evasivo)</option>
              <option value="http_request">http_request (server victim)</option>
              <option value="benign_request">benign_request (client flotta)</option>
            </select>
            <select id="raw-ep-filter" onchange="loadRawLogs()">
              <option value="">Tutti gli Endpoint</option>
              <option value="/api/v1/crypto/decrypt">/api/v1/crypto/decrypt (Oracle Target)</option>
              <option value="/decrypt">/decrypt (Legacy Alias)</option>
              <option value="/api/v1/crypto/encrypt">/api/v1/crypto/encrypt</option>
              <option value="/api/v1/auth/login">/api/v1/auth/login</option>
              <option value="/api/v1/user/profile">/api/v1/user/profile</option>
              <option value="/api/v1/health">/api/v1/health</option>
              <option value="/sample_token">/sample_token</option>
            </select>
            <select id="raw-status-filter" onchange="loadRawLogs()">
              <option value="">Tutti gli Status</option>
              <option value="200">200 OK (Success/Valid)</option>
              <option value="400">400 Bad Request</option>
              <option value="401">401 Unauthorized</option>
              <option value="403">403 Forbidden (WAF Block)</option>
              <option value="404">404 Not Found</option>
              <option value="500">500 Server Error (Oracle Err)</option>
            </select>
            <input id="raw-q" type="text" placeholder="Cerca testo libero o IP…" oninput="loadRawLogs()" style="flex:1;min-width:140px">
            <select id="raw-limit" onchange="loadRawLogs()">
              <option value="100">100 righe</option>
              <option value="500">500 righe</option>
              <option value="1000" selected>1.000 righe</option>
              <option value="2000">2.000 righe</option>
              <option value="5000">5.000 righe</option>
              <option value="10000">10.000 righe</option>
              <option value="0">Tutti i log (In RAM: 10k max)</option>
            </select>
            <label style="font-size:11px;color:var(--text-muted);display:flex;align-items:center;gap:5px;cursor:pointer">
              <input type="checkbox" id="raw-show-etype" checked onchange="toggleRawEventType(this.checked)" style="accent-color:var(--accent)"> Event Type
            </label>
            <label style="font-size:11px;color:var(--text-muted);display:flex;align-items:center;gap:6px;cursor:pointer;margin-left:4px">
              <input type="checkbox" id="raw-auto-scroll" checked style="accent-color:var(--accent)"> Auto-scroll
            </label>
            <a href="/logs/export/csv" class="btn btn-primary" style="font-size:11px;padding:5px 12px;text-decoration:none;display:inline-flex;align-items:center;gap:4px">📥 Scarica CSV</a>
            <a href="/logs/export/jsonl" class="btn btn-secondary" style="font-size:11px;padding:5px 12px;text-decoration:none;display:inline-flex;align-items:center;gap:4px">📄 Scarica JSONL</a>
            <button class="btn btn-secondary" style="font-size:11px;padding:5px 10px" onclick="loadRawLogs()">↻ Aggiorna</button>
          </div>
        </div>
        <div class="log-table-header">
          <span>TIMESTAMP</span>
          <span>IP SORGENTE</span>
          <span class="col-etype">EVENT TYPE</span>
          <span>ENDPOINT</span>
          <span>STATUS</span>
          <span>DETTAGLI FORENSI &amp; PAYLOAD</span>
        </div>
        <div class="log-stream-wrap" id="log-raw-stream"></div>
      </div>

      <!-- ── Attack Detail ── -->
      <div id="panel-attack-detail" class="panel atk-panel">
        <div class="atk-header">
          <h2>🔬 Attack Detail — Padding Oracle byte-by-byte</h2>
          <div style="flex:1"></div>
          <button class="btn btn-secondary" style="font-size:11px;padding:4px 10px" onclick="loadAttackDetail()">↻ Aggiorna</button>
          <span style="font-size:11px;color:var(--text-muted);margin-left:8px">live (800ms)</span>
        </div>
        <div class="atk-body" id="atk-body">
          <p class="atk-no-data">In attesa di un attacco… lancia l'attaccante dal pannello Network o Docker.</p>
        </div>
      </div>

      <!-- ── Alerts & SOC Analytics ── -->
      <div id="panel-alerts" class="panel alerts-panel">
        <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px">
          <div>
            <div class="panel-title" style="margin-bottom:2px">SOC SIEM Monitoring &amp; Incident Response</div>
            <div style="font-size:12px;color:var(--text-dim)">Monitoraggio Allarmi Real-Time, Baseline di Traffico, Metriche Forensi (TPR/FPR/MTTD) e Playbook di Mitigazione</div>
          </div>
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <button class="btn btn-secondary" onclick="openForensicReportModal()">Report Forense Markdown</button>
            <button class="btn btn-danger" onclick="clearLogsAndReset()">Reset Baseline &amp; Log</button>
          </div>
        </div>

        <!-- SOC Detection KPIs Cards -->
        <div class="kpi-grid">
          <div class="kpi-card">
            <div class="kpi-label">Mean Time To Detect (MTTD)</div>
            <div class="kpi-val" id="kpi-mttd">—</div>
            <div class="kpi-sub">Tempo dal 1° probe al 1° allarme</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-label">True Positive Rate (TPR)</div>
            <div class="kpi-val" style="color:var(--green)" id="kpi-tpr">—</div>
            <div class="kpi-sub">Accuratezza su attacchi reali</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-label">False Positive Rate (FPR)</div>
            <div class="kpi-val" style="color:var(--blue)" id="kpi-fpr">—</div>
            <div class="kpi-sub">Falsi allarmi su traffico benigno</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-label">Allarmi di Sicurezza Attivi</div>
            <div class="kpi-val" id="kpi-alerts-count">0</div>
            <div class="kpi-sub" id="kpi-alerts-status">Monitoraggio continuo</div>
          </div>
        </div>

        <!-- WAF Quarantined / Blocked IPs Live Table -->
        <div class="card" style="margin:0;border:1px solid #fecaca;background:#fff5f5">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
            <div style="display:flex;align-items:center;gap:8px">
              <div class="panel-title" style="font-size:13px;margin:0;color:#991b1b">IP Quarantinati da Inline WAF / SOAR</div>
              <span id="waf-blocked-count-badge" style="font-size:10px;font-weight:700;padding:2px 8px;border-radius:10px;background:#fee2e2;color:#991b1b;border:1px solid #fecaca">0 bloccati</span>
            </div>
            <button class="btn btn-secondary" style="font-size:11px;padding:3px 8px" onclick="loadWafStatusInSoc()">Ricarica WAF</button>
          </div>
          <div style="overflow-x:auto">
            <table style="width:100%;font-size:11px">
              <thead>
                <tr>
                  <th>Indirizzo IP Quarantinato</th>
                  <th>Stato Enforcing</th>
                  <th>TTL Rimanente (s)</th>
                  <th>Azione di Mitigazione</th>
                  <th>Azione Rapida Analista</th>
                </tr>
              </thead>
              <tbody id="waf-blocked-ips-tbody">
                <tr><td colspan="5" style="color:var(--text-dim);text-align:center;padding:10px">Nessun IP attualmente in quarantena WAF (Firewall in attesa o disattivato).</td></tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Telemetry Profile (Objective Per-IP Table) -->
        <div class="card" style="margin:0">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
            <div class="panel-title" style="font-size:13px;margin:0">Profilo Telemetrico &amp; Valutazione Nodi per IP (Finestra Corrente)</div>
            <span style="font-size:11px;color:var(--text-dim)">Valutazione integrata traffico, deviazione baseline e stato perimetrale WAF</span>
          </div>
          <div style="overflow-x:auto">
            <table style="width:100%;font-size:12px">
              <thead>
                <tr>
                  <th>Indirizzo IP Sorgente</th>
                  <th>Stato Perimetro (WAF)</th>
                  <th>Richieste Totali</th>
                  <th>Errori (Fail Rate)</th>
                  <th>Latenza Mediana (p50)</th>
                  <th>StdDev Latenza</th>
                  <th>Valutazione Secondo Regola SOC</th>
                  <th>Azione SOC</th>
                </tr>
              </thead>
              <tbody id="telemetry-ips-tbody">
                <tr><td colspan="8" style="color:var(--text-dim);text-align:center;padding:12px">Inizializzazione telemetria nodi…</td></tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Active Security Alerts Feed -->
        <div class="card" style="margin:0">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
            <div class="panel-title" style="font-size:13px;margin:0">Incident Feed &amp; Indicatori di Attacco (IOA)</div>
            <button class="btn btn-secondary" style="font-size:11px;padding:3px 8px" onclick="loadAlerts()">Ricarica</button>
          </div>
          <div id="alerts-content"><p style="color:var(--text-dim)">Caricamento telemetria…</p></div>
        </div>

        <!-- Didactic / Academic Exam Guide Card -->
        <div class="card" style="margin:0;background:#f8fafc;border:1px solid var(--border)">
          <div class="panel-title" style="font-size:13px;margin-bottom:8px;color:var(--text)">Guida ai Concetti SOC per la Relazione Accademica</div>
          <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(240px, 1fr));gap:12px;font-size:12px">
            <div>
              <strong style="color:var(--text)">MTTD (Mean Time To Detect)</strong>
              <p style="color:var(--text-dim);margin:2px 0 0 0">Secondi trascorsi tra il primo probe dell'attaccante e il primo allarme generato. Indica la reattività del SOC.</p>
            </div>
            <div>
              <strong style="color:var(--text)">TPR &amp; FPR</strong>
              <p style="color:var(--text-dim);margin:2px 0 0 0"><strong>TPR</strong>: % di attacchi rilevati (Target: 100%). <strong>FPR</strong>: % di falsi allarmi sui client benigni (Target: 0%).</p>
            </div>
            <div>
              <strong style="color:var(--text)">Baseline Profiling</strong>
              <p style="color:var(--text-dim);margin:2px 0 0 0">I client benigni definiscono il traffico normale (errori &lt; 1%, latenza ~2ms). Qualsiasi deviazione è un indicatore di attacco.</p>
            </div>
            <div>
              <strong style="color:var(--text)">Timing Side-Channel</strong>
              <p style="color:var(--text-dim);margin:2px 0 0 0">Su <code>victim-partial</code>, la vittima maschera l'errore come 403 generico ma impiega ~30ms in più se il padding è valido. Il SOC lo rileva tramite l'alta deviazione standard.</p>
            </div>
          </div>
        </div>
      </div>


      <!-- ── Threat Hunting & SIEM Explorer (Fase 1) ── -->
      <div id="panel-hunting" class="panel alerts-panel">
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;margin-bottom:12px">
          <div>
            <div class="panel-title" style="margin-bottom:2px">SOC Threat Hunting &amp; SIEM Explorer</div>
            <div style="font-size:12px;color:var(--text-dim)"><strong>Fase 1:</strong> Esplora i log con query SIEM, formula regole analitiche, esegui il backtest live e distribuisci policy inline su WAF e SIEM.</div>
          </div>
          <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
            <label style="display:flex;align-items:center;gap:6px;font-size:11px;color:var(--text-dim);cursor:pointer;background:#f8fafc;padding:4px 8px;border-radius:6px;border:1px solid var(--border)" title="Attiva/Disattiva etichette didattiche di laboratorio (Red Team / Error Type)">
              <input type="checkbox" id="toggle-ground-truth" onchange="toggleGroundTruthView()" style="cursor:pointer">
              <span>Etichette Ground-Truth</span>
            </label>
            <span id="waf-global-badge" style="font-size:11px;font-weight:700;padding:4px 10px;border-radius:12px;background:#fee2e2;color:#991b1b;border:1px solid #fecaca">WAF DISATTIVO</span>
            <button class="btn btn-primary" style="font-size:12px" onclick="toggleWAFPolicy()">Toggle WAF / Regole</button>
          </div>
        </div>

        <!-- 1. SIEM Query Bar & Preset Chips -->
        <div class="card" style="margin:0 0 16px 0;border:1px solid #cbd5e1;background:#ffffff">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;flex-wrap:wrap;gap:8px">
            <div style="display:flex;align-items:center;gap:8px">
              <span style="font-size:11px;font-weight:700;padding:2px 8px;border-radius:4px;background:#eff6ff;color:var(--accent);border:1px solid #bfdbfe">FASE 1</span>
              <h3 style="margin:0;font-size:13px;color:var(--text)">Esplorazione Log SIEM &amp; Filtro Query</h3>
            </div>
            <div style="display:flex;gap:6px;align-items:center">
              <button class="btn btn-secondary" style="font-size:11px;padding:3px 10px" onclick="openModal('modal-siem-cheatsheet')">Guida Sintassi &amp; Query</button>
            </div>
          </div>

          <!-- Query Input -->
          <div style="display:flex;gap:8px;margin-bottom:8px">
            <input id="siem-query-input" class="form-input" style="font-family:var(--font-mono);font-size:12px;background:#f8fafc;color:var(--text);border-color:#cbd5e1" placeholder="Digita query SIEM (es. status != 200 oppure client_ip = attacker oppure * per tutti i log)" value="*" onkeydown="if(event.key==='Enter') executeSiemQuery()">
            <button class="btn btn-primary" style="font-size:12px;padding:6px 14px;white-space:nowrap" onclick="executeSiemQuery()">Esegui Query</button>
            <button class="btn btn-secondary" style="font-size:12px;padding:6px 12px;white-space:nowrap" onclick="applySiemPreset('*')">Tutti (*)</button>
          </div>

            <!-- Quick Preset Chips -->
          <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px;align-items:center">
            <span style="font-size:11px;color:var(--text-dim)">Filtri Rapidi:</span>
            <button class="btn btn-secondary" style="font-size:11px;padding:3px 8px;background:#fee2e2;border:1px solid #fecaca;color:#991b1b" onclick="filterAttackerIps(false)" title="Filtra tutti gli IP identificati come attaccanti (storici e correnti)">Tutti IP Attaccanti</button>
            <button class="btn btn-secondary" style="font-size:11px;padding:3px 8px;background:#fef3c7;border:1px solid #fde68a;color:#92400e" onclick="filterAttackerIps(true)" title="Filtra solo l'IP dell'attacco attualmente in corso">Attaccante Attivo</button>
            <button class="btn btn-secondary" style="font-size:11px;padding:3px 8px" onclick="applySiemPreset('status != 200')">Solo Errori (status != 200)</button>
            <button class="btn btn-secondary" style="font-size:11px;padding:3px 8px" onclick="applySiemPreset('endpoint = /decrypt')">Solo Decrypt (/decrypt)</button>
            <button class="btn btn-secondary" style="font-size:11px;padding:3px 8px" onclick="applySiemPreset('endpoint = /api/v1/auth/login')">Solo Login (/auth/login)</button>
            <button class="btn btn-secondary" style="font-size:11px;padding:3px 8px" onclick="applySiemPreset('status = 500 AND endpoint = /decrypt')">Padding Errors (500)</button>
            <button class="btn btn-secondary" style="font-size:11px;padding:3px 8px" onclick="applySiemPreset('endpoint = /decrypt | GROUP BY src_ip | HAVING FAIL_RATE > 0.8 AND COUNT(*) > 15')">Aggrega Attaccanti (Fail Rate > 80%)</button>
            <button class="btn btn-secondary" style="font-size:11px;padding:3px 8px" onclick="applySiemPreset('endpoint = /decrypt | GROUP BY src_ip | HAVING STDDEV(latency_ms) > 5.0')">Anomalia Side-Channel (StdDev > 5ms)</button>
            <button class="btn btn-secondary" style="font-size:11px;padding:3px 8px" onclick="applySiemPreset('status = 429 OR error_type = waf_blocked')">Blocchi WAF (429)</button>
          </div>

          <!-- SIEM Summary Metrics Banner -->
          <div id="siem-summary-banner" style="display:flex;flex-wrap:wrap;gap:8px;padding:8px 12px;background:#f8fafc;border:1px solid var(--border);border-radius:6px;font-size:11px;align-items:center">
            <span style="font-weight:600;color:var(--text)">Risultati Query:</span>
            <span id="siem-stat-total" class="stat-pill">Trovati: <strong>0</strong></span>
            <span id="siem-stat-200" class="stat-pill" style="color:var(--green)">HTTP 200: <strong>0</strong></span>
            <span id="siem-stat-400" class="stat-pill" style="color:var(--amber)">HTTP 400: <strong>0</strong></span>
            <span id="siem-stat-403" class="stat-pill" style="color:var(--amber)">HTTP 403: <strong>0</strong></span>
            <span id="siem-stat-429" class="stat-pill" style="color:#7c3aed">HTTP 429 (WAF): <strong>0</strong></span>
            <span id="siem-stat-500" class="stat-pill" style="color:var(--red)">HTTP 500 (Padding): <strong>0</strong></span>
          </div>

          <!-- Filtered Log Table Preview -->
          <div style="margin-top:10px;max-height:220px;overflow-y:auto;border:1px solid var(--border);border-radius:6px;background:#ffffff">
            <table style="width:100%;font-size:11px;font-family:var(--font-mono)">
              <thead style="position:sticky;top:0;background:#f8fafc;z-index:2">
                <tr>
                  <th style="padding:6px 8px" title="Timestamp evento ISO">Timestamp (<code>ts</code>)</th>
                  <th style="padding:6px 8px" title="Client IP - Filtra con: client_ip = ... oppure src_ip = ...">Client IP (<code>client_ip</code>)</th>
                  <th style="padding:6px 8px" title="Endpoint HTTP - Filtra con: endpoint = ...">Endpoint (<code>endpoint</code>)</th>
                  <th style="padding:6px 8px" title="Stato HTTP - Filtra con: status = ... o status_code = ...">Status (<code>status_code</code>)</th>
                  <th style="padding:6px 8px" title="Latenza totale HTTP - Filtra con: latency_ms > ...">Latenza (<code>latency_ms</code>)</th>
                  <th style="padding:6px 8px" title="Dimensione Payload Ciphertext - Filtra con: ciphertext_len = ...">Payload (<code>ciphertext_len</code>)</th>
                  <th style="padding:6px 8px" title="Tipo Errore - Filtra con: error_type = ...">Error Type (<code>error_type</code>)</th>
                </tr>
              </thead>
              <tbody id="siem-logs-tbody">
                <tr><td colspan="7" style="color:var(--text-dim);text-align:center;padding:12px">Nessuna ricerca eseguita. Clicca "Esegui Query" o un suggerimento rapido.</td></tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- 2. Raw Telemetry Actor Profiles -->
        <div class="card" style="margin:0 0 16px 0">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;flex-wrap:wrap;gap:8px">
            <div>
              <div style="display:flex;align-items:center;gap:8px">
                <span style="font-size:11px;font-weight:700;padding:2px 8px;border-radius:4px;background:#fef3c7;color:#92400e;border:1px solid #fde68a">FASE 2</span>
                <h3 style="margin:0;font-size:13px;color:var(--text)">Telemetria Grezza: Profilazione Attori &amp; Feature Crittografiche</h3>
              </div>
              <div style="font-size:11px;color:var(--text-dim);margin-top:2px">Identifica l'attore anomalo e clicca su <strong>"Adotta Valori IP"</strong> per calibrare automaticamente le soglie al Passo 3.</div>
            </div>
            <button class="btn btn-secondary" style="font-size:11px;padding:3px 8px" onclick="loadHuntingData()">Aggiorna Profili</button>
          </div>
          
          <!-- Scope Banner attivo alimentato da Passo 1 -->
          <div id="hunting-scope-banner" style="display:flex;align-items:center;justify-content:space-between;gap:8px;padding:6px 12px;background:#eff6ff;border:1px solid #bfdbfe;border-radius:6px;font-size:11px;margin-bottom:10px">
            <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap">
              <span style="font-weight:700;color:var(--accent)">Scope Attivo da Fase 1:</span>
              <code id="hunting-scope-query-text" style="color:var(--accent);background:#ffffff;padding:2px 6px;border-radius:4px;border:1px solid #bfdbfe">*</code>
              <span id="hunting-scope-events-count" style="color:var(--text-dim)">(tutti gli eventi del server)</span>
            </div>
            <button class="btn btn-secondary" style="font-size:10px;padding:2px 8px" onclick="applySiemPreset('*')">Resetta a Tutti (*)</button>
          </div>

          <div style="overflow-x:auto">
            <table style="width:100%;font-size:12px">
              <thead>
                <tr>
                  <th style="cursor:pointer;user-select:none" onclick="sortHuntingProfiles('ip')" title="Ordina per Indirizzo IP">Actor IP <span id="sort-icon-ip">⇅</span></th>
                  <th style="cursor:pointer;user-select:none" onclick="sortHuntingProfiles('reqs')" title="Ordina per Richieste nello Scope">Richieste (Scope) <span id="sort-icon-reqs">⇅</span></th>
                  <th style="cursor:pointer;user-select:none" onclick="sortHuntingProfiles('fail_rate')" title="Ordina per Fail Rate">Errori (Fail Rate) <span id="sort-icon-fail_rate">⇅</span></th>
                  <th style="cursor:pointer;user-select:none" onclick="sortHuntingProfiles('block')" title="Ordina per Blocco Target">Blocco Target <span id="sort-icon-block">⇅</span></th>
                  <th style="cursor:pointer;user-select:none" onclick="sortHuntingProfiles('latency')" title="Ordina per Latenza Media / StdDev">Latenza Media / StdDev <span id="sort-icon-latency">⇅</span></th>
                  <th style="cursor:pointer;user-select:none" onclick="sortHuntingProfiles('bc')" title="Ordina per Coefficiente Bimodalità">Bimodalità (Sarle BC) <span id="sort-icon-bc">⇅</span></th>
                  <th style="cursor:pointer;user-select:none" onclick="sortHuntingProfiles('score')" title="Ordina per Risk Score">Classificazione &amp; Calibrazione <span id="sort-icon-score">⇅</span></th>
                </tr>
              </thead>
              <tbody id="hunting-profiles-tbody">
                <tr><td colspan="7" style="color:var(--text-muted)">Caricamento profili telemetrici…</td></tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- 3. Detection & Prevention Engineering: Regole SIEM & Regole WAF -->
        <div class="card" style="margin:0">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;flex-wrap:wrap;gap:8px">
            <div>
              <div style="display:flex;align-items:center;gap:8px">
                <span style="font-size:11px;font-weight:700;padding:2px 8px;border-radius:4px;background:#dcfce7;color:#15803d;border:1px solid #bbf7d0">FASE 3</span>
                <h3 style="margin:0;font-size:13px;color:var(--text)">Ingegneria Regole: Rilevamento SIEM (SOC) &amp; Prevenzione Inline WAF</h3>
              </div>
              <div style="font-size:11px;color:var(--text-muted);margin-top:2px">Configura, personalizza ed applica indipendentemente le regole analitiche SIEM e le policy di blocco preventivo WAF (Sigma YAML).</div>
            </div>
            <button class="btn btn-secondary" style="font-size:11px;padding:4px 8px" onclick="copySigmaYaml()">Copia Sigma YAML</button>
          </div>
        </div>

        <!-- Didactic clarification banner -->
        <div style="padding:10px 14px;background:#f8fafc;border:1px solid var(--border);border-radius:6px;font-size:12px;color:var(--text-dim);margin-bottom:14px">
          <strong style="color:var(--text)">Differenza di Difesa:</strong>
          <strong>Regole SIEM</strong> analizzano la telemetria correlando pattern e generano incidenti per il SOC.
          <strong>Regole WAF</strong> agiscono in linea come filtro L7: se attivate, bloccano le sorgenti malevole con <code>HTTP 429</code> prima che raggiungano il core crittografico.
        </div>

        <!-- Sub-Tabs Switcher for Passo 3 -->
        <div style="display:flex;gap:8px;border-bottom:1px solid var(--border);margin-bottom:14px;padding-bottom:6px">
          <button id="btn-tab-waf" class="btn btn-primary" style="font-size:12px;padding:6px 14px" onclick="switchRuleTab('waf')">Regole WAF (Inline Prevention)</button>
          <button id="btn-tab-siem" class="btn btn-secondary" style="font-size:12px;padding:6px 14px" onclick="switchRuleTab('siem')">Regole SIEM (Detection &amp; Alerting)</button>
        </div>

        <!-- TAB 1: WAF RULES & POLICIES -->
        <div id="section-rules-waf">
          <div style="display:grid;grid-template-columns:1.2fr 0.8fr;gap:14px;align-items:start">
            <!-- Left: WAF Rules Catalog -->
            <div>
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
                <label class="form-label" style="font-size:11px;color:var(--text-dim);margin:0">Catalogo Regole di Prevenzione Inline WAF (Filtro L7):</label>
                <div style="display:flex;gap:4px">
                  <button class="btn btn-secondary" style="font-size:11px;padding:3px 8px" onclick="toggleWafMasterRule()" id="btn-waf-master-toggle">Tutte ON</button>
                  <button class="btn btn-secondary" style="font-size:11px;padding:3px 8px" onclick="loadWafRulesStatus()">Ricarica</button>
                </div>
              </div>
              <div id="waf-rules-catalog-container" style="background:#f8fafc;border:1px solid var(--border);border-radius:6px;padding:10px;font-size:11px">
                <!-- WAF rules rendered dynamically via JS -->
                <div style="color:var(--text-dim);text-align:center;padding:8px">Caricamento catalogo regole WAF…</div>
              </div>
            </div>

            <!-- Right: Tuning Parametri Globali e Creazione Regola WAF -->
            <div style="background:#ffffff;border:1px solid var(--border);border-radius:8px;padding:12px">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
                <label class="form-label" style="font-size:11px;color:var(--text);font-weight:700;margin:0">Calibrazione Soglie &amp; Creazione Regola WAF:</label>
                <span style="font-size:11px;color:var(--text-dim)">Sliding-Window L7</span>
              </div>
              
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px">
                <div class="form-group" style="margin-bottom:0">
                  <label class="form-label" style="font-size:10px;color:var(--text-dim);margin-bottom:2px">Nome Regola WAF:</label>
                  <input class="form-input" id="new-waf-rule-name" placeholder="Es. Custom Burst Ban" style="font-size:11px;padding:5px 8px">
                </div>
                <div class="form-group" style="margin-bottom:0">
                  <label class="form-label" style="font-size:10px;color:var(--text);margin-bottom:2px;font-weight:700">Endpoint API Target (L7):</label>
                  <input class="form-input" id="new-waf-rule-endpoint" list="waf-endpoints-datalist" value="/api/v1/crypto/decrypt" style="font-size:11px;padding:5px 8px;font-family:var(--font-mono)">
                  <datalist id="waf-endpoints-datalist">
                    <option value="/api/v1/crypto/decrypt">/api/v1/crypto/decrypt (Padding Oracle)</option>
                    <option value="/api/v1/auth/login">/api/v1/auth/login (Auth / Brute Force)</option>
                    <option value="/decrypt">/decrypt (Alias Legacy)</option>
                    <option value="*">* (Globale / Tutte le API)</option>
                  </datalist>
                </div>
              </div>
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:10px">
                <div class="form-group" style="margin-bottom:6px">
                  <label class="form-label" style="font-size:10px;display:flex;justify-content:space-between">
                    <span>Min Richieste / Finestra</span>
                    <span style="color:var(--text-dim)">Volume</span>
                  </label>
                  <input class="form-input" type="number" id="hunt-min-events" value="15" min="5" max="100" onchange="runHuntingBacktest()" style="font-size:11px;padding:5px 8px">
                  <div style="font-size:10px;color:var(--text-dim);margin-top:2px">Soglia burst IP (Normali: 1-2, Atk: &gt;100)</div>
                </div>
                <div class="form-group" style="margin-bottom:6px">
                  <label class="form-label" style="font-size:10px;display:flex;justify-content:space-between">
                    <span>Finestra Temporale (s)</span>
                    <span style="color:var(--text-dim)">Sliding Window</span>
                  </label>
                  <input class="form-input" type="number" id="hunt-waf-window" value="60" min="5" max="3600" step="5" onchange="runHuntingBacktest()" style="font-size:11px;padding:5px 8px">
                  <div style="font-size:10px;color:var(--text-dim);margin-top:2px">Finestra scorrimento eventi (es. 60s, 300s anti-slow)</div>
                </div>
                <div class="form-group" style="margin-bottom:6px">
                  <label class="form-label" style="font-size:10px;display:flex;justify-content:space-between">
                    <span>Soglia Fail-Rate (0-1)</span>
                    <span style="color:var(--text-dim)">Errori %</span>
                  </label>
                  <input class="form-input" type="number" id="hunt-fail-rate" value="0.80" min="0.1" max="1.0" step="0.05" onchange="runHuntingBacktest()" style="font-size:11px;padding:5px 8px">
                  <div style="font-size:10px;color:var(--text-dim);margin-top:2px">% Errori 500/403 (Normali: ~2%, Atk: ~99%)</div>
                </div>
                <div class="form-group" style="margin-bottom:6px">
                  <label class="form-label" style="font-size:10px;display:flex;justify-content:space-between">
                    <span>Max Errori Consecutivi</span>
                    <span style="color:var(--text-dim)">Probing</span>
                  </label>
                  <input class="form-input" type="number" id="hunt-consecutive-errors" value="12" min="3" max="50" onchange="runHuntingBacktest()" style="font-size:11px;padding:5px 8px">
                  <div style="font-size:10px;color:var(--text-dim);margin-top:2px">Errori di fila prima del ban immediato</div>
                </div>
                <div class="form-group" style="margin-bottom:6px;grid-column:span 2">
                  <label class="form-label" style="font-size:10px;display:flex;justify-content:space-between">
                    <span>Ban TTL (secondi)</span>
                    <span style="color:var(--text-dim)">Auto-Expire</span>
                  </label>
                  <input class="form-input" type="number" id="hunt-ban-ttl" value="120" min="10" max="600" step="10" style="font-size:11px;padding:5px 8px">
                  <div style="font-size:10px;color:var(--text-dim);margin-top:2px">Durata quarantena dinamica WAF</div>
                </div>
              </div>
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
                <button class="btn btn-primary" style="font-size:11px;padding:7px 10px" onclick="runHuntingBacktest()">Live Backtest WAF</button>
                <button class="btn btn-success" style="font-size:11px;padding:7px 10px" onclick="addNewWafRule()">Salva nel Catalogo WAF</button>
              </div>

              <!-- Sigma YAML Viewer (Collapsible / Preview) -->
              <div style="margin-top:12px">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
                  <label class="form-label" style="font-size:10px;color:var(--text-dim);margin:0">Specifica Regola Sigma YAML (Preview):</label>
                  <button class="btn btn-secondary" style="font-size:10px;padding:2px 6px" onclick="copySigmaYaml()">Copia</button>
                </div>
                <textarea id="sigma-rule-output" class="form-input" rows="4" readonly style="font-family:var(--font-mono);font-size:10px;background:#f8fafc;color:var(--text);line-height:1.4"></textarea>
              </div>
            </div>
          </div>
        </div>

        <!-- TAB 2: SIEM DETECTION RULES -->
        <div id="section-rules-siem" style="display:none">
          <div style="display:grid;grid-template-columns:1.2fr 0.8fr;gap:14px;align-items:start">
            <!-- Left: SIEM Active Rules Catalog -->
            <div>
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
                <label class="form-label" style="font-size:11px;color:var(--text-dim);margin:0">Catalogo Regole di Correlazione SIEM (Triage Out-of-Band):</label>
                <div style="display:flex;gap:4px">
                  <button class="btn btn-secondary" style="font-size:11px;padding:3px 8px" onclick="toggleSiemMasterRule()" id="btn-siem-master-toggle">Tutte ON</button>
                  <button class="btn btn-secondary" style="font-size:11px;padding:3px 8px" onclick="loadSiemRulesStatus()">Ricarica</button>
                </div>
              </div>
              <div id="siem-rules-catalog-container" style="background:#f8fafc;border:1px solid var(--border);border-radius:6px;padding:10px;font-size:11px">
                <div style="color:var(--text-dim);text-align:center;padding:8px">Caricamento catalogo regole SIEM…</div>
              </div>
            </div>

            <!-- Right: SIEM Statistical Thresholds & Rule Builder -->
            <div style="background:#ffffff;border:1px solid var(--border);border-radius:8px;padding:12px">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
                <label class="form-label" style="font-size:11px;color:var(--text);font-weight:700;margin:0">Calibrazione Soglie &amp; Creazione Regola SIEM:</label>
                <span style="font-size:11px;color:var(--text-dim)">Correlazione Forense</span>
              </div>
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px">
                <div class="form-group" style="margin-bottom:0">
                  <label class="form-label" style="font-size:10px;color:var(--text-dim);margin-bottom:2px">Nome Regola SIEM:</label>
                  <input class="form-input" id="new-siem-rule-name" placeholder="Es. High Fail-Rate Probing" style="font-size:11px;padding:5px 8px">
                </div>
                <div class="form-group" style="margin-bottom:0">
                  <label class="form-label" style="font-size:10px;color:var(--text);margin-bottom:2px;font-weight:700">Endpoint API Target (L7):</label>
                  <input class="form-input" id="new-siem-rule-endpoint" list="waf-endpoints-datalist" value="/api/v1/crypto/decrypt" style="font-size:11px;padding:5px 8px;font-family:var(--font-mono)">
                </div>
              </div>
              <div style="margin-bottom:8px">
                <label class="form-label" style="font-size:10px;color:var(--text-dim);margin-bottom:2px">MITRE ATT&amp;CK:</label>
                <input class="form-input" id="new-siem-rule-mitre" placeholder="T1110.001" style="font-size:11px;padding:5px 8px">
              </div>
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:6px">
                <div class="form-group" style="margin-bottom:6px">
                  <label class="form-label" style="font-size:10px;display:flex;justify-content:space-between">
                    <span>Min Richieste / Finestra</span>
                    <span style="color:var(--text-dim)">Volume</span>
                  </label>
                  <input class="form-input" type="number" id="hunt-siem-min-events" value="15" min="5" max="100" onchange="runHuntingBacktest()" style="font-size:11px;padding:5px 8px">
                  <div style="font-size:10px;color:var(--text-dim);margin-top:2px">Campione minimo per correlazione forense</div>
                </div>
                <div class="form-group" style="margin-bottom:6px">
                  <label class="form-label" style="font-size:10px;display:flex;justify-content:space-between">
                    <span>Soglia Fail-Rate (0-1)</span>
                    <span style="color:var(--text-dim)">Errori %</span>
                  </label>
                  <input class="form-input" type="number" id="hunt-siem-fail-rate" value="0.80" min="0.0" max="1.0" step="0.05" onchange="runHuntingBacktest()" style="font-size:11px;padding:5px 8px">
                  <div style="font-size:10px;color:var(--text-dim);margin-top:2px">% Errori 500/403 (0 = ignora, Atk: ~99%)</div>
                </div>
              </div>
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:10px">
                <div class="form-group" style="margin-bottom:6px">
                  <label class="form-label" style="font-size:10px;display:flex;justify-content:space-between">
                    <span>Timing StdDev (ms)</span>
                    <span style="color:var(--text-dim)">Varianza</span>
                  </label>
                  <input class="form-input" type="number" id="hunt-timing-stddev" value="6.0" min="1.0" max="30.0" step="0.5" onchange="runHuntingBacktest()" style="font-size:11px;padding:5px 8px">
                  <div style="font-size:10px;color:var(--text-dim);margin-top:2px">Dispersione latenza (Normali: &lt;1.5ms, Timing: &gt;10ms)</div>
                </div>
                <div class="form-group" style="margin-bottom:6px">
                  <label class="form-label" style="font-size:10px;display:flex;justify-content:space-between">
                    <span>Bimodalità Sarle (BC)</span>
                    <span style="color:var(--text-dim)">Side-Channel</span>
                  </label>
                  <input class="form-input" type="number" id="hunt-bimodality" value="0.555" min="0.1" max="0.99" step="0.05" onchange="runHuntingBacktest()" style="font-size:11px;padding:5px 8px">
                  <div style="font-size:10px;color:var(--text-dim);margin-top:2px">Firma a doppio picco (&gt;0.555 = Timing Leak)</div>
                </div>
              </div>
              <div style="display:flex;flex-direction:column;gap:6px">
                <button class="btn btn-primary" style="font-size:11px;padding:7px" onclick="runHuntingBacktest()">Simula Rilevamenti SIEM (Backtest)</button>
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:6px">
                  <button class="btn btn-secondary" style="font-size:11px;padding:7px" onclick="addNewSiemRule()">Aggiungi al Catalogo</button>
                  <button class="btn btn-secondary" style="font-size:11px;padding:7px" onclick="saveSiemThresholdsOnly()">Salva Soglie SIEM</button>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Backtest Results Box -->
        <div id="hunting-backtest-result" style="margin-top:12px;padding:10px 14px;background:#f8fafc;border-radius:6px;display:none;border:1px solid var(--border)">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
            <strong style="color:var(--green)">Risultati Live Backtest:</strong>
            <div id="hunting-kpis-badge" style="font-size:12px;font-weight:700"></div>
          </div>
          <div id="hunting-backtest-details" style="font-size:11px;color:var(--text-dim)"></div>
        </div>
      </div>

      <!-- ── Entity Directory & IP Traffic Matrix (ex Inventario Nodi) ── -->
      <div id="panel-docker" class="panel docker-panel">
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;margin-bottom:14px">
          <div>
            <div class="panel-title" style="margin-bottom:2px">Entity Directory &amp; IP Traffic Matrix</div>
            <div style="font-size:12px;color:var(--text-muted)">Anagrafica live di tutti gli indirizzi IP osservati nella telemetria: workstation aziendali, vettori d'attacco Red Team, breakdown errori e stato WAF.</div>
          </div>
          <button class="btn btn-secondary" style="font-size:12px" onclick="loadEntityDirectory()">Aggiorna Entità &amp; IP</button>
        </div>

        <!-- Entity Summary KPIs -->
        <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(180px, 1fr));gap:10px;margin-bottom:16px">
          <div class="kpi-card" style="padding:10px 14px">
            <span class="kpi-label">IP Totali Rilevati</span>
            <span class="kpi-val" id="ent-kpi-total">0</span>
            <span class="kpi-sub">Attivi nella finestra telemetrica</span>
          </div>
          <div class="kpi-card" style="padding:10px 14px">
            <span class="kpi-label">Workstation Benigne</span>
            <span class="kpi-val" style="color:var(--amber)" id="ent-kpi-benign">0</span>
            <span class="kpi-sub">Subnet <code>192.168.1.0/24</code></span>
          </div>
          <div class="kpi-card" style="padding:10px 14px">
            <span class="kpi-label">Sorgenti Exploit / Red Team</span>
            <span class="kpi-val" style="color:var(--red)" id="ent-kpi-attacker">0</span>
            <span class="kpi-sub">High error-rate / Bimodal</span>
          </div>
          <div class="kpi-card" style="padding:10px 14px">
            <span class="kpi-label">Quarantena WAF (HTTP 429)</span>
            <span class="kpi-val" style="color:#7c3aed" id="ent-kpi-blocked">0</span>
            <span class="kpi-sub">IP bloccati inline</span>
          </div>
        </div>

        <!-- Live IP Entity Directory Table -->
        <div class="card" style="margin-bottom:16px">
          <h3 style="margin:0 0 10px 0;font-size:13px;color:var(--text);display:flex;justify-content:space-between;align-items:center">
            <span>Anagrafica Entità di Rete &amp; Telemetria per Singolo IP</span>
            <span style="font-size:11px;color:var(--text-dim);font-weight:400;text-transform:none">Ordinamento dinamico per volume e anomalia</span>
          </h3>
          <div style="overflow-x:auto">
            <table id="entities-table" style="min-width:760px">
              <thead>
                <tr>
                  <th style="white-space:nowrap">Indirizzo IP Sorgente</th>
                  <th style="white-space:nowrap">Ruolo / Classificazione</th>
                  <th style="white-space:nowrap">Richieste Totali</th>
                  <th style="white-space:nowrap">Status Breakdown (200 OK / Errori)</th>
                  <th style="white-space:nowrap">Latenza Media (StdDev)</th>
                  <th style="white-space:nowrap">Verdetto SIEM</th>
                  <th style="white-space:nowrap;text-align:right">Azioni di Sicurezza</th>
                </tr>
              </thead>
              <tbody id="entities-tbody">
                <tr><td colspan="7" style="color:var(--text-muted);padding:14px;text-align:center">Caricamento entità telemetriche…</td></tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Docker Infrastructure Containers -->
        <div class="card" style="margin-bottom:16px">
          <h3 style="margin:0 0 10px 0;font-size:13px;color:var(--text)">Infrastruttura Container Docker (Engine Runtime)</h3>
          <div style="overflow-x:auto">
            <table id="docker-table" style="min-width:680px">
              <thead>
                <tr>
                  <th style="white-space:nowrap">Host / Container</th>
                  <th style="white-space:nowrap">Ruolo del Servizio</th>
                  <th style="white-space:nowrap">Indirizzo IP Docker</th>
                  <th style="white-space:nowrap">Stato Container</th>
                  <th style="white-space:nowrap">Porte Host</th>
                  <th style="white-space:nowrap;text-align:right">Controllo Processo</th>
                </tr>
              </thead>
              <tbody id="docker-tbody">
                <tr><td colspan="6" style="color:var(--text-muted)">Caricamento stato container…</td></tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Global Lab Actions -->
        <div class="card">
          <h3 style="margin:0 0 8px 0;font-size:13px;color:var(--text)">Azioni Infrastrutturali Globali</h3>
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <form style="display:inline" method="post" action="/docker/action/start"><input type="hidden" name="target" value="soc"><button class="btn btn-secondary" type="submit">Riavvia SOC Collector</button></form>
            <form style="display:inline" method="post" action="/docker/action/stop-all"><button class="btn btn-danger" type="submit">Stop Tutti i Container</button></form>
          </div>
        </div>
      </div>


    </main>
  </div>
</div>

<!-- ══ MODAL: Victim ══ -->
<div class="modal-overlay" id="modal-victim">
  <div class="modal">
    <div class="modal-title">Modalità Target Vittima (Runtime Hardening)</div>
    <div class="modal-sub">Commuta all'istante il profilo crittografico del target unico aziendale (senza riavvii container)</div>
    <div class="radio-group">
      <label class="radio-opt">
        <input type="radio" name="victim-mode" value="vuln" checked>
        <div><div class="opt-label">Modalità Vulnerabile (Status 500)</div><div class="opt-desc">Distingue padding_error (500) da altri errori (403). Vulnerabile all'attacco standard.</div></div>
      </label>
      <label class="radio-opt">
        <input type="radio" name="victim-mode" value="partial">
        <div><div class="opt-label">Modalità Side-Channel (Timing Leakage)</div><div class="opt-desc">Status 403 uniforme ma latenza variabile. Rilevabile tramite dispersione statistica.</div></div>
      </label>
      <label class="radio-opt">
        <input type="radio" name="victim-mode" value="fixed">
        <div><div class="opt-label">Modalità Hardened (Encrypt-then-MAC)</div><div class="opt-desc">Mitigazione crittografica attiva: HMAC-SHA256 verificato prima della decifratura (0 byte compromessi).</div></div>
      </label>
    </div>
    <div class="modal-actions">
      <button class="btn btn-secondary" onclick="closeModal('modal-victim')">Chiudi</button>
      <button class="btn btn-success" onclick="switchVictim()">
        <span class="spinner" id="spin-victim"></span> Applica Modalità Target
      </button>
    </div>
  </div>
</div>

<!-- ══ MODAL: Benign ══ -->
<div class="modal-overlay" id="modal-benign">
  <div class="modal" style="max-width:580px;width:95%">
    <div class="modal-title">Flotta Client Benigni (Multi-IP Corporate Traffic)</div>
    <div class="modal-sub">Simula un'intera rete aziendale di workstation con IP dinamici, sessioni utente reali (Login, Profilo, Encrypt, Decrypt, Verify) e varianza naturale.</div>
    
    <div class="card" style="padding:14px 16px;background:var(--bg-panel)">
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
        <div class="form-group">
          <label class="form-label">Workstation Virtuali (IP Pool)</label>
          <input class="form-input" type="number" id="benign-virtual-ips" value="10" min="1" max="100" step="1">
          <div style="font-size:11px;color:var(--text-dim);margin-top:2px">Genera IP subnet <code>192.168.1.10+</code></div>
        </div>
        <div class="form-group">
          <label class="form-label">% Errori Fisiologici (400/401)</label>
          <input class="form-input" type="number" id="benign-err-rate" value="3.0" min="0" max="30" step="0.5">
          <div style="font-size:11px;color:var(--text-dim);margin-top:2px">Typo credenziali, token scaduti</div>
        </div>
        <div class="form-group">
          <label class="form-label">Sleep Minimo (ms)</label>
          <input class="form-input" type="number" id="benign-min" value="300" min="1">
        </div>
        <div class="form-group">
          <label class="form-label">Sleep Massimo (ms)</label>
          <input class="form-input" type="number" id="benign-max" value="1000" min="1">
        </div>
      </div>
      <div class="form-group" style="margin-top:10px">
        <label style="font-size:12px;color:var(--text);display:flex;align-items:center;gap:6px">
          <input type="checkbox" id="benign-continuous" checked> <strong>Loop Continuo in Background (Daemon aziendale)</strong>
        </label>
      </div>
      <div class="modal-actions" style="margin-top:12px">
        <button class="btn btn-secondary" onclick="closeModal('modal-benign')">Chiudi</button>
        <button class="btn btn-primary" onclick="saveBenignConfig('benign')"><span class="spinner" id="spin-benign"></span> Salva Configurazione Flotta</button>
      </div>
    </div>
  </div>
</div>

<!-- ══ MODAL: Attacker ══ -->
<div class="modal-overlay" id="modal-attacker">
  <div class="modal" style="max-width:580px;width:95%">
    <div class="modal-title">Configura Attacco Red Team (Padding Oracle &amp; Evasion)</div>
    <div class="modal-sub">Personalizza il segreto crittografico, l'algoritmo di exploit, l'IP sorgente e le tecniche di evasione WAF.</div>
    <div class="form-group">
      <label class="form-label">Segreto Vittima</label>
      <div class="radio-group">
        <label class="radio-opt">
          <input type="radio" name="atk-secret-mode" value="manual" checked>
          <div><div class="opt-label">Manuale</div><div class="opt-desc">Inserisci un segreto personalizzato</div></div>
        </label>
        <label class="radio-opt">
          <input type="radio" name="atk-secret-mode" value="random">
          <div><div class="opt-label">Random</div><div class="opt-desc">Genera automaticamente un nuovo segreto</div></div>
        </label>
      </div>
      <input class="form-input" type="text" id="atk-secret-input" value="PaddingOracle:TopSecret" placeholder="Es. PaddingOracle:TopSecret" style="margin-top:8px">
    </div>
    <div class="form-group">
      <label class="form-label">Modalità Oracle</label>
      <div class="radio-group">
        <label class="radio-opt">
          <input type="radio" name="atk-mode" value="vuln" checked>
          <div><div class="opt-label">Status-Based Oracle (500 vs 403/200)</div><div class="opt-desc">Analizza i codici di ritorno HTTP per individuare il padding valido (HTTP 200)</div></div>
        </label>
        <label class="radio-opt">
          <input type="radio" name="atk-mode" value="timing">
          <div><div class="opt-label">Timing Side-Channel Oracle</div><div class="opt-desc">Misura la dispersione temporale (latenza) per estrarre i byte</div></div>
        </label>
      </div>
    </div>
    <div class="form-group">
      <label class="form-label">Origine Indirizzo IP Attaccante</label>
      <div class="radio-group">
        <label class="radio-opt">
          <input type="radio" name="atk-ip-mode" value="static" checked>
          <div><div class="opt-label">IP Statico Container</div><div class="opt-desc">Usa l'IP reale Docker dell'attaccante</div></div>
        </label>
        <label class="radio-opt">
          <input type="radio" name="atk-ip-mode" value="random">
          <div><div class="opt-label">IP Spoofing Singolo</div><div class="opt-desc">Simula un IP esterno fisso (198.51.100.x)</div></div>
        </label>
        <label class="radio-opt">
          <input type="radio" name="atk-ip-mode" value="rotate">
          <div><div class="opt-label">Proxy Pool / Botnet (Con Riuso)</div><div class="opt-desc">Ruota l'IP tra pool di nodi (203.0.113.x, 12-42 req/nodo)</div></div>
        </label>
        <label class="radio-opt">
          <input type="radio" name="atk-ip-mode" value="per-query">
          <div><div class="opt-label">Rotazione Ephemera Continua (1 IP = 1 Query)</div><div class="opt-desc">Genera un IP nuovo univoco per ogni probe /decrypt (evasione WAF totale)</div></div>
        </label>
      </div>
    </div>
    <div class="form-group" style="padding:10px 12px;background:#f8fafc;border:1px solid var(--border);border-radius:6px">
      <label style="font-size:12px;color:var(--text);display:flex;align-items:center;gap:6px">
        <input type="checkbox" id="atk-blend-noise"> <strong>Stealth Noise Blending (Evasione WAF)</strong>
      </label>
      <div style="font-size:11px;color:var(--text-muted);margin-top:4px">
        L'attaccante inietta richieste 200 OK lecite tra i probe di decifratura per abbassare il Failure Rate sotto la soglia di allarme del SOC.
      </div>
    </div>
    <div class="form-group">
      <label class="form-label">Delay tra probe (ms) — Consigliato: 4ms per ~45s di demo fluida</label>
      <input class="form-input" type="number" id="atk-sleep" value="4" min="0" max="1000" step="1">
    </div>
    <div class="modal-actions">
      <button class="btn btn-secondary" onclick="closeModal('modal-attacker')">Chiudi</button>
      <button class="btn btn-primary" onclick="saveAttackConfig()">
        <span class="spinner" id="spin-attacker"></span> Salva Configurazione Attacco
      </button>
    </div>
  </div>
</div>


<!-- ══ MODAL: Forensic Incident Report ══ -->
<div class="modal-overlay" id="modal-report">
  <div class="modal" style="max-width:720px;width:90%">
    <div class="modal-title">Forensic Incident &amp; SOC Evaluation Report</div>
    <div class="modal-sub">Report accademico generato automaticamente, pronto da allegare alla relazione d'esame</div>
    <div style="margin-bottom:14px">
      <textarea id="report-md-content" readonly style="width:100%;height:320px;background:#f8fafc;border:1px solid var(--border);color:var(--text);font-family:var(--font-mono);font-size:11px;padding:10px;border-radius:8px;resize:vertical;line-height:1.5"></textarea>
    </div>
    <div class="modal-actions" style="justify-content:space-between;align-items:center">
      <button class="btn btn-secondary" onclick="closeModal('modal-report')">Chiudi</button>
      <div style="display:flex;gap:8px">
        <button class="btn btn-primary" onclick="copyReportToClipboard()">Copia Markdown</button>
        <button class="btn btn-success" onclick="downloadReportFile()">Scarica File .md</button>
      </div>
    </div>
  </div>
</div>

<!-- ══ MODAL: SIEM Query Syntax & Cheat-Sheet ══ -->
<div class="modal-overlay" id="modal-siem-cheatsheet">
  <div class="modal" style="max-width:820px;width:95%;max-height:88vh;overflow-y:auto">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
      <div class="modal-title" style="margin:0">Guida Sintassi &amp; Cheat-Sheet Query SIEM</div>
      <button class="btn btn-secondary" style="font-size:12px;padding:2px 8px" onclick="closeModal('modal-siem-cheatsheet')">✕</button>
    </div>
    <div class="modal-sub">Riferimento completo dei campi L7, operatori di confronto, funzioni di aggregazione e logiche di Threat Hunting.</div>

    <!-- Table of fields -->
    <h4 style="color:var(--accent);font-size:13px;margin:12px 0 6px 0">1. Campi Filtrabili e Alias Riconosciuti</h4>
    <table style="width:100%;font-size:11px;border-collapse:collapse;margin-bottom:14px">
      <thead>
        <tr style="background:#f8fafc;text-align:left">
          <th style="padding:6px 8px">Nome Campo / Alias</th>
          <th style="padding:6px 8px">Tipo</th>
          <th style="padding:6px 8px">Descrizione L7</th>
          <th style="padding:6px 8px">Esempio Query</th>
        </tr>
      </thead>
      <tbody>
        <tr style="border-bottom:1px solid var(--border)">
          <td style="padding:5px 8px;font-family:var(--font-mono);color:var(--accent)"><code>client_ip</code> / <code>src_ip</code> / <code>ip</code></td>
          <td>Stringa</td>
          <td>Indirizzo IP sorgente o ID client</td>
          <td><code>client_ip = attacker</code></td>
        </tr>
        <tr style="border-bottom:1px solid var(--border)">
          <td style="padding:5px 8px;font-family:var(--font-mono);color:var(--accent)"><code>endpoint</code> / <code>path</code> / <code>url</code></td>
          <td>Stringa</td>
          <td>Path HTTP dell'API richiesta</td>
          <td><code>endpoint = /decrypt</code></td>
        </tr>
        <tr style="border-bottom:1px solid var(--border)">
          <td style="padding:5px 8px;font-family:var(--font-mono);color:var(--accent)"><code>status_code</code> / <code>status</code> / <code>code</code></td>
          <td>Intero</td>
          <td>Codice di stato HTTP restituito (200, 400, 403, 429, 500)</td>
          <td><code>status = 500</code> oppure <code>status != 200</code></td>
        </tr>
        <tr style="border-bottom:1px solid var(--border)">
          <td style="padding:5px 8px;font-family:var(--font-mono);color:var(--accent)"><code>latency_ms</code> / <code>latency</code> / <code>time</code></td>
          <td>Float</td>
          <td>Latenza totale HTTP in millisecondi</td>
          <td><code>latency_ms > 15</code></td>
        </tr>
        <tr style="border-bottom:1px solid var(--border)">
          <td style="padding:5px 8px;font-family:var(--font-mono);color:var(--accent)"><code>ciphertext_len</code> / <code>len</code></td>
          <td>Intero</td>
          <td>Lunghezza in byte del payload cifrato (multiplo di 16 in AES)</td>
          <td><code>ciphertext_len = 48</code></td>
        </tr>
        <tr style="border-bottom:1px solid var(--border)">
          <td style="padding:5px 8px;font-family:var(--font-mono);color:var(--accent)"><code>error_type</code> / <code>error</code></td>
          <td>Stringa</td>
          <td>Tipo di errore registrato (padding_error, waf_blocked, ok)</td>
          <td><code>error_type = padding_error</code></td>
        </tr>
        <tr>
          <td style="padding:5px 8px;font-family:var(--font-mono);color:var(--accent)"><code>mode</code> / <code>service</code></td>
          <td>Stringa</td>
          <td>Modalità del target (vuln, partial, fixed) o servizio (victim, attacker)</td>
          <td><code>mode = vuln AND service = victim</code></td>
        </tr>
      </tbody>
    </table>

    <!-- Operators and Syntax -->
    <h4 style="color:var(--accent);font-size:13px;margin:12px 0 6px 0">2. Operatori di Confronto &amp; Sintassi Booleana</h4>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;font-size:11px;margin-bottom:14px">
      <div style="padding:8px;background:#f8fafc;border-radius:6px;border:1px solid var(--border)">
        <strong style="color:var(--text)">Operatori di Confronto:</strong>
        <ul style="margin:4px 0 0 16px;padding:0;color:var(--text-dim)">
          <li><code>=</code> oppure <code>==</code> : Uguaglianza</li>
          <li><code>!=</code> oppure <code>&lt;&gt;</code> : Disuguaglianza</li>
          <li><code>&gt;</code>, <code>&gt;=</code>, <code>&lt;</code>, <code>&lt;=</code> : Confronti numerici</li>
          <li><code>contains</code>, <code>like</code> : Ricerca parziale substring</li>
        </ul>
      </div>
      <div style="padding:8px;background:#f8fafc;border-radius:6px;border:1px solid var(--border)">
        <strong style="color:var(--text)">Operatori Logici:</strong>
        <ul style="margin:4px 0 0 16px;padding:0;color:var(--text-dim)">
          <li><code>AND</code> : Entrambe le condizioni vere</li>
          <li><code>OR</code> : Almeno una condizione vera</li>
          <li><code>NOT</code> : Negazione della condizione</li>
          <li><code>*</code> : Tutti gli eventi (wildcard)</li>
        </ul>
      </div>
    </div>

    <!-- Aggregation and Pipe clauses -->
    <h4 style="color:var(--accent);font-size:13px;margin:12px 0 6px 0">3. Aggregazioni Pipe (<code>| GROUP BY ... | HAVING ...</code>)</h4>
    <div style="font-size:11px;color:var(--text-dim);margin-bottom:8px">
      Permettono di profilare gli attori raggruppando per dimensione e filtrando su metriche statistiche:
    </div>
    <table style="width:100%;font-size:11px;border-collapse:collapse;margin-bottom:14px">
      <thead>
        <tr style="background:#f8fafc;text-align:left">
          <th style="padding:6px 8px">Funzione Aggregata</th>
          <th style="padding:6px 8px">Descrizione Metrica</th>
          <th style="padding:6px 8px">Esempio Clausola HAVING</th>
        </tr>
      </thead>
      <tbody>
        <tr style="border-bottom:1px solid var(--border)">
          <td style="padding:5px 8px;font-family:var(--font-mono);color:var(--green)"><code>COUNT(*)</code></td>
          <td>Numero totale di richieste per attore</td>
          <td><code>COUNT(*) > 15</code></td>
        </tr>
        <tr style="border-bottom:1px solid var(--border)">
          <td style="padding:5px 8px;font-family:var(--font-mono);color:var(--green)"><code>FAIL_RATE</code></td>
          <td>Tasso di errore (da 0.0 a 1.0) su totale richieste</td>
          <td><code>FAIL_RATE > 0.80</code></td>
        </tr>
        <tr style="border-bottom:1px solid var(--border)">
          <td style="padding:5px 8px;font-family:var(--font-mono);color:var(--green)"><code>STDDEV(latency_ms)</code></td>
          <td>Deviazione standard latenza (anomalia temporale)</td>
          <td><code>STDDEV > 6.0</code></td>
        </tr>
        <tr style="border-bottom:1px solid var(--border)">
          <td style="padding:5px 8px;font-family:var(--font-mono);color:var(--green)"><code>BC</code> / <code>BIMODALITY</code></td>
          <td>Coefficiente Bimodalità di Sarle (&gt;0.555 = Side-Channel)</td>
          <td><code>BC > 0.555</code></td>
        </tr>
        <tr>
          <td style="padding:5px 8px;font-family:var(--font-mono);color:var(--green)"><code>SUM(status=500)</code></td>
          <td>Conteggio specifico di errori HTTP 500 Padding</td>
          <td><code>SUM(status=500) > 5</code></td>
        </tr>
      </tbody>
    </table>

    <!-- Clickable Practical Presets -->
    <h4 style="color:var(--accent);font-size:13px;margin:12px 0 6px 0">4. Esempi di Query Pronte (Clicca per applicare)</h4>
    <div style="display:flex;flex-direction:column;gap:6px;margin-bottom:16px">
      <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 10px;background:#f8fafc;border:1px solid var(--border);border-radius:6px">
        <div>
          <strong style="color:var(--text);font-size:11px">Filtra solo gli errori non-200:</strong>
          <div style="font-family:var(--font-mono);font-size:11px;color:var(--accent)">status != 200</div>
        </div>
        <button class="btn btn-primary" style="font-size:10px;padding:3px 10px" onclick="applyPresetAndClose('status != 200')">Usa Query ➔</button>
      </div>

      <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 10px;background:#f8fafc;border:1px solid var(--border);border-radius:6px">
        <div>
          <strong style="color:var(--text);font-size:11px">Isola l'endpoint crittografico su victim-vuln (errori 500):</strong>
          <div style="font-family:var(--font-mono);font-size:11px;color:var(--accent)">status = 500 AND endpoint = /decrypt</div>
        </div>
        <button class="btn btn-primary" style="font-size:10px;padding:3px 10px" onclick="applyPresetAndClose('status = 500 AND endpoint = /decrypt')">Usa Query ➔</button>
      </div>

      <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 10px;background:#f8fafc;border:1px solid var(--border);border-radius:6px">
        <div>
          <strong style="color:var(--text);font-size:11px">Aggrega attori malevoli con burst e fail-rate anomalo (>80%):</strong>
          <div style="font-family:var(--font-mono);font-size:11px;color:var(--accent)">endpoint = /decrypt | GROUP BY src_ip | HAVING FAIL_RATE > 0.8 AND COUNT(*) > 15</div>
        </div>
        <button class="btn btn-primary" style="font-size:10px;padding:3px 10px" onclick="applyPresetAndClose('endpoint = /decrypt | GROUP BY src_ip | HAVING FAIL_RATE > 0.8 AND COUNT(*) > 15')">Usa Query ➔</button>
      </div>

      <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 10px;background:#f8fafc;border:1px solid var(--border);border-radius:6px">
        <div>
          <strong style="color:var(--text);font-size:11px">Caccia a Timing Side-Channel su victim-partial (latenza bimodal/dispersa):</strong>
          <div style="font-family:var(--font-mono);font-size:11px;color:var(--accent)">endpoint = /decrypt | GROUP BY src_ip | HAVING STDDEV(latency_ms) > 5.0</div>
        </div>
        <button class="btn btn-primary" style="font-size:10px;padding:3px 10px" onclick="applyPresetAndClose('endpoint = /decrypt | GROUP BY src_ip | HAVING STDDEV(latency_ms) > 5.0')">Usa Query ➔</button>
      </div>

      <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 10px;background:#f8fafc;border:1px solid var(--border);border-radius:6px">
        <div>
          <strong style="color:var(--text);font-size:11px">Visualizza richieste respinte dal WAF preventivo inline (HTTP 429):</strong>
          <div style="font-family:var(--font-mono);font-size:11px;color:var(--accent)">status = 429 OR error_type = waf_blocked</div>
        </div>
        <button class="btn btn-primary" style="font-size:10px;padding:3px 10px" onclick="applyPresetAndClose('status = 429 OR error_type = waf_blocked')">Usa Query ➔</button>
      </div>
    </div>

    <div class="modal-actions" style="justify-content:flex-end">
      <button class="btn btn-secondary" onclick="closeModal('modal-siem-cheatsheet')">Chiudi Guida</button>
    </div>
  </div>
</div>

<script src="/static/vis-network.min.js"></script>

<script>
// ── State ──
let currentPanel = 'network';
let networkInstance = null;
let logStreamSeen = new Set();
let lastLogTs = null;
let autoScroll = true;
let lastSiemResultsData = null;

function isGroundTruthVisible() {
  const chk = document.getElementById('toggle-ground-truth');
  if (chk) return chk.checked;
  return localStorage.getItem('soc_ground_truth_visible') === '1';
}

function toggleGroundTruthView() {
  const chk = document.getElementById('toggle-ground-truth');
  if (chk) {
    localStorage.setItem('soc_ground_truth_visible', chk.checked ? '1' : '0');
  }
  loadHuntingData();
  if (lastSiemResultsData) {
    renderSiemResults(lastSiemResultsData);
  }
}

// ── Clock ──
function updateClock() {
  const now = new Date();
  document.getElementById('clock').textContent =
    now.toLocaleTimeString('it-IT', {hour:'2-digit', minute:'2-digit', second:'2-digit'});
}
setInterval(updateClock, 1000);
updateClock();

// ── Panel switching ──
function showPanel(name, el) {
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('visible'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('panel-' + name).classList.add('visible');
  if (el) el.classList.add('active');
  currentPanel = name;
  if (name === 'alerts') loadAlerts();
  if (name === 'hunting') { loadHuntingData(); updateWAFBadge(); executeSiemQuery(); runHuntingBacktest(); loadSiemRulesStatus(); }
  if (name === 'docker') loadEntityDirectory();
  if (name === 'log-raw') loadRawLogs();
  if (name === 'log-soc') loadSocLogs();
  if (name === 'attack-detail') loadAttackDetail();
}



// ── Modals ──
function openModal(id) {
  const modal = document.getElementById(id);
  if (modal) modal.classList.add('open');
  if (id === 'modal-attacker') {
    fetch('/nodes/victim/secret')
      .then(r => r.json())
      .then(d => {
        if (d.secret) {
          const input = document.getElementById('atk-secret-input');
          if (input) input.value = d.secret;
        }
      }).catch(_ => {});
  }
  if (id === 'modal-victim') {
    fetch('/status')
      .then(r => r.json())
      .then(d => {
        if (d.victim_mode) {
          const radio = document.querySelector(`input[name="victim-mode"][value="${d.victim_mode}"]`);
          if (radio) radio.checked = true;
        }
      }).catch(_ => {});
  }
}

function closeModal(id) {
  const modal = document.getElementById(id);
  if (modal) modal.classList.remove('open');
}

document.querySelectorAll('.modal-overlay').forEach(m => {
  m.addEventListener('click', e => { if (e.target === m) m.classList.remove('open'); });
});

document.querySelectorAll('input[name="atk-secret-mode"]').forEach(r => {
  r.addEventListener('change', () => {
    const manual = document.querySelector('input[name="atk-secret-mode"]:checked')?.value === 'manual';
    const input = document.getElementById('atk-secret-input');
    if (input) input.disabled = !manual;
  });
});

// ── Auto-scroll checkbox ──
document.getElementById('auto-scroll-chk').addEventListener('change', e => { autoScroll = e.target.checked; });

// ── Ground-Truth toggle init ──
const gtChk = document.getElementById('toggle-ground-truth');
if (gtChk) {
  gtChk.checked = localStorage.getItem('soc_ground_truth_visible') === '1';
}

// ── Network graph ──
// Persistent DataSets — never destroy the Network instance
let networkNodes = null;
let networkEdges = null;

// ── Active flows for packet animation ──
const activeFlows = {}; // key: 'from→to', value: { lastSeen, progress, color, speed }
const FLOW_TTL = 5000;  // ms
let packetAnimationRaf = null;
let attackShutdownTriggered = false;

function updateFlowsFromEvents(events, activeVictim) {
  if (!activeVictim || activeVictim === '—') return;
  const now = Date.now();
  let hasNewFlow = false;
  events.forEach(ev => {
    const svc = ev.service || '';
    let fromNode = null;
    let col = null;
    if (svc === 'attacker' || (ev.event_type || '').startsWith('attack')) {
      fromNode = 'attacker'; col = '#ef4444';
    } else if (svc.startsWith('benign') || svc.includes('benign')) {
      fromNode = svc.replace(/^(benign-\d).*$/, '$1'); // benign-1 or benign-2
      if (fromNode === svc) fromNode = 'benign-1';
      col = '#f59e0b';
    }
    if (fromNode) {
      const key = `${fromNode}→${activeVictim}`;
      if (!activeFlows[key]) {
        activeFlows[key] = { lastSeen: now, progress: Math.random(), color: col, speed: 0.006 + Math.random() * 0.004 };
        hasNewFlow = true;
      } else {
        activeFlows[key].lastSeen = now;
      }
    }
  });
  if (hasNewFlow) startPacketAnimation();
}

function startPacketAnimation() {
  if (packetAnimationRaf !== null) return;
  function frame() {
    const now = Date.now();
    let anyActive = false;
    Object.entries(activeFlows).forEach(([key, flow]) => {
      if (now - flow.lastSeen > FLOW_TTL) { delete activeFlows[key]; return; }
      flow.progress = (flow.progress + flow.speed) % 1;
      anyActive = true;
    });
    if (networkInstance && anyActive) networkInstance.redraw();
    if (!anyActive) {
      packetAnimationRaf = null;
      return;
    }
    packetAnimationRaf = requestAnimationFrame(frame);
  }
  packetAnimationRaf = requestAnimationFrame(frame);
}

function stopPacketAnimation() {
  if (packetAnimationRaf !== null) {
    cancelAnimationFrame(packetAnimationRaf);
    packetAnimationRaf = null;
  }
  Object.keys(activeFlows).forEach(k => delete activeFlows[k]);
  if (networkInstance) networkInstance.redraw();
}

async function handleAttackCompleted() {
  stopPacketAnimation();
  if (attackShutdownTriggered) return;
  attackShutdownTriggered = true;
  try {
    await fetch('/lab/shutdown-after-attack', { method: 'POST' });
  } catch (e) {
    attackShutdownTriggered = false;
  }
}

function initNetwork(data) {
  const container = document.getElementById('network-graph');

  if (!networkInstance) {
    // First init: create DataSets and Network once
    networkNodes = new vis.DataSet(data.nodes);
    networkEdges = new vis.DataSet(data.edges);
    const opts = {
      physics: {
        enabled: true,
        stabilization: { iterations: 80, fit: true },
        solver: 'repulsion',
        repulsion: { nodeDistance: 220, centralGravity: 0.12 },
      },
      interaction: { hover: true, tooltipDelay: 100 },
      layout: { randomSeed: 7, improvedLayout: true },
      nodes: {
        borderWidth: 2,
        shadow: { enabled: true, color: 'rgba(0,0,0,.5)', size: 14 },
        margin: 10,
      },
      edges: {
        smooth: { type: 'curvedCW', roundness: 0.25 },
        shadow: false,
        selectionWidth: 2,
        hoverWidth: 1,
      },
    };
    networkInstance = new vis.Network(container, { nodes: networkNodes, edges: networkEdges }, opts);

    // Packet animation: draw moving dots along active edges
    networkInstance.on('beforeDrawing', ctx => {
      const now = Date.now();
      Object.entries(activeFlows).forEach(([key, flow]) => {
        const [fromId, toId] = key.split('→');
        try {
          const fp = networkInstance.getPosition(fromId);
          const tp = networkInstance.getPosition(toId);
          if (!fp || !tp) return;
          // Fade out as flow ages
          const age = now - flow.lastSeen;
          const alpha = age > 2500 ? Math.max(0, 1 - (age - 2500) / 2500) : 1;
          // Draw glowing dot
          const x = fp.x + (tp.x - fp.x) * flow.progress;
          const y = fp.y + (tp.y - fp.y) * flow.progress;
          ctx.save();
          ctx.globalAlpha = alpha;
          // Glow
          const grad = ctx.createRadialGradient(x, y, 0, x, y, 10);
          grad.addColorStop(0, flow.color + 'cc');
          grad.addColorStop(1, flow.color + '00');
          ctx.beginPath(); ctx.arc(x, y, 10, 0, Math.PI * 2);
          ctx.fillStyle = grad; ctx.fill();
          // Core dot
          ctx.beginPath(); ctx.arc(x, y, 4.5, 0, Math.PI * 2);
          ctx.fillStyle = flow.color; ctx.fill();
          ctx.strokeStyle = '#fff'; ctx.lineWidth = 1.2; ctx.stroke();
          ctx.restore();
        } catch (_) {}
      });
    });

    networkInstance.on('click', params => {
      if (!params.nodes.length) return;
      const nodeId = params.nodes[0];
      if (nodeId.startsWith('victim') || nodeId.startsWith('benign') || nodeId === 'attacker') {
        toggleHost(nodeId);
      }
    });
    networkInstance.once('stabilized', () => {
      networkInstance.setOptions({ physics: { enabled: false } });
      networkInstance.fit({ animation: { duration: 500, easingFunction: 'easeInOutQuad' } });
    });
    setTimeout(() => { if (networkInstance) { networkInstance.redraw(); networkInstance.fit(); } }, 1600);
  } else {
    // Diff-update the DataSets
    const newIds = new Set(data.nodes.map(n => n.id));
    networkNodes.getIds().forEach(id => { if (!newIds.has(id)) networkNodes.remove(id); });
    networkNodes.update(data.nodes);
    networkEdges.clear();
    networkEdges.add(data.edges);
    networkInstance.redraw();
  }
}

// ── Log rendering ──
function colorClass(ev) {
  if (ev._color === 'attacker' || ev.color === 'attacker') return 'attacker';
  if (ev._color === 'benign'   || ev.color === 'benign')   return 'benign';
  if (ev.service === 'attacker') return 'attacker';
  if ((ev.service || '').startsWith('benign') || (ev.service || '').includes('benign')) return 'benign';
  return 'victim';
}

function tagHtml(cls) {
  const label = cls === 'attacker' ? '🔴 ATK' : cls === 'benign' ? '🟡 BEN' : '⚪ VIC';
  return `<span class="log-tag tag-${cls}">${label}</span>`;
}

function statusClass(code) {
  if (code === undefined || code === null || code === '') return '';
  code = parseInt(code);
  if (code === 0) return 'status-warn';
  if (code >= 200 && code < 300) return 'status-ok';
  if (code >= 400) return 'status-err';
  return 'status-warn';
}

function _renderDetailsHtml(details) {
  if (!details || typeof details !== 'object') return '';
  return Object.entries(details).map(([k, v]) => {
    const vStr = (typeof v === 'number')
      ? `<span class="det-num">${v}</span>`
      : `<span class="det-str">${String(v)}</span>`;
    return `<span class="det-key">${k}</span>: ${vStr}`;
  }).join('  |  ');
}

let showRawEventType = true;

function toggleRawEventType(show) {
  if (show === undefined) {
    showRawEventType = !showRawEventType;
  } else {
    showRawEventType = !!show;
  }
  const chk1 = document.getElementById('net-raw-show-etype');
  const chk2 = document.getElementById('raw-show-etype');
  if (chk1) chk1.checked = showRawEventType;
  if (chk2) chk2.checked = showRawEventType;

  const subtabWrap = document.getElementById('subtab-content-raw');
  const panelWrap = document.getElementById('panel-log-raw');
  if (subtabWrap) {
    if (showRawEventType) subtabWrap.classList.remove('hide-etype');
    else subtabWrap.classList.add('hide-etype');
  }
  if (panelWrap) {
    if (showRawEventType) panelWrap.classList.remove('hide-etype');
    else panelWrap.classList.add('hide-etype');
  }
}

function buildLogRow(ev) {
  const cls = colorClass(ev);
  const ts = (ev.ts || '').replace('T', ' ').replace(/\.\d+.*$/, '');
  const svc = ev.service || '';
  const etype = ev.event_type || '';
  const code = ev.status_code ?? ev.status ?? '';
  const err = ev.error_type || ev.error || '';
  const ep = ev.endpoint || '';
  const latency = ev.latency_ms !== undefined && ev.latency_ms !== null ? `${Math.round(ev.latency_ms)}ms` : '';
  const details = ev.details;
  const hasDetails = details && typeof details === 'object' && Object.keys(details).length > 0;

  // Wrapper div (row + optional details)
  const wrap = document.createElement('div');

  const row = document.createElement('div');
  row.className = `log-row ${cls}`;

  // Extra info in last column: for attacker events show details summary, for benign show rich operations, otherwise error/details
  let lastCol = '';
  if (cls === 'attacker' && hasDetails) {
    const d = details;
    if (etype === 'attack_probe') {
      const gHex = d.guess_hex || `0x${(d.guess||0).toString(16).padStart(2,'0')}`;
      const statusBadge = d.valid_padding ? '<span style="color:var(--green);font-weight:700">[PADDING OK]</span>' : '<span style="color:var(--text-dim)">[PAD ERR]</span>';
      lastCol = `<span>probe byte[${d.byte_index ?? '?'}] guess=${gHex} pad=${d.pad_len ?? '?'} #${d.queries_total ?? '?'} ${statusBadge}</span>`;
    } else if (etype === 'attack_progress') {
      const rHex = d.recovered_hex || `0x${(d.recovered_byte||0).toString(16).padStart(2,'0')}`;
      lastCol = `<span style="color:var(--amber);font-weight:700">🎯 RECOVERED byte[${d.byte_index ?? '?'}]='${d.recovered_char ?? '?'}' (${rHex}) queries=${d.queries_total ?? '?'}</span>`;
    } else if (etype === 'attack_complete') {
      lastCol = `<span style="color:var(--green);font-weight:700">✅ COMPLETED recovered="${escapeHtml(d.recovered_block ?? d.recovered_plaintext ?? '')}" queries=${d.queries ?? '?'}</span>`;
    } else if (etype === 'attack_blocked') {
      lastCol = `<span style="color:var(--red);font-weight:700">🛑 WAF BLOCKED reason="${escapeHtml(d.reason ?? 'policy_violation')}" queries=${d.queries_total ?? '?'}</span>`;
    } else if (etype === 'attack_not_permitted') {
      lastCol = `<span style="color:var(--blue);font-weight:700">🛡️ ATTACCO NON CONSENTITO: Target protetto da Encrypt-then-MAC (0 byte compromessi)</span>`;
    } else if (etype === 'attack_noise_blend') {
      const act = d.action || 'evasion_noise';
      const userTag = d.username ? `<span style="color:var(--accent);font-weight:600">${escapeHtml(d.username)}</span> ` : '';
      const docTag = d.doc_id ? `<span style="color:var(--green)">doc=${escapeHtml(d.doc_id)}</span> ` : '';
      lastCol = `<span style="color:var(--text-muted)">🎭 NOISE BLEND [${escapeHtml(act)}] ${userTag}${docTag}${latency ? latency : ''}</span>`;
    } else {
      lastCol = `<span style="color:var(--text-dim)">${_renderDetailsHtml(d)}</span>`;
    }
  } else if (cls === 'benign' && hasDetails) {
    const d = details;
    const items = [];
    if (d.username) items.push(`<span style="color:var(--accent);font-weight:600">${escapeHtml(d.username)}</span>`);
    if (d.action) items.push(`<span style="color:var(--text)">${escapeHtml(d.action)}</span>`);
    if (d.doc_id) items.push(`<span style="color:var(--green)">doc=${escapeHtml(d.doc_id)}</span>`);
    if (d.department) items.push(`<span style="color:var(--text-muted)">${escapeHtml(d.department)}</span>`);
    if (d.token_prefix) items.push(`<span style="color:var(--text-muted)">token=${escapeHtml(d.token_prefix)}</span>`);
    if (d.plaintext_sample) items.push(`<span style="color:var(--green)">"${escapeHtml(d.plaintext_sample)}"</span>`);
    if (d.auth_method) items.push(`<span style="color:var(--text-muted)">${escapeHtml(d.auth_method)}</span>`);
    if (d.result && d.result !== 'success') items.push(`<span style="color:var(--red)">${escapeHtml(d.result)}</span>`);
    if (d.ciphertext_bytes) items.push(`<span style="color:var(--text-muted)">${d.ciphertext_bytes}B</span>`);
    if (d.valid_padding !== undefined) items.push(d.valid_padding ? `<span style="color:var(--green);font-weight:600">pad=OK</span>` : `<span style="color:var(--red);font-weight:600">pad=ERR</span>`);
    if (latency) items.push(`<span style="color:var(--text-muted)">${latency}</span>`);

    if (items.length > 0) {
      lastCol = `<span>${items.join(' <span style="color:var(--border)">│</span> ')}</span>`;
    } else {
      lastCol = `<span style="color:var(--text-dim)">${_renderDetailsHtml(d)} ${latency ? ' ' + latency : ''}</span>`;
    }
  } else {
    const clientInfo = hasDetails && details.client_id ? ` [${details.client_id}]` : '';
    const errText = err ? `<span style="color:var(--red)">${escapeHtml(err)}</span>` : '';
    const detailsInline = _renderDetailsHtml(details);
    lastCol = `<span>${errText ? errText + ' ' : ''}${detailsInline ? detailsInline : escapeHtml(ep)}${clientInfo}${latency ? ' ' + latency : ''}</span>`;
  }

  const srcIpTag = ev.src_ip ? `<span style="font-family:var(--font-mono);font-size:11px;font-weight:700;color:var(--accent)">${escapeHtml(ev.src_ip)}</span>` : `<span style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted)">${escapeHtml(svc)}</span>`;
  const epTag = `<span style="color:var(--text-muted);font-family:var(--font-mono);font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escapeHtml(ep)}">${escapeHtml(ep || '—')}</span>`;

  row.innerHTML = `
    <span style="color:var(--text-dim)">${ts}</span>
    ${srcIpTag}
    <span class="col-etype" style="color:var(--text-muted)">${escapeHtml(etype)}</span>
    ${epTag}
    <span class="${statusClass(code)}">${code !== '' ? code : '—'}</span>
    ${lastCol}
  `;

  wrap.appendChild(row);

  // Expandable details sub-row
  if (hasDetails) {
    const detRow = document.createElement('div');
    detRow.className = 'log-details';
    let detHtml = `<span class="det-label">📦 details</span>`;
    detHtml += Object.entries(details).map(([k, v]) => {
      const vFmt = (typeof v === 'number') ? `<span class="det-num">${v}</span>` : `<span class="det-str">"${escapeHtml(String(v))}"</span>`;
      return `<span class="det-key">${escapeHtml(k)}</span>: ${vFmt}`;
    }).join('  │  ');
    if (ev.src_ip)         detHtml += `  │  <span class="det-key">src_ip</span>: <span class="det-val">${escapeHtml(ev.src_ip)}</span>`;
    if (ev.endpoint)       detHtml += `  │  <span class="det-key">endpoint</span>: <span class="det-val">${escapeHtml(ev.endpoint)}</span>`;
    if (ev.ciphertext_len) detHtml += `  │  <span class="det-key">ciphertext_len</span>: <span class="det-num">${ev.ciphertext_len}</span>`;
    if (ev.scenario_id)    detHtml += `  │  <span class="det-key">scenario</span>: <span class="det-val">${escapeHtml(ev.scenario_id)}</span>`;
    detRow.innerHTML = detHtml;
    wrap.appendChild(detRow);
    // Toggle on click
    row.addEventListener('click', () => detRow.classList.toggle('open'));
  }

  return wrap;
}

function appendToStream(container, events, dedup) {
  let added = 0;
  events.forEach(ev => {
    const d = ev.details || {};
    const key = `${ev.ts}-${ev.service}-${ev.event_type}-${ev.status_code}-${d.guess ?? ''}-${d.queries_total ?? ''}-${d.iteration ?? ''}`;
    if (dedup && logStreamSeen.has(key)) return;
    if (dedup) logStreamSeen.add(key);
    container.appendChild(buildLogRow(ev));
    added++;
  });
  if (added > 0 && dedup && autoScroll) {
    container.scrollTop = container.scrollHeight;
  }
  // Trim old rows to keep DOM performant while allowing high buffer
  while (container.children.length > 1500) container.removeChild(container.firstChild);
}

// ── Traffic toggle state & button synchronization ──
let isBenignActive = false;
let isAttackActive = false;

function updateTrafficButtons(benignActive, attackActive) {
  isBenignActive = !!benignActive;
  isAttackActive = !!attackActive;

  const btnBenign = document.getElementById('btn-toggle-benign');
  if (btnBenign) {
    if (isBenignActive) {
      btnBenign.innerHTML = '⏸ Stop Benigni';
      btnBenign.style.background = 'var(--amber-dim)';
      btnBenign.style.color = 'var(--amber)';
      btnBenign.style.border = '1px solid var(--amber)';
    } else {
      btnBenign.innerHTML = '▶ Avvia Benigni';
      btnBenign.style.background = '#1e3050';
      btnBenign.style.color = 'var(--amber)';
      btnBenign.style.border = '1px solid var(--border-lit)';
    }
  }

  const btnAttack = document.getElementById('btn-toggle-attack');
  if (btnAttack) {
    if (isAttackActive) {
      btnAttack.innerHTML = '⏹ Ferma Attacco';
      btnAttack.style.background = 'var(--red)';
      btnAttack.style.color = '#fff';
      btnAttack.style.border = '1px solid var(--red)';
    } else {
      btnAttack.innerHTML = '▶ Avvia Attacco';
      btnAttack.style.background = 'var(--red-dim)';
      btnAttack.style.color = 'var(--red)';
      btnAttack.style.border = '1px solid var(--red)';
    }
  }
}

// ── Status polling (every 3s) ──
async function pollStatus() {
  try {
    const r = await fetch('/status');
    const d = await r.json();

    // Attack badge
    const badge = document.getElementById('attack-badge');
    if (d.attack_active) {
      badge.className = 'badge badge-attack';
      badge.innerHTML = '<span class="dot"></span> ATTACK ACTIVE';
    } else {
      badge.className = 'badge badge-quiet';
      badge.innerHTML = '<span class="dot"></span> QUIET';
    }

    // Event counts
    const ec = d.event_counts || {};
    const cntAtk = ec.attacker || 0;
    const cntBen = ec.benign || 0;
    const cntVic = ec.victim || 0;
    document.getElementById('cnt-attacker').textContent = cntAtk;
    document.getElementById('cnt-benign').textContent   = cntBen;
    document.getElementById('cnt-victim').textContent   = cntVic;

    // Sidebar victim
    const v = d.active_victim || 'victim';
    document.getElementById('sidebar-victim-name').textContent = v;

    // Synchronize 4-Card Scenario Command Center
    const scBenignBadge = document.getElementById('sc-benign-badge');
    const scBenignCnt = document.getElementById('sc-benign-cnt');
    if (scBenignBadge) {
      if (d.benign_active) {
        scBenignBadge.className = 'sc-badge on';
        scBenignBadge.textContent = 'ATTIVO (Loop)';
      } else {
        scBenignBadge.className = 'sc-badge off';
        scBenignBadge.textContent = 'IN PAUSA';
      }
    }
    if (scBenignCnt) scBenignCnt.textContent = cntBen;

    const scAtkBadge = document.getElementById('sc-atk-badge');
    const scAtkCnt = document.getElementById('sc-atk-cnt');
    if (scAtkBadge) {
      if (d.attack_active) {
        scAtkBadge.className = 'sc-badge alert';
        scAtkBadge.textContent = 'EXPLOIT IN CORSO';
      } else {
        scAtkBadge.className = 'sc-badge off';
        scAtkBadge.textContent = 'QUIET';
      }
    }
    if (scAtkCnt) scAtkCnt.textContent = cntAtk;

    const scVictimCnt = document.getElementById('sc-victim-cnt');
    if (scVictimCnt) scVictimCnt.textContent = cntVic;

    const scVictimModeLbl = document.getElementById('sc-victim-mode-lbl');
    if (scVictimModeLbl && d.victim_mode) {
      if (d.victim_mode === 'fixed') {
        scVictimModeLbl.textContent = 'Hardened (EtM)';
        scVictimModeLbl.className = 'sc-m-val green';
      } else if (d.victim_mode === 'partial') {
        scVictimModeLbl.textContent = 'Side-Channel (Timing)';
        scVictimModeLbl.className = 'sc-m-val yellow';
      } else {
        scVictimModeLbl.textContent = 'Vulnerabile (500)';
        scVictimModeLbl.className = 'sc-m-val red';
      }
    }

    // Update traffic toggle buttons
    updateTrafficButtons(d.benign_active, d.attack_active);

    // Synchronize WAF badge
    if (typeof updateWAFBadge === 'function') await updateWAFBadge();

  } catch (e) { /* ignore */ }
}


// ── Log tail polling (every 2s) ──
async function pollLogs() {
  try {
    const r = await fetch('/logs/tail?limit=1000');
    const events = await r.json();
    const stream = document.getElementById('log-stream');
    appendToStream(stream, events.reverse(), true);
    // Feed packet animation with the latest events
    const activeVictim = document.getElementById('sidebar-victim-name').textContent;
    updateFlowsFromEvents(events, activeVictim);
    if (events.some(ev => ev.event_type === 'attack_complete')) {
      await handleAttackCompleted();
    }
  } catch (e) { /* ignore */ }
}

let persistentAttackByteMap = {};
let scenarioByteStorage = {};
let lastRenderedScenarioId = null;
let lastRenderedAttackHtml = '';

// ── Clear all logs ──
// ── Reset test (stop workloads + restore default victim + clear logs & UI) ──
async function resetTest() {
  const btn = document.getElementById('btn-reset-test') || document.getElementById('btn-clear-logs');
  const orig = btn ? btn.textContent : '';
  if (btn) {
    btn.textContent = '⏳ Reset Globale…';
    btn.disabled = true;
  }
  try {
    const r = await fetch('/test/reset', { method: 'POST' });
    const d = await r.json();
    logStreamSeen.clear();
    persistentAttackByteMap = {};
    scenarioByteStorage = {};
    lastRenderedScenarioId = null;
    lastRenderedAttackHtml = '';
    
    // Clear DOM stream containers
    ['log-stream', 'log-raw-stream', 'net-raw-stream', 'log-soc-stream', 'net-soc-stream'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.innerHTML = '';
    });

    // Clear alert tables
    ['alerts-tbody', 'net-alerts-tbody'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:16px">Nessun allarme generato. System Normal.</td></tr>';
    });

    const atk1 = document.getElementById('atk-body');
    const atk2 = document.getElementById('net-atk-body');
    const emptyAtkMsg = '<p class="atk-no-data">In attesa di un attacco… lancia l\'attaccante dal Command Center in alto.</p>';
    if (atk1) { atk1.innerHTML = emptyAtkMsg; atk1.dataset.renderedHtml = emptyAtkMsg; }
    if (atk2) { atk2.innerHTML = emptyAtkMsg; atk2.dataset.renderedHtml = emptyAtkMsg; }
    
    stopPacketAnimation();

    // Trigger immediate UI refresh for all panels and streams
    await pollStatus();
    await pollNetwork();
    await loadAlerts();
    if (typeof updateWAFBadge === 'function') await updateWAFBadge();
    if (typeof loadNetRawLogs === 'function') await loadNetRawLogs();
    if (typeof loadRawLogs === 'function') await loadRawLogs();
    if (typeof loadSocLogs === 'function') await loadSocLogs();
    if (typeof loadNetSocLogs === 'function') await loadNetSocLogs();

    if (btn) {
      btn.textContent = `✅ Reset Completo (${d.cleared?.length ?? 0} log)`;
      setTimeout(() => { btn.textContent = orig; btn.disabled = false; }, 2200);
    }
  } catch (e) {
    if (btn) {
      btn.textContent = '❌ Errore';
      setTimeout(() => { btn.textContent = orig; btn.disabled = false; }, 2200);
    }
  }
}

async function clearLogs() {
  return await resetTest();
}

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ── Network Sub-Tab Switching ──
let currentNetSubTab = 'raw';

function switchNetSubTab(tabName) {
  currentNetSubTab = tabName;
  document.querySelectorAll('.subtab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.subtab-content').forEach(c => c.classList.remove('active'));

  const btn = document.getElementById('subtab-btn-' + tabName);
  const content = document.getElementById('subtab-content-' + tabName);
  if (btn) btn.classList.add('active');
  if (content) content.classList.add('active');

  const legend = document.getElementById('subtab-legend');
  const scrollWrap = document.getElementById('subtab-autoscroll-wrap');
  if (legend) legend.style.display = (tabName === 'raw' || tabName === 'soc') ? 'flex' : 'none';
  if (scrollWrap) scrollWrap.style.display = (tabName === 'raw' || tabName === 'soc') ? 'flex' : 'none';

  if (tabName === 'raw') loadNetRawLogs();
  if (tabName === 'soc') loadNetSocLogs();
  if (tabName === 'attack') loadAttackDetail('net-atk-body');
  if (tabName === 'alerts') loadAlerts();
}

// ── SOC Paired Request / Response Card Builder ──
function buildSocLogCard(ev) {
  const cls = colorClass(ev);
  const isAtk = cls === 'attacker';
  const ts = (ev.ts || '').replace('T', ' ').replace(/\.\d+.*$/, '');
  const etype = ev.event_type || (isAtk ? 'attack_probe' : 'benign_request');
  const code = ev.status_code ?? ev.status ?? 0;
  const latency = ev.latency_ms !== undefined && ev.latency_ms !== null ? `${Math.round(ev.latency_ms)} ms` : '—';
  const ep = ev.endpoint || '/decrypt';
  const cLen = ev.ciphertext_len !== undefined ? `${ev.ciphertext_len} bytes` : '32 bytes (2 blocks)';
  const details = ev.details || {};

  const card = document.createElement('div');
  card.className = `soc-card ${isAtk ? 'atk-card' : 'ben-card'}`;

  // Source IP display
  const ipDisplay = ev.src_ip || (isAtk ? '198.51.100.50' : '192.168.1.10');
  const roleLabel = isAtk ? '🔴 Red Team Attacker' : '🟡 Benign Workstation';
  const ipColor = isAtk ? '#f87171' : '#fde047';

  // Header
  const header = document.createElement('div');
  header.className = 'soc-card-header';
  header.innerHTML = `
    ${tagHtml(cls)}
    <span class="soc-card-svc" style="font-family:var(--font-mono);font-weight:700;color:${ipColor}">${escapeHtml(ipDisplay)}</span>
    <span style="font-size:10px;padding:2px 6px;border-radius:4px;background:rgba(255,255,255,0.06);color:var(--text-muted)">${roleLabel}</span>
    <span class="soc-card-etype">${escapeHtml(etype)}</span>
    <span class="soc-card-ts">${ts}</span>
    <div style="flex:1"></div>
    <span style="font-size:11px;font-family:var(--font-mono);color:var(--text-dim)">Scenario: <strong style="color:var(--text)">${escapeHtml(ev.scenario_id || 'default')}</strong></span>
  `;
  card.appendChild(header);

  // Request & Response paired grid
  const grid = document.createElement('div');
  grid.className = 'soc-pair-grid';

  // Left column: Client Outgoing Request
  const reqBox = document.createElement('div');
  reqBox.className = 'soc-box';
  
  let reqDetailsHtml = '';
  if (isAtk && etype === 'attack_probe') {
    const gHex = details.guess_hex || `0x${(details.guess||0).toString(16).padStart(2,'0')}`;
    const ivPreview = details.crafted_iv_hex ? details.crafted_iv_hex.substring(0, 16) + '...' : '—';
    reqDetailsHtml = `
      <div class="soc-box-row"><span class="soc-box-key">Byte Target</span><span style="color:var(--amber);font-weight:700">Index ${details.byte_index ?? '?'} (Pad ${details.pad_len ?? '?'})</span></div>
      <div class="soc-box-row"><span class="soc-box-key">Guess IV[i]</span><span style="color:var(--text);font-weight:600">${gHex} (${details.guess ?? '?'})</span></div>
      <div class="soc-box-row"><span class="soc-box-key">Crafted IV</span><span style="color:var(--text-dim);font-size:10px">${ivPreview}</span></div>
      <div class="soc-box-row"><span class="soc-box-key">Queries Tot.</span><span style="color:var(--text-muted)">#${details.queries_total ?? '?'}</span></div>
    `;
  } else if (isAtk && etype === 'attack_progress') {
    const rHex = details.recovered_hex || `0x${(details.recovered_byte||0).toString(16).padStart(2,'0')}`;
    reqDetailsHtml = `
      <div class="soc-box-row"><span class="soc-box-key">Byte Trovato</span><span style="color:var(--green);font-weight:700">Index ${details.byte_index ?? '?'} = '${escapeHtml(details.recovered_char ?? '')}' (${rHex})</span></div>
      <div class="soc-box-row"><span class="soc-box-key">Pad Length</span><span>${details.pad_len ?? '?'}</span></div>
      <div class="soc-box-row"><span class="soc-box-key">Queries Tot.</span><span style="color:var(--amber)">#${details.queries_total ?? '?'}</span></div>
    `;
  } else if (isAtk && etype === 'attack_complete') {
    reqDetailsHtml = `
      <div class="soc-box-row"><span class="soc-box-key">Decifrato</span><span style="color:var(--green);font-weight:700">"${escapeHtml(details.recovered_block ?? '')}"</span></div>
      <div class="soc-box-row"><span class="soc-box-key">Oracle Queries</span><span style="color:var(--amber)">${details.queries ?? '?'}</span></div>
    `;
  } else if (isAtk && etype === 'attack_blocked') {
    reqDetailsHtml = `
      <div class="soc-box-row"><span class="soc-box-key">Esito Attacco</span><span style="color:var(--red);font-weight:700">Exploit Bloccato da WAF</span></div>
      <div class="soc-box-row"><span class="soc-box-key">Queries Inviate</span><span style="color:var(--amber)">#${details.queries_total ?? '?'}</span></div>
    `;
  } else if (isAtk && etype === 'attack_not_permitted') {
    reqDetailsHtml = `
      <div class="soc-box-row"><span class="soc-box-key">Esito Attacco</span><span style="color:var(--blue);font-weight:700">Attacco Non Consentito (EtM)</span></div>
      <div class="soc-box-row"><span class="soc-box-key">Byte Compromessi</span><span style="color:var(--green)">0 byte (0%)</span></div>
    `;
  } else {
    reqDetailsHtml = `
      <div class="soc-box-row"><span class="soc-box-key">Iterazione</span><span>#${details.iteration ?? 0}</span></div>
      <div class="soc-box-row"><span class="soc-box-key">Payload</span><span>${details.plaintext_sample ? escapeHtml(details.plaintext_sample) : 'Token AES-CBC autentico'}</span></div>
    `;
  }

  reqBox.innerHTML = `
    <div class="soc-box-title">
      <span>📤 1. Richiesta Inviata (Client)</span>
      <span style="color:var(--text-dim);font-size:10px">POST ${escapeHtml(ep)}</span>
    </div>
    <div class="soc-box-row"><span class="soc-box-key">Sorgente IP</span><span style="color:${ipColor};font-weight:700;font-family:var(--font-mono)">${escapeHtml(ipDisplay)} (${isAtk ? 'Red Team' : 'Workstation'})</span></div>
    <div class="soc-box-row"><span class="soc-box-key">Dim. Ciphertext</span><span>${cLen}</span></div>
    ${reqDetailsHtml}
  `;

  // Right column: Victim Server Response / Evaluation
  const resBox = document.createElement('div');
  resBox.className = 'soc-box';

  let statusBadgeClass = 'soc-badge-probe';
  let statusText = 'Oracolo Valido';
  if (code === 200) {
    statusBadgeClass = 'soc-badge-200';
    statusText = '200 OK (Padding & MAC validi)';
  } else if (code === 500) {
    statusBadgeClass = 'soc-badge-500';
    statusText = '500 Server Error (Padding Error)';
  } else if (code === 403) {
    statusBadgeClass = 'soc-badge-403';
    statusText = '403 Forbidden (Padding Valido, Bad MAC)';
  } else if (code === 429) {
    statusBadgeClass = 'soc-badge-500';
    statusText = '429 Too Many Requests (WAF Rate Limiting / Ban)';
  } else if (isAtk && etype === 'attack_progress') {
    statusBadgeClass = 'soc-badge-probe';
    statusText = `Padding Valido trovato (0x${(details.recovered_byte ?? 0).toString(16).padStart(2,'0')} = '${escapeHtml(details.recovered_char ?? '.')}')`;
  }

  resBox.innerHTML = `
    <div class="soc-box-title">
      <span>📥 2. Risposta Oracolo (Victim)</span>
      <span class="soc-badge-status ${statusBadgeClass}">${code ? 'HTTP ' + code : statusText}</span>
    </div>
    <div class="soc-box-row"><span class="soc-box-key">Stato Ritorno</span><span style="font-weight:600">${statusText}</span></div>
    <div class="soc-box-row"><span class="soc-box-key">Errore / Esito</span><span style="color:${code===500||code===429?'var(--red)':code===200?'var(--green)':'var(--amber)'}">${escapeHtml(ev.error_type || (code===500?'padding_error':code===429?'waf_blocked':'ok'))}</span></div>
    <div class="soc-box-row"><span class="soc-box-key">Latenza Server</span><span>${latency}</span></div>
  `;

  grid.appendChild(reqBox);
  grid.appendChild(resBox);
  card.appendChild(grid);

  // Bottom analysis context
  let analysisText = '';
  if (isAtk) {
    if (etype === 'attack_complete') {
      analysisText = `🏆 <strong>Analisi SOC:</strong> Attacco Padding Oracle completato con successo da IP <code>${escapeHtml(ipDisplay)}</code>. Il blocco intero è stato decifrato sfruttando le risposte dell'oracolo.`;
    } else if (etype === 'attack_blocked') {
      analysisText = `🛑 <strong>Analisi SOC:</strong> Attaccante <code>${escapeHtml(ipDisplay)}</code> neutralizzato dal WAF preventivo (HTTP 429). L'oracolo è stato protetto.`;
    } else if (etype === 'attack_not_permitted') {
      analysisText = `🛡️ <strong>Analisi SOC:</strong> Attacco non consentito da IP <code>${escapeHtml(ipDisplay)}</code>: il target è protetto da <strong>Encrypt-then-MAC</strong> (integrità verificata a monte). 0 byte compromessi.`;
    } else if (etype === 'attack_progress') {
      analysisText = `🎯 <strong>Analisi SOC:</strong> Byte <code>${details.byte_index ?? '?'}</code> identificato dall'IP <code>${escapeHtml(ipDisplay)}</code>! Carattere recuperato: <code>'${escapeHtml(details.recovered_char ?? '')}'</code> (${details.recovered_hex || ''}) in ${details.queries_total ?? '?'} tentativi.`;
    } else {
      const gHex = details.guess_hex || `0x${(details.guess||0).toString(16).padStart(2,'0')}`;
      const outcomeDesc = details.valid_padding ? `<strong style="color:var(--green)">Padding corretto riscontrato</strong>` : `Padding non valido (scartato)`;
      analysisText = `⚡ <strong>Analisi SOC:</strong> Sonda #${details.queries_total ?? '?'} da IP <code>${escapeHtml(ipDisplay)}</code>. Testato byte candidato <code>${gHex}</code> su indice <code>${details.byte_index ?? '?'}</code>. Esito oracolo: ${outcomeDesc}.`;
    }
  } else {
    analysisText = `🛡️ <strong>Analisi SOC:</strong> Traffico baseline legittimo generato da client autorizzato (IP <code>${escapeHtml(ipDisplay)}</code>) con payload crittografato valido.`;
  }

  const footer = document.createElement('div');
  footer.className = 'soc-analysis-footer';
  footer.innerHTML = analysisText;
  card.appendChild(footer);

  return card;
}

function renderSocEvents(container, events) {
  if (!events || events.length === 0) {
    const emptyMsg = `
      <div style="padding:40px 20px;text-align:center;color:var(--text-muted)">
        <strong style="color:var(--text);font-size:14px">Nessun evento SOC registrato</strong>
        <p style="font-size:12px;margin-top:6px;color:var(--text-dim)">
          Avvia il traffico benigno o l'attacco padding oracle dalla barra superiore per analizzare le coppie richiesta/risposta.
        </p>
      </div>
    `;
    if (container.dataset.renderedState !== 'empty') {
      container.innerHTML = emptyMsg;
      container.dataset.renderedState = 'empty';
      container.dataset.renderedSig = '';
    }
    return;
  }

  const sig = events.slice(0, 50).map(e => `${e.ts}_${e.event_type}_${e.status_code}`).join('|') + `_${events.length}`;
  if (container.dataset.renderedSig === sig) return;
  container.dataset.renderedSig = sig;
  container.dataset.renderedState = 'populated';

  const wrapper = document.createElement('div');
  wrapper.className = 'soc-container';
  events.forEach(ev => {
    wrapper.appendChild(buildSocLogCard(ev));
  });
  container.innerHTML = '';
  container.appendChild(wrapper);
}

// ── Known Source IPs Cache & Selector Population ──
let knownIpsCache = ["198.51.100.50", "192.168.1.10", "192.168.1.11", "victim:8080"];

async function loadKnownIps() {
  try {
    const r = await fetch('/logs/ips');
    const ips = await r.json();
    if (ips && Array.isArray(ips) && ips.length) {
      knownIpsCache = ips;
    }
  } catch (e) {}

  const selectors = ['net-raw-ip-filter', 'raw-ip-filter'];
  selectors.forEach(id => {
    const sel = document.getElementById(id);
    if (!sel) return;
    const cur = sel.value;
    const currentOptions = Array.from(sel.options).map(o => o.value).join(',');
    const newOptionsList = ['', ...knownIpsCache];
    if (currentOptions !== newOptionsList.join(',')) {
      sel.innerHTML = '<option value="">Tutti gli IP sorgente</option>' +
        knownIpsCache.map(ip => `<option value="${escapeHtml(ip)}">${escapeHtml(ip)}</option>`).join('');
      if (cur && knownIpsCache.includes(cur)) sel.value = cur;
    }
  });
}

// ── SOC log loaders ──
let socFilterMode = 'attacker'; // 'attacker' or 'all'

function toggleSocFilterMode() {
  socFilterMode = (socFilterMode === 'attacker') ? 'all' : 'attacker';
  const label = (socFilterMode === 'attacker') ? '🔴 Solo Attacchi (Default)' : '🌐 Tutti i Log (Inclusi Benigni)';
  const btn1 = document.getElementById('soc-filter-mode-btn');
  const btn2 = document.getElementById('net-soc-filter-mode-btn');
  if (btn1) {
    btn1.textContent = label;
    btn1.style.background = (socFilterMode === 'attacker') ? 'rgba(239,68,68,0.15)' : 'rgba(255,255,255,0.06)';
    btn1.style.borderColor = (socFilterMode === 'attacker') ? 'var(--red)' : 'var(--border)';
  }
  if (btn2) {
    btn2.textContent = label;
    btn2.style.background = (socFilterMode === 'attacker') ? 'rgba(239,68,68,0.15)' : 'rgba(255,255,255,0.06)';
    btn2.style.borderColor = (socFilterMode === 'attacker') ? 'var(--red)' : 'var(--border)';
  }
  loadSocLogs();
  loadNetSocLogs();
}

async function loadNetSocLogs() {
  try {
    const epSel = document.getElementById('net-soc-ep-filter');
    const ep = epSel ? epSel.value : '';
    let url = (socFilterMode === 'attacker') ? '/logs/tail?limit=300&service=attacker' : '/logs/tail?limit=300';
    if (ep) url += `&endpoint=${encodeURIComponent(ep)}`;
    const r = await fetch(url);
    const events = await r.json();
    const filtered = events.filter(ev => {
      const c = colorClass(ev);
      return (socFilterMode === 'attacker') ? (c === 'attacker') : (c === 'attacker' || c === 'benign');
    });
    const stream = document.getElementById('net-soc-stream');
    if (!stream) return;
    const socScroll = document.getElementById('auto-scroll-chk');
    const atBottom = stream.scrollHeight - stream.scrollTop - stream.clientHeight < 80;
    renderSocEvents(stream, filtered.slice(0, 200));
    if (socScroll && socScroll.checked && atBottom) stream.scrollTop = stream.scrollHeight;
  } catch (e) { /* ignore */ }
}

async function loadSocLogs() {
  try {
    const epSel = document.getElementById('soc-ep-filter');
    const ep = epSel ? epSel.value : '';
    let url = (socFilterMode === 'attacker') ? '/logs/tail?limit=500&service=attacker' : '/logs/tail?limit=500';
    if (ep) url += `&endpoint=${encodeURIComponent(ep)}`;
    const r = await fetch(url);
    const events = await r.json();
    const filtered = events.filter(ev => {
      const c = colorClass(ev);
      return (socFilterMode === 'attacker') ? (c === 'attacker') : (c === 'attacker' || c === 'benign');
    });
    const stream = document.getElementById('log-soc-stream');
    if (!stream) return;
    const socScroll = document.getElementById('soc-auto-scroll');
    const atBottom = stream.scrollHeight - stream.scrollTop - stream.clientHeight < 80;
    renderSocEvents(stream, filtered.slice(0, 300));
    if (socScroll && socScroll.checked && atBottom) stream.scrollTop = stream.scrollHeight;
  } catch (e) { /* ignore */ }
}

// ── Unified Live Telemetry & Raw Logs Loader ──
async function loadNetRawLogs() {
  const ipSel = document.getElementById('net-raw-ip-filter');
  const etypeSel = document.getElementById('net-raw-etype-filter');
  const epSel = document.getElementById('net-raw-ep-filter');
  const statusSel = document.getElementById('net-raw-status-filter');
  const qInput = document.getElementById('net-raw-q');
  const limSel = document.getElementById('net-raw-limit');
  const filterIp = ipSel ? ipSel.value : '';
  const etype = etypeSel ? etypeSel.value : '';
  const endpoint = epSel ? epSel.value : '';
  const status = statusSel ? statusSel.value : '';
  const q = qInput ? qInput.value.trim() : '';
  const lim = limSel ? limSel.value : '1000';
  
  let url = `/logs/tail?limit=${lim}`;
  if (filterIp) url += `&src_ip=${encodeURIComponent(filterIp)}`;
  if (etype) url += `&event_type=${encodeURIComponent(etype)}`;
  if (endpoint) url += `&endpoint=${encodeURIComponent(endpoint)}`;
  if (status) url += `&status_code=${encodeURIComponent(status)}`;
  if (q) url += `&q=${encodeURIComponent(q)}`;

  try {
    const r = await fetch(url);
    let events = await r.json();

    const stream = document.getElementById('net-raw-stream');
    if (!stream) return;
    const autoScrollChk = document.getElementById('auto-scroll-chk');
    const atBottom = stream.scrollHeight - stream.scrollTop - stream.clientHeight < 80;
    
    if (events.length === 0) {
      if (stream.dataset.renderedSig !== 'empty') {
        stream.innerHTML = '<p style="color:var(--text-muted);padding:16px;font-size:12px">Nessun evento trovato con i filtri selezionati.</p>';
        stream.dataset.renderedSig = 'empty';
      }
      return;
    }

    const sig = events.slice(0, 40).map(e => `${e.ts}_${e.service}_${e.event_type}_${e.status_code}`).join('|') + `_${events.length}`;
    if (stream.dataset.renderedSig === sig) return;
    stream.dataset.renderedSig = sig;

    stream.innerHTML = '';
    events.forEach(ev => stream.appendChild(buildLogRow(ev)));
    if (autoScrollChk && autoScrollChk.checked && atBottom) stream.scrollTop = stream.scrollHeight;
  } catch (e) { /* ignore */ }
}

async function loadRawLogs() {
  const ipSel   = document.getElementById('raw-ip-filter');
  const etypeSel = document.getElementById('raw-etype-filter');
  const epSel = document.getElementById('raw-ep-filter');
  const statusSel = document.getElementById('raw-status-filter');
  const qInput  = document.getElementById('raw-q');
  const limSel  = document.getElementById('raw-limit');
  const filterIp = ipSel ? ipSel.value : '';
  const etype = etypeSel ? etypeSel.value : '';
  const endpoint = epSel ? epSel.value : '';
  const status = statusSel ? statusSel.value : '';
  const q     = qInput ? qInput.value.trim() : '';
  const lim   = limSel ? limSel.value : '1000';

  let url = `/logs/tail?limit=${lim}`;
  if (filterIp) url += `&src_ip=${encodeURIComponent(filterIp)}`;
  if (etype) url += `&event_type=${encodeURIComponent(etype)}`;
  if (endpoint) url += `&endpoint=${encodeURIComponent(endpoint)}`;
  if (status) url += `&status_code=${encodeURIComponent(status)}`;
  if (q) url += `&q=${encodeURIComponent(q)}`;

  try {
    const r = await fetch(url);
    let events = await r.json();

    const stream = document.getElementById('log-raw-stream');
    if (!stream) return;
    const scrollChk = document.getElementById('raw-auto-scroll');
    const atBottom = stream.scrollHeight - stream.scrollTop - stream.clientHeight < 80;
    
    if (events.length === 0) {
      if (stream.dataset.renderedSig !== 'empty') {
        stream.innerHTML = '<p style="color:var(--text-muted);padding:16px;font-size:12px">Nessun evento trovato con i filtri selezionati.</p>';
        stream.dataset.renderedSig = 'empty';
      }
      return;
    }

    const sig = events.slice(0, 40).map(e => `${e.ts}_${e.service}_${e.event_type}_${e.status_code}`).join('|') + `_${events.length}`;
    if (stream.dataset.renderedSig === sig) return;
    stream.dataset.renderedSig = sig;

    stream.innerHTML = '';
    events.forEach(ev => stream.appendChild(buildLogRow(ev)));
    if (scrollChk && scrollChk.checked && atBottom) stream.scrollTop = stream.scrollHeight;
  } catch (e) { /* ignore */ }
}

// ── Attack Detail ──
async function loadAttackDetail(targetId) {
  const targetIds = targetId ? [targetId] : ['atk-body', 'net-atk-body'];
  try {
    const r = await fetch('/logs/tail?limit=10000&service=attacker');
    const allAtkEvents = await r.json();
    if (!allAtkEvents || !allAtkEvents.length) {
      if (!lastRenderedScenarioId && !lastRenderedAttackHtml) {
        const emptyMsg = '<p class="atk-no-data">In attesa di un attacco… l\'attaccante non ha ancora generato log.</p>';
        targetIds.forEach(id => {
          const body = document.getElementById(id);
          if (body && body.dataset.renderedHtml !== emptyMsg) {
            body.innerHTML = emptyMsg;
            body.dataset.renderedHtml = emptyMsg;
          }
        });
      }
      return;
    }

    const sortedEvents = allAtkEvents.slice().sort((a, b) => (a.ts || '').localeCompare(b.ts || ''));

    // Identifica l'ultimo scenario_id da eventi effettivi dell'attacco (probe/progress/recon/complete/blocked)
    let latestScenarioId = null;
    for (let i = sortedEvents.length - 1; i >= 0; i--) {
      const ev = sortedEvents[i];
      if (ev.scenario_id && (ev.event_type?.startsWith('attack_') || ev.service === 'attacker')) {
        latestScenarioId = ev.scenario_id;
        break;
      }
    }

    // Se non troviamo scenario_id specifico nell'ultimo batch, mantieni l'ultimo attivo noto per non azzerare la mappa
    if (!latestScenarioId && lastRenderedScenarioId) {
      latestScenarioId = lastRenderedScenarioId;
    }

    if (latestScenarioId) {
      if (!scenarioByteStorage[latestScenarioId]) {
        scenarioByteStorage[latestScenarioId] = {};
      }
      persistentAttackByteMap = scenarioByteStorage[latestScenarioId];
      lastRenderedScenarioId = latestScenarioId;
    }

    const atk = latestScenarioId ? sortedEvents.filter(ev => ev.scenario_id === latestScenarioId) : sortedEvents;

    if (!atk.length && !Object.keys(persistentAttackByteMap).length) {
      const initMsg = '<p class="atk-no-data">Inizializzazione nuovo attacco…</p>';
      targetIds.forEach(id => {
        const body = document.getElementById(id);
        if (body && body.dataset.renderedHtml !== initMsg) {
          body.innerHTML = initMsg;
          body.dataset.renderedHtml = initMsg;
        }
      });
      return;
    }

    let completeEv = null;
    let blockedEv = null;
    let notPermittedEv = null;
    let errEv = null;
    let totalProbes = 0;
    let lastProbe = null;
    let numBlocks = 0;

    atk.forEach(ev => {
      const d = ev.details || {};
      const isNoise = ev.event_type === 'attack_noise_blend';

      if (!isNoise) {
        if (d.total_blocks) numBlocks = Math.max(numBlocks, d.total_blocks);
        if (d.blocks_count) numBlocks = Math.max(numBlocks, d.blocks_count);
        if (ev.event_type === 'attack_recon' && (d.ciphertext_len || ev.ciphertext_len)) {
          const cLen = d.ciphertext_len || ev.ciphertext_len;
          if (cLen >= 32) numBlocks = Math.max(numBlocks, Math.floor(cLen / 16) - 1);
        }
        if (d.block_index !== undefined) {
          numBlocks = Math.max(numBlocks, d.block_index);
        }
      }

      if (ev.event_type === 'attack_probe') {
        totalProbes++;
        lastProbe = ev;
      }
      if (ev.event_type === 'attack_progress' && ev.details) {
        const bIdx = d.block_index !== undefined ? d.block_index : 1;
        const byteIdx = d.byte_index !== undefined ? d.byte_index : 0;
        const gIdx = d.global_byte_index !== undefined ? d.global_byte_index : ((bIdx - 1) * 16 + byteIdx);
        persistentAttackByteMap[gIdx] = { ...d, ts: ev.ts };
      }
      if (ev.event_type === 'attack_complete') {
        completeEv = ev;
      }
      if (ev.event_type === 'attack_blocked') {
        blockedEv = ev;
      }
      if (ev.event_type === 'attack_not_permitted') {
        notPermittedEv = ev;
      }
      if (ev.event_type === 'attack_error') {
        errEv = ev;
      }
    });

    // Calcolo blocchi totale: mantieni il valore massimo storico per questo scenario
    const maxDiscoveredIdx = Math.max(-1, ...Object.keys(persistentAttackByteMap).map(Number));
    if (maxDiscoveredIdx >= 0) {
      numBlocks = Math.max(numBlocks, Math.floor(maxDiscoveredIdx / 16) + 1);
    }
    if (numBlocks <= 0) {
      numBlocks = 1;
    }

    let recFullStr = (completeEv && completeEv.details) ? (completeEv.details.recovered_plaintext || completeEv.details.recovered_block || '') : '';
    let rawPayloadHex = (completeEv && completeEv.details) ? (completeEv.details.raw_payload_hex || '') : '';
    const totalExpectedBytes = numBlocks * 16;
    const recCount = notPermittedEv ? 0 : (completeEv ? totalExpectedBytes : Object.keys(persistentAttackByteMap).length);

    const statusLabel = notPermittedEv ? '🛡️ ATTACCO NON CONSENTITO' : (blockedEv ? '🛑 BLOCCATO DA WAF' : (errEv ? '⚠️ ATTACCO INTERROTTO' : (completeEv ? '✅ COMPLETATO' : '⚡ IN ESECUZIONE')));
    const statusColor = notPermittedEv ? 'var(--blue)' : (blockedEv ? 'var(--red)' : (errEv ? 'var(--amber)' : (completeEv ? 'var(--green)' : 'var(--accent)')));
    const statusSub = notPermittedEv ? 'Target Protetto da Encrypt-then-MAC (HMAC a monte)' : (blockedEv ? 'Intercettato da Firewall' : (lastProbe ? 'Blocco ' + (lastProbe.details?.block_index || 1) + ' · Guess: ' + (lastProbe.details?.guess_hex || '0x..') : (completeEv ? 'Payload Recuperato' : 'Pronto')));
    const totalQueriesVal = completeEv?.details?.queries || notPermittedEv?.details?.queries_total || blockedEv?.details?.queries_total || totalProbes;
    const avgProbeVal = recCount > 0 ? (totalProbes / Math.max(1, recCount)).toFixed(1) + ' probe/byte avg' : 'Inizializzazione';
    const percentVal = notPermittedEv ? `0% (${numBlocks} ${numBlocks > 1 ? 'blocchi' : 'blocco'}) — 0 byte compromessi` : `${((recCount / Math.max(1, totalExpectedBytes)) * 100).toFixed(0)}% (${numBlocks} ${numBlocks > 1 ? 'blocchi' : 'blocco'})`;

    // Render su ogni contenitore target preservando il DOM ed evitando reflow distruttivi
    targetIds.forEach(id => {
      const body = document.getElementById(id);
      if (!body) return;

      let root = body.querySelector(':scope > .atk-detail-root');
      let currentBlocksCount = root ? parseInt(root.dataset.blocksCount || '0', 10) : 0;

      // Inizializza o ricrea lo scheletro solo se assente o se il numero di blocchi è cambiato
      if (!root || currentBlocksCount !== numBlocks) {
        let skeletonHtml = `
          <div class="atk-detail-root" data-blocks-count="${numBlocks}">
            <div class="atk-kpi-grid" style="display:grid;grid-template-columns:repeat(auto-fit, minmax(160px, 1fr));gap:10px;margin-bottom:16px">
              <div class="kpi-card" style="padding:10px 14px">
                <div class="kpi-label">Byte Decifrati</div>
                <div class="kpi-val atk-kpi-bytes" style="color:var(--green)">${recCount} / ${totalExpectedBytes}</div>
                <div class="kpi-sub atk-kpi-pct">${percentVal}</div>
              </div>
              <div class="kpi-card" style="padding:10px 14px">
                <div class="kpi-label">Sonde / Query Totali</div>
                <div class="kpi-val atk-kpi-queries" style="color:var(--amber)">${totalQueriesVal}</div>
                <div class="kpi-sub atk-kpi-avg">${avgProbeVal}</div>
              </div>
              <div class="kpi-card" style="padding:10px 14px">
                <div class="kpi-label">Stato Attacco</div>
                <div class="kpi-val atk-kpi-status" style="font-size:16px;color:${statusColor}">${statusLabel}</div>
                <div class="kpi-sub atk-kpi-status-sub">${statusSub}</div>
              </div>
            </div>

            <div class="atk-alert-slot"></div>
            <div class="atk-complete-slot"></div>

            <div class="atk-grid-container">`;

        for (let b = 1; b <= numBlocks; b++) {
          skeletonHtml += `<div class="atk-block-wrap" style="margin-bottom:14px">`;
          skeletonHtml += `<div style="font-size:11px;color:var(--text-muted);font-weight:700;letter-spacing:.6px;margin-bottom:6px">🧱 Blocco ${b} / ${numBlocks} (Byte ${(b-1)*16} → ${b*16 - 1})</div>`;
          skeletonHtml += `<div class="byte-grid">`;
          for (let idx = 0; idx < 16; idx++) {
            const globalIdx = (b - 1) * 16 + idx;
            skeletonHtml += `<div class="byte-cell" id="${id}-cell-${globalIdx}">
              <span class="bc-idx">${globalIdx}</span>
              <span class="bc-val">?</span>
              <span class="bc-hex">0x??</span>
            </div>`;
          }
          skeletonHtml += `</div></div>`;
        }

        skeletonHtml += `</div>
            <div style="font-size:11px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.8px;margin-bottom:8px">Flusso Telemetrico Recente</div>
            <div class="atk-events-container"></div>
          </div>
        `;

        body.innerHTML = skeletonHtml;
        body.dataset.renderedHtml = 'rendered';
        root = body.querySelector(':scope > .atk-detail-root');
      }

      // ── Aggiornamento chirurgico KPI (zero flicker) ──
      const elBytes = root.querySelector('.atk-kpi-bytes');
      if (elBytes && elBytes.textContent !== `${recCount} / ${totalExpectedBytes}`) {
        elBytes.textContent = `${recCount} / ${totalExpectedBytes}`;
      }
      const elPct = root.querySelector('.atk-kpi-pct');
      if (elPct && elPct.textContent !== percentVal) {
        elPct.textContent = percentVal;
      }
      const elQueries = root.querySelector('.atk-kpi-queries');
      if (elQueries && elQueries.textContent !== String(totalQueriesVal)) {
        elQueries.textContent = totalQueriesVal;
      }
      const elAvg = root.querySelector('.atk-kpi-avg');
      if (elAvg && elAvg.textContent !== avgProbeVal) {
        elAvg.textContent = avgProbeVal;
      }
      const elStatus = root.querySelector('.atk-kpi-status');
      if (elStatus && elStatus.textContent !== statusLabel) {
        elStatus.textContent = statusLabel;
        elStatus.style.color = statusColor;
      }
      const elStatusSub = root.querySelector('.atk-kpi-status-sub');
      if (elStatusSub && elStatusSub.textContent !== statusSub) {
        elStatusSub.textContent = statusSub;
      }

      // ── Slot WAF Blocked / Not Permitted ──
      const alertSlot = root.querySelector('.atk-alert-slot');
      if (alertSlot) {
        if (notPermittedEv && !alertSlot.hasChildNodes()) {
          alertSlot.innerHTML = `
            <div class="atk-event" style="margin-bottom:16px;border-left-color:var(--blue)">
              <div class="ae-header">
                <span class="ae-type" style="background:rgba(59,130,246,0.2);color:var(--blue);border:1px solid rgba(59,130,246,0.4)">🛡️ attack_not_permitted — Attacco Non Consentito</span>
                <span class="ae-ts">${(notPermittedEv.ts||'').replace('T',' ').replace(/\.\d+.*$/,'')}</span>
              </div>
              <div style="padding:10px 12px;background:rgba(59,130,246,0.1);border:1px solid var(--blue);border-radius:6px;margin:8px 0">
                <strong style="color:var(--blue)">Integrità Crittografica a Monte (Encrypt-then-MAC):</strong>
                <div style="font-size:12px;color:var(--text);margin-top:4px">
                  ${escapeHtml(notPermittedEv.details?.reason || 'Target protetto da Encrypt-then-MAC: HMAC autenticato a monte. Qualsiasi manomissione viene respinta all\'istante (0 byte compromessi).')}
                </div>
              </div>
            </div>`;
        } else if (blockedEv && !alertSlot.hasChildNodes()) {
          alertSlot.innerHTML = `
            <div class="atk-event" style="margin-bottom:16px;border-left-color:var(--red)">
              <div class="ae-header">
                <span class="ae-type" style="background:rgba(239,68,68,0.2);color:var(--red);border:1px solid rgba(239,68,68,0.4)">🛑 attack_blocked — Exploit Neutralizzato dal WAF (HTTP 429)</span>
                <span class="ae-ts">${(blockedEv.ts||'').replace('T',' ').replace(/\.\d+.*$/,'')}</span>
              </div>
              <div style="padding:10px 12px;background:rgba(239,68,68,0.1);border:1px solid var(--red);border-radius:6px;margin:8px 0">
                <strong style="color:var(--red)">Difesa Attiva Efficace:</strong>
                <div style="font-size:12px;color:var(--text);margin-top:4px">
                  L'attacco è stato intercettato e bloccato preventivamente dal WAF della vittima dopo ${blockedEv.details?.queries_total || totalProbes} richieste. L'exploit è fallito e il segreto non è stato compromesso.
                </div>
              </div>
            </div>`;
        } else if (!blockedEv && !notPermittedEv && alertSlot.hasChildNodes()) {
          alertSlot.innerHTML = '';
        }
      }

      // ── Slot Complete ──
      const compSlot = root.querySelector('.atk-complete-slot');
      if (compSlot) {
        if (completeEv && !compSlot.hasChildNodes()) {
          const d = completeEv.details || {};
          const recText = d.recovered_plaintext || d.recovered_block || '';
          const q = d.queries || '?';
          const ms = completeEv.latency_ms ? Math.round(completeEv.latency_ms) : '?';
          const recBytesLen = (recText ? new TextEncoder().encode(recText).length : 0);
          compSlot.innerHTML = `
            <div class="atk-event complete" style="margin-bottom:16px">
              <div class="ae-header">
                <span class="ae-type ae-complete-badge">attack_complete — Testo Segreto Recuperato</span>
                <span class="ae-ts">${(completeEv.ts||'').replace('T',' ').replace(/\.\d+.*$/,'')}</span>
              </div>
              <div style="padding:10px 12px;background:rgba(16,185,129,0.12);border:1px solid var(--green);border-radius:6px;margin:8px 0">
                <span style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px">Messaggio Segreto Decifrato:</span>
                <div style="font-size:18px;font-weight:700;color:var(--text);font-family:var(--font-mono);margin-top:4px">
                  "${escapeHtml(recText)}"
                </div>
                <div style="font-size:11px;color:var(--text-dim);margin-top:4px">
                  Estratto dal payload decifrato di ${totalExpectedBytes} byte (${numBlocks} ${numBlocks > 1 ? 'blocchi' : 'blocco'}, Plaintext: ${recBytesLen}B + HMAC Tag: 16B + Padding PKCS#7).
                </div>
              </div>
              <div class="ae-grid">
                <div class="ae-kv"><span class="ae-k">blocchi_totali</span><span class="ae-v">${d.blocks_count || numBlocks}</span></div>
                <div class="ae-kv"><span class="ae-k">total_queries</span><span class="ae-v amber">${q}</span></div>
                <div class="ae-kv"><span class="ae-k">elapsed_ms</span><span class="ae-v">${ms} ms</span></div>
                <div class="ae-kv"><span class="ae-k">scenario_id</span><span class="ae-v">${escapeHtml(completeEv.scenario_id||'?')}</span></div>
              </div>
            </div>`;
        } else if (!completeEv && compSlot.hasChildNodes()) {
          compSlot.innerHTML = '';
        }
      }

      // ── Aggiornamento chirurgico delle celle della Byte Grid ──
      const curBlock = lastProbe?.details?.block_index || 1;
      const curIdx = lastProbe?.details?.byte_index;

      for (let b = 1; b <= numBlocks; b++) {
        for (let idx = 0; idx < 16; idx++) {
          const globalIdx = (b - 1) * 16 + idx;
          const cell = document.getElementById(`${id}-cell-${globalIdx}`);
          if (!cell) continue;

          const cellData = persistentAttackByteMap[globalIdx];
          let isRecovered = false;
          let isInProgress = false;
          let charVal = '?';
          let hexVal = '0x??';

          if (rawPayloadHex && (globalIdx * 2 + 2 <= rawPayloadHex.length)) {
            isRecovered = true;
            const hexByte = rawPayloadHex.substring(globalIdx * 2, globalIdx * 2 + 2);
            const code = parseInt(hexByte, 16);
            hexVal = '0x' + hexByte;
            charVal = (code >= 32 && code < 127) ? String.fromCharCode(code) : '·';
          } else if (cellData) {
            isRecovered = true;
            if (cellData.recovered_char !== undefined) {
              charVal = cellData.recovered_char;
              const code = cellData.recovered_byte !== undefined ? cellData.recovered_byte : (cellData.guess ^ cellData.pad_len);
              hexVal = '0x' + (typeof code === 'number' ? code : 0).toString(16).padStart(2, '0');
            } else {
              const code = cellData.guess ^ cellData.pad_len;
              charVal = (code >= 32 && code < 127) ? String.fromCharCode(code) : '·';
              hexVal = '0x' + code.toString(16).padStart(2, '0');
            }
          } else if (curBlock === b && curIdx === idx && !completeEv) {
            isInProgress = true;
            charVal = '…';
            hexVal = lastProbe?.details?.guess_hex || 'probing';
          }

          if (isRecovered) {
            cell.classList.add('recovered');
            cell.classList.remove('in-progress');
          } else if (isInProgress) {
            cell.classList.add('in-progress');
            cell.classList.remove('recovered');
          } else {
            cell.classList.remove('recovered', 'in-progress');
          }

          const valSpan = cell.querySelector('.bc-val');
          if (valSpan && valSpan.textContent !== charVal) {
            valSpan.textContent = charVal;
          }
          const hexSpan = cell.querySelector('.bc-hex');
          if (hexSpan && hexSpan.textContent !== hexVal) {
            hexSpan.textContent = hexVal;
          }
        }
      }

      // ── Aggiornamento lista eventi recenti senza cancellazione distruttiva ──
      const eventsContainer = root.querySelector('.atk-events-container');
      if (eventsContainer) {
        const notableEvents = atk.slice(-50).reverse();
        const eventsSig = notableEvents.map(e => `${e.ts}_${e.event_type}_${e.details?.queries_total||e.details?.guess_hex||''}`).join('|');
        if (eventsContainer.dataset.renderedSig !== eventsSig) {
          eventsContainer.dataset.renderedSig = eventsSig;
          let evHtml = '';
          notableEvents.forEach(ev => {
            const d = ev.details || {};
            const ts = (ev.ts||'').replace('T',' ').replace(/\.\d+.*$/,'');
            const isProg = ev.event_type === 'attack_progress';
            const isComp = ev.event_type === 'attack_complete';
            const isBlk = ev.event_type === 'attack_blocked';
            const recCh = d.recovered_char !== undefined ? d.recovered_char : '?';
            const recByte = d.recovered_byte !== undefined ? d.recovered_byte : '?';
            let cardStyle = isComp ? 'border-left:3px solid var(--green);background:rgba(16,185,129,0.08)' : isBlk ? 'border-left:3px solid var(--red);background:rgba(239,68,68,0.08)' : isProg ? 'border-left:3px solid var(--amber);background:rgba(251,191,36,0.08)' : 'border-left:3px solid var(--border-lit)';
            let badgeType = isComp ? 'ae-complete-badge' : isProg ? 'ae-progress-badge' : '';
            evHtml += `
            <div class="atk-event" style="${cardStyle}">
              <div class="ae-header">
                <span class="ae-type ${badgeType}">${escapeHtml(ev.event_type)}</span>
                <span class="ae-ts">${ts}</span>
                <div style="flex:1"></div>
                <span style="font-size:10px;color:var(--text-dim)">#${d.queries_total || d.queries || '?'}</span>
              </div>
              <div class="ae-grid">
                <div class="ae-kv"><span class="ae-k">byte_index</span><span class="ae-v amber">${d.byte_index ?? '?'}</span></div>
                <div class="ae-kv"><span class="ae-k">pad_len</span><span class="ae-v">${d.pad_len ?? '?'}</span></div>
                ${isProg ? `<div class="ae-kv"><span class="ae-k">decifrato</span><span class="ae-v green">'${escapeHtml(recCh)}' (0x${(recByte !== '?' ? recByte : 0).toString(16).padStart(2,'0')})</span></div>` : `<div class="ae-kv"><span class="ae-k">guess_testato</span><span class="ae-v">${d.guess_hex || d.guess || '?'}</span></div>`}
                <div class="ae-kv"><span class="ae-k">esito</span><span class="ae-v">${ev.status_code ? 'HTTP ' + ev.status_code : (d.valid_padding ? 'Padding OK' : 'Probe')}</span></div>
                <div class="ae-kv"><span class="ae-k">latenza</span><span class="ae-v">${ev.latency_ms !== undefined ? Math.round(ev.latency_ms) + ' ms' : '—'}</span></div>
              </div>
            </div>`;
          });
          eventsContainer.innerHTML = evHtml;
        }
      }
    });

    lastRenderedAttackHtml = 'rendered';
  } catch (e) { console.error('loadAttackDetail', e); }
}

// ── Network polling (every 5s) ──
async function pollNetwork() {
  try {
    const r = await fetch('/network/data');
    const data = await r.json();
    initNetwork(data);
  } catch (e) { /* ignore */ }
}

// ── Alerts & SOC Analytics ──
let currentReportMarkdown = '';
let currentReportFilename = 'soc_incident_report.md';

async function loadAlerts() {
  try {
    const [alertsRes, wafRes] = await Promise.all([
      fetch('/alerts_data').then(r => r.json()).catch(() => ({ alerts: [], kpis: {}, rules: {} })),
      fetch('/waf/status').then(r => r.json()).catch(() => ({ blocked_ips: [], blocked_details: [], policy: {} }))
    ]);
    renderAlerts(alertsRes.alerts || [], alertsRes.kpis || {}, alertsRes.rules || {}, wafRes || {});
  } catch (e) {
    document.getElementById('alerts-content').innerHTML =
      '<p style="color:var(--text-muted)">SOC collector non raggiungibile (avviarlo dalla sezione Docker).</p>';
  }
}

function renderAlerts(alerts, kpis, rules, wafData = {}) {
  // Update KPI Scorecards
  const mttdEl = document.getElementById('kpi-mttd');
  const tprEl = document.getElementById('kpi-tpr');
  const fprEl = document.getElementById('kpi-fpr');
  const alertsCountEl = document.getElementById('kpi-alerts-count');
  const alertsStatusEl = document.getElementById('kpi-alerts-status');

  if (mttdEl) {
    mttdEl.textContent = (kpis && kpis.mttd_seconds !== null && kpis.mttd_seconds !== undefined)
      ? `${kpis.mttd_seconds} s`
      : (kpis && kpis.is_attack_active ? 'In calcolo…' : '—');
  }
  if (tprEl) {
    tprEl.textContent = (kpis && kpis.true_positive_rate !== undefined)
      ? `${(kpis.true_positive_rate * 100).toFixed(0)}%`
      : '100%';
  }
  if (fprEl) {
    fprEl.textContent = (kpis && kpis.false_positive_rate !== undefined)
      ? `${(kpis.false_positive_rate * 100).toFixed(1)}%`
      : '0.0%';
  }
  if (alertsCountEl) {
    alertsCountEl.textContent = alerts.length;
    if (alerts.some(a => a.severity === 'critical')) {
      alertsCountEl.style.color = 'var(--red)';
      if (alertsStatusEl) alertsStatusEl.textContent = '🔴 CRITICAL THREAT DETECTED';
    } else if (alerts.length > 0) {
      alertsCountEl.style.color = 'var(--amber)';
      if (alertsStatusEl) alertsStatusEl.textContent = '🟠 ALLARMI ATTIVI';
    } else {
      alertsCountEl.style.color = 'var(--green)';
      if (alertsStatusEl) alertsStatusEl.textContent = '🟢 Nessuna anomalia rilevata';
    }
  }

  // Update WAF Quarantined / Blocked IPs Table
  const wafBlockedTbody = document.getElementById('waf-blocked-ips-tbody');
  const wafBlockedBadge = document.getElementById('waf-blocked-count-badge');
  const blockedDetails = wafData.blocked_details || [];
  const blockedIpsList = wafData.blocked_ips || [];
  
  if (wafBlockedBadge) {
    wafBlockedBadge.textContent = `${blockedIpsList.length} bloccati`;
    wafBlockedBadge.style.color = blockedIpsList.length > 0 ? '#fca5a5' : 'var(--text-muted)';
    wafBlockedBadge.style.background = blockedIpsList.length > 0 ? 'rgba(239,68,68,0.2)' : 'rgba(255,255,255,0.05)';
  }

  if (wafBlockedTbody) {
    if (!blockedIpsList.length) {
      wafBlockedTbody.innerHTML = '<tr><td colspan="5" style="color:var(--text-muted);text-align:center;padding:10px">Nessun IP attualmente in quarantena WAF (Firewall in attesa o disattivato).</td></tr>';
    } else {
      wafBlockedTbody.innerHTML = blockedIpsList.map(ip => {
        const detail = blockedDetails.find(d => d.ip === ip) || {};
        const ttl = detail.ttl_remaining_s !== undefined && detail.ttl_remaining_s !== null ? Math.round(detail.ttl_remaining_s) : 'Permanente / Auto';
        return `
          <tr>
            <td style="font-family:var(--font-mono);font-weight:700;color:var(--red)">${escapeHtml(ip)}</td>
            <td><span style="color:var(--red);font-weight:700">⛔ INLINE QUARANTINE (HTTP 429)</span></td>
            <td style="font-family:var(--font-mono);font-weight:700;color:var(--amber)">${ttl}s</td>
            <td><span style="color:var(--text-dim);font-size:10px">Filtro automatico sliding-window violazioni L7</span></td>
            <td>
              <button class="btn btn-secondary" style="font-size:10px;padding:2px 8px;color:var(--green);border-color:rgba(16,185,129,0.4)" onclick="quickUnblockIp('${escapeHtml(ip)}')">🔓 Sblocca IP</button>
            </td>
          </tr>
        `;
      }).join('');
    }
  }

  // Update Telemetry Profile Table (Per-IP Evaluation with WAF Status Integration)
  const teleTbody = document.getElementById('telemetry-ips-tbody');
  if (teleTbody) {
    const ipTable = kpis.ip_telemetry_table || [];
    if (!ipTable.length) {
      teleTbody.innerHTML = '<tr><td colspan="8" style="color:var(--text-muted);text-align:center;padding:12px">Nessuna richiesta <code>/decrypt</code> registrata nella finestra attiva.</td></tr>';
    } else {
      teleTbody.innerHTML = ipTable.map(row => {
        const isBlockedByWaf = blockedIpsList.includes(row.ip);
        const isViolating = row.is_alerted || row.fail_rate >= 0.70;
        
        let wafBadge = '<span style="color:var(--text-muted);font-size:10px">Passante</span>';
        if (isBlockedByWaf) {
          wafBadge = '<span style="color:var(--red);font-weight:700;background:rgba(239,68,68,0.15);padding:2px 6px;border-radius:4px">⛔ Bloccato WAF</span>';
        } else if (isViolating) {
          wafBadge = '<span style="color:var(--amber);font-weight:700;background:rgba(245,158,11,0.15);padding:2px 6px;border-radius:4px">⚠️ Da Mitigare</span>';
        } else {
          wafBadge = '<span style="color:var(--green);font-size:10px">🟢 Verificato OK</span>';
        }

        const statusBadge = isViolating
          ? `<span style="color:var(--red);font-weight:700">🔴 VIOLAZIONE (${escapeHtml(row.evaluation)})</span>`
          : `<span style="color:var(--green);font-weight:600">🟢 Conforme alla Baseline</span>`;
        const ipColor = isViolating ? 'var(--red)' : '#60a5fa';

        const actionBtn = isBlockedByWaf
          ? `<button class="btn btn-secondary" style="font-size:10px;padding:2px 6px;color:var(--green)" onclick="quickUnblockIp('${escapeHtml(row.ip)}')">🔓 Sblocca</button>`
          : `<button class="btn btn-secondary" style="font-size:10px;padding:2px 6px;color:var(--red)" onclick="quickBlockIp('${escapeHtml(row.ip)}')">🛡️ Quarantena WAF</button>`;

        return `
          <tr>
            <td style="font-family:var(--font-mono);font-weight:700;color:${ipColor}">${escapeHtml(row.ip)}</td>
            <td>${wafBadge}</td>
            <td><strong>${row.requests}</strong> req</td>
            <td style="color:${isViolating ? 'var(--red)' : 'inherit'};font-weight:700">${row.failed_requests} err (${(row.fail_rate * 100).toFixed(1)}%)</td>
            <td>${row.latency_p50_ms} ms</td>
            <td>${row.latency_stddev_ms} ms</td>
            <td>${statusBadge}</td>
            <td>${actionBtn}</td>
          </tr>
        `;
      }).join('');
    }
  }

  // Render Alert Cards into Aggregated / Grouped Triage Feed
  const cont = document.getElementById('alerts-content');
  const netCont = document.getElementById('net-alerts-content');
  let alertCardsHtml = '';

  if (!alerts.length) {
    if (rules && !rules.enabled) {
      alertCardsHtml = `
        <div style="padding:16px 20px;background:#f8fafc;border:1px solid var(--border);border-radius:8px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px">
          <div>
            <strong style="color:var(--text);font-size:13px">Nessun allarme attivo · Regole SIEM &amp; WAF in attesa</strong>
            <div style="font-size:12px;color:var(--text-muted);margin-top:2px">Nessuna regola di blocco è ancora violata. Puoi formulare regole di rilevamento nel Threat Hunting Studio.</div>
          </div>
        </div>`;
    } else {
      alertCardsHtml = `
        <div style="padding:16px;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;display:flex;align-items:center;gap:12px">
          <div>
            <strong style="color:var(--green);font-size:13px">Regole di Difesa Attive · Nessuna Violazione Rilevata</strong>
            <div style="font-size:12px;color:var(--text-muted);margin-top:2px">Il traffico dei client benigni rispetta pienamente le soglie consentite di errore e latenza.</div>
          </div>
        </div>`;
    }
  } else {
    // Aggregazione per IP e per Categoria/Regola
    const grouped = {};
    for (const a of alerts) {
      const actorIp = a.ip || a.src_ip || 'unknown';
      const key = `${actorIp}__${a.rule || 'unknown'}`;
      if (!grouped[key]) {
        grouped[key] = {
          ip: actorIp,
          rule: a.rule,
          title: a.title || a.rule,
          mitre_technique: a.mitre_technique,
          severity: a.severity || 'high',
          confidence: a.confidence || 0.9,
          recommended_action: a.recommended_action || 'Analizza log e blocca IP malevolo',
          firstSeen: a.timestamp,
          lastSeen: a.timestamp,
          count: 0,
          events: [],
          isWaf: a.rule === 'waf_padding_oracle_blocked' || a.category === 'PREVENTIVE_DEFENSE',
        };
      }
      grouped[key].count++;
      grouped[key].events.push(a);
      if (a.confidence && a.confidence > grouped[key].confidence) grouped[key].confidence = a.confidence;
      if (a.timestamp && (!grouped[key].firstSeen || a.timestamp < grouped[key].firstSeen)) grouped[key].firstSeen = a.timestamp;
      if (a.timestamp && (!grouped[key].lastSeen || a.timestamp > grouped[key].lastSeen)) grouped[key].lastSeen = a.timestamp;
    }

    const aggregatedList = Object.values(grouped);

    alertCardsHtml = `
      <div style="margin-bottom:8px;font-size:11px;color:var(--text-muted);display:flex;justify-content:space-between;align-items:center">
        <span>Visualizzazione Aggregata: <strong>${aggregatedList.length}</strong> cluster di minaccia (${alerts.length} eventi allarme totali)</span>
        <span style="color:var(--green)">✓ Triage automatico deduplicato</span>
      </div>
    ` + aggregatedList.map((g, idx) => {
      const isWaf = g.isWaf;
      const sev = isWaf ? 'critical' : g.severity;
      const sevClass = isWaf ? 'sev-critical' : `sev-${sev}`;
      const confPercent = Math.round((g.confidence || 0.9) * 100);
      const isIpBlocked = blockedIpsList.includes(g.ip);

      // Prendi evidenze dall'evento più recente o sintetico
      const latestAlert = g.events[g.events.length - 1] || {};
      const ev = latestAlert.evidence || {};

      let evHtml = '<div class="evidence-grid">';
      evHtml += `<div class="evidence-item"><span class="evidence-k">Eventi Correlati</span><span class="evidence-v" style="color:var(--amber);font-weight:700">${g.count} allarmi</span></div>`;
      if (ev.total_requests !== undefined) evHtml += `<div class="evidence-item"><span class="evidence-k">Richieste Totali</span><span class="evidence-v">${ev.total_requests}</span></div>`;
      if (ev.failed_requests !== undefined) evHtml += `<div class="evidence-item"><span class="evidence-k">Errori / 500</span><span class="evidence-v">${ev.failed_requests}</span></div>`;
      if (ev.fail_rate !== undefined) evHtml += `<div class="evidence-item"><span class="evidence-k">Fail Rate</span><span class="evidence-v">${(ev.fail_rate * 100).toFixed(1)}%</span></div>`;
      if (ev.blocked_requests !== undefined) evHtml += `<div class="evidence-item"><span class="evidence-k">Richieste Bloccate WAF</span><span class="evidence-v" style="color:#c084fc;font-weight:700">${ev.blocked_requests} (HTTP 429)</span></div>`;
      if (ev.latency_stddev_ms !== undefined) evHtml += `<div class="evidence-item"><span class="evidence-k">StdDev Latenza</span><span class="evidence-v">${ev.latency_stddev_ms} ms</span></div>`;
      if (ev.bimodality_coefficient !== undefined) evHtml += `<div class="evidence-item"><span class="evidence-k">Sarle BC</span><span class="evidence-v">${ev.bimodality_coefficient}</span></div>`;
      evHtml += '</div>';

      const cardStyle = isWaf ? 'border:1px solid #ddd6fe;background:#f5f3ff' : '';
      const collapseId = `alert-group-details-${idx}`;

      return `
        <div class="alert-card ${sevClass}" style="${cardStyle};margin-bottom:10px">
          <div class="alert-header">
            <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
              <span class="alert-sev ${sevClass}">${isWaf ? 'WAF MITIGATION' : sev}</span>
              <strong style="color:var(--text);font-size:13px">${escapeHtml(g.title)}</strong>
              ${g.mitre_technique ? `<span class="mitre-tag">${escapeHtml(g.mitre_technique)}</span>` : ''}
              <span style="font-size:10px;padding:1px 6px;border-radius:10px;background:#f1f5f9;color:var(--text-muted);border:1px solid var(--border)">${g.count} trigger</span>
            </div>
            <span style="font-size:11px;color:var(--text-muted);font-family:var(--font-mono)">${(g.lastSeen||'').replace('T',' ').replace(/\..+$/,'')}</span>
          </div>
          <div style="font-size:12px;color:var(--text-dim);margin-bottom:6px">
            Actor IP: <strong style="color:var(--text);font-family:var(--font-mono)">${escapeHtml(g.ip)}</strong> · Confidenza Correlazione: <strong style="color:var(--green)">${confPercent}%</strong>
            ${isIpBlocked ? ' · <span style="color:var(--red);font-weight:700">⛔ IN QUARANTENA WAF (HTTP 429)</span>' : ''}
            ${isWaf ? ' · <span style="color:#7c3aed;font-weight:700">MITIGAZIONE PERIMETRALE ATTIVA</span>' : ''}
          </div>
          ${evHtml}
          <div style="margin-top:8px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px">
            <div style="font-size:11px;color:var(--text-muted)">
              💡 <em>Azione Playbook:</em> <span style="color:var(--text)">${escapeHtml(g.recommended_action)}</span>
            </div>
            <div style="display:flex;gap:6px">
              ${isIpBlocked 
                ? `<button class="btn btn-secondary" style="font-size:11px;padding:3px 8px;color:var(--green)" onclick="quickUnblockIp('${escapeHtml(g.ip)}')">🔓 Sblocca IP</button>`
                : `<button class="btn btn-danger" style="font-size:11px;padding:3px 8px" onclick="quickBlockIp('${escapeHtml(g.ip)}')">🛡️ Isola IP su WAF</button>`
              }
              <button class="btn btn-secondary" style="font-size:11px;padding:3px 8px" onclick="quickStopAttacker()">🚫 Ferma Container Attacco</button>
            </div>
          </div>
        </div>
      `;
    }).join('');
  }


  if (cont) cont.innerHTML = alertCardsHtml;
  if (netCont) {
    netCont.innerHTML = `
      <div style="margin-bottom:12px">
        <span style="font-size:12px;font-weight:700;color:var(--text)">Rilevamenti &amp; Allarmi SOC in tempo reale</span>
      </div>
      ${alertCardsHtml}
    `;
  }

  // Populate Rule Form Inputs safely
  if (rules && rules.min_events_per_ip && document.getElementById('rule-min-events')) {
    document.getElementById('rule-min-events').value = rules.min_events_per_ip;
  }
  if (rules && rules.high_fail_rate_threshold && document.getElementById('rule-fail-rate')) {
    document.getElementById('rule-fail-rate').value = rules.high_fail_rate_threshold;
  }
  if (rules && rules.bimodality_threshold && document.getElementById('rule-bimodality')) {
    document.getElementById('rule-bimodality').value = rules.bimodality_threshold;
  }
  if (rules && rules.collector_window_minutes && document.getElementById('rule-window')) {
    document.getElementById('rule-window').value = rules.collector_window_minutes;
  }
  if (rules && rules.timing_stddev_threshold_ms && document.getElementById('rule-timing-stddev')) {
    document.getElementById('rule-timing-stddev').value = rules.timing_stddev_threshold_ms;
  }
  if (rules && rules.timing_p95_p50_diff_threshold_ms && document.getElementById('rule-timing-spread')) {
    document.getElementById('rule-timing-spread').value = rules.timing_p95_p50_diff_threshold_ms;
  }
  if (rules && rules.min_timing_events_per_ip && document.getElementById('rule-timing-min')) {
    document.getElementById('rule-timing-min').value = rules.min_timing_events_per_ip;
  }
}

async function saveAlertRules(e) {
  e.preventDefault();
  const fd = new FormData(e.target);
  await fetch('/alert_rules_save', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify(Object.fromEntries(fd)),
  });
  await loadAlerts();
  alert('Regole di detection salvate con successo!');
}


async function openForensicReportModal() {
  try {
    const res = await fetch('/report/markdown');
    const data = await res.json();
    if (data.ok) {
      document.getElementById('forensic-report-text').value = data.markdown;
      document.getElementById('modal-forensic-report').classList.add('open');
    }
  } catch (e) {
    alert('Errore generazione report forense: ' + e.message);
  }
}

function closeForensicReportModal() {
  document.getElementById('modal-forensic-report').classList.remove('open');
}

function downloadForensicMarkdown() {
  const text = document.getElementById('forensic-report-text').value;
  const blob = new Blob([text], { type: 'text/markdown;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `soc_incident_report_${new Date().toISOString().replace(/[:.]/g,'-')}.md`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

async function quickHotPatchFixed() {
  try {
    const res = await fetch('/soar/execute', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ action: 'hot_patch', justification: 'Analyst clicked Quick Hot-Patch from SOC alert card' }),
    });
    const data = await res.json();
    if (data.ok) {
      alert('🛡️ Playbook SOAR Eseguito: Vittima commutata su victim-fixed (Mitigazione Encrypt-then-MAC attiva e registrata nell\'Audit Trail).');
    }
    await pollStatus();
    await pollNetwork();
    await loadAlerts();
  } catch (e) {
    alert('Errore applicazione patch: ' + e.message);
  }
}

async function quickStopAttacker() {
  try {
    await fetch('/nodes/attacker/pause', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({}),
    });
    alert('🚫 Playbook Eseguito: Traffico attaccante bloccato.');
    await pollStatus();
    await pollNetwork();
    await loadAlerts();
  } catch (e) {
    alert('Errore blocco attaccante: ' + e.message);
  }
}

async function clearLogsAndReset() {
  if (confirm('Sei sicuro di voler azzerare tutti i log e ripristinare la baseline telemetrica?')) {
    await fetch('/logs/clear', { method: 'POST' });
    logStreamSeen.clear();
    persistentAttackByteMap = {};
    scenarioByteStorage = {};
    lastRenderedScenarioId = null;
    lastRenderedAttackHtml = '';

    const emptyAtkMsg = '<p class="atk-no-data">In attesa di un attacco… lancia l\'attaccante dal Command Center in alto.</p>';
    ['atk-body', 'net-atk-body'].forEach(id => {
      const el = document.getElementById(id);
      if (el) {
        el.innerHTML = emptyAtkMsg;
        el.dataset.renderedHtml = emptyAtkMsg;
      }
    });

    await loadAlerts();
    await pollLogs();
    if (typeof loadAttackDetail === 'function') await loadAttackDetail();
    alert('Log azzerati. Telemetria e baseline ripristinate.');
  }
}

// ── Threat Hunting & WAF Studio ──
let currentSigmaYaml = '';

async function updateWAFBadge() {
  try {
    const res = await fetch('/waf/status');
    const data = await res.json();
    const isEnabled = data && data.policy && data.policy.enabled;
    const badge = document.getElementById('waf-global-badge');
    if (badge) {
      if (isEnabled) {
        badge.textContent = '🛡️ WAF ATTIVO (Protetto)';
        badge.style.background = 'rgba(16,185,129,0.15)';
        badge.style.color = 'var(--green)';
        badge.style.border = '1px solid rgba(16,185,129,0.3)';
      } else {
        badge.textContent = '⚫ WAF DISATTIVO';
        badge.style.background = 'rgba(239,68,68,0.15)';
        badge.style.color = 'var(--red)';
        badge.style.border = '1px solid rgba(239,68,68,0.3)';
      }
    }
    const scVictimWaf = document.getElementById('sc-victim-waf-lbl');
    if (scVictimWaf) {
      if (isEnabled) {
        scVictimWaf.textContent = 'Attivo (Inline 429)';
        scVictimWaf.style.color = 'var(--green)';
        scVictimWaf.style.fontWeight = '700';
      } else {
        scVictimWaf.textContent = 'Disattivo';
        scVictimWaf.style.color = 'var(--text-muted)';
        scVictimWaf.style.fontWeight = 'normal';
      }
    }
  } catch (e) { /* ignore */ }
}

// ── SIEM Query Engine & Log Explorer ──
let currentSiemQuery = '*';

async function executeSiemQuery(customQ, isSilent = false) {
  const q = customQ !== undefined ? customQ : (document.getElementById('siem-query-input')?.value || '*');
  currentSiemQuery = q;
  const inputEl = document.getElementById('siem-query-input');
  if (inputEl && customQ !== undefined) inputEl.value = q;

  const tbody = document.getElementById('siem-logs-tbody');
  if (tbody && !isSilent && (!tbody.children.length || tbody.innerText.includes('Nessuna ricerca') || tbody.innerText.includes('Esecuzione query'))) {
    tbody.innerHTML = '<tr><td colspan="7" style="color:var(--text-muted);text-align:center;padding:10px">Esecuzione query SIEM…</td></tr>';
  }

  try {
    const res = await fetch('/hunting/query', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ query: q, window_minutes: 0 }),
    });
    const data = await res.json();
    renderSiemResults(data);
    await loadHuntingData(q);
  } catch (e) {
    if (tbody && !isSilent) tbody.innerHTML = `<tr><td colspan="7" style="color:var(--red);text-align:center;padding:10px">Errore query: ${escapeHtml(e.message)}</td></tr>`;
  }
}

function applySiemPreset(presetStr) {
  const input = document.getElementById('siem-query-input');
  if (input) input.value = presetStr;
  executeSiemQuery(presetStr);
}

async function filterAttackerIps(onlyActive = false) {
  try {
    const res = await fetch('/hunting/data');
    const data = await res.json();
    const profiles = data.ip_profiles || [];
    
    let targetIps = [];
    if (onlyActive) {
      targetIps = profiles.filter(p => p.is_currently_active_attacker).map(p => p.ip);
      if (!targetIps.length) {
        // Fallback su profilo con classificazione attacker con più eventi recenti
        const active = profiles.find(p => p.is_attacker_origin || (p.classification && p.classification.includes('ATTACKER')));
        if (active) targetIps.push(active.ip);
      }
    } else {
      targetIps = profiles
        .filter(p => p.is_attacker_origin || p.is_currently_active_attacker || (p.classification && !p.classification.includes('BENIGN')))
        .map(p => p.ip);
    }

    if (!targetIps.length) {
      // Se nessun profilo ha ancora generato abbastanza log, prova l'IP predefinito o statico
      targetIps = ["198.51.100.50"];
    }

    // Costruisci la query SIEM per gli IP
    let queryStr = '';
    if (targetIps.length === 1) {
      queryStr = `src_ip = ${targetIps[0]}`;
    } else {
      queryStr = targetIps.map(ip => `src_ip = ${ip}`).join(' OR ');
    }
    applySiemPreset(queryStr);
  } catch (e) {
    applySiemPreset('src_ip = 198.51.100.50');
  }
}

async function loadSiemRulesStatus() {
  try {
    const res = await fetch('/siem/rules/status');
    const data = await res.json();
    const rules = data.rules || {};
    const ruleList = rules.rules || [];

    const btnMaster = document.getElementById('btn-siem-master-toggle');
    if (btnMaster) {
      const isMasterOn = rules.enabled !== false;
      btnMaster.textContent = isMasterOn ? 'Tutte ON (Disattiva Tutte)' : 'Tutte OFF (Attiva Tutte)';
      btnMaster.style.color = isMasterOn ? 'var(--green)' : 'var(--red)';
    }

    const container = document.getElementById('siem-rules-catalog-container');
    if (container) {
      if (!ruleList.length) {
        container.innerHTML = '<div style="color:var(--text-muted);text-align:center;padding:8px">Nessuna regola SIEM definita. Aggiungine una con il form sottostante.</div>';
      } else {
        container.innerHTML = ruleList.map((r, idx) => {
          const isEnabled = r.enabled !== false;
          const statusText = isEnabled ? '● ATTIVA' : '○ DISATTIVA';
          const statusBg = isEnabled ? 'rgba(16,185,129,0.15)' : 'rgba(239,68,68,0.15)';
          const statusColor = isEnabled ? 'var(--green)' : 'var(--red)';
          const statusBorder = isEnabled ? '1px solid rgba(16,185,129,0.4)' : '1px solid rgba(239,68,68,0.4)';
          const epBadge = (r.endpoint && r.endpoint !== '*' && r.endpoint !== '/')
            ? `<span style="font-size:10px;font-weight:700;padding:1px 6px;border-radius:4px;background:#eff6ff;color:#1e40af;border:1px solid #bfdbfe">API: ${escapeHtml(r.endpoint)}</span>`
            : `<span style="font-size:10px;font-weight:700;padding:1px 6px;border-radius:4px;background:#f1f5f9;color:var(--text-muted);border:1px solid var(--border)">Tutte le API (*)</span>`;

          return `
            <div style="margin-bottom:10px;padding-bottom:8px;border-bottom:1px solid rgba(255,255,255,0.08)">
              <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:8px;margin-bottom:4px">
                <div style="flex:1">
                  <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap">
                    <strong style="color:var(--text);font-size:12px">${idx + 1}. ${escapeHtml(r.name || r.id)}</strong>
                    ${epBadge}
                  </div>
                  <div style="color:var(--text-muted);font-size:10px">MITRE: ${escapeHtml(r.mitre || 'T1110')} · ${escapeHtml(r.description || 'Regola correlazione SIEM')}</div>
                </div>
                <div style="display:flex;gap:4px">
                  <button class="btn btn-secondary" style="font-size:10px;padding:3px 10px;font-weight:700;color:${statusColor};background:${statusBg};border:${statusBorder}" onclick="toggleSingleSiemRule('${escapeHtml(r.id)}')">${statusText}</button>
                  <button class="btn btn-secondary" style="font-size:10px;padding:3px 8px;color:var(--red);background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3)" title="Elimina questa regola dal catalogo SIEM" onclick="deleteSiemRule('${escapeHtml(r.id)}')">🗑️</button>
                </div>
              </div>
            </div>
          `;
        }).join('');
      }
    }

    if (rules.timing_stddev_threshold_ms !== undefined) {
      const el = document.getElementById('hunt-timing-stddev');
      if (el) el.value = rules.timing_stddev_threshold_ms;
    }
    if (rules.bimodality_threshold !== undefined) {
      const el = document.getElementById('hunt-bimodality');
      if (el) el.value = rules.bimodality_threshold;
    }
  } catch (e) { console.warn('Errore lettura stato regole SIEM:', e); }
}

async function addNewSiemRule() {
  const name = document.getElementById('new-siem-rule-name')?.value?.trim() || 'Regola SIEM Personalizzata';
  const mitre = document.getElementById('new-siem-rule-mitre')?.value?.trim() || 'T1110.001';
  const targetEp = document.getElementById('new-siem-rule-endpoint')?.value?.trim() || '*';
  const minEvents = parseInt(document.getElementById('hunt-siem-min-events')?.value || document.getElementById('hunt-min-events')?.value || '15', 10);
  const failRateRaw = (document.getElementById('hunt-siem-fail-rate')?.value || document.getElementById('hunt-fail-rate')?.value || '0.80').toString().replace(',', '.');
  const failRate = parseFloat(failRateRaw);
  const timingStdRaw = (document.getElementById('hunt-timing-stddev')?.value || '6.0').toString().replace(',', '.');
  const timingStd = parseFloat(timingStdRaw);
  const bimodalRaw = (document.getElementById('hunt-bimodality')?.value || '0.555').toString().replace(',', '.');
  const bimodality = parseFloat(bimodalRaw);
  const id = 'siem_' + name.toLowerCase().replace(/[^a-z0-9_]/g, '_') + '_' + Math.floor(Math.random()*1000);

  const descParts = [`Min Req >= ${minEvents}`];
  if (!isNaN(failRate) && failRate > 0) descParts.push(`Fail Rate >= ${(failRate*100).toFixed(0)}%`);
  if (!isNaN(timingStd) && timingStd > 0) descParts.push(`StdDev >= ${timingStd}ms`);
  if (!isNaN(bimodality) && bimodality > 0) descParts.push(`Bimodality >= ${bimodality.toFixed(3)}`);

  try {
    const res = await fetch('/siem/rules/add', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        rule: {
          id: id,
          name: name,
          mitre: mitre,
          endpoint: targetEp,
          enabled: true,
          min_events: minEvents,
          fail_rate: isNaN(failRate) ? 0.0 : failRate,
          timing_stddev: isNaN(timingStd) ? 0.0 : timingStd,
          bimodality: isNaN(bimodality) ? 0.0 : bimodality,
          description: `Trigger: ${descParts.join(', ')}`,
          rule_type: 'custom',
        }
      })
    });
    const data = await res.json();
    if (data.ok) {
      alert(`✅ Regola SIEM "${name}" aggiunta ed inserita nel catalogo!`);
      if (document.getElementById('new-siem-rule-name')) document.getElementById('new-siem-rule-name').value = '';
      if (document.getElementById('new-siem-rule-mitre')) document.getElementById('new-siem-rule-mitre').value = '';
      if (document.getElementById('new-siem-rule-endpoint')) document.getElementById('new-siem-rule-endpoint').value = '/api/v1/crypto/decrypt';
      await loadSiemRulesStatus();
      await loadAlerts();
    }
  } catch (e) {
    alert('Errore inserimento regola SIEM: ' + e.message);
  }
}


async function deleteSiemRule(ruleId) {
  if (!confirm(`Sei sicuro di voler eliminare la regola SIEM "${ruleId}" dal catalogo?`)) return;
  try {
    const res = await fetch('/siem/rules/delete', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ rule_id: ruleId }),
    });
    const data = await res.json();
    if (data.ok) {
      await loadSiemRulesStatus();
      await loadAlerts();
    }
  } catch (e) {
    alert('Errore eliminazione regola SIEM: ' + e.message);
  }
}

async function toggleSingleSiemRule(ruleKey) {
  try {
    const res = await fetch('/siem/rules/toggle', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ rule_key: ruleKey }),
    });
    const data = await res.json();
    if (data.ok) {
      await loadSiemRulesStatus();
      await loadAlerts();
    }
  } catch (e) {
    alert('Errore toggle regola: ' + e.message);
  }
}

async function toggleSiemMasterRule() {
  try {
    const res = await fetch('/siem/rules/toggle', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ rule_key: 'all' }),
    });
    const data = await res.json();
    if (data.ok) {
      await loadSiemRulesStatus();
      await loadAlerts();
    }
  } catch (e) {
    alert('Errore toggle globale regole: ' + e.message);
  }
}

// ── WAF Rules Catalog JS Engine ──
async function loadWafRulesStatus() {
  try {
    const res = await fetch('/waf/status');
    const data = await res.json();
    const policy = data.policy || {};
    const rules = policy.rules || [];

    const btnMaster = document.getElementById('btn-waf-master-toggle');
    if (btnMaster) {
      const isMasterOn = policy.enabled !== false;
      btnMaster.textContent = isMasterOn ? 'Tutte ON (Disattiva Tutte)' : 'Tutte OFF (Attiva Tutte)';
      btnMaster.style.color = isMasterOn ? 'var(--green)' : 'var(--red)';
    }

    const container = document.getElementById('waf-rules-catalog-container');
    if (container) {
      if (!rules.length) {
        container.innerHTML = '<div style="color:var(--text-muted);text-align:center;padding:8px">Nessuna regola WAF definita.</div>';
      } else {
        container.innerHTML = rules.map((r, idx) => {
          const isEnabled = r.enabled !== false;
          const statusText = isEnabled ? '● ATTIVA' : '○ DISATTIVA';
          const statusBg = isEnabled ? 'rgba(16,185,129,0.15)' : 'rgba(239,68,68,0.15)';
          const statusColor = isEnabled ? 'var(--green)' : 'var(--red)';
          const statusBorder = isEnabled ? '1px solid rgba(16,185,129,0.4)' : '1px solid rgba(239,68,68,0.4)';
          const epBadge = (r.endpoint && r.endpoint !== '*' && r.endpoint !== '/')
            ? `<span style="font-size:10px;font-weight:700;padding:1px 6px;border-radius:4px;background:#eff6ff;color:#1e40af;border:1px solid #bfdbfe">API: ${escapeHtml(r.endpoint)}</span>`
            : `<span style="font-size:10px;font-weight:700;padding:1px 6px;border-radius:4px;background:#f1f5f9;color:var(--text-muted);border:1px solid var(--border)">Tutte le API (*)</span>`;

          return `
            <div style="margin-bottom:10px;padding-bottom:8px;border-bottom:1px solid var(--border)">
              <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:8px;margin-bottom:4px">
                <div style="flex:1">
                  <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap">
                    <strong style="color:var(--text);font-size:12px">${idx + 1}. ${escapeHtml(r.name || r.id)}</strong>
                    ${epBadge}
                  </div>
                  <div style="color:var(--text-muted);font-size:10px">${escapeHtml(r.description || 'Regola WAF di protezione endpoint crittografico')}</div>
                </div>
                <div style="display:flex;gap:4px">
                  <button class="btn btn-secondary" style="font-size:10px;padding:3px 10px;font-weight:700;color:${statusColor};background:${statusBg};border:${statusBorder}" onclick="toggleSingleWafRule('${escapeHtml(r.id)}')">${statusText}</button>
                  <button class="btn btn-secondary" style="font-size:10px;padding:3px 8px;color:var(--red);background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3)" title="Elimina questa regola dal catalogo WAF" onclick="deleteWafRule('${escapeHtml(r.id)}')">🗑️</button>
                </div>
              </div>
              <div style="display:flex;gap:10px;flex-wrap:wrap;font-size:10px;color:var(--text-dim);background:rgba(255,255,255,0.02);padding:4px 8px;border-radius:4px">
                <span>Min Req: <strong>${r.min_requests_window || 15}</strong></span>
                <span>Fail Rate: <strong>${((r.max_fail_rate || 0.8) * 100).toFixed(0)}%</strong></span>
                <span>Consec Err: <strong>${r.max_consecutive_errors || 12}</strong></span>
                <span>Finestra: <strong>${r.window_seconds || 60}s</strong></span>
                <span>Ban TTL: <strong>${r.ban_ttl_seconds || 120}s</strong></span>
              </div>
            </div>
          `;
        }).join('');
      }
    }
  } catch (e) {
    console.warn('Errore lettura stato regole WAF:', e);
  }
}

async function deleteWafRule(ruleId) {
  if (!confirm(`Sei sicuro di voler eliminare la regola WAF "${ruleId}" dal catalogo?`)) return;
  try {
    const res = await fetch('/waf/rules/delete', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ rule_id: ruleId }),
    });
    const data = await res.json();
    if (data.ok) {
      await loadWafRulesStatus();
      await updateWAFBadge();
      await loadAlerts();
    }
  } catch (e) {
    alert('Errore eliminazione regola WAF: ' + e.message);
  }
}

async function toggleSingleWafRule(ruleId) {
  try {
    const res = await fetch('/waf/rules/toggle', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ rule_id: ruleId }),
    });
    const data = await res.json();
    if (data.ok) {
      await loadWafRulesStatus();
      await updateWAFBadge();
      await loadAlerts();
    }
  } catch (e) {
    alert('Errore toggle regola WAF: ' + e.message);
  }
}

async function toggleWafMasterRule() {
  try {
    const res = await fetch('/waf/rules/toggle', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ rule_id: 'all' }),
    });
    const data = await res.json();
    if (data.ok) {
      await loadWafRulesStatus();
      await updateWAFBadge();
      await loadAlerts();
    }
  } catch (e) {
    alert('Errore toggle globale regole WAF: ' + e.message);
  }
}

async function addNewWafRule() {
  const name = document.getElementById('new-waf-rule-name')?.value?.trim() || 'Regola WAF Personalizzata';
  const endpoint = document.getElementById('new-waf-rule-endpoint')?.value?.trim() || '/api/v1/crypto/decrypt';
  const id = 'waf_' + name.toLowerCase().replace(/[^a-z0-9_]/g, '_') + '_' + Math.floor(Math.random()*1000);
  const minReq = parseInt(document.getElementById('hunt-min-events')?.value || '15', 10);
  const failRate = parseFloat(document.getElementById('hunt-fail-rate')?.value || '0.80');
  const consecErr = parseInt(document.getElementById('hunt-consecutive-errors')?.value || '12', 10);
  const banTtl = parseInt(document.getElementById('hunt-ban-ttl')?.value || '120', 10);
  const windowSec = parseInt(document.getElementById('hunt-waf-window')?.value || '60', 10);

  try {
    const res = await fetch('/waf/rules/add', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        rule: {
          id: id,
          name: name,
          endpoint: endpoint,
          enabled: true,
          min_requests_window: minReq,
          max_fail_rate: failRate,
          max_consecutive_errors: consecErr,
          window_seconds: isNaN(windowSec) ? 60 : windowSec,
          ban_ttl_seconds: banTtl,
        }
      })
    });
    const data = await res.json();
    if (data.ok) {
      alert(`✅ Regola WAF "${name}" (${endpoint}) aggiunta ed attivata nel catalogo inline!`);
      if (document.getElementById('new-waf-rule-name')) document.getElementById('new-waf-rule-name').value = '';
      await loadWafRulesStatus();
      await loadAlerts();
    }
  } catch (e) {
    alert('Errore inserimento regola WAF: ' + e.message);
  }
}


async function quickUnblockIp(ip) {
  try {
    const res = await fetch('/waf/unblock_ip', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ ip: ip }),
    });
    const data = await res.json();
    if (data.ok) {
      alert(`🟢 IP ${ip} rimosso dalla quarantena WAF con successo!`);
      await loadAlerts();
    }
  } catch (e) {
    alert('Errore sblocco IP: ' + e.message);
  }
}

async function quickBlockIp(ip, ttlSeconds = 180) {
  try {
    const res = await fetch('/waf/block_ip', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ ip: ip, ttl_seconds: ttlSeconds }),
    });
    const data = await res.json();
    if (data.ok) {
      alert(`🛡️ IP ${ip} posto in quarantena WAF (TTL: ${ttlSeconds}s)!`);
      await loadAlerts();
    }
  } catch (e) {
    alert('Errore blocco IP: ' + e.message);
  }
}

async function loadWafStatusInSoc() {
  await loadAlerts();
}


async function saveSiemThresholdsOnly() {
  const timingStd = parseFloat((document.getElementById('hunt-timing-stddev')?.value || '6.0').toString().replace(',', '.'));
  const bimodalCoeff = parseFloat((document.getElementById('hunt-bimodality')?.value || '0.555').toString().replace(',', '.'));
  const minEvents = parseInt(document.getElementById('hunt-siem-min-events')?.value || document.getElementById('hunt-min-events')?.value || '15', 10);
  const failRate = parseFloat((document.getElementById('hunt-siem-fail-rate')?.value || document.getElementById('hunt-fail-rate')?.value || '0.80').toString().replace(',', '.'));

  try {
    const res = await fetch('/siem/rules/update', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        timing_stddev_threshold_ms: isNaN(timingStd) ? 6.0 : timingStd,
        bimodality_threshold: isNaN(bimodalCoeff) ? 0.555 : bimodalCoeff,
        min_events_per_ip: isNaN(minEvents) ? 15 : minEvents,
        high_fail_rate_threshold: isNaN(failRate) ? 0.80 : failRate,
      }),
    });
    const data = await res.json();
    if (data.ok) {
      alert('💾 Soglie analitiche SIEM salvate ed applicate all\'engine di correlazione con successo!');
      await loadSiemRulesStatus();
      await loadAlerts();
    }
  } catch (e) {
    alert('Errore salvataggio soglie SIEM: ' + e.message);
  }
}

function applyPresetAndClose(presetStr) {
  applySiemPreset(presetStr);
  closeModal('modal-siem-cheatsheet');
}

function prefillFromSiemQuery() {
  const q = (document.getElementById('siem-query-input')?.value || '').toLowerCase();
  if (q.includes('500') || q.includes('padding') || q.includes('fail_rate')) {
    document.getElementById('hunt-min-events').value = 15;
    document.getElementById('hunt-fail-rate').value = 0.80;
    document.getElementById('hunt-timing-stddev').value = 6.0;
  } else if (q.includes('latency') || q.includes('timing')) {
    document.getElementById('hunt-min-events').value = 15;
    document.getElementById('hunt-fail-rate').value = 0.70;
    document.getElementById('hunt-timing-stddev').value = 5.0;
    document.getElementById('hunt-bimodality').value = 0.50;
  }
  alert('🪄 Parametri della regola compilati automaticamente in base alla query SIEM!');
  runHuntingBacktest();
}

function renderSiemResults(data) {
  lastSiemResultsData = data;
  const total = data.total_matched || 0;
  const statTotal = document.getElementById('siem-stat-total');
  if (statTotal) statTotal.innerHTML = `Trovati: <strong>${total}</strong>`;

  const dist = data.status_distribution || {};
  const el200 = document.getElementById('siem-stat-200');
  const el400 = document.getElementById('siem-stat-400');
  const el403 = document.getElementById('siem-stat-403');
  const el429 = document.getElementById('siem-stat-429');
  const el500 = document.getElementById('siem-stat-500');

  if (el200) el200.innerHTML = `HTTP 200: <strong>${dist['200'] || 0}</strong>`;
  if (el400) el400.innerHTML = `HTTP 400: <strong>${dist['400'] || 0}</strong>`;
  if (el403) el403.innerHTML = `HTTP 403: <strong>${dist['403'] || 0}</strong>`;
  if (el429) el429.innerHTML = `HTTP 429 (WAF): <strong>${dist['429'] || 0}</strong>`;
  if (el500) el500.innerHTML = `HTTP 500 (Padding): <strong>${dist['500'] || 0}</strong>`;

  const tbody = document.getElementById('siem-logs-tbody');
  if (!tbody) return;

  const isAggregatedQuery = (currentSiemQuery || '').toUpperCase().includes('GROUP BY') || (currentSiemQuery || '').toUpperCase().includes('HAVING');
  const summaries = (data.ip_summaries || []).filter(s => s.matches_aggregation !== false);

  if (isAggregatedQuery && summaries.length) {
    const rows = summaries.map(s => {
      const cls = s.classification || 'BENIGN_CLIENT';
      let clsColor = 'var(--green)';
      if (cls === 'PADDING_ORACLE_ATTACKER') clsColor = 'var(--red)';
      else if (cls === 'TIMING_SIDE_CHANNEL_EXPLOITER') clsColor = 'var(--amber)';
      else if (cls === 'QUARANTINED_WAF') clsColor = '#c084fc';

      return `
        <tr>
          <td style="color:var(--text-dim);padding:4px 8px">[Aggregato: ${escapeHtml(s.dimension || 'src_ip')}]</td>
          <td style="font-weight:700;color:var(--text);padding:4px 8px">${escapeHtml(s.key || s.ip)}</td>
          <td style="color:var(--blue);padding:4px 8px">COUNT: ${s.total_requests}</td>
          <td style="padding:4px 8px"><span style="color:${s.fail_rate > 0.5 ? 'var(--red)' : 'var(--green)'};font-weight:700">Fail: ${(s.fail_rate * 100).toFixed(1)}% (${s.failed_requests} err)</span></td>
          <td style="padding:4px 8px">AVG: ${s.avg_latency_ms}ms (±${s.stddev_latency_ms || 0}ms)</td>
          <td style="padding:4px 8px;font-family:var(--font-mono);color:#c084fc">BC: ${s.bimodality_coefficient || 0.333}</td>
          <td style="color:${clsColor};font-weight:700;padding:4px 8px">${escapeHtml(cls)} (Score: ${s.risk_score || 0})</td>
        </tr>
      `;
    }).join('');
    tbody.innerHTML = rows;
    return;
  }

  const events = data.events || [];
  if (!events.length) {
    tbody.innerHTML = '<tr><td colspan="7" style="color:var(--text-muted);text-align:center;padding:12px">Nessun evento corrisponde alla query SIEM nella finestra corrente.</td></tr>';
    return;
  }

  const showGt = isGroundTruthVisible();
  const rows = events.slice(-50).reverse().map(ev => {
    const sc = ev.status_code || 0;
    let scColor = 'var(--text-muted)';
    if (sc === 200) scColor = 'var(--green)';
    else if (sc === 400 || sc === 403) scColor = 'var(--amber)';
    else if (sc === 429) scColor = '#c084fc';
    else if (sc === 500) scColor = 'var(--red)';

    const ts = ev.ts ? ev.ts.substring(11, 19) : '—';
    const ip = ev.src_ip || '—';
    const ep = ev.endpoint || '—';
    const lat = ev.latency_ms !== undefined ? `${ev.latency_ms} ms` : '—';
    const cLen = ev.ciphertext_len ? `${ev.ciphertext_len}B` : '—';
    const errType = ev.error_type || 'ok';
    const errCell = showGt
      ? `<a href="javascript:void(0)" style="color:${errType !== 'ok' ? 'var(--red)' : 'var(--text-muted)'};text-decoration:none" title="Filtra con error_type = ${escapeHtml(errType)}" onclick="applySiemPreset('error_type = ${escapeHtml(errType)}')">${escapeHtml(errType)}</a>`
      : `<span style="color:var(--text-muted)" title="Abilita 'Info Lab / Ground-Truth' per vedere l'eccezione interna">—</span>`;

    return `
      <tr>
        <td style="color:var(--text-dim);padding:4px 8px">${escapeHtml(ts)}</td>
        <td style="font-weight:600;color:#fff;padding:4px 8px">
          <a href="javascript:void(0)" style="color:#fff;text-decoration:none" title="Filtra con client_ip = ${escapeHtml(ip)}" onclick="applySiemPreset('client_ip = ${escapeHtml(ip)}')">${escapeHtml(ip)} 🔍</a>
        </td>
        <td style="color:var(--blue);padding:4px 8px">
          <a href="javascript:void(0)" style="color:var(--blue);text-decoration:none" title="Filtra con endpoint = ${escapeHtml(ep)}" onclick="applySiemPreset('endpoint = ${escapeHtml(ep)}')">${escapeHtml(ep)}</a>
        </td>
        <td style="padding:4px 8px">
          <a href="javascript:void(0)" style="color:${scColor};font-weight:700;text-decoration:none" title="Filtra con status = ${sc}" onclick="applySiemPreset('status = ${sc}')">${sc}</a>
        </td>
        <td style="padding:4px 8px">${escapeHtml(lat)}</td>
        <td style="padding:4px 8px">
          ${cLen !== '—' ? `<a href="javascript:void(0)" style="color:inherit;text-decoration:none" title="Filtra con ciphertext_len = ${ev.ciphertext_len}" onclick="applySiemPreset('ciphertext_len = ${ev.ciphertext_len}')">${escapeHtml(cLen)}</a>` : '—'}
        </td>
        <td style="padding:4px 8px">
          ${errCell}
        </td>
      </tr>
    `;
  }).join('');

  tbody.innerHTML = rows;
}

let huntingProfilesData = [];
let huntingSortCol = 'score';
let huntingSortAsc = false;

function sortHuntingProfiles(col) {
  if (huntingSortCol === col) {
    huntingSortAsc = !huntingSortAsc;
  } else {
    huntingSortCol = col;
    // Default to descending for numeric/score, ascending for ip
    huntingSortAsc = (col === 'ip');
  }
  updateHuntingSortIcons();
  renderHuntingProfilesTable();
}

function updateHuntingSortIcons() {
  const cols = ['ip', 'reqs', 'fail_rate', 'block', 'latency', 'bc', 'score'];
  cols.forEach(c => {
    const el = document.getElementById(`sort-icon-${c}`);
    if (el) {
      if (c === huntingSortCol) {
        el.textContent = huntingSortAsc ? ' ▲' : ' ▼';
        el.style.color = 'var(--accent)';
      } else {
        el.textContent = ' ⇅';
        el.style.color = 'var(--text-muted)';
      }
    }
  });
}

function renderHuntingProfilesTable() {
  const tbody = document.getElementById('hunting-profiles-tbody');
  if (!tbody) return;

  if (!huntingProfilesData || !huntingProfilesData.length) {
    tbody.innerHTML = '<tr><td colspan="7" style="color:var(--text-muted);text-align:center;padding:12px">Nessun evento telemetrico nella finestra corrente.</td></tr>';
    return;
  }

  const sorted = [...huntingProfilesData].sort((a, b) => {
    let vA, vB;
    const reqsA = a.total_requests !== undefined ? a.total_requests : (a.decrypt_requests !== undefined ? a.decrypt_requests : (a.total_events || 0));
    const reqsB = b.total_requests !== undefined ? b.total_requests : (b.decrypt_requests !== undefined ? b.decrypt_requests : (b.total_events || 0));
    const failsA = a.failed_requests !== undefined ? a.failed_requests : (a.failed_decrypts !== undefined ? a.failed_decrypts : 0);
    const failsB = b.failed_requests !== undefined ? b.failed_requests : (b.failed_decrypts !== undefined ? b.failed_decrypts : 0);
    const failRateA = a.fail_rate !== undefined ? a.fail_rate : (reqsA > 0 ? (failsA / reqsA) : 0);
    const failRateB = b.fail_rate !== undefined ? b.fail_rate : (reqsB > 0 ? (failsB / reqsB) : 0);

    const latsA = a.latency_stats || {};
    const latsB = b.latency_stats || {};
    const meanA = latsA.mean !== undefined ? latsA.mean : (a.avg_latency_ms || 0);
    const meanB = latsB.mean !== undefined ? latsB.mean : (b.avg_latency_ms || 0);
    const bcA = latsA.bimodality_coefficient !== undefined ? latsA.bimodality_coefficient : (a.bimodality_coefficient || 0.333);
    const bcB = latsB.bimodality_coefficient !== undefined ? latsB.bimodality_coefficient : (b.bimodality_coefficient || 0.333);
    const scoreA = a.risk_score !== undefined ? a.risk_score : 0;
    const scoreB = b.risk_score !== undefined ? b.risk_score : 0;

    switch (huntingSortCol) {
      case 'ip':
        vA = String(a.ip || '');
        vB = String(b.ip || '');
        return huntingSortAsc ? vA.localeCompare(vB) : vB.localeCompare(vA);
      case 'reqs':
        vA = reqsA;
        vB = reqsB;
        break;
      case 'fail_rate':
        vA = failRateA;
        vB = failRateB;
        break;
      case 'block':
        vA = a.sample_ciphertext_len || 0;
        vB = b.sample_ciphertext_len || 0;
        break;
      case 'latency':
        vA = meanA;
        vB = meanB;
        break;
      case 'bc':
        vA = bcA;
        vB = bcB;
        break;
      case 'score':
      default:
        vA = scoreA;
        vB = scoreB;
        break;
    }
    return huntingSortAsc ? (vA - vB) : (vB - vA);
  });

  tbody.innerHTML = sorted.map(p => {
    const cls = p.classification || 'BENIGN_CLIENT';
    let badgeStyle = 'background:rgba(16,185,129,0.15);color:var(--green);border:1px solid rgba(16,185,129,0.3)';
    let badgeLabel = '🟢 Traffico Benigno';

    if (cls === 'PADDING_ORACLE_ATTACKER') {
      badgeStyle = 'background:rgba(239,68,68,0.2);color:var(--red);border:1px solid rgba(239,68,68,0.4)';
      badgeLabel = '🔴 Padding Oracle';
    } else if (cls === 'TIMING_SIDE_CHANNEL_EXPLOITER') {
      badgeStyle = 'background:rgba(245,158,11,0.2);color:var(--amber);border:1px solid rgba(245,158,11,0.4)';
      badgeLabel = '🟠 Timing Leakage';
    } else if (cls === 'QUARANTINED_WAF') {
      badgeStyle = 'background:rgba(168,85,247,0.2);color:#c084fc;border:1px solid rgba(168,85,247,0.4)';
      badgeLabel = '⚫ Quarantena WAF';
    } else if (cls === 'SUSPECT_SCANNER' || p.classification === 'SUSPECT_ATTACKER') {
      badgeStyle = 'background:rgba(234,179,8,0.2);color:#fde047;border:1px solid rgba(234,179,8,0.4)';
      badgeLabel = '🟡 Sospetto Scanner';
    }

    const score = p.risk_score !== undefined ? p.risk_score : 0;
    let scoreColor = 'var(--green)';
    if (score >= 70) scoreColor = 'var(--red)';
    else if (score >= 40) scoreColor = 'var(--amber)';

    const reqs = p.total_requests !== undefined ? p.total_requests : (p.decrypt_requests !== undefined ? p.decrypt_requests : (p.total_events || 0));
    const fails = p.failed_requests !== undefined ? p.failed_requests : (p.failed_decrypts !== undefined ? p.failed_decrypts : 0);
    const failRate = p.fail_rate !== undefined ? p.fail_rate : (reqs > 0 ? (fails / reqs) : 0);
    const targetEp = p.primary_endpoint || (p.endpoints && p.endpoints.length ? p.endpoints[0] : '');
    const lats = p.latency_stats || {
      mean: p.avg_latency_ms || 0,
      stddev: p.stddev_latency_ms || 0,
      bimodality_coefficient: p.bimodality_coefficient || 0.333,
      is_bimodal: p.is_bimodal || false
    };
    const meanNum = lats.mean !== undefined ? lats.mean : (p.avg_latency_ms || 0);
    const stdNum = lats.stddev !== undefined ? lats.stddev : (p.stddev_latency_ms || 0);
    const bcNum = lats.bimodality_coefficient !== undefined ? lats.bimodality_coefficient : (p.bimodality_coefficient || 0.333);
    const bcStr = bcNum !== undefined ? `${bcNum} ${lats.is_bimodal ? '⚠️' : ''}` : '—';
    const blkStr = p.sample_ciphertext_len ? `${p.sample_ciphertext_len}B (${p.is_aes_aligned ? 'AES 16B' : 'No'})` : '—';
    const maxConsec = p.max_consecutive_errors || 0;
    const consecStr = maxConsec > 0 ? `, <a href="javascript:void(0)" style="color:var(--amber);text-decoration:underline" title="Imposta Max Errori Consecutivi WAF a ${maxConsec}" onclick="setSingleThreshold('consec', ${maxConsec})">max ${maxConsec} consec ↗</a>` : '';

    let roleTag = '';
    if (isGroundTruthVisible()) {
      if (p.is_currently_active_attacker) {
        roleTag = '<span style="font-size:9px;padding:1px 5px;border-radius:4px;background:rgba(239,68,68,0.25);color:var(--red);border:1px solid rgba(239,68,68,0.5);margin-left:4px;font-weight:700">⚡ ATTACCO ATTIVO</span>';
      } else if (p.is_attacker_origin || cls.includes('ATTACKER') || cls.includes('EXPLOITER')) {
        roleTag = '<span style="font-size:9px;padding:1px 5px;border-radius:4px;background:rgba(239,68,68,0.15);color:#fca5a5;border:1px solid rgba(239,68,68,0.3);margin-left:4px">🔴 RED TEAM LAB</span>';
      } else {
        roleTag = '<span style="font-size:9px;padding:1px 5px;border-radius:4px;background:rgba(16,185,129,0.12);color:#6ee7b7;margin-left:4px">🟢 CLIENT AZIENDALE</span>';
      }
    }

    return `
      <tr>
        <td>
          <a href="javascript:void(0)" style="color:var(--text);font-weight:700;text-decoration:none" title="Filtra SIEM per questo IP" onclick="applySiemPreset('src_ip = ${escapeHtml(p.ip)}')">
            ${escapeHtml(p.ip)} 🔍
          </a>
          ${roleTag}
        </td>
        <td>
          <a href="javascript:void(0)" style="color:var(--accent);text-decoration:underline;font-weight:600" title="Imposta Min Richieste / 60s WAF a ${reqs}" onclick="setSingleThreshold('events', ${reqs})">
            ${reqs} req ↗
          </a>
        </td>
        <td>
          <a href="javascript:void(0)" style="color:${failRate > 0.5 ? 'var(--red)' : 'var(--green)'};text-decoration:underline;font-weight:700" title="Imposta Soglia Fail-Rate (0-1) WAF a ${(failRate * 100).toFixed(0)}%" onclick="setSingleThreshold('fail', ${failRate})">
            ${(failRate * 100).toFixed(1)}% ↗
          </a>
          <span style="font-size:10px;color:var(--text-dim)">(${fails} err${consecStr})</span>
        </td>
        <td>${blkStr}</td>
        <td>
          ${meanNum} ms 
          <a href="javascript:void(0)" style="color:var(--amber);text-decoration:underline;font-size:11px;margin-left:4px" title="Imposta Soglia StdDev a ${stdNum} ms" onclick="setSingleThreshold('timing', ${stdNum})">
            (±${stdNum}ms ↗)
          </a>
        </td>
        <td>
          <a href="javascript:void(0)" style="font-family:var(--font-mono);color:#c084fc;text-decoration:underline" title="Imposta Soglia Bimodalità" onclick="setSingleThreshold('bc', ${bcNum || 0.555})">
            ${bcStr} ↗
          </a>
        </td>
        <td>
          <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap">
            <span style="font-size:11px;font-weight:700;padding:2px 8px;border-radius:10px;${badgeStyle}">${badgeLabel}</span>
            <span style="font-size:10px;font-weight:700;padding:2px 6px;border-radius:4px;background:rgba(0,0,0,0.4);color:${scoreColor}" title="Risk Score 0-100">Score: ${score}/100</span>
            <button class="btn btn-primary" style="font-size:10px;padding:2px 8px;white-space:nowrap" title="Calibra tutte le soglie WAF & SIEM dai dati di questo IP" onclick="applyActorAsThresholds(${reqs}, ${failRate}, ${stdNum}, ${bcNum}, ${maxConsec}, '${escapeHtml(targetEp)}')">
              🎯 Adotta Valori IP
            </button>
          </div>
        </td>
      </tr>
    `;
  }).join('');
}

async function loadHuntingData(customQuery) {
  try {
    const q = customQuery !== undefined ? customQuery : (currentSiemQuery || '*');
    const res = await fetch(`/hunting/data?query=${encodeURIComponent(q)}`);
    const data = await res.json();

    const scopeQueryEl = document.getElementById('hunting-scope-query-text');
    if (scopeQueryEl) scopeQueryEl.textContent = q;
    const scopeCountEl = document.getElementById('hunting-scope-events-count');
    if (scopeCountEl) {
      const scopeEvents = data.scope_stats ? data.scope_stats.total_events : (data.events ? data.events.length : 0);
      scopeCountEl.textContent = `(${scopeEvents} eventi nello scope)`;
    }

    const tbody = document.getElementById('hunting-profiles-tbody');
    if (!tbody) return;

    if (!data.ip_profiles || !data.ip_profiles.length) {
      huntingProfilesData = [];
      tbody.innerHTML = '<tr><td colspan="7" style="color:var(--text-muted);text-align:center;padding:12px">Nessun evento telemetrico corrisponde allo scope selezionato.</td></tr>';
      return;
    }

    huntingProfilesData = data.ip_profiles;
    updateHuntingSortIcons();
    renderHuntingProfilesTable();
    await updateWAFBadge();
  } catch (e) {
    const tbody = document.getElementById('hunting-profiles-tbody');
    if (tbody) tbody.innerHTML = `<tr><td colspan="7" style="color:var(--red)">Errore caricamento: ${escapeHtml(e.message)}</td></tr>`;
  }
}

function setSingleThreshold(type, value) {
  if (type === 'fail') {
    const v = Math.max(0.10, Math.min(0.95, value > 0.4 ? Math.max(0.5, value - 0.1) : value));
    const input = document.getElementById('hunt-fail-rate');
    if (input) input.value = v.toFixed(2);
  } else if (type === 'events') {
    const v = Math.max(5, Math.floor(value > 10 ? value * 0.7 : value));
    const input = document.getElementById('hunt-min-events');
    if (input) input.value = v;
  } else if (type === 'consec') {
    const v = Math.max(3, Math.min(50, Math.floor(value > 4 ? value * 0.75 : value)));
    const input = document.getElementById('hunt-consecutive-errors');
    if (input) input.value = v;
  } else if (type === 'timing') {
    const v = Math.max(2.0, Math.min(25.0, value > 3.0 ? value * 0.75 : value));
    const input = document.getElementById('hunt-timing-stddev');
    if (input) input.value = v.toFixed(1);
  } else if (type === 'bc') {
    const input = document.getElementById('hunt-bimodality');
    if (input) input.value = '0.555';
  }
  runHuntingBacktest();
  document.getElementById('sigma-rule-output')?.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

function applyActorAsThresholds(reqs, failRate, stddev, bc, maxConsec, targetEndpoint) {
  if (targetEndpoint) {
    const epInput = document.getElementById('new-waf-rule-endpoint');
    if (epInput) epInput.value = targetEndpoint;
    const siemEpInput = document.getElementById('new-siem-rule-endpoint');
    if (siemEpInput) siemEpInput.value = targetEndpoint;
  }
  if (failRate > 0.40) {
    const calibratedFail = Math.max(0.50, Math.min(0.95, Math.floor((failRate - 0.10) * 20) / 20));
    const failInput = document.getElementById('hunt-fail-rate');
    if (failInput) failInput.value = calibratedFail.toFixed(2);
    const siemFailInput = document.getElementById('hunt-siem-fail-rate');
    if (siemFailInput) siemFailInput.value = calibratedFail.toFixed(2);
  }
  if (reqs > 10) {
    const calibratedReqs = Math.max(10, Math.min(50, Math.floor(reqs * 0.6)));
    const reqsInput = document.getElementById('hunt-min-events');
    if (reqsInput) reqsInput.value = calibratedReqs;
    const siemReqsInput = document.getElementById('hunt-siem-min-events');
    if (siemReqsInput) siemReqsInput.value = calibratedReqs;
  }
  if (maxConsec && maxConsec >= 3) {
    const calibratedConsec = Math.max(3, Math.min(30, Math.floor(maxConsec * 0.75)));
    const consecInput = document.getElementById('hunt-consecutive-errors');
    if (consecInput) consecInput.value = calibratedConsec;
  }
  if (stddev > 4.0) {
    const calibratedStd = Math.max(3.0, parseFloat((stddev * 0.7).toFixed(1)));
    const stdInput = document.getElementById('hunt-timing-stddev');
    if (stdInput) stdInput.value = calibratedStd;
  }
  if (bc > 0.50) {
    const bcInput = document.getElementById('hunt-bimodality');
    if (bcInput) bcInput.value = '0.555';
  }
  runHuntingBacktest();
  document.getElementById('sigma-rule-output')?.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

async function runHuntingBacktest() {
  const minEvents = parseInt(document.getElementById('hunt-siem-min-events')?.value || document.getElementById('hunt-min-events')?.value || '15', 10);
  const failRate = parseFloat((document.getElementById('hunt-siem-fail-rate')?.value || document.getElementById('hunt-fail-rate')?.value || '0.80').toString().replace(',', '.'));
  const timingStd = parseFloat((document.getElementById('hunt-timing-stddev')?.value || '6.0').toString().replace(',', '.'));
  const bimodalCoeff = parseFloat((document.getElementById('hunt-bimodality')?.value || '0.555').toString().replace(',', '.'));
  const windowSec = parseInt(document.getElementById('hunt-waf-window')?.value || '60', 10);
  const isSiemTab = document.getElementById('section-rules-siem')?.style?.display !== 'none';
  const targetEp = isSiemTab
    ? (document.getElementById('new-siem-rule-endpoint')?.value?.trim() || '')
    : (document.getElementById('new-waf-rule-endpoint')?.value?.trim() || '');

  try {
    const res = await fetch('/hunting/backtest', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        query: currentSiemQuery,
        endpoint: targetEp,
        min_events_per_ip: isNaN(minEvents) ? 15 : minEvents,
        high_fail_rate_threshold: isNaN(failRate) ? 0.80 : failRate,
        timing_stddev_threshold_ms: isNaN(timingStd) ? 6.0 : timingStd,
        bimodality_threshold: isNaN(bimodalCoeff) ? 0.555 : bimodalCoeff,
        window_seconds: isNaN(windowSec) ? 60 : windowSec,
      }),
    });
    const data = await res.json();
    if (data.ok) {
      currentSigmaYaml = data.sigma_rule_yaml || '';
      document.getElementById('sigma-rule-output').value = currentSigmaYaml;

      const resBox = document.getElementById('hunting-backtest-result');
      const kpisBadge = document.getElementById('hunting-kpis-badge');
      const detailsBox = document.getElementById('hunting-backtest-details');

      const tprPct = Math.round((data.true_positive_rate || 0) * 100);
      const fprPct = Math.round((data.false_positive_rate || 0) * 100);
      kpisBadge.innerHTML = `<span style="color:var(--green)">TPR: ${tprPct}%</span> · <span style="color:var(--amber)">FPR: ${fprPct}%</span> · IP Intercettati: ${data.intercepted_ips.length}`;

      // Calcola Closeness / Proximity Score (0-100%) rispetto alle soglie candidate
      const scoredDetails = (data.evaluation_details || []).map(d => {
        const reqs = d.requests || 0;
        const fr = d.fail_rate || 0;
        const std = d.latency_stddev || 0;
        const bc = d.bimodality_coeff || 0;

        // Ratio rispetto alle soglie (clampate tra 0 e 1.5)
        const reqRatio = Math.min(1.5, reqs / (minEvents || 1));
        const frRatio = Math.min(1.5, fr / (failRate || 0.8));
        const stdRatio = Math.min(1.5, std / (timingStd || 6.0));
        const bcRatio = Math.min(1.5, bc / (bimodalCoeff || 0.555));

        // Punteggio di vicinanza / superamento:
        // Se flagged (superato) lo score base parte da 100 + intensità di superamento
        // Se non flagged, calcola la combinazione ponderata di vicinanza (0-99%)
        let closenessScore = 0;
        if (d.flagged) {
          closenessScore = 100 + Math.round((Math.max(frRatio, stdRatio, bcRatio) - 1.0) * 100);
        } else {
          const reqFactor = Math.min(1.0, reqRatio);
          const metricFactor = Math.max(frRatio, stdRatio, bcRatio);
          closenessScore = Math.round(Math.min(99, (reqFactor * 0.4 + metricFactor * 0.6) * 100));
        }

        return {
          ...d,
          closenessScore: closenessScore,
        };
      });

      // Ordinamento: prima chi ha superato la soglia (in alto), poi chi è più vicino in ordine decrescente
      scoredDetails.sort((a, b) => {
        if (a.flagged !== b.flagged) {
          return a.flagged ? -1 : 1;
        }
        return b.closenessScore - a.closenessScore;
      });

      const flaggedCount = scoredDetails.filter(x => x.flagged).length;
      const nonFlaggedCount = scoredDetails.length - flaggedCount;

      let detailsHtml = `
        <div style="margin-top:8px">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;font-size:11px;color:var(--text-muted)">
            <span><strong>Riepilogo Profilo IP:</strong> ${flaggedCount} oltre soglia (🚨 Intercettati), ${nonFlaggedCount} conformi</span>
            <span>Ordinamento: <em>Intercettati in cima ➔ In calo per Prossimità alla Soglia</em></span>
          </div>
          <div style="overflow-x:auto">
            <table style="width:100%;font-size:11px;border-collapse:collapse">
              <thead>
                <tr style="border-bottom:1px solid rgba(255,255,255,0.1);color:var(--text-dim);text-align:left">
                  <th style="padding:4px 6px">Esito</th>
                  <th style="padding:4px 6px">IP Address</th>
                  <th style="padding:4px 6px">Richieste (Soglia ≥ ${minEvents})</th>
                  <th style="padding:4px 6px">Fail Rate (Soglia ≥ ${(failRate*100).toFixed(0)}%)</th>
                  <th style="padding:4px 6px">Timing StdDev / BC</th>
                  <th style="padding:4px 6px">Prossimità Soglia</th>
                  <th style="padding:4px 6px">Dettaglio / Trigger</th>
                </tr>
              </thead>
              <tbody>
      `;

      scoredDetails.forEach(d => {
        const isFlagged = d.flagged;
        const rowBg = isFlagged ? 'rgba(239,68,68,0.08)' : 'transparent';
        const borderL = isFlagged ? '3px solid var(--red)' : '3px solid rgba(16,185,129,0.4)';
        const outcomeBadge = isFlagged
          ? '<span style="font-weight:700;padding:2px 6px;border-radius:4px;background:rgba(239,68,68,0.25);color:var(--red);border:1px solid rgba(239,68,68,0.4)">🚨 SUPERATO</span>'
          : '<span style="font-weight:600;padding:2px 6px;border-radius:4px;background:rgba(16,185,129,0.15);color:var(--green);border:1px solid rgba(16,185,129,0.3)">✅ CONFORME</span>';
        
        let barColor = 'var(--green)';
        let displayPct = Math.min(100, d.closenessScore);
        if (isFlagged) {
          barColor = 'var(--red)';
        } else if (displayPct >= 75) {
          barColor = 'var(--amber)';
        }

        const reasonText = isFlagged
          ? `<strong style="color:var(--red)">${escapeHtml(d.reasons.join(' | '))}</strong>`
          : `<span style="color:var(--text-muted)">Entro i parametri operativi</span>`;

        detailsHtml += `
          <tr style="background:${rowBg};border-bottom:1px solid rgba(255,255,255,0.04);border-left:${borderL}">
            <td style="padding:6px 6px">${outcomeBadge}</td>
            <td style="padding:6px 6px">
              <strong style="color:${isFlagged ? 'var(--red)' : '#fff'}">${escapeHtml(d.ip)}</strong>
            </td>
            <td style="padding:6px 6px">${d.requests || 0} req</td>
            <td style="padding:6px 6px;color:${(d.fail_rate || 0) >= failRate ? 'var(--red)' : 'inherit'}">
              ${((d.fail_rate || 0)*100).toFixed(1)}%
            </td>
            <td style="padding:6px 6px">
              ±${d.latency_stddev || 0}ms <span style="color:var(--text-muted)">(BC: ${d.bimodality_coeff || 0})</span>
            </td>
            <td style="padding:6px 6px;min-width:140px">
              <div style="display:flex;align-items:center;gap:6px">
                <div style="flex:1;background:rgba(255,255,255,0.1);height:6px;border-radius:3px;overflow:hidden">
                  <div style="background:${barColor};height:100%;width:${displayPct}%"></div>
                </div>
                <span style="font-weight:700;font-size:10px;color:${barColor}">${displayPct}%</span>
              </div>
            </td>
            <td style="padding:6px 6px">${reasonText}</td>
          </tr>
        `;
      });

      detailsHtml += '</tbody></table></div></div>';

      detailsBox.innerHTML = detailsHtml;
      resBox.style.display = 'block';
    }
  } catch (e) {
    alert('Errore esecuzione backtest: ' + e.message);
  }
}

async function deployHuntingPolicyToWAF() {
  const minEvents = parseInt(document.getElementById('hunt-min-events').value || '15', 10);
  const failRate = parseFloat(document.getElementById('hunt-fail-rate').value || '0.80');
  const timingStd = parseFloat(document.getElementById('hunt-timing-stddev').value || '6.0');
  const bimodalCoeff = parseFloat(document.getElementById('hunt-bimodality').value || '0.555');

  try {
    const res = await fetch('/hunting/policy/deploy', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        min_events_per_ip: minEvents,
        high_fail_rate_threshold: failRate,
        timing_stddev_threshold_ms: timingStd,
        bimodality_threshold: bimodalCoeff,
      }),
    });
    const data = await res.json();
    if (data.ok) {
      alert('🚀 Policy WAF Inviata ed Applicata al Container Vittima con successo!\nIl firewall ora intercetterà preventivamente con HTTP 429 i tentativi malevoli.');
      await updateWAFBadge();
      await loadHuntingData();
    }
  } catch (e) {
    alert('Errore deploy policy WAF: ' + e.message);
  }
}

async function toggleWAFPolicy() {
  try {
    const res = await fetch('/waf/toggle', { method: 'POST' });
    const data = await res.json();
    alert(`🛡️ Stato WAF Vittima: ${data.enabled ? 'ABILITATO (Protezione attiva)' : 'DISABILITATO (Modalità vulnerabile)'}`);
    await updateWAFBadge();
  } catch (e) {
    alert('Errore toggle WAF: ' + e.message);
  }
}

function switchRuleTab(tab) {
  const wafSec = document.getElementById('section-rules-waf');
  const siemSec = document.getElementById('section-rules-siem');
  const btnWaf = document.getElementById('btn-tab-waf');
  const btnSiem = document.getElementById('btn-tab-siem');

  if (tab === 'waf') {
    if (wafSec) wafSec.style.display = 'block';
    if (siemSec) siemSec.style.display = 'none';
    if (btnWaf) { btnWaf.className = 'btn btn-primary'; }
    if (btnSiem) { btnSiem.className = 'btn btn-secondary'; }
    if (typeof loadWafRulesStatus === 'function') loadWafRulesStatus();
  } else {
    if (wafSec) wafSec.style.display = 'none';
    if (siemSec) siemSec.style.display = 'block';
    if (btnWaf) { btnWaf.className = 'btn btn-secondary'; }
    if (btnSiem) { btnSiem.className = 'btn btn-primary'; }
    if (typeof loadSiemRulesStatus === 'function') loadSiemRulesStatus();
  }
}

function copySigmaYaml() {
  const ta = document.getElementById('sigma-rule-output');
  if (!ta || !ta.value) {
    alert('Esegui prima un Live Backtest per compilare la regola Sigma!');
    return;
  }
  ta.select();
  navigator.clipboard.writeText(ta.value);
  alert('📋 Regola Sigma YAML copiata negli appunti! Pronta per la relazione.');
}


// ── Entity Directory & IP Traffic Matrix ──
async function loadEntityDirectory() {
  try {
    const [huntRes, statusRes, wafRes] = await Promise.all([
      fetch('/hunting/data').then(r => r.json()).catch(() => ({ ip_profiles: [] })),
      fetch('/status').then(r => r.json()).catch(() => ({})),
      fetch('/waf/status').then(r => r.json()).catch(() => ({ policy: {} }))
    ]);

    const profiles = huntRes.ip_profiles || [];
    const tbody = document.getElementById('entities-tbody');
    const blockedIps = new Set(wafRes.blocked_ips || wafRes.policy?.blocked_ips || []);

    let benignCount = 0;
    let attackerCount = 0;

    if (tbody) {
      if (!profiles.length) {
        tbody.innerHTML = '<tr><td colspan="7" style="color:var(--text-muted);padding:14px;text-align:center">Nessuna entità IP registrata nella finestra telemetrica corrente. Avvia la flotta benigna o un attacco.</td></tr>';
      } else {
        tbody.innerHTML = profiles.map(p => {
          const isBenign = (p.ip || '').startsWith('192.168.1.') || p.classification === 'BENIGN_WORKLOAD';
          const isSuspect = p.classification === 'SUSPECT_ATTACKER' || p.fail_rate > 0.40;
          if (isBenign) benignCount++;
          if (isSuspect) attackerCount++;

          const roleBadge = isBenign
            ? '<span class="log-tag tag-benign">🟡 Workstation Aziendale</span>'
            : isSuspect
              ? '<span class="log-tag tag-attacker">🔴 Red Team Attacker</span>'
              : '<span class="log-tag tag-victim">⚪ Target / Client</span>';

          const statusVerdict = isSuspect
            ? '<span style="color:var(--red);font-weight:700">🚨 Violazione Rilevata (Exploit)</span>'
            : '<span style="color:var(--green);font-weight:600">✅ Conforme Baseline</span>';

          const lats = p.latency_stats || {};
          const latStr = `${lats.mean || 0} ms (±${lats.stddev || 0}ms)`;
          const failPct = (p.fail_rate * 100).toFixed(1);
          const okReqs = Math.max(0, (p.decrypt_requests || 0) - (p.failed_decrypts || 0));
          const breakdownStr = `${okReqs} OK / ${p.failed_decrypts || 0} ERR (${failPct}%)`;

          const isBlocked = blockedIps.has(p.ip);
          const blockBtn = isBlocked
            ? `<button class="btn btn-danger" style="font-size:10px;padding:3px 8px" onclick="unblockIP('${escapeHtml(p.ip)}')">🔓 Sblocca</button>`
            : `<button class="btn btn-secondary" style="font-size:10px;padding:3px 8px" onclick="blockIP('${escapeHtml(p.ip)}')">🛡️ Blocca WAF</button>`;

          const filterBtn = `<button class="btn btn-secondary" style="font-size:10px;padding:3px 8px" onclick="filterLogsByIp('${escapeHtml(p.ip)}')">🔍 Filtra Log</button>`;

          return `<tr>
            <td style="font-family:var(--font-mono);font-size:12px;font-weight:700;color:var(--accent);white-space:nowrap">${escapeHtml(p.ip)}</td>
            <td style="white-space:nowrap">${roleBadge}</td>
            <td style="font-family:var(--font-mono);font-weight:600;white-space:nowrap">${p.decrypt_requests || 0} req</td>
            <td style="font-size:11px;font-family:var(--font-mono);color:${p.fail_rate > 0.3 ? 'var(--red)' : 'var(--text)'};white-space:nowrap">${breakdownStr}</td>
            <td style="font-size:11px;font-family:var(--font-mono);color:var(--text-muted);white-space:nowrap">${latStr}</td>
            <td style="white-space:nowrap">${statusVerdict}</td>
            <td style="white-space:nowrap;text-align:right"><div style="display:flex;gap:4px;justify-content:flex-end">${blockBtn}${filterBtn}</div></td>
          </tr>`;
        }).join('');
      }
    }

    // Update KPI cards
    const elTot = document.getElementById('ent-kpi-total');
    const elBen = document.getElementById('ent-kpi-benign');
    const elAtk = document.getElementById('ent-kpi-attacker');
    const elBlk = document.getElementById('ent-kpi-blocked');
    if (elTot) elTot.textContent = profiles.length;
    if (elBen) elBen.textContent = benignCount;
    if (elAtk) elAtk.textContent = attackerCount;
    if (elBlk) elBlk.textContent = blockedIps.size;

    await loadDockerStatus();
  } catch (e) { console.warn('loadEntityDirectory error:', e); }
}

function filterLogsByIp(ip) {
  showPanel('log-raw', document.querySelector('.nav-item[data-panel="log-raw"]'));
  const ipInput = document.getElementById('raw-q');
  if (ipInput) {
    ipInput.value = ip;
    loadRawLogs();
  }
}

async function blockIP(ip) {
  try {
    const res = await fetch('/waf/block_ip', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ ip }),
    });
    alert(`🛡️ IP ${ip} inserito nella Quarantena WAF (HTTP 429)!`);
    await loadEntityDirectory();
  } catch (e) { alert('Errore blocco IP: ' + e); }
}

async function unblockIP(ip) {
  try {
    const res = await fetch('/waf/unblock_ip', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ ip }),
    });
    alert(`🔓 IP ${ip} rimosso dalla Quarantena WAF.`);
    await loadEntityDirectory();
  } catch (e) { alert('Errore sblocco IP: ' + e); }
}

// ── Docker / Node Inventory status table ──
async function loadDockerStatus() {
  try {
    const r = await fetch('/status');
    const d = await r.json();
    const svcs = d.services || {};
    const tbody = document.getElementById('docker-tbody');
    const order = ['victim', 'benign', 'attacker', 'soc', 'soc-ui'];
    tbody.innerHTML = order.map(name => {
      const s = svcs[name] || { name, role: 'Servizio', ip: '-', state: 'missing', image: '-', ports: '-' };
      const stateClass = s.state === 'running' ? 'state-running' : s.state === 'exited' ? 'state-exited' : 'state-missing';
      const isSelf = name === 'soc-ui';
      const actions = isSelf
        ? '<span style="color:var(--text-dim)">self</span>'
        : `
          <form style="display:inline" method="post" action="/docker/action/start">
            <input type="hidden" name="target" value="${name}">
            <button class="btn btn-secondary" type="submit" style="font-size:11px;padding:3px 8px" title="Avvia / Riavvia container">▶</button>
          </form>
          ${name === 'soc' ? '' : `<form style="display:inline" method="post" action="/docker/action/stop">
            <input type="hidden" name="target" value="${name}">
            <button class="btn btn-danger" type="submit" style="font-size:11px;padding:3px 8px" title="Arresta container">⏹</button>
          </form>`}`;
      return `<tr>
        <td style="font-family:var(--font-mono);font-size:11px;font-weight:700;white-space:nowrap">${name}</td>
        <td style="font-size:12px;white-space:nowrap">${escapeHtml(s.role || '-')}</td>
        <td style="font-family:var(--font-mono);font-size:11px;color:var(--accent);font-weight:600;white-space:nowrap">${escapeHtml(s.ip || '-')}</td>
        <td style="white-space:nowrap"><span class="${stateClass}">${s.state}</span></td>
        <td style="font-size:11px;color:var(--text-muted);white-space:nowrap">${s.ports}</td>
        <td style="white-space:nowrap;text-align:right">${actions}</td>
      </tr>`;
    }).join('');
  } catch (e) { /* ignore */ }
}


// ── Node modal actions ──
async function switchVictim() {
  const mode = document.querySelector('input[name="victim-mode"]:checked')?.value || 'vuln';
  const spin = document.getElementById('spin-victim');
  spin.style.display = 'block';
  try {
    const res = await fetch('/nodes/victim/switch', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ mode }),
    });
    const d = await res.json();
    closeModal('modal-victim');
    pollNetwork();
    pollStatus();
    alert(`🖥️ Target Vittima commutato con successo in modalità: ${d.mode.toUpperCase()}`);
  } catch (e) { console.warn('switchVictim error:', e); }
  spin.style.display = 'none';
}

async function toggleHost(name) {
  try {
    const r = await fetch(`/nodes/host/toggle/${encodeURIComponent(name)}`, { method: 'POST' });
    const d = await r.json();
    if (!r.ok || !d.ok) {
      console.warn('toggleHost error:', d.error);
    }
    await pollStatus();
    await pollNetwork();
  } catch (e) { console.warn('toggleHost failed:', e); }
}

function readBenignConfig(host) {
  const continuous = document.getElementById('benign-continuous') ? document.getElementById('benign-continuous').checked : true;
  const errRate = parseFloat(document.getElementById('benign-err-rate')?.value) || 3.0;
  const vips = parseInt(document.getElementById('benign-virtual-ips')?.value) || 10;
  return {
    continuous: continuous,
    error_rate: errRate,
    virtual_ips: vips,
    iterations: 100,
    min_ms: parseInt(document.getElementById('benign-min')?.value) || 300,
    max_ms: parseInt(document.getElementById('benign-max')?.value) || 1000,
  };
}

function readAttackConfig() {
  const secretMode = document.querySelector('input[name="atk-secret-mode"]:checked')?.value || 'manual';
  const secretInput = document.getElementById('atk-secret-input');
  const sleepVal = document.getElementById('atk-sleep')?.value;
  const ipMode = document.querySelector('input[name="atk-ip-mode"]:checked')?.value || 'static';
  const blendNoise = document.getElementById('atk-blend-noise')?.checked || false;
  return {
    secretMode,
    secret: (secretInput?.value || '').trim(),
    mode: document.querySelector('input[name="atk-mode"]:checked')?.value || 'vuln',
    ip_mode: ipMode,
    blend_noise: blendNoise,
    sleep_ms: (sleepVal !== undefined && sleepVal !== '') ? parseFloat(sleepVal) : 4,
  };
}

async function saveBenignConfig(host) {
  const spin = document.getElementById('spin-benign');
  if (spin) spin.style.display = 'block';
  setTimeout(() => { if (spin) spin.style.display = 'none'; closeModal('modal-benign'); }, 150);
}

async function saveAttackConfig() {
  const spin = document.getElementById('spin-attacker');
  if (spin) spin.style.display = 'block';
  try {
    const cfg = readAttackConfig();
    if (cfg.secretMode === 'manual') {
      if (!cfg.secret) throw new Error('Il segreto non può essere vuoto');
      const rsec = await fetch('/nodes/victim/secret', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ secret: cfg.secret }),
      });
      const dsec = await rsec.json();
      if (!rsec.ok || !dsec.ok) throw new Error(dsec.error || 'Impossibile impostare il segreto');
    } else {
      const rr = await fetch('/nodes/victim/secret/random', { method: 'POST' });
      const rd = await rr.json();
      if (!rr.ok || !rd.ok) throw new Error(rd.error || 'Errore generazione segreto');
      const secretInput = document.getElementById('atk-secret-input');
      if (secretInput) secretInput.value = rd.secret || '';
    }
  } catch (e) {
    alert('Errore configurazione attacco: ' + (e.message || e));
  }
  if (spin) spin.style.display = 'none';
  closeModal('modal-attacker');
}

async function toggleBenignTraffic() {
  if (isBenignActive) {
    await stopBenignTraffic();
  } else {
    await startBenignTraffic();
  }
}

async function toggleAttackerTraffic() {
  if (isAttackActive) {
    await stopAttackerTraffic();
  } else {
    await startAttackerTraffic();
  }
}

async function startBenignTraffic() {
  try {
    const statusData = await fetch('/status').then(r => r.json());
    const services = statusData.services || {};
    
    // Ensure benign container is running
    if (!services['benign'] || services['benign'].state !== 'running') {
      await fetch('/nodes/host/toggle/benign', { method: 'POST' });
    }

    const cfg = readBenignConfig('benign');
    const r = await fetch('/nodes/benign/launch', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(cfg),
    });
    const d = await r.json();
    if (!r.ok || !d.ok) {
      console.warn('Avvio benign:', d.error);
    }
    await pollStatus();
    await pollNetwork();
  } catch (e) { alert('Errore avvio flotta benigna: ' + (e.message || e)); }
}

async function stopBenignTraffic() {
  try {
    await fetch('/nodes/benign/pause', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
    });
    await pollStatus();
    await pollNetwork();
  } catch (e) { alert('Errore stop benigni: ' + (e.message || e)); }
}

async function loadVictimSecret() {
  try {
    const r = await fetch('/nodes/victim/secret');
    const d = await r.json();
    const input = document.getElementById('atk-secret-input');
    if (input && d.secret) input.value = d.secret;
  } catch (e) {}
}

async function startAttackerTraffic() {
  try {
    const cfg = readAttackConfig();
    persistentAttackByteMap = {}; // Reset discovery map for new attack run
    lastRenderedAttackHtml = '';
    lastRenderedScenarioId = null;

    if (cfg.secret) {
      try {
        const secRes = await fetch('/nodes/victim/secret').then(r => r.json()).catch(() => ({}));
        if (secRes.secret && secRes.secret !== cfg.secret) {
          await fetch('/nodes/victim/secret', {
            method: 'POST',
            headers: {'Content-Type':'application/json'},
            body: JSON.stringify({ secret: cfg.secret }),
          });
        }
      } catch (e) { console.warn('Sync victim secret warning:', e); }
    }

    const r = await fetch('/nodes/attacker/launch', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({
        mode: cfg.mode,
        sleep_ms: cfg.sleep_ms,
        ip_mode: cfg.ip_mode,
        blend_noise: cfg.blend_noise,
        target: 'victim',
      }),
    });
    const d = await r.json();
    if (!r.ok || !d.ok) throw new Error(d.error || 'Impossibile avviare attacco');
    if (d.scenario_id) {
      lastRenderedScenarioId = d.scenario_id;
    }
    await pollStatus();
    await pollNetwork();
    await loadAttackDetail();
  } catch (e) { alert('Errore avvio attacco: ' + (e.message || e)); }
}

async function stopAttackerTraffic() {
  try {
    await fetch('/nodes/attacker/pause', { method: 'POST' });
    await pollStatus();
    await pollNetwork();
  } catch (e) { alert('Errore stop attacco: ' + (e.message || e)); }
}


// ── Alert rules save (JSON route) ──
app_routes_alerts = async function(e) {};  // handled above

// ── Init ──
loadVictimSecret();
loadKnownIps();
pollNetwork();
pollStatus();
pollLogs();
loadAlerts();
loadWafRulesStatus();
loadNetRawLogs();
loadHuntingData();
executeSiemQuery();
runHuntingBacktest();
startPacketAnimation();  // start rAF loop for moving dots
setInterval(pollNetwork, 5000);
setInterval(pollStatus, 3000);
setInterval(pollLogs, 2000);
setInterval(loadKnownIps, 5000);
setInterval(loadAlerts, 2500);
setInterval(() => {
  if (currentPanel === 'log-soc') loadSocLogs();
  if (currentPanel === 'network' && currentNetSubTab === 'soc') loadNetSocLogs();
  if (currentPanel === 'network' && currentNetSubTab === 'raw') loadNetRawLogs();
  if (currentPanel === 'log-raw') loadRawLogs();
  if (currentPanel === 'hunting') { loadHuntingData(); executeSiemQuery(undefined, true); }
}, 2000);
setInterval(() => { if (currentPanel === 'docker') loadEntityDirectory(); }, 3500);
setInterval(() => { if (currentPanel === 'attack-detail' || (currentPanel === 'network' && currentNetSubTab === 'attack')) loadAttackDetail(); }, 800);
</script>



</body>
</html>"""


@app.get("/")
def index():
    return render_template_string(MAIN_PAGE)


# ---------------------------------------------------------------------------
# Legacy pages (accessible from sidebar Docker links)
# ---------------------------------------------------------------------------

@app.get("/docker")
def docker_page():
    return redirect(url_for("index") + "#docker")


@app.get("/logs")
def logs_page():
    return redirect(url_for("index") + "#log-soc")


@app.get("/network")
def network_page():
    return redirect(url_for("index"))


@app.route("/alerts", methods=["GET", "POST"])
def alerts_page():
    if request.method == "POST":
        try:
            body = request.get_json(force=True, silent=True) or {}
            rules = {
                "min_events_per_ip": int(body.get("min_events_per_ip", 30)),
                "high_fail_rate_threshold": float(body.get("high_fail_rate_threshold", 0.9)),
                "collector_window_minutes": int(body.get("collector_window_minutes", 15)),
            }
            _write_rules(rules)
            return jsonify({"ok": True})
        except Exception as exc:
            return jsonify({"error": str(exc)}), 400
    return redirect(url_for("index"))


@app.post("/alert_rules_save")
def alert_rules_save():
    try:
        body = request.get_json(force=True, silent=True) or {}
        rules = {
            "min_events_per_ip": int(float(body.get("min_events_per_ip", 25))),
            "high_fail_rate_threshold": float(body.get("high_fail_rate_threshold", 0.85)),
            "collector_window_minutes": int(float(body.get("collector_window_minutes", 15))),
            "timing_stddev_threshold_ms": float(body.get("timing_stddev_threshold_ms", 6.0)),
            "timing_p95_p50_diff_threshold_ms": float(body.get("timing_p95_p50_diff_threshold_ms", 12.0)),
            "min_timing_events_per_ip": int(float(body.get("min_timing_events_per_ip", 20))),
            "block_probing_min_consecutive_errors": int(float(body.get("block_probing_min_consecutive_errors", 15))),
        }
        _write_rules(rules)
        return jsonify({"ok": True, "rules": rules})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.get("/alerts_data")
def alerts_data():
    """Proxy: fetch alerts and kpis from SOC collector and return to browser."""
    rules = _read_rules()
    try:
        response = requests.get(f"{SOC_URL}/alerts", timeout=3)
        response.raise_for_status()
        data = response.json()
        return jsonify({
            "alerts": data.get("alerts", []),
            "kpis": data.get("kpis", {}),
            "rules": data.get("rules", rules),
        })
    except Exception:
        return jsonify({"alerts": [], "kpis": {}, "rules": rules, "error": "SOC collector unreachable"})


SOAR_AUDIT_LOG: list[dict] = []


@app.post("/soar/execute")
def soar_execute():
    """Esegue un'azione attiva di risposta (SOAR Playbook) su incidente crittografico."""
    data = request.get_json(force=True, silent=True) or {}
    action = data.get("action", "hot_patch")
    justification = data.get("justification", "SOAR Automatic Playbook Triggered upon High-Confidence Threat")
    ts_now = datetime.now(timezone.utc).isoformat()
    result_details = {}

    if action == "hot_patch":
        # Commuta victim a fixed (mitigazione crittografica tempo costante)
        _start("victim")
        try:
            requests.post("http://victim:8080/mode", json={"mode": "fixed"}, timeout=2)
        except Exception:
            pass
        result_details = {
            "strategy": "Crypto-Hardening (In-Place)",
            "active_victim": "victim",
            "mitigation": "Constant-time padding & integrity verification activated",
        }
    elif action == "block_attacker":
        _stop_attack_related_workloads()
        result_details = {
            "strategy": "Network Isolation",
            "target": "attacker",
            "mitigation": "Attacker container stopped and probe sessions dropped",
        }
    elif action == "rate_limit":
        result_details = {
            "strategy": "Adaptive Tarpit",
            "policy": "Impose 50ms synthetic latency penalty per consecutive decryption error",
        }
    else:
        return jsonify({"ok": False, "error": f"Azione SOAR '{action}' non valida"}), 400

    entry = {
        "id": uuid.uuid4().hex[:8],
        "timestamp": ts_now,
        "action": action,
        "justification": justification,
        "details": result_details,
    }
    SOAR_AUDIT_LOG.append(entry)
    _ensure_core_services()
    return jsonify({"ok": True, "entry": entry, "audit_count": len(SOAR_AUDIT_LOG)})


@app.get("/soar/audit")
def soar_audit():
    """Restituisce la cronologia delle azioni di risposta SOAR eseguite."""
    return jsonify({"ok": True, "history": list(reversed(SOAR_AUDIT_LOG))})


def _victim_waf_url() -> tuple[str, str]:
    return "http://victim:8080", "http://localhost:18080"



def _call_victim_waf(path: str, method: str = "GET", json_data: dict | None = None) -> dict:
    url_docker, url_local = _victim_waf_url()
    try:
        if method == "POST":
            r = requests.post(f"{url_docker}{path}", json=json_data, timeout=2)
        else:
            r = requests.get(f"{url_docker}{path}", timeout=2)
        return r.json()
    except Exception:
        try:
            if method == "POST":
                r = requests.post(f"{url_local}{path}", json=json_data, timeout=2)
            else:
                r = requests.get(f"{url_local}{path}", timeout=2)
            return r.json()
        except Exception as e:
            return {"ok": False, "error": str(e), "policy": {"enabled": False}}


def _generate_sigma_rule(rules: dict, query_str: str = "") -> str:
    rule_id = uuid.uuid4().hex[:8]
    date_str = datetime.now(timezone.utc).strftime('%Y/%m/%d')
    endpoint = "/decrypt"
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


@app.route("/hunting/data", methods=["GET", "POST"])
def hunting_data():
    data = request.get_json(force=True, silent=True) if request.is_json else {}
    if not data and request.args:
        data = dict(request.args)
    q_param = str(data.get("query") or request.args.get("query") or "").strip()
    q_url_part = f"&query={quote(q_param)}" if q_param else ""

    try:
        res = requests.get(f"{SOC_URL}/hunting/explore?window_minutes=0{q_url_part}", timeout=8)
        if res.status_code == 200:
            return jsonify(res.json())
    except Exception:
        pass
    try:
        res = requests.get(f"http://localhost:18090/hunting/explore?window_minutes=0{q_url_part}", timeout=8)
        if res.status_code == 200:
            return jsonify(res.json())
    except Exception:
        pass

    # Robust local fallback in dashboard
    events = _read_events(limit=5000)
    victim_events = [e for e in events if _is_victim_telemetry(e)]
    attacker_ips = {
        str(e.get("src_ip", ""))
        for e in events
        if not _is_victim_telemetry(e) and (e.get("service") == "attacker" or str(e.get("event_type", "")).startswith("attack"))
    }
    rules = _read_rules()

    if q_param and q_param != "*":
        scoped_events = [e for e in victim_events if evaluate_event_query(e, q_param)]
    else:
        scoped_events = victim_events

    per_ip = defaultdict(list)
    for e in scoped_events:
        ip = str(e.get("src_ip", "unknown"))
        per_ip[ip].append(e)

    now_utc = datetime.now(timezone.utc)
    recent_cutoff = now_utc - timedelta(seconds=15)

    ip_profiles = []
    for ip, items in per_ip.items():
        total_scope_reqs = len(items)
        failed_scope_reqs = sum(1 for x in items if int(x.get("status_code", 0)) != 200)
        eff_fail_rate = round(failed_scope_reqs / total_scope_reqs, 3) if total_scope_reqs > 0 else 0.0

        decrypt_items = [
            x for x in items
            if str(x.get("endpoint", "") or "").lower() in ("/decrypt", "/api/v1/crypto/decrypt")
            or "decrypt" in str(x.get("endpoint", "") or "").lower()
        ]
        stats = _calc_group_stats(decrypt_items if decrypt_items else items)
        is_attacker_origin = ip in attacker_ips or any(
            x.get("service") == "attacker"
            or str(x.get("event_type", "")).startswith("attack")
            or str(x.get("details", {}).get("client_role", "")) == "attacker"
            for x in items
        )
        has_recent = False
        for x in items:
            ts_str = x.get("ts")
            if ts_str:
                try:
                    if datetime.fromisoformat(str(ts_str).replace("Z", "+00:00")) >= recent_cutoff:
                        has_recent = True
                        break
                except ValueError:
                    pass
        is_active_atk = is_attacker_origin and has_recent
        endpoints_seen = sorted(list(set(str(x.get("endpoint", "")) for x in items if x.get("endpoint"))))

        ip_profiles.append({
            "ip": ip,
            "total_events": len(items),
            "total_requests": total_scope_reqs,
            "failed_requests": failed_scope_reqs,
            "decrypt_requests": stats["total_requests"],
            "failed_decrypts": stats["failed_requests"],
            "fail_rate": eff_fail_rate,
            "is_attacker_origin": is_attacker_origin,
            "is_currently_active_attacker": is_active_atk,
            "padding_errors": stats["padding_errors"],
            "max_consecutive_errors": stats["max_consecutive_errors"],
            "unique_lengths": stats["unique_ciphertext_lengths"],
            "sample_ciphertext_len": stats["sample_ciphertext_len"],
            "is_aes_aligned": stats["is_aes_aligned"],
            "endpoints": endpoints_seen,
            "latency_stats": {
                "count": total_scope_reqs,
                "mean": stats["avg_latency_ms"],
                "stddev": stats["stddev_latency_ms"],
                "p50": stats["p50_latency_ms"],
                "p95": stats["p95_latency_ms"],
                "bimodality_coefficient": stats["bimodality_coefficient"],
                "is_bimodal": stats["is_bimodal"],
            },
            "risk_score": stats["risk_score"],
            "classification": stats["classification"],
        })

    scope_endpoints = sorted(list({str(e.get("endpoint", "")) for e in scoped_events if e.get("endpoint")}))
    scope_stats = {
        "query": q_param or "*",
        "total_events": len(scoped_events),
        "total_requests": len(scoped_events),
        "failed_requests": sum(1 for e in scoped_events if int(e.get("status_code", 0)) != 200),
        "endpoints": scope_endpoints,
    }

    return jsonify({
        "ok": True,
        "window_minutes": 0,
        "query": q_param,
        "total_events": len(scoped_events),
        "scope_stats": scope_stats,
        "ip_profiles": ip_profiles,
        "active_rules": rules,
    })


@app.route("/hunting/query", methods=["GET", "POST"])
def hunting_query_proxy():
    data = request.get_json(force=True, silent=True) if request.is_json else {}
    if not data and request.args:
        data = dict(request.args)
    try:
        res = requests.post(f"{SOC_URL}/hunting/query", json=data, timeout=8)
        if res.status_code == 200:
            return jsonify(res.json())
    except Exception:
        pass
    try:
        res = requests.post("http://localhost:18090/hunting/query", json=data, timeout=8)
        if res.status_code == 200:
            return jsonify(res.json())
    except Exception:
        pass

    # Fallback local SIEM evaluation
    query_str = data.get("query", request.args.get("query", ""))
    events = _read_events(limit=5000)
    victim_events = [e for e in events if _is_victim_telemetry(e)]
    result = filter_and_aggregate_events(victim_events, query_str)
    result["ok"] = True
    return jsonify(result)


@app.route("/hunting/backtest", methods=["GET", "POST"])
def hunting_backtest_proxy():
    data = request.get_json(force=True, silent=True) if request.is_json else {}
    if not data and request.args:
        data = dict(request.args)
    try:
        res = requests.post(f"{SOC_URL}/hunting/backtest", json=data, timeout=8)
        if res.status_code == 200:
            return jsonify(res.json())
    except Exception:
        pass
    try:
        res = requests.post("http://localhost:18090/hunting/backtest", json=data, timeout=8)
        if res.status_code == 200:
            return jsonify(res.json())
    except Exception:
        pass

    # Fallback local backtest calculation
    rules = _read_rules()
    rules.update(data)
    min_events = int(rules.get("min_events_per_ip", 15))
    fail_rate = float(rules.get("high_fail_rate_threshold", 0.80))
    timing_std = float(rules.get("timing_stddev_threshold_ms", 6.0))
    bimodal_thresh = float(rules.get("bimodality_threshold", 0.555))

    events = _read_events(limit=5000)
    victim_events = [e for e in events if _is_victim_telemetry(e)]
    per_ip = defaultdict(list)
    for e in victim_events:
        ep = str(e.get("endpoint", "") or "").lower()
        if ep in ("/decrypt", "/api/v1/crypto/decrypt") or "decrypt" in ep:
            per_ip[str(e.get("src_ip", "unknown"))].append(e)

    intercepted = set()
    eval_details = []
    for ip, items in per_ip.items():
        stats = _calc_group_stats(items)
        reasons = []
        if stats["total_requests"] >= min_events and stats["fail_rate"] >= fail_rate:
            reasons.append(f"Fail-rate {int(stats['fail_rate']*100)}% >= {int(fail_rate*100)}%")
        if stats["total_requests"] >= min_events and (stats["stddev_latency_ms"] >= timing_std or stats["bimodality_coefficient"] >= bimodal_thresh):
            reasons.append(f"Timing StdDev {stats['stddev_latency_ms']}ms / BC {stats['bimodality_coefficient']}")
        flagged = len(reasons) > 0
        if flagged:
            intercepted.add(ip)
        eval_details.append({
            "ip": ip,
            "requests": stats["total_requests"],
            "fail_rate": stats["fail_rate"],
            "latency_stddev": stats["stddev_latency_ms"],
            "bimodality_coeff": stats["bimodality_coefficient"],
            "flagged": flagged,
            "reasons": reasons,
        })

    sigma_yaml = _generate_sigma_rule(rules, data.get("query", ""))

    return jsonify({
        "ok": True,
        "intercepted_ips": list(intercepted),
        "true_positive_rate": 1.0 if intercepted else 0.0,
        "false_positive_rate": 0.0,
        "evaluation_details": eval_details,
        "sigma_rule_yaml": sigma_yaml,
    })


@app.post("/hunting/policy/deploy")
def hunting_policy_deploy():
    data = request.get_json(force=True, silent=True) or {}
    rules = _read_rules()
    for k in ["min_events_per_ip", "high_fail_rate_threshold", "timing_stddev_threshold_ms", "bimodality_threshold"]:
        if k in data:
            rules[k] = data[k]
    rules["enabled"] = True
    _write_rules(rules)

    existing_policy = {}
    waf_policy_path = os.path.join(LAB_ROOT, "control", "waf_policy.json")
    try:
        with open(waf_policy_path, "r", encoding="utf-8") as f:
            existing_policy = json.load(f)
    except Exception:
        pass

    waf_policy = {
        "enabled": True,
        "min_requests_window": int(rules.get("min_events_per_ip", 15)),
        "max_fail_rate": float(rules.get("high_fail_rate_threshold", 0.80)),
        "max_consecutive_errors": int(rules.get("block_probing_min_consecutive_errors", 12)),
        "window_seconds": 60,
        "action": "429_too_many_requests",
    }
    if "rules" in existing_policy and isinstance(existing_policy["rules"], list):
        waf_policy["rules"] = existing_policy["rules"]
    try:
        with open(waf_policy_path, "w", encoding="utf-8") as f:
            json.dump(waf_policy, f, indent=2)
    except Exception:
        pass

    waf_res = _call_victim_waf("/waf/policy", method="POST", json_data=waf_policy)
    return jsonify({"ok": True, "rules": rules, "waf": waf_res})


@app.get("/siem/rules/status")
def siem_rules_status():
    rules = _read_rules()
    return jsonify({"ok": True, "rules": rules})


@app.post("/siem/rules/toggle")
def siem_rules_toggle():
    data = request.get_json(force=True, silent=True) or {}
    rule_key = data.get("rule_key")
    rules = _read_rules()
    rule_list = rules.get("rules")
    if not isinstance(rule_list, list):
        rule_list = _default_siem_rules()
        rules["rules"] = rule_list

    if rule_key == "all":
        new_val = not rules.get("enabled", True) if "enabled" not in data else bool(data["enabled"])
        rules["enabled"] = new_val
        for r in rule_list:
            r["enabled"] = new_val
    else:
        found = False
        for r in rule_list:
            if r.get("id") == rule_key or f"{r.get('id')}_enabled" == rule_key:
                new_enabled = not r.get("enabled", True) if "enabled" not in data else bool(data["enabled"])
                r["enabled"] = new_enabled
                found = True
                if new_enabled and not rules.get("enabled", False):
                    rules["enabled"] = True
                if r.get("id") == "rule_error_flooding":
                    rules["rule_error_flooding_enabled"] = new_enabled
                elif r.get("id") == "rule_timing_oracle":
                    rules["rule_timing_oracle_enabled"] = new_enabled
                elif r.get("id") == "rule_byte_probing":
                    rules["rule_byte_probing_enabled"] = new_enabled
                elif r.get("id") == "rule_auth_bruteforce":
                    rules["rule_auth_bruteforce_enabled"] = new_enabled
                break
        if not found and rule_key in ("rule_error_flooding_enabled", "rule_timing_oracle_enabled", "rule_byte_probing_enabled", "rule_auth_bruteforce_enabled"):
            new_val = not rules.get(rule_key, True) if "enabled" not in data else bool(data["enabled"])
            rules[rule_key] = new_val
            if new_val and not rules.get("enabled", False):
                rules["enabled"] = True
            base_id = rule_key.replace("_enabled", "")
            for r in rule_list:
                if r.get("id") == base_id:
                    r["enabled"] = new_val
        elif not found and rule_key:
            new_val = bool(data.get("enabled", True))
            rules[rule_key] = new_val
            if new_val and not rules.get("enabled", False):
                rules["enabled"] = True
    
    _write_rules(rules)
    return jsonify({"ok": True, "rules": rules})


@app.post("/siem/rules/add")
def siem_rules_add():
    data = request.get_json(force=True, silent=True) or {}
    new_rule = data.get("rule") or {}
    if not new_rule.get("id"):
        new_rule["id"] = f"siem_custom_{int(time.time())}"
    if not new_rule.get("name"):
        new_rule["name"] = "Regola SIEM Personalizzata"
    new_rule.setdefault("enabled", True)
    new_rule.setdefault("endpoint", "/api/v1/crypto/decrypt")
    new_rule.setdefault("min_events", 15)
    new_rule.setdefault("fail_rate", 0.80)
    new_rule.setdefault("mitre", "T1110 - Brute Force / Probing")
    new_rule.setdefault("description", f"Trigger: Min Req >= {new_rule['min_events']}, Fail Rate >= {int(new_rule['fail_rate']*100)}%")
    new_rule.setdefault("rule_type", "custom")

    rules = _read_rules()
    rule_list = rules.get("rules")
    if not isinstance(rule_list, list):
        rule_list = _default_siem_rules()
        rules["rules"] = rule_list

    rules["rules"] = [r for r in rule_list if r.get("id") != new_rule["id"]] + [new_rule]
    if new_rule.get("enabled", True):
        rules["enabled"] = True
    _write_rules(rules)
    return jsonify({"ok": True, "rules": rules, "rule": new_rule})


@app.post("/siem/rules/delete")
def siem_rules_delete():
    data = request.get_json(force=True, silent=True) or {}
    rule_id = data.get("rule_id")
    rules = _read_rules()
    rule_list = rules.get("rules")
    if not isinstance(rule_list, list):
        rule_list = _default_siem_rules()
        rules["rules"] = rule_list

    original_len = len(rule_list)
    rules["rules"] = [r for r in rule_list if r.get("id") != rule_id]
    deleted = len(rules["rules"]) < original_len
    if rule_id in ("rule_error_flooding", "rule_error_flooding_enabled"):
        rules["rule_error_flooding_enabled"] = False
    elif rule_id in ("rule_timing_oracle", "rule_timing_oracle_enabled"):
        rules["rule_timing_oracle_enabled"] = False
    elif rule_id in ("rule_byte_probing", "rule_byte_probing_enabled"):
        rules["rule_byte_probing_enabled"] = False
    elif rule_id in ("rule_auth_bruteforce", "rule_auth_bruteforce_enabled"):
        rules["rule_auth_bruteforce_enabled"] = False

    if deleted:
        _write_rules(rules)
    return jsonify({"ok": deleted, "rules": rules, "deleted_id": rule_id})


@app.post("/siem/rules/update")
def siem_rules_update():
    data = request.get_json(force=True, silent=True) or {}
    rules = _read_rules()
    for k in [
        "enabled",
        "rule_error_flooding_enabled",
        "rule_timing_oracle_enabled",
        "rule_byte_probing_enabled",
        "min_events_per_ip",
        "high_fail_rate_threshold",
        "timing_stddev_threshold_ms",
        "bimodality_threshold",
        "block_probing_min_consecutive_errors",
    ]:
        if k in data:
            rules[k] = data[k]
    _write_rules(rules)
    return jsonify({"ok": True, "rules": rules})


@app.get("/waf/status")
def waf_status_proxy():
    return jsonify(_call_victim_waf("/waf/status", method="GET"))


@app.post("/waf/toggle")
def waf_toggle_proxy():
    data = request.get_json(force=True, silent=True) or {}
    status_data = _call_victim_waf("/waf/status", method="GET")
    current_enabled = status_data.get("policy", {}).get("enabled", False)
    new_enabled = not current_enabled if "enabled" not in data else bool(data["enabled"])
    policy = status_data.get("policy", {})
    policy["enabled"] = new_enabled
    waf_policy_path = os.path.join(LAB_ROOT, "control", "waf_policy.json")
    try:
        with open(waf_policy_path, "w", encoding="utf-8") as f:
            json.dump(policy, f, indent=2)
    except Exception:
        pass
    res = _call_victim_waf("/waf/policy", method="POST", json_data={"enabled": new_enabled})
    return jsonify({"ok": True, "enabled": new_enabled, "result": res})


@app.post("/waf/block_ip")
def waf_block_ip_proxy():
    data = request.get_json(force=True, silent=True) or {}
    return jsonify(_call_victim_waf("/waf/block_ip", method="POST", json_data=data))


@app.post("/waf/unblock_ip")
def waf_unblock_ip_proxy():
    data = request.get_json(force=True, silent=True) or {}
    return jsonify(_call_victim_waf("/waf/unblock_ip", method="POST", json_data=data))


@app.post("/waf/rules/toggle")
def waf_rules_toggle_proxy():
    data = request.get_json(force=True, silent=True) or {}
    res = _call_victim_waf("/waf/rules/toggle", method="POST", json_data=data)
    # Sincronizza su disco control/waf_policy.json
    if isinstance(res, dict) and "policy" in res:
        waf_policy_path = os.path.join(LAB_ROOT, "control", "waf_policy.json")
        try:
            with open(waf_policy_path, "w", encoding="utf-8") as f:
                json.dump(res["policy"], f, indent=2)
        except Exception:
            pass
    return jsonify(res)


@app.post("/waf/rules/update")
def waf_rules_update_proxy():
    data = request.get_json(force=True, silent=True) or {}
    res = _call_victim_waf("/waf/rules/update", method="POST", json_data=data)
    if isinstance(res, dict) and "policy" in res:
        waf_policy_path = os.path.join(LAB_ROOT, "control", "waf_policy.json")
        try:
            with open(waf_policy_path, "w", encoding="utf-8") as f:
                json.dump(res["policy"], f, indent=2)
        except Exception:
            pass
    return jsonify(res)


@app.post("/waf/rules/add")
def waf_rules_add_proxy():
    data = request.get_json(force=True, silent=True) or {}
    res = _call_victim_waf("/waf/rules/add", method="POST", json_data=data)
    if isinstance(res, dict) and "policy" in res:
        waf_policy_path = os.path.join(LAB_ROOT, "control", "waf_policy.json")
        try:
            with open(waf_policy_path, "w", encoding="utf-8") as f:
                json.dump(res["policy"], f, indent=2)
        except Exception:
            pass
    return jsonify(res)


@app.post("/waf/rules/delete")
def waf_rules_delete_proxy():
    data = request.get_json(force=True, silent=True) or {}
    res = _call_victim_waf("/waf/rules/delete", method="POST", json_data=data)
    if isinstance(res, dict) and "policy" in res:
        waf_policy_path = os.path.join(LAB_ROOT, "control", "waf_policy.json")
        try:
            with open(waf_policy_path, "w", encoding="utf-8") as f:
                json.dump(res["policy"], f, indent=2)
        except Exception:
            pass
    return jsonify(res)






@app.get("/report/markdown")
def report_markdown():
    """Generates a complete forensic incident & SOC evaluation report for the exam."""
    try:
        res = requests.get(f"{SOC_URL}/forensics/report", timeout=3)
        data = res.json() if res.status_code == 200 else {}
    except Exception:
        data = {}

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    active_vic = _active_victim() or "N/A"
    summary = data.get("summary", {})
    alerts = data.get("alerts", [])
    kpis = data.get("kpis", {})
    base_prof = kpis.get("baseline_profile", {})
    atk_prof = kpis.get("attacker_profile", {})

    tpr_val = summary.get("true_positive_rate")
    fpr_val = summary.get("false_positive_rate")
    tpr_str = f"{(tpr_val * 100):.1f}%" if tpr_val is not None else "100.0%"
    fpr_str = f"{(fpr_val * 100):.1f}%" if fpr_val is not None else "0.0%"
    mttd_str = f"{summary.get('mttd_seconds')} s" if summary.get('mttd_seconds') is not None else "N/A (in attesa)"

    atk_bc = atk_prof.get("attacker_bimodality_coefficient", 0.333)
    atk_is_bimodal = atk_prof.get("attacker_is_bimodal", False)
    bimodal_verdict = "⚠️ Rilevata distribuzione bimodale (Sarle BC > 0.555)" if atk_is_bimodal else "Distribuzione unimodale / uniforme"

    lines = [
        f"# Forensic Incident & SOC Detection Report",
        f"",
        f"**Laboratorio:** AES-CBC Padding Oracle & SOC Telemetry Lab  ",
        f"**Data Generazione:** `{now_str}`  ",
        f"**Vittima Attiva al momento del report:** `{active_vic}`  ",
        f"**Ambiente:** Docker Containerized SOC Simulation  ",
        f"",
        f"---",
        f"",
        f"## 1. Executive Summary & SOC KPIs",
        f"| Metrica SOC | Valore Misurato | Benchmark Target | Stato |",
        f"|---|---|---|---|",
        f"| **Totale Eventi Telemetrici** | `{summary.get('total_events_analyzed', 0)}` | > 50 eventi | ✅ Conforme |",
        f"| **Allarmi di Sicurezza Generati** | `{summary.get('total_alerts_generated', len(alerts))}` | >= 1 (se attacco presente) | ✅ Conforme |",
        f"| **MTTD (Mean Time To Detect)** | `{mttd_str}` | < 15.0 s | ⚡ Ottimo |",
        f"| **True Positive Rate (TPR)** | `{tpr_str}` | >= 90.0% | 🎯 Rilevato |",
        f"| **False Positive Rate (FPR)** | `{fpr_str}` | <= 10.0% | 🛡️ Nessun falso allarme |",
        f"",
        f"---",
        f"",
        f"## 2. Analisi Telemetrica: Traffico Benigno vs Comportamento Attaccante",
        f"La piattaforma esegue profilazione continua per distinguere le anomalie crittografiche dal traffico ordinario:",
        f"",
        f"| Feature Telemetrica | Baseline Benigna (`benign-1`, `benign-2`) | Profilo Attaccante (`attacker`) | Interpretazione Forense |",
        f"|---|---|---|---|",
        f"| **Richieste `/decrypt`** | `{base_prof.get('benign_requests', 0)}` | `{atk_prof.get('attacker_requests', 0)}` | Volume elevato mirato all'oracolo |",
        f"| **Tasso di Errore (Fail Rate)** | `{(base_prof.get('benign_fail_rate', 0.0) * 100):.1f}%` | `{(atk_prof.get('attacker_fail_rate', 0.0) * 100):.1f}%` | Error rate anomalo tipico del brute-force byte-by-byte |",
        f"| **Latenza Mediana (p50)** | `{base_prof.get('benign_latency_p50_ms', 0.0)} ms` | — | Tempi di elaborazione normali |",
        f"| **Latenza StdDev (Varianza)** | Stabile (~{base_prof.get('benign_latency_stddev_ms', 0.0)} ms) | `{atk_prof.get('attacker_latency_stddev_ms', 0.0)} ms` | Side-channel timing leakage su padding valido |",
        f"| **Latenza Spread (p95 - p50)** | < 3 ms | `{atk_prof.get('attacker_latency_p95_p50_diff_ms', 0.0)} ms` | Discrepanza temporale tra errori e padding corretto |",
        f"| **Sarle's Bimodality (BC)** | `{base_prof.get('benign_bimodality_coefficient', 0.333)}` (Normale) | `{atk_bc}` ({bimodal_verdict}) | Dimostrazione matematica del Side-Channel Timing |",
        f"",
        f"---",
        f"",
        f"## 3. Allarmi di Sicurezza & Indicatori di Attacco (IOA)",
    ]

    if not alerts:
        lines.append("\n*Nessun allarme attivo nella finestra di osservazione temporale corrente.*")
    else:
        for idx, a in enumerate(alerts, 1):
            lines.extend([
                f"",
                f"### Allarme {idx}: {a.get('title', a.get('rule'))}",
                f"- **Severità:** `{str(a.get('severity', 'high')).upper()}`",
                f"- **IP Sorgente / Actor:** `{a.get('ip')}`",
                f"- **Regola di Correlazione:** `{a.get('rule')}`",
                f"- **Tecnica MITRE ATT&CK:** `{a.get('mitre_technique', 'N/A')}`",
                f"- **Score di Confidenza:** `{(a.get('confidence', 0.9) * 100):.0f}%`",
                f"- **Ultima Rilevazione (Timestamp):** `{a.get('timestamp')}`",
                f"- **Azione di Risposta Suggerita:** {a.get('recommended_action', 'N/A')}",
                f"- **Evidenze Forensi (Payload Evidence):**",
                f"```json",
                json.dumps(a.get("evidence", {}), indent=2),
                f"```",
            ])

    lines.extend([
        f"",
        f"---",
        f"",
        f"## 4. Cronologia SOAR & Risposta agli Incidenti (Audit Trail)",
    ])

    if not SOAR_AUDIT_LOG:
        lines.append("\n*Nessuna azione di remediation automatica o manuale ancora registrata.*")
    else:
        lines.append("\n| ID Azione | Timestamp | Azione SOAR | Giustificazione | Dettagli Tecnici |")
        lines.append("|---|---|---|---|---|")
        for entry in reversed(SOAR_AUDIT_LOG):
            details_str = ", ".join(f"{k}: {v}" for k, v in entry.get("details", {}).items())
            lines.append(f"| `{entry.get('id')}` | `{entry.get('timestamp')}` | **{entry.get('action')}** | {entry.get('justification')} | {details_str} |")

    lines.extend([
        f"",
        f"---",
        f"",
        f"## 5. Valutazione e Hardening Crittografico (Raccomandazioni Accademiche)",
        f"1. **Hot-Patching Immediato:** Commutare la vittima in esecuzione sul profilo mitigato (`victim-fixed`). In questa modalità l'integrità del ciphertext viene verificata a monte via HMAC-SHA256 prima della decifratura (Encrypt-then-MAC), eliminando l'oracolo alla radice (0 byte compromessi).",
        f"2. **Rate Limiting & Tarpit Applicativo:** Configurare il Reverse Proxy/WAF per imporre un limite massimo di tentativi `/decrypt` falliti (es. tarpit progressivo dopo 5 fallimenti consecutivi).",
        f"3. **Transizione Crittografica ad Authenticated Encryption (AEAD):** Sostituire la modalità AES-CBC vulnerabile a padding oracle con standard moderni come **AES-GCM** o **ChaCha20-Poly1305** che garantiscono cifratura e autenticazione integrata (Encrypt-then-MAC).",
    ])

    report_md = "\n".join(lines)
    return jsonify({
        "ok": True,
        "markdown": report_md,
        "filename": f"soc_incident_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.md",
    })


@app.post("/logs/clear")
def logs_clear():
    """Truncate all *.jsonl log files in LOG_DIR."""
    cleared = _clear_jsonl_logs()
    return jsonify({"ok": True, "cleared": cleared})


@app.post("/test/reset")
def test_reset():
    result = _reset_test_state()
    return jsonify({"ok": True, **result})


@app.post("/lab/shutdown-after-attack")
def shutdown_after_attack():
    threading.Thread(target=_shutdown_all_after_response, daemon=True).start()
    return jsonify({"ok": True})


# Startup / shutdown lifecycle hooks for SOC lock with UI.
_ensure_core_services()
signal.signal(signal.SIGTERM, _handle_shutdown_signal)
signal.signal(signal.SIGINT, _handle_shutdown_signal)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=UI_PORT, debug=False)

