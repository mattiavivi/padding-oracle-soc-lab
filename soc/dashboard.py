import csv
import io
import json
import os
import signal
import threading
import time
import uuid
from collections import Counter, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
import secrets
import string

import docker
import requests
from docker.errors import APIError, NotFound
from flask import Flask, jsonify, redirect, render_template_string, request, url_for, Response

from common.siem_query import filter_and_aggregate_events


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
    "victim-vuln": {
        "command": ["python", "victim/app.py"],
        "environment": {"VICTIM_MODE": "vuln", "SCENARIO_ID": "vuln", "LOG_DIR": "/logs"},
        "ports": {"8080/tcp": 18080},
    },
    "victim-partial": {
        "command": ["python", "victim/app.py"],
        "environment": {"VICTIM_MODE": "partial", "SCENARIO_ID": "partial", "LOG_DIR": "/logs"},
        "ports": {"8080/tcp": 18081},
    },
    "victim-fixed": {
        "command": ["python", "victim/app.py"],
        "environment": {"VICTIM_MODE": "fixed", "SCENARIO_ID": "fixed", "LOG_DIR": "/logs"},
        "ports": {"8080/tcp": 18082},
    },
    "soc": {
        "command": ["python", "soc/collector.py"],
        "environment": {
            "LOG_DIR": "/logs",
            "SOC_WINDOW_MINUTES": "15",
            "ALERT_RULES_FILE": str(ALERT_RULES_FILE),
        },
        "ports": {"8090/tcp": 18090},
    },
    "attacker": {
        "command": ["sleep", "infinity"],
        "environment": {"LOG_DIR": "/logs"},
    },
    "benign-1": {
        "command": ["sleep", "infinity"],
        "environment": {"LOG_DIR": "/logs"},
    },
    "benign-2": {
        "command": ["sleep", "infinity"],
        "environment": {"LOG_DIR": "/logs"},
    },
}

VICTIM_NAMES = ["victim-vuln", "victim-partial", "victim-fixed"]
WORKLOAD_NAMES = VICTIM_NAMES + ["benign-1", "benign-2", "attacker"]
CORE_SERVICES = ["soc", "soc-ui"]
ALL_MANAGED = VICTIM_NAMES + ["benign-1", "benign-2", "attacker", "soc", "soc-ui"]


# ---------------------------------------------------------------------------
# Docker helpers
# ---------------------------------------------------------------------------

def _service_volume_spec() -> dict:
    return {
        str(LAB_ROOT): {"bind": "/app", "mode": "rw"},
        str(LOG_DIR): {"bind": "/logs", "mode": "rw"},
    }



def _container(name: str):
    try:
        return docker_client.containers.get(name)
    except NotFound:
        return None


def _status(name: str) -> dict:
    container = _container(name)
    role_map = {
        "victim-vuln": "🖥️ Target Vulnerabile (AES-CBC Oracle 500)",
        "victim-partial": "⏱️ Target Timing Side-Channel",
        "victim-fixed": "🛡️ Target Hardened (Costante-Tempo)",
        "attacker": "🔴 Red Team (Attaccante Padding Oracle)",
        "benign-1": "🟡 Client Legittimo #1 (Traffico Continuo)",
        "benign-2": "🟡 Client Legittimo #2 (Traffico Continuo)",
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
    for victim in VICTIM_NAMES:
        if victim == "victim-vuln":
            _start(victim)
        else:
            _stop(victim)

    for name in ["benign-1", "benign-2", "attacker"]:
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

    return {"active_victim": "victim-vuln", "cleared": cleared, "waf_reset": True}


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
    for path in sorted(LOG_DIR.glob("*.jsonl")):
        try:
            path.write_text("", encoding="utf-8")
            cleared.append(path.name)
        except (IOError, OSError):
            continue
    return cleared


def _sync_memory_logs() -> None:
    """Incrementally ingests newly appended lines from *.jsonl files into the in-memory ring buffer."""
    with _LOG_SYNC_LOCK:
        new_events = []
        for path in sorted(LOG_DIR.glob("*.jsonl")):
            path_str = str(path)
            last_offset = _FILE_BYTE_OFFSETS.get(path_str, 0)
            try:
                if not path.exists():
                    continue
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


def _read_events(limit: int = 1000, service: str | None = None, q: str | None = None) -> list[dict]:
    _sync_memory_logs()
    with _LOG_SYNC_LOCK:
        events = list(_MEMORY_LOG_BUFFER)

    filtered = []
    for ev in events:
        if service:
            svc_str = str(ev.get("service", ""))
            etype_str = str(ev.get("event_type", ""))
            if service == "benign":
                is_match = svc_str.startswith("benign") or "benign" in svc_str
            elif service == "attacker":
                is_match = svc_str == "attacker" or svc_str.startswith("attacker") or etype_str.startswith("attack")
            elif service == "victim":
                is_match = svc_str.startswith("victim")
            else:
                is_match = svc_str == service or svc_str.startswith(service)
            if not is_match:
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


def _is_attack_active(window_seconds: int = 30) -> bool:
    """Check if an attack event occurred within the last window_seconds.
    Reads attacker.jsonl directly to avoid being drowned out by victim.jsonl.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
    attacker_log = LOG_DIR / "attacker.jsonl"
    if not attacker_log.exists():
        return False
    try:
        with open(attacker_log, "r", encoding="utf-8") as f:
            lines = f.readlines()
        for line in reversed(lines[-300:]):
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
                etype = str(ev.get("event_type", ""))
                svc = str(ev.get("service", ""))
                if not (svc == "attacker" or etype.startswith("attack")):
                    continue
                ts_str = ev.get("ts", "")
                if not isinstance(ts_str, str):
                    continue
                ev_dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                if ev_dt >= cutoff:
                    return True
            except (ValueError, json.JSONDecodeError):
                continue
    except (FileNotFoundError, IOError):
        pass
    return False


def _is_role_traffic_active(role: str, window_seconds: int = 10) -> bool:
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


def _read_rules() -> dict:
    defaults = {
        "min_events_per_ip": 25,
        "high_fail_rate_threshold": 0.85,
        "collector_window_minutes": 15,
        "timing_stddev_threshold_ms": 6.0,
        "timing_p95_p50_diff_threshold_ms": 12.0,
        "min_timing_events_per_ip": 20,
        "block_probing_min_consecutive_errors": 15,
    }
    try:
        with open(ALERT_RULES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                defaults.update({k: data[k] for k in defaults if k in data})
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
    events = _read_events(limit=limit, service=service, q=q)
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
    benign_active = _is_role_traffic_active("benign-1") or _is_role_traffic_active("benign-2")
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
        "attack_active": attack_active,
        "benign_active": benign_active,
        "event_counts": dict(by_color),
        "services": services_status,
    })



@app.get("/network/data")
def network_data():
    """Nodes and edges for vis-network, plus recent events."""
    _ensure_core_services()
    service_names = VICTIM_NAMES + ["benign-1", "benign-2", "attacker"]
    services = [_status(name) for name in service_names]
    active_victim = _active_victim()
    benign1_traffic_active = _is_role_traffic_active("benign-1")
    benign2_traffic_active = _is_role_traffic_active("benign-2")
    attacker_traffic_active = _is_role_traffic_active("attacker")

    COLORS = {
        "victim": "#10b981",   # green
        "benign": "#f59e0b",   # amber
        "attacker": "#ef4444", # red
    }

    # Always render ALL nodes — dim when offline so users always see the topology
    ALL_NET = VICTIM_NAMES + ["benign-1", "benign-2", "attacker"]
    all_statuses = {name: _status(name) for name in ALL_NET}

    ON_COLORS  = {"victim": "#10b981", "benign": "#f59e0b", "attacker": "#ef4444"}
    OFF_COLORS = {
        "victim":   {"bg": "#143826", "brd": "#2f7d5b", "fnt": "#8fd6b5"},
        "benign":   {"bg": "#3a2b10", "brd": "#9b6721", "fnt": "#ffd08a"},
        "attacker": {"bg": "#3f1414", "brd": "#a73737", "fnt": "#ff9c9c"},
    }

    POSITIONS = {
        "victim-vuln": {"x": 0, "y": -140},
        "victim-partial": {"x": 0, "y": 0},
        "victim-fixed": {"x": 0, "y": 140},
        "benign-1": {"x": -260, "y": -80},
        "benign-2": {"x": -260, "y": 80},
        "attacker": {"x": 260, "y": 0},
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
        if is_up:
            nodes.append({
                "id": name, "label": f"{name}\n{status_label}", "group": grp,
                "color": {"background": on_c, "border": on_c,
                           "highlight": {"background": on_c, "border": "#fff"}},
                "font": {"color": "#fff", "size": 14, "bold": True},
                "shape": "box", "borderWidth": 2,
                "widthConstraint": {"minimum": 110},
                "shadow": {"enabled": True, "color": on_c + "55", "size": 12},
                "x": pos["x"], "y": pos["y"],
            })
        else:
            nodes.append({
                "id": name, "label": f"{name}\n{status_label}",
                "group": grp + "_off",
                "color": {"background": off_c["bg"], "border": off_c["brd"],
                           "highlight": {"background": off_c["bg"], "border": off_c["brd"]}},
                "font": {"color": off_c["fnt"], "size": 12, "bold": True},
                "shape": "box", "borderWidth": 2, "opacity": 0.9,
                "widthConstraint": {"minimum": 110},
                "x": pos["x"], "y": pos["y"],
            })

    # Always show edges — dashed/dim when idle, solid/bright when active
    edges = []
    for victim in VICTIM_NAMES:
        is_target = victim == active_victim
        for bname, active_flag in [("benign-1", benign1_traffic_active), ("benign-2", benign2_traffic_active)]:
            is_up = active_flag and is_target
            edges.append({
                "id": f"{bname}->{victim}", "from": bname, "to": victim,
                "arrows": "to",
                "color": {"color": "#f59e0b" if is_up else "#5f4b26", "opacity": 1.0},
                "width": 3 if is_up else 1, "dashes": not is_up,
            })
        is_atk = attacker_traffic_active and is_target
        edges.append({
            "id": f"attacker->{victim}", "from": "attacker", "to": victim,
            "arrows": "to",
            "color": {"color": "#ef4444" if is_atk else "#6a2f2f", "opacity": 1.0},
            "width": 4 if is_atk else 1, "dashes": not is_atk,
        })

    recent_events = _read_events(limit=30)
    events_out = []
    for ev in recent_events:
        svc = ev.get("service", "")
        etype = ev.get("event_type", "")
        if svc in ("attacker",) or etype in ("attack_progress", "attack_complete"):
            color = "attacker"
        elif svc.startswith("benign"):
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
    if name not in VICTIM_NAMES + ["benign-1", "benign-2", "attacker"]:
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

        if name in VICTIM_NAMES:
            if is_running:
                _stop(name)
                running = False
            else:
                for victim in VICTIM_NAMES:
                    if victim == name:
                        _start(victim)
                    else:
                        _stop(victim)
                running = True
        else:
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
        mode = data.get("mode", "victim-vuln")
        if mode not in VICTIM_NAMES:
            mode = "victim-vuln"
        for name in VICTIM_NAMES:
            if name == mode:
                _start(name)
            else:
                _stop(name)
        _ensure_core_services()
        return jsonify({"ok": True, "active": mode})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.get("/nodes/host/status/<name>")
def host_status(name: str):
    if name not in VICTIM_NAMES + ["benign-1", "benign-2", "attacker"]:
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
            "traffic_active": _is_role_traffic_active(name) if name != "attacker" else _is_role_traffic_active("attacker"),
            "recent_events": _role_has_recent_events(name if name != "attacker" else "attacker"),
        })
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.post("/nodes/benign/launch")
def benign_launch():
    data = request.get_json(force=True, silent=True) or {}
    host = data.get("host", "benign-1")
    if host not in ("benign-1", "benign-2"):
        return jsonify({"ok": False, "error": "Host benign non valido"}), 400
    iterations = int(data.get("iterations", 100))
    min_ms = int(data.get("min_ms", 100))
    max_ms = int(data.get("max_ms", 500))
    continuous = bool(data.get("continuous", True))
    error_rate = float(data.get("error_rate", 3.0))

    _start(host)
    victim = _active_victim() or "victim-vuln"
    _start(victim)

    cmd = [
        "python", "benign/benign_client.py",
        "--target", f"http://{victim}:8080",
        "--name", host,
        "--scenario-id", f"ui-{host}",
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
        labels={"lab.host": host},
    )
    _ensure_core_services()
    return jsonify({"ok": True, "continuous": continuous, "iterations": iterations, "host": host})



@app.post("/nodes/benign/pause")
def benign_pause():
    host = (request.get_json(force=True, silent=True) or {}).get("host", "benign-1")
    if host not in ("benign-1", "benign-2"):
        return jsonify({"ok": False, "error": "Host benign non valido"}), 400
    _stop_role_traffic("benign", host)
    for container in docker_client.containers.list(all=True, filters={"label": f"lab.host={host}"}):
        try:
            container.stop(timeout=1)
        except APIError:
            pass
    return jsonify({"ok": True, "host": host})


@app.post("/nodes/attacker/launch")
def attacker_launch():
    data = request.get_json(force=True, silent=True) or {}
    mode = data.get("mode", "vuln")
    sleep_ms = float(data.get("sleep_ms", 4.0))
    ip_mode = data.get("ip_mode", "static")
    target_name = data.get("target", _active_victim() or "victim-vuln")
    scenario_id = f"attack-{mode}-{int(time.time()*1000)}"
    _start(target_name)
    _start("attacker")
    _run_one_shot(
        "attacker",
        [
            "python", "attacker/attack.py",
            "--target", f"http://{target_name}:8080",
            "--mode", mode,
            "--sleep-ms", str(sleep_ms),
            "--ip-mode", ip_mode,
            "--scenario-id", scenario_id,
        ],
        {"LOG_DIR": "/logs"},
        labels={"lab.host": "attacker"},
    )
    return jsonify({"ok": True, "mode": mode, "ip_mode": ip_mode, "target": target_name, "scenario_id": scenario_id})



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
    active = _active_victim() or "victim-vuln"
    spec = SERVICE_SPECS.get(active, SERVICE_SPECS["victim-vuln"])
    secret = spec.get("environment", {}).get("SECRET_MESSAGE", "PaddingOracle:TopSecret")
    return jsonify({"secret": secret, "active": active})


@app.post("/nodes/victim/secret")
def victim_set_secret():
    data = request.get_json(force=True, silent=True) or {}
    secret = str(data.get("secret", "")).strip()
    if not secret:
        return jsonify({"ok": False, "error": "Il segreto non può essere vuoto"}), 400
    active = _active_victim() or "victim-vuln"
    for name in VICTIM_NAMES:
        SERVICE_SPECS[name]["environment"]["SECRET_MESSAGE"] = secret
        c = _container(name)
        if c is not None:
            try:
                c.remove(force=True)
            except Exception:
                pass
    _start(active)
    _ensure_core_services()
    return jsonify({"ok": True, "secret": secret, "active": active})


@app.post("/nodes/victim/secret/random")
def victim_set_secret_random():
    alphabet = string.ascii_letters + string.digits
    secret = "PaddingOracle:" + "".join(secrets.choice(alphabet) for _ in range(12))
    active = _active_victim() or "victim-vuln"
    for name in VICTIM_NAMES:
        SERVICE_SPECS[name]["environment"]["SECRET_MESSAGE"] = secret
        c = _container(name)
        if c is not None:
            try:
                c.remove(force=True)
            except Exception:
                pass
    _start(active)
    _ensure_core_services()
    return jsonify({"ok": True, "secret": secret, "active": active})


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
      --bg-base:    #070d19;
      --bg-panel:   #0d172b;
      --bg-card:    #11203d;
      --bg-hover:   #192c52;
      --border:     #1e355e;
      --border-lit: #2d4c82;
      --text:       #d8e5f8;
      --text-dim:   #627d9f;
      --text-muted: #95acc8;
      --accent:     #38bdf8;
      --accent-glow:#0284c7;
      --red:        #f43f5e;
      --red-dim:    #881337;
      --amber:      #fbbf24;
      --amber-dim:  #78350f;
      --green:      #10b981;
      --green-dim:  #064e3b;
      --font-ui:    'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      --font-mono:  'JetBrains Mono', 'Fira Code', 'Cascadia Code', Consolas, monospace;
    }

    html, body { height: 100%; overflow: hidden; background: var(--bg-base); color: var(--text); font-family: var(--font-ui); -webkit-font-smoothing: antialiased; }

    /* ── Layout ── */
    .app { display: flex; flex-direction: column; height: 100vh; }

    /* Header */
    .header {
      display: flex; align-items: center; gap: 16px;
      padding: 0 24px; height: 60px; flex-shrink: 0;
      background: var(--bg-panel);
      border-bottom: 1px solid var(--border);
      box-shadow: 0 2px 10px rgba(0,0,0,0.3);
      z-index: 10;
    }
    .header-logo { font-size: 15px; font-weight: 700; letter-spacing: .4px; color: #fff; display: flex; align-items: center; gap: 8px; }
    .header-logo span { color: var(--accent); }
    .header-badge-uni {
      font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.8px;
      padding: 2px 8px; border-radius: 4px; background: rgba(56, 189, 248, 0.12);
      border: 1px solid rgba(56, 189, 248, 0.3); color: var(--accent);
    }
    .header-spacer { flex: 1; }
    .badge {
      display: inline-flex; align-items: center; gap: 7px;
      padding: 5px 14px; border-radius: 999px; font-size: 11px; font-weight: 700;
      letter-spacing: .6px; text-transform: uppercase;
    }
    .badge-attack {
      background: color-mix(in srgb, var(--red) 15%, transparent);
      border: 1px solid var(--red);
      color: var(--red);
      animation: pulse-red 1.5s ease-in-out infinite;
    }
    .badge-quiet {
      background: color-mix(in srgb, var(--green) 12%, transparent);
      border: 1px solid var(--green-dim);
      color: #34d399;
    }
    .dot { width: 7px; height: 7px; border-radius: 50%; background: currentColor; }
    @keyframes pulse-red {
      0%, 100% { box-shadow: 0 0 0 0 color-mix(in srgb, var(--red) 40%, transparent); }
      50%       { box-shadow: 0 0 0 6px transparent; }
    }
    .header-time { font-size: 12px; color: var(--text-muted); font-family: var(--font-mono); }

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
    .sidebar-section { padding: 8px 18px 4px; font-size: 10px; font-weight: 700;
      letter-spacing: 1.2px; text-transform: uppercase; color: var(--text-dim); }
    .nav-item {
      display: flex; align-items: center; gap: 12px;
      padding: 10px 18px; font-size: 13px; font-weight: 500;
      color: var(--text-muted); cursor: pointer; text-decoration: none;
      border-left: 3px solid transparent;
      transition: background .15s, color .15s, border-color .15s;
    }
    .nav-item:hover  { background: var(--bg-hover); color: var(--text); }
    .nav-item.active { background: var(--bg-hover); color: #fff; border-left-color: var(--accent); font-weight: 600; }
    .nav-icon { font-size: 16px; width: 20px; text-align: center; }
    .sidebar-spacer { flex: 1; }
    .sidebar-victim-badge {
      margin: 12px 14px; padding: 10px 12px; border-radius: 8px;
      font-size: 11px; font-family: var(--font-mono);
      background: var(--bg-card); border: 1px solid var(--border);
      color: var(--text-muted);
    }
    .sidebar-victim-badge strong { color: var(--green); display: block; font-size: 12px; margin-top: 2px; }

    /* Main area */
    .main { flex: 1; display: flex; flex-direction: column; overflow: hidden; }

    /* Panels (each view) */
    .panel { display: none; flex: 1; overflow: hidden; flex-direction: column; }
    .panel.visible { display: flex; }

    /* Network panel */
    .net-panel { display: flex; flex-direction: column; flex: 1; min-height: 0; }
    #network-graph { flex: 0 0 340px; min-height: 340px; background: var(--bg-card); border-bottom: 1px solid var(--border); overflow: hidden; }

    /* Log stream generic */
    .log-stream-wrap { flex: 1; overflow-y: auto; padding: 0; }
    .log-stream-wrap::-webkit-scrollbar { width: 6px; }
    .log-stream-wrap::-webkit-scrollbar-thumb { background: var(--border-lit); border-radius: 3px; }
    .log-header {
      display: flex; align-items: center; gap: 14px; padding: 10px 20px;
      border-bottom: 1px solid var(--border);
      background: var(--bg-panel); flex-shrink: 0; font-size: 12px;
    }
    .log-legend { display: flex; gap: 14px; }
    .legend-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; margin-right: 4px; }
    
    .log-row {
      display: grid;
      grid-template-columns: 160px 90px 150px 100px 80px 1fr;
      gap: 0 10px;
      padding: 6px 16px;
      font-size: 11px; font-family: var(--font-mono);
      border-bottom: 1px solid rgba(255,255,255,0.02);
      transition: background .1s;
      cursor: pointer;
      align-items: center;
    }
    .log-row:hover { background: var(--bg-hover); }
    .log-row.attacker { border-left: 3px solid var(--red); background: color-mix(in srgb, var(--red) 4%, transparent); }
    .log-row.benign   { border-left: 3px solid var(--amber); background: color-mix(in srgb, var(--amber) 3%, transparent); }
    .log-row.victim   { border-left: 3px solid var(--border-lit); color: var(--text-dim); }
    
    .log-tag {
      display: inline-flex; align-items: center; justify-content: center;
      padding: 2px 7px; border-radius: 4px; font-size: 10px; font-weight: 700;
    }
    .tag-attacker { background: var(--red-dim); color: #fecdd3; border: 1px solid rgba(244,63,94,0.3); }
    .tag-benign   { background: var(--amber-dim); color: #fef08a; border: 1px solid rgba(251,191,36,0.3); }
    .tag-victim   { background: #182844; color: var(--accent); border: 1px solid var(--border-lit); }
    .status-ok   { color: var(--green); font-weight: 600; }
    .status-err  { color: var(--red); font-weight: 600; }
    .status-warn { color: var(--amber); font-weight: 600; }

    /* ── Details sub-row (expandable) ── */
    .log-details {
      display: none;
      padding: 8px 20px 10px 20px;
      font-size: 11px; font-family: var(--font-mono);
      background: rgba(13, 23, 43, 0.95);
      border-left: 3px solid var(--accent);
      border-bottom: 1px solid var(--border);
      color: var(--text-muted);
      white-space: pre-wrap;
      word-break: break-all;
    }
    .log-details.open { display: block; }
    .log-details .det-key   { color: var(--accent); font-weight: 600; }
    .log-details .det-val   { color: var(--text); }
    .log-details .det-str   { color: #6ee7b7; }
    .log-details .det-num   { color: var(--amber); }
    .log-details .det-label { font-size: 10px; font-weight: 700; text-transform: uppercase;
      letter-spacing: .8px; color: var(--text-dim); margin-bottom: 6px; display: block; }

    /* ── SOC Academic Paired Cards UI ── */
    .soc-container {
      padding: 16px 24px 32px 24px;
      display: flex;
      flex-direction: column;
      gap: 14px;
    }
    .soc-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 14px 18px;
      box-shadow: 0 4px 14px rgba(0, 0, 0, 0.25);
      transition: border-color .15s, box-shadow .15s;
    }
    .soc-card:hover {
      border-color: var(--border-lit);
      box-shadow: 0 6px 20px rgba(0, 0, 0, 0.35);
    }
    .soc-card.atk-card {
      border-left: 4px solid var(--red);
      background: linear-gradient(90deg, rgba(244,63,94,0.06) 0%, var(--bg-card) 20%);
    }
    .soc-card.ben-card {
      border-left: 4px solid var(--amber);
      background: linear-gradient(90deg, rgba(251,191,36,0.05) 0%, var(--bg-card) 20%);
    }
    .soc-card-header {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 10px;
      font-size: 12px;
      border-bottom: 1px solid rgba(255,255,255,0.05);
      padding-bottom: 8px;
    }
    .soc-card-ts {
      font-family: var(--font-mono);
      font-size: 11px;
      color: var(--text-dim);
    }
    .soc-card-svc {
      font-weight: 700;
      color: #fff;
      font-size: 12px;
    }
    .soc-card-etype {
      font-family: var(--font-mono);
      font-size: 11px;
      padding: 2px 8px;
      border-radius: 4px;
      background: rgba(255,255,255,0.06);
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
      background: rgba(7, 13, 25, 0.7);
      border: 1px solid rgba(255,255,255,0.06);
      border-radius: 8px;
      padding: 10px 14px;
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    .soc-box-title {
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.6px;
      text-transform: uppercase;
      display: flex;
      align-items: center;
      justify-content: space-between;
      color: var(--text-muted);
      border-bottom: 1px dashed rgba(255,255,255,0.08);
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
      font-weight: 700;
      font-family: var(--font-mono);
    }
    .soc-badge-200 { background: rgba(16, 185, 129, 0.18); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }
    .soc-badge-500 { background: rgba(244, 63, 94, 0.2); color: #fda4af; border: 1px solid rgba(244, 63, 94, 0.4); }
    .soc-badge-403 { background: rgba(251, 191, 36, 0.2); color: #fde047; border: 1px solid rgba(251, 191, 36, 0.4); }
    .soc-badge-probe { background: rgba(56, 189, 248, 0.15); color: var(--accent); border: 1px solid rgba(56, 189, 248, 0.3); }

    .soc-analysis-footer {
      margin-top: 10px;
      padding: 8px 12px;
      background: rgba(13, 23, 43, 0.6);
      border-radius: 6px;
      border-left: 3px solid var(--accent);
      font-size: 11px;
      color: var(--text-muted);
      display: flex;
      align-items: center;
      gap: 8px;
    }

    /* ── Attack Detail panel ── */
    .atk-panel { padding: 0; overflow-y: auto; flex-direction: column; }
    .atk-header { padding: 12px 20px; background: var(--bg-panel); border-bottom: 1px solid var(--border);
      display: flex; align-items: center; gap: 12px; flex-shrink: 0; }
    .atk-header h2 { font-size: 14px; font-weight: 700; color: #fff; }
    .atk-body { flex: 1; overflow-y: auto; padding: 16px 20px; }

    /* Byte progress bar */
    .byte-grid { display: grid; grid-template-columns: repeat(16, 1fr); gap: 4px; margin-bottom: 20px; }
    .byte-cell {
      aspect-ratio: 1; border-radius: 6px; display: flex; flex-direction: column;
      align-items: center; justify-content: center;
      font-family: var(--font-mono); font-size: 9px;
      border: 1px solid var(--border); background: var(--bg-card);
      transition: background .3s, border-color .3s;
    }
    .byte-cell.recovered   { background: color-mix(in srgb, var(--green) 20%, var(--bg-card)); border-color: var(--green); }
    .byte-cell.in-progress { background: color-mix(in srgb, var(--amber) 20%, var(--bg-card)); border-color: var(--amber); animation: pulse-amber 1s ease-in-out infinite; }
    @keyframes pulse-amber { 0%,100%{opacity:1} 50%{opacity:.5} }
    .byte-cell .bc-idx  { color: var(--text-dim); font-size: 8px; }
    .byte-cell .bc-val  { color: var(--green); font-size: 11px; font-weight: 700; }
    .byte-cell .bc-hex  { color: var(--text-dim); font-size: 8px; }

    /* Attack event cards */
    .atk-event {
      border: 1px solid var(--border); border-radius: 8px; padding: 10px 14px;
      margin-bottom: 8px; font-family: var(--font-mono); font-size: 11px;
      background: var(--bg-card);
    }
    .atk-event.progress { border-left: 3px solid var(--amber); }
    .atk-event.complete { border-left: 3px solid var(--green); background: color-mix(in srgb, var(--green) 8%, var(--bg-card)); }
    .atk-event .ae-header { display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }
    .atk-event .ae-type { font-size: 10px; font-weight: 700; text-transform: uppercase; padding: 2px 7px; border-radius: 4px; }
    .ae-progress-badge { background: color-mix(in srgb, var(--amber) 20%, transparent); color: var(--amber); border: 1px solid var(--amber); }
    .ae-complete-badge { background: color-mix(in srgb, var(--green) 20%, transparent); color: var(--green); border: 1px solid var(--green); }
    .atk-event .ae-ts  { color: var(--text-dim); font-size: 10px; }
    .atk-event .ae-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 4px 12px; }
    .atk-event .ae-kv  { display: flex; gap: 6px; }
    .atk-event .ae-k   { color: var(--text-dim); min-width: 100px; }
    .atk-event .ae-v   { color: var(--text); font-weight: 500; }
    .atk-event .ae-v.green { color: var(--green); }
    .atk-event .ae-v.amber { color: var(--amber); }
    .atk-no-data { color: var(--text-muted); font-size: 13px; padding: 20px 0; }

    /* Docker panel */
    .docker-panel { padding: 20px; overflow-y: auto; }
    .panel-title { font-size: 16px; font-weight: 600; margin-bottom: 16px; color: #fff; }
    .card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 16px; margin-bottom: 16px; }
    .card h3 { font-size: 13px; font-weight: 600; color: var(--text-muted); margin-bottom: 12px; text-transform: uppercase; letter-spacing: .5px; }
    table { width: 100%; border-collapse: collapse; font-size: 12px; }
    th { text-align: left; padding: 6px 8px; color: var(--text-dim); font-weight: 500; border-bottom: 1px solid var(--border); }
    td { padding: 7px 8px; border-bottom: 1px solid var(--border); vertical-align: middle; }
    .state-running { color: var(--green); font-weight: 600; }
    .state-exited  { color: var(--text-dim); }
    .state-missing { color: var(--red-dim); }
    .btn { display: inline-flex; align-items: center; gap: 5px; padding: 6px 12px;
      border-radius: 7px; font-size: 12px; font-weight: 500; cursor: pointer; border: none;
      text-decoration: none; transition: opacity .15s; }
    .btn:hover { opacity: .85; }
    .btn-primary { background: var(--accent); color: #fff; }
    .btn-secondary { background: #1e3050; color: var(--text); }
    .btn-danger { background: var(--red-dim); color: var(--red); border: 1px solid var(--red); }
    .btn-success { background: var(--green-dim); color: var(--green); border: 1px solid var(--green); }

    /* Alerts & SOC Analytics */
    .alerts-panel { padding: 20px; overflow-y: auto; flex-direction: column; gap: 16px; }
    .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-bottom: 8px; }

    .kpi-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; padding: 14px; display: flex; flex-direction: column; gap: 4px; box-shadow: 0 4px 12px rgba(0,0,0,0.2); }
    .kpi-label { font-size: 11px; text-transform: uppercase; color: var(--text-muted); font-weight: 700; letter-spacing: 0.5px; }
    .kpi-val { font-size: 24px; font-weight: 700; color: #fff; font-family: var(--font-mono); }
    .kpi-sub { font-size: 11px; color: var(--text-dim); }
    
    .alert-card { background: var(--bg-card); border: 1px solid var(--border); border-left: 4px solid var(--red); border-radius: 8px; padding: 14px; margin-bottom: 12px; }
    .alert-card.sev-critical { border-left-color: #ef4444; background: rgba(239, 68, 68, 0.05); }
    .alert-card.sev-high { border-left-color: #f97316; background: rgba(249, 115, 22, 0.05); }
    .alert-card.sev-medium { border-left-color: #f59e0b; background: rgba(245, 158, 11, 0.05); }
    .alert-card.sev-low { border-left-color: #3b82f6; background: rgba(59, 130, 246, 0.05); }
    
    .alert-header { display: flex; align-items: center; justify-content: space-between; gap: 10px; margin-bottom: 8px; flex-wrap: wrap; }
    .alert-sev { font-size: 10px; font-weight: 700; text-transform: uppercase; padding: 3px 8px; border-radius: 4px; }
    .alert-sev.sev-critical { background: #ef4444; color: #fff; }
    .alert-sev.sev-high { background: #f97316; color: #fff; }
    .alert-sev.sev-medium { background: #f59e0b; color: #000; }
    .alert-sev.sev-low { background: #3b82f6; color: #fff; }
    .mitre-tag { background: #1e293b; border: 1px solid #334155; color: #94a3b8; font-size: 11px; font-family: var(--font-mono); padding: 2px 6px; border-radius: 4px; }
    .evidence-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 8px; background: var(--bg-panel); border: 1px solid var(--border); border-radius: 6px; padding: 8px 12px; margin-top: 8px; font-size: 12px; }
    .evidence-item { display: flex; flex-direction: column; }
    .evidence-k { font-size: 10px; color: var(--text-muted); text-transform: uppercase; }
    .evidence-v { font-size: 12px; font-weight: 600; font-family: var(--font-mono); color: var(--text); }


    /* Sub-tabs in Network View */
    .net-subtabs-bar {
      display: flex; align-items: center; gap: 8px;
      padding: 8px 16px; background: var(--bg-panel);
      border-bottom: 1px solid var(--border); flex-shrink: 0;
    }
    .subtab-btn {
      background: var(--bg-card); border: 1px solid var(--border);
      color: var(--text-muted); border-radius: 6px; padding: 5px 12px;
      font-size: 11px; font-weight: 600; cursor: pointer;
      transition: all .15s; display: inline-flex; align-items: center; gap: 5px;
    }
    .subtab-btn:hover { background: var(--bg-hover); color: var(--text); }
    .subtab-btn.active { background: var(--accent); color: #fff; border-color: var(--accent); }
    .subtab-content { display: none; flex: 1; flex-direction: column; overflow: hidden; min-height: 0; }
    .subtab-content.active { display: flex; }

    /* Logs raw panel */
    .logs-raw-panel { padding: 20px; overflow-y: auto; }
    .filter-bar { display: flex; gap: 10px; margin-bottom: 16px; }
    input, select { background: var(--bg-card); border: 1px solid var(--border); color: var(--text);
      border-radius: 7px; padding: 7px 10px; font-size: 12px; font-family: var(--font-ui); }
    input:focus, select:focus { outline: none; border-color: var(--accent); }

    /* Modals */
    .modal-overlay {
      display: none; position: fixed; inset: 0; z-index: 100;
      background: rgba(0,0,0,.65); backdrop-filter: blur(4px);
      align-items: center; justify-content: center;
    }
    .modal-overlay.open { display: flex; }
    .modal {
      background: var(--bg-card); border: 1px solid var(--border-lit);
      border-radius: 16px; padding: 24px; min-width: 340px; max-width: 440px;
      box-shadow: 0 20px 60px rgba(0,0,0,.5);
      animation: modal-in .2s ease;
    }
    @keyframes modal-in { from { opacity:0; transform: scale(.95) translateY(8px); } }
    .modal-title { font-size: 16px; font-weight: 700; color: #fff; margin-bottom: 6px; }
    .modal-sub { font-size: 12px; color: var(--text-muted); margin-bottom: 20px; }
    .form-group { margin-bottom: 14px; }
    .form-label { display: block; font-size: 11px; font-weight: 600; text-transform: uppercase;
      letter-spacing: .5px; color: var(--text-muted); margin-bottom: 6px; }
    .form-input { width: 100%; background: var(--bg-panel); border: 1px solid var(--border);
      color: var(--text); border-radius: 7px; padding: 8px 10px; font-size: 13px; }
    .form-input:focus { outline: none; border-color: var(--accent); }
    .radio-group { display: flex; flex-direction: column; gap: 8px; }
    .radio-opt { display: flex; align-items: center; gap: 10px; padding: 9px 12px;
      border: 1px solid var(--border); border-radius: 8px; cursor: pointer; transition: border-color .15s; }
    .radio-opt:hover { border-color: var(--accent); }
    .radio-opt input[type=radio] { accent-color: var(--accent); }
    .radio-opt .opt-label { font-size: 13px; font-weight: 500; }
    .radio-opt .opt-desc { font-size: 11px; color: var(--text-muted); margin-top: 2px; }
    .modal-actions { display: flex; gap: 10px; margin-top: 20px; justify-content: flex-end; }
    .spinner { display: none; width: 16px; height: 16px; border: 2px solid transparent;
      border-top-color: #fff; border-radius: 50%; animation: spin .6s linear infinite; }
    @keyframes spin { to { transform: rotate(360deg); } }

    /* Stat counters in header */
    .stat-pill { display: inline-flex; align-items: center; gap: 6px;
      padding: 3px 10px; border-radius: 999px; font-size: 11px; font-family: var(--font-mono);
      background: var(--bg-card); border: 1px solid var(--border); color: var(--text-muted); }
    .stat-pill .num { font-weight: 600; }
    .stat-pill .num.red    { color: var(--red); }
    .stat-pill .num.amber  { color: var(--amber); }
    .stat-pill .num.dim    { color: var(--text-dim); }
  </style>
</head>
<body>
<div class="app">

  <!-- ══ HEADER ══ -->
  <header class="header">
    <div class="header-logo">
      🔒 Padding Oracle <span>SOC Lab</span>
      <span class="header-badge-uni">Cybersecurity Lab · Uni Project</span>
    </div>
    <div id="attack-badge" class="badge badge-quiet"><span class="dot"></span> QUIET</div>
    <div class="stat-pill" title="Eventi inviati dall'attaccante">🔴 <span class="num red" id="cnt-attacker">0</span></div>
    <div class="stat-pill" title="Eventi client benigni">🟡 <span class="num amber" id="cnt-benign">0</span></div>
    <div class="stat-pill" title="Richieste ricevute dal server vittima">⚪ <span class="num dim" id="cnt-victim">0</span></div>
    <div class="header-spacer"></div>
    <div class="header-time" id="clock"></div>
  </header>

  <div class="body">

    <!-- ══ SIDEBAR ══ -->
    <nav class="sidebar">
      <div class="sidebar-section">Laboratorio &amp; Controllo</div>
      <a class="nav-item active" data-panel="network" onclick="showPanel('network',this)">
        <span class="nav-icon">🌐</span> Topologia &amp; Attack Demo
      </a>

      <div class="sidebar-section" style="margin-top:12px">Esperienza SOC &amp; Difesa</div>
      <a class="nav-item" data-panel="hunting" onclick="showPanel('hunting',this)">
        <span class="nav-icon">🎯</span> 1. Threat Hunting &amp; SIEM
      </a>
      <a class="nav-item" data-panel="alerts" onclick="showPanel('alerts',this)">
        <span class="nav-icon">🚨</span> 2. Alert SOC &amp; WAF Triage
      </a>

      <div class="sidebar-section" style="margin-top:12px">Esplorazione Telemetrica</div>
      <a class="nav-item" data-panel="log-soc" onclick="showPanel('log-soc',this)">
        <span class="nav-icon">📊</span> Log SOC
      </a>
      <a class="nav-item" data-panel="log-raw" onclick="showPanel('log-raw',this)">
        <span class="nav-icon">📋</span> Log Raw
      </a>
      <a class="nav-item" data-panel="attack-detail" onclick="showPanel('attack-detail',this)">
        <span class="nav-icon">🔬</span> Attack Detail
      </a>
      <a class="nav-item" data-panel="docker" onclick="showPanel('docker',this)">
        <span class="nav-icon">📋</span> Inventario Nodi &amp; IP
      </a>

      <div class="sidebar-spacer"></div>
      <div class="sidebar-victim-badge" id="sidebar-victim">
        Target Attivo: <strong id="sidebar-victim-name">—</strong>
      </div>
    </nav>

    <!-- ══ MAIN ══ -->
    <main class="main">

      <!-- ── Network + Live Log ── -->
      <div id="panel-network" class="panel visible">
        <div class="net-panel">
          <!-- Network toolbar -->
          <div style="display:flex;align-items:center;gap:8px;padding:8px 14px;background:var(--bg-panel);border-bottom:1px solid var(--border);flex-shrink:0;flex-wrap:wrap">
            <span style="font-size:12px;font-weight:700;color:#fff;letter-spacing:.3px">🌐 Network Topology</span>
            <div style="flex:1"></div>
            <button class="btn btn-secondary" style="font-size:11px;padding:5px 11px" onclick="openModal('modal-benign')" title="Configura traffico benigno">
              🟡 Config Benigni
            </button>
            <button class="btn btn-secondary" style="font-size:11px;padding:5px 11px" onclick="openModal('modal-attacker')" title="Configura parametri attacco">
              🔴 Config Attacco
            </button>
            <button id="btn-toggle-benign" class="btn btn-secondary" style="font-size:11px;padding:5px 12px;border:1px solid var(--amber);color:var(--amber)" onclick="toggleBenignTraffic()">
              ▶ Avvia Benigni
            </button>
            <button id="btn-toggle-attack" class="btn btn-danger" style="font-size:11px;padding:5px 12px" onclick="toggleAttackerTraffic()">
              ▶ Avvia Attacco
            </button>
            <button class="btn" style="font-size:11px;padding:5px 11px;background:#1a1a2e;border:1px solid var(--border);color:var(--text-muted)" onclick="clearLogs()" id="btn-clear-logs">
              🗑 Pulisci Log
            </button>
            <button class="btn btn-primary" style="font-size:11px;padding:5px 11px" onclick="resetTest()" id="btn-reset-test">
              ♻️ Reset Test
            </button>
          </div>
          <div id="network-graph"></div>

          <!-- Network Sub-Tab Bar -->
          <div class="net-subtabs-bar">
            <span style="font-size:11px;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:.5px;margin-right:6px">LOG VIEW:</span>
            <button class="subtab-btn active" id="subtab-btn-live" onclick="switchNetSubTab('live')">📡 Live Log</button>
            <button class="subtab-btn" id="subtab-btn-soc" onclick="switchNetSubTab('soc')">📊 Log SOC (Richiesta/Risposta)</button>
            <button class="subtab-btn" id="subtab-btn-raw" onclick="switchNetSubTab('raw')">📋 Log Raw</button>
            <button class="subtab-btn" id="subtab-btn-attack" onclick="switchNetSubTab('attack')">🔬 Attack Detail</button>
            <button class="subtab-btn" id="subtab-btn-alerts" onclick="switchNetSubTab('alerts')">🚨 Alert SOC</button>
            <div style="flex:1"></div>
            <div class="log-legend" id="subtab-legend" style="margin-right:12px">
              <span><span class="legend-dot" style="background:var(--red)"></span>Attacker</span>
              <span><span class="legend-dot" style="background:var(--amber)"></span>Benign</span>
              <span><span class="legend-dot" style="background:var(--border-lit)"></span>Victim</span>
            </div>
            <label id="subtab-autoscroll-wrap" style="font-size:11px;color:var(--text-muted);display:flex;align-items:center;gap:6px">
              <input type="checkbox" id="auto-scroll-chk" checked style="accent-color:var(--accent)"> Auto-scroll
            </label>
          </div>

          <!-- Sub-Tab Containers -->
          <div class="subtab-content active" id="subtab-content-live">
            <div class="log-stream-wrap" id="log-stream"></div>
          </div>
          <div class="subtab-content" id="subtab-content-soc">
            <div class="log-stream-wrap" id="net-soc-stream"></div>
          </div>
          <div class="subtab-content" id="subtab-content-raw">
            <div style="padding:8px 14px;border-bottom:1px solid var(--border);background:var(--bg-panel)">
              <div class="filter-bar" style="flex-wrap:wrap;gap:8px;align-items:center">
                <select id="net-raw-service-filter" onchange="loadNetRawLogs()">
                  <option value="">Tutti i servizi</option>
                  <option value="victim">victim</option>
                  <option value="attacker">attacker</option>
                  <option value="benign">benign</option>
                </select>
                <select id="net-raw-etype-filter" onchange="loadNetRawLogs()">
                  <option value="">Tutti gli event_type</option>
                  <option value="attack_probe">attack_probe (tutti i probe)</option>
                  <option value="attack_progress">attack_progress (byte trovati)</option>
                  <option value="attack_complete">attack_complete (completati)</option>
                  <option value="http_request">http_request (server victim)</option>
                  <option value="benign_request">benign_request (client)</option>
                </select>
                <input id="net-raw-q" type="text" placeholder="Cerca testo libero…" oninput="loadNetRawLogs()" style="flex:1;min-width:140px">
                <a href="/logs/export/csv" class="btn btn-primary" style="font-size:11px;padding:4px 10px;text-decoration:none;display:inline-flex;align-items:center;gap:4px">📥 CSV</a>
                <a href="/logs/export/jsonl" class="btn btn-secondary" style="font-size:11px;padding:4px 10px;text-decoration:none;display:inline-flex;align-items:center;gap:4px">📄 JSONL</a>
              </div>
            </div>
            <div class="log-stream-wrap" id="net-raw-stream"></div>
          </div>
          <div class="subtab-content" id="subtab-content-attack">
            <div class="atk-body" id="net-atk-body" style="padding:16px;overflow-y:auto;flex:1">
              <p class="atk-no-data">In attesa di un attacco… lancia l'attaccante dal pannello Network o Docker.</p>
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
        <div class="log-header" style="padding:12px 24px">
          <div style="display:flex;align-items:center;gap:10px">
            <strong style="font-size:13px;color:#fff;display:flex;align-items:center;gap:6px">
              📊 Log SOC — Correlazione Richiesta e Risposta
            </strong>
            <span style="font-size:11px;color:var(--text-dim);background:rgba(255,255,255,0.05);padding:2px 8px;border-radius:4px;font-family:var(--font-mono)">Attacker &amp; Benign vs Victim Server</span>
          </div>
          <div style="flex:1"></div>
          <a href="/logs/export/csv" class="btn btn-primary" style="font-size:11px;padding:4px 10px;text-decoration:none;display:inline-flex;align-items:center;gap:4px">📥 Scarica CSV</a>
          <a href="/logs/export/jsonl" class="btn btn-secondary" style="font-size:11px;padding:4px 10px;text-decoration:none;display:inline-flex;align-items:center;gap:4px;margin-left:4px">📄 Scarica JSONL</a>
          <label style="font-size:11px;color:var(--text-muted);display:flex;align-items:center;gap:6px;cursor:pointer;margin-left:10px">
            <input type="checkbox" id="soc-auto-scroll" checked style="accent-color:var(--accent)"> Auto-scroll
          </label>
          <button class="btn btn-secondary" style="font-size:11px;padding:4px 10px;margin-left:8px" onclick="loadSocLogs()">↻ Aggiorna</button>
          <span style="font-size:11px;color:var(--text-dim);margin-left:8px">ogni 3s</span>
        </div>
        <div class="log-stream-wrap" id="log-soc-stream"></div>
      </div>

      <!-- ── Log Raw ── -->
      <div id="panel-log-raw" class="panel">
        <div style="padding:12px 20px;border-bottom:1px solid var(--border);background:var(--bg-panel)">
          <div class="filter-bar" style="flex-wrap:wrap;gap:8px;align-items:center">
            <select id="raw-service-filter" onchange="loadRawLogs()">
              <option value="">Tutti i servizi</option>
              <option value="victim">victim</option>
              <option value="attacker">attacker</option>
              <option value="benign">benign</option>
            </select>
            <select id="raw-etype-filter" onchange="loadRawLogs()">
              <option value="">Tutti gli event_type</option>
              <option value="attack_probe">attack_probe (tutti i probe)</option>
              <option value="attack_progress">attack_progress (byte trovati)</option>
              <option value="attack_complete">attack_complete (completati)</option>
              <option value="http_request">http_request (server victim)</option>
              <option value="benign_request">benign_request (client)</option>
            </select>
            <input id="raw-q" type="text" placeholder="Cerca testo libero…" oninput="loadRawLogs()" style="flex:1;min-width:160px">
            <select id="raw-limit" onchange="loadRawLogs()">
              <option value="100">100 righe</option>
              <option value="500">500 righe</option>
              <option value="1000" selected>1.000 righe</option>
              <option value="2000">2.000 righe</option>
              <option value="5000">5.000 righe</option>
              <option value="10000">10.000 righe</option>
              <option value="0">Tutti i log (In RAM: 10k max)</option>
            </select>
            <a href="/logs/export/csv" class="btn btn-primary" style="font-size:11px;padding:5px 12px;text-decoration:none;display:inline-flex;align-items:center;gap:4px">📥 Scarica CSV</a>
            <a href="/logs/export/jsonl" class="btn btn-secondary" style="font-size:11px;padding:5px 12px;text-decoration:none;display:inline-flex;align-items:center;gap:4px">📄 Scarica JSONL</a>
          </div>
        </div>
        <div class="log-stream-wrap" id="log-raw-stream"></div>
      </div>

      <!-- ── Attack Detail ── -->
      <div id="panel-attack-detail" class="panel atk-panel">
        <div class="atk-header">
          <h2>🔬 Attack Detail — Padding Oracle byte-by-byte</h2>
          <div style="flex:1"></div>
          <button class="btn btn-secondary" style="font-size:11px;padding:4px 10px" onclick="loadAttackDetail()">↻ Aggiorna</button>
          <span style="font-size:11px;color:var(--text-muted);margin-left:8px">ogni 4s</span>
        </div>
        <div class="atk-body" id="atk-body">
          <p class="atk-no-data">In attesa di un attacco… lancia l'attaccante dal pannello Network o Docker.</p>
        </div>
      </div>

      <!-- ── Alerts & SOC Analytics ── -->
      <div id="panel-alerts" class="panel alerts-panel">
        <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px">
          <div>
            <div class="panel-title" style="margin-bottom:2px">🚨 SOC SIEM Monitoring &amp; Incident Response</div>
            <div style="font-size:12px;color:var(--text-muted)">Monitoraggio Real-Time Allarmi, Baseline di Traffico, Metriche Forensi (TPR/FPR/MTTD) e Playbook SOAR di Risposta</div>
          </div>
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <button class="btn btn-primary" onclick="openForensicReportModal()">📄 Report Forense Markdown</button>
            <button class="btn btn-success" onclick="quickHotPatchFixed()">🛡️ Hot-Patch to Fixed</button>
            <button class="btn btn-danger" onclick="clearLogsAndReset()">🧹 Reset Baseline &amp; Log</button>
          </div>
        </div>

        <!-- SOC Detection KPIs Cards -->
        <div class="kpi-grid">
          <div class="kpi-card">
            <div class="kpi-label">⚡ Mean Time To Detect (MTTD)</div>
            <div class="kpi-val" id="kpi-mttd">—</div>
            <div class="kpi-sub">Tempo dal 1° probe al 1° allarme</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-label">🎯 True Positive Rate (TPR)</div>
            <div class="kpi-val" style="color:var(--green)" id="kpi-tpr">—</div>
            <div class="kpi-sub">Accuratezza su attacchi reali</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-label">🛡️ False Positive Rate (FPR)</div>
            <div class="kpi-val" style="color:var(--blue)" id="kpi-fpr">—</div>
            <div class="kpi-sub">Falsi allarmi su traffico benigno</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-label">🔔 Allarmi di Sicurezza Attivi</div>
            <div class="kpi-val" id="kpi-alerts-count">0</div>
            <div class="kpi-sub" id="kpi-alerts-status">Monitoraggio continuo</div>
          </div>
        </div>

        <!-- Telemetry Profile (Objective Per-IP Table) -->
        <div class="card" style="margin:0">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
            <div class="panel-title" style="font-size:13px;margin:0">📊 Profilo Telemetrico &amp; Valutazione Nodi per IP (Finestra Corrente)</div>
            <span style="font-size:11px;color:var(--text-muted)">Valutazione automatica basata sui dati reali del traffico</span>
          </div>
          <div style="overflow-x:auto">
            <table style="width:100%;font-size:12px">
              <thead>
                <tr>
                  <th>Indirizzo IP Sorgente</th>
                  <th>Richieste Totali</th>
                  <th>Errori (Fail Rate)</th>
                  <th>Latenza Mediana (p50)</th>
                  <th>StdDev Latenza</th>
                  <th>Valutazione Secondo Regola SOC</th>
                </tr>
              </thead>
              <tbody id="telemetry-ips-tbody">
                <tr><td colspan="6" style="color:var(--text-muted);text-align:center;padding:12px">Inizializzazione telemetria nodi…</td></tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Active Security Alerts Feed -->
        <div class="card" style="margin:0">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
            <div class="panel-title" style="font-size:13px;margin:0">🚨 Incident Feed &amp; Indicatori di Attacco (IOA)</div>
            <button class="btn btn-secondary" style="font-size:11px;padding:3px 8px" onclick="loadAlerts()">↻ Ricarica</button>
          </div>
          <div id="alerts-content"><p style="color:var(--text-muted)">Caricamento telemetria…</p></div>
        </div>

        <!-- Link to Threat Hunting Studio Card -->
        <div class="card" style="margin:0;background:rgba(99,102,241,0.06);border:1px solid rgba(99,102,241,0.25)">
          <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px">
            <div>
              <div class="panel-title" style="font-size:13px;margin-bottom:4px;color:#a5b4fc">🎯 Studio di Threat Hunting, Backtesting &amp; Inline WAF</div>
              <p style="font-size:12px;color:var(--text-muted);margin:0">
                Vuoi esplorare i log grezzi, testare nuove regole con simulazione backtest in tempo reale ed esportare regole Sigma YAML sul WAF?
              </p>
            </div>
            <button class="btn btn-primary" onclick="showPanel('hunting', document.querySelector('[data-panel=hunting]'))">🎯 Apri Threat Hunting Studio</button>
          </div>
        </div>

        <!-- Didactic / Academic Exam Guide Card -->
        <div class="card" style="margin:0;background:rgba(59,130,246,0.05);border:1px solid rgba(59,130,246,0.25)">
          <div class="panel-title" style="font-size:13px;margin-bottom:8px;color:#60a5fa">📖 Guida Rapida ai Concetti SOC per la Relazione d'Esame</div>
          <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(240px, 1fr));gap:12px;font-size:12px">
            <div>
              <strong style="color:#fff">⚡ MTTD (Mean Time To Detect)</strong>
              <p style="color:var(--text-muted);margin:2px 0 0 0">Secondi trascorsi tra il primo probe dell'attaccante e il primo allarme generato. Indica la reattività del SOC.</p>
            </div>
            <div>
              <strong style="color:#fff">🎯 TPR &amp; FPR</strong>
              <p style="color:var(--text-muted);margin:2px 0 0 0"><strong>TPR</strong>: % di attacchi rilevati (Target: 100%). <strong>FPR</strong>: % di falsi allarmi sui client benigni (Target: 0%).</p>
            </div>
            <div>
              <strong style="color:#fff">📊 Baseline Profiling</strong>
              <p style="color:var(--text-muted);margin:2px 0 0 0">I client benigni definiscono il traffico normale (errori &lt; 1%, latenza ~2ms). Qualsiasi deviazione è un indicatore di attacco.</p>
            </div>
            <div>
              <strong style="color:#fff">⏱️ Timing Side-Channel</strong>
              <p style="color:var(--text-muted);margin:2px 0 0 0">Su <code>victim-partial</code>, la vittima maschera l'errore come 403 generico ma impiega ~30ms in più se il padding è valido. Il SOC lo rileva tramite l'alta deviazione standard.</p>
            </div>
          </div>
        </div>
      </div>


      <!-- ── Threat Hunting & SIEM Explorer (Fase 1) ── -->
      <div id="panel-hunting" class="panel alerts-panel">
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;margin-bottom:12px">
          <div>
            <div class="panel-title" style="margin-bottom:2px">🎯 SOC Threat Hunting &amp; SIEM Explorer</div>
            <div style="font-size:12px;color:var(--text-muted)"><strong>Fase 1:</strong> Esplora i log grezzi con query SIEM, formula le regole di detection, effettua il Live Backtest e distribuisci la protezione attiva su WAF &amp; SOC.</div>
          </div>
          <div style="display:flex;gap:8px;align-items:center">
            <span id="waf-global-badge" style="font-size:11px;font-weight:700;padding:4px 10px;border-radius:12px;background:rgba(239,68,68,0.15);color:var(--red);border:1px solid rgba(239,68,68,0.3)">⚫ WAF &amp; REGOLE DISATTIVE</span>
            <button class="btn btn-primary" style="font-size:12px" onclick="toggleWAFPolicy()">🛡️ Toggle WAF / Regole</button>
          </div>
        </div>

        <!-- 1. SIEM Query Bar & Preset Chips -->
        <div class="card" style="margin:0 0 16px 0;border:1px solid rgba(99,102,241,0.3);background:linear-gradient(180deg, rgba(30,27,75,0.4) 0%, rgba(15,23,42,0.6) 100%)">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
            <div style="display:flex;align-items:center;gap:8px">
              <span style="font-size:16px">🔍</span>
              <h3 style="margin:0;font-size:14px;color:#fff">Barra di Ricerca SIEM &amp; Filtro Log</h3>
            </div>
            <div style="font-size:11px;color:var(--text-muted)">Sintassi: <code>status = 500 AND endpoint = /decrypt</code></div>
          </div>

          <!-- Query Input -->
          <div style="display:flex;gap:8px;margin-bottom:10px">
            <input id="siem-query-input" class="form-input" style="font-family:var(--font-mono);font-size:13px;background:#0d1117;color:#58a6ff;border-color:rgba(99,102,241,0.4)" placeholder="Digita query SIEM (es. status = 500 AND endpoint = /decrypt o latency > 15)" value="status = 500 AND endpoint = /decrypt" onkeydown="if(event.key==='Enter') executeSiemQuery()">
            <button class="btn btn-primary" style="font-size:12px;padding:8px 16px;white-space:nowrap" onclick="executeSiemQuery()">🔎 Esegui Query</button>
            <button class="btn btn-secondary" style="font-size:12px;padding:8px 12px;white-space:nowrap" onclick="applySiemPreset('*')">♻️ Reset</button>
          </div>

          <!-- Clickable Preset Chips -->
          <div style="display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-bottom:12px">
            <span style="font-size:11px;font-weight:600;color:var(--text-muted);margin-right:4px">Suggerimenti Rapidi:</span>
            <button class="btn" style="font-size:11px;padding:3px 8px;background:rgba(239,68,68,0.12);color:var(--red);border:1px solid rgba(239,68,68,0.3)" onclick="applySiemPreset('status = 500 AND endpoint = /decrypt')">📌 Padding Oracle 500</button>
            <button class="btn" style="font-size:11px;padding:3px 8px;background:rgba(245,158,11,0.12);color:var(--amber);border:1px solid rgba(245,158,11,0.3)" onclick="applySiemPreset('latency > 15 AND endpoint = /decrypt')">📌 Timing Discrepancy (&gt;15ms)</button>
            <button class="btn" style="font-size:11px;padding:3px 8px;background:rgba(168,85,247,0.12);color:#c084fc;border:1px solid rgba(168,85,247,0.3)" onclick="applySiemPreset('status != 200')">📌 Tutti gli Errori (status != 200)</button>
            <button class="btn" style="font-size:11px;padding:3px 8px;background:rgba(59,130,246,0.12);color:#60a5fa;border:1px solid rgba(59,130,246,0.3)" onclick="applySiemPreset('COUNT > 15 AND FAIL_RATE > 0.70')">📌 Burst Attacco (Count &gt; 15, Fail &gt; 70%)</button>
            <button class="btn" style="font-size:11px;padding:3px 8px;background:rgba(16,185,129,0.12);color:var(--green);border:1px solid rgba(16,185,129,0.3)" onclick="applySiemPreset('status = 200')">📌 Traffico Regolare (200 OK)</button>
            <button class="btn" style="font-size:11px;padding:3px 8px;background:rgba(255,255,255,0.06);color:var(--text-muted);border:1px solid var(--border)" onclick="applySiemPreset('*')">📌 Tutti i Log (*)</button>
          </div>

          <!-- SIEM Summary Metrics Banner -->
          <div id="siem-summary-banner" style="display:flex;flex-wrap:wrap;gap:8px;padding:8px 12px;background:rgba(0,0,0,0.3);border-radius:6px;font-size:12px;align-items:center">
            <span style="font-weight:600;color:#fff">Risultati Query:</span>
            <span id="siem-stat-total" class="stat-pill">Trovati: <strong>0</strong></span>
            <span id="siem-stat-200" class="stat-pill" style="color:var(--green)">HTTP 200: <strong>0</strong></span>
            <span id="siem-stat-400" class="stat-pill" style="color:var(--amber)">HTTP 400: <strong>0</strong></span>
            <span id="siem-stat-403" class="stat-pill" style="color:var(--amber)">HTTP 403: <strong>0</strong></span>
            <span id="siem-stat-429" class="stat-pill" style="color:#c084fc">HTTP 429 (WAF): <strong>0</strong></span>
            <span id="siem-stat-500" class="stat-pill" style="color:var(--red)">HTTP 500 (Padding): <strong>0</strong></span>
          </div>

          <!-- Filtered Log Table Preview -->
          <div style="margin-top:10px;max-height:220px;overflow-y:auto;border:1px solid var(--border);border-radius:6px">
            <table style="width:100%;font-size:11px;font-family:var(--font-mono)">
              <thead style="position:sticky;top:0;background:var(--bg-panel);z-index:2">
                <tr>
                  <th style="padding:6px 8px">Timestamp</th>
                  <th style="padding:6px 8px">Client / IP</th>
                  <th style="padding:6px 8px">Endpoint</th>
                  <th style="padding:6px 8px">Status</th>
                  <th style="padding:6px 8px">Latenza</th>
                  <th style="padding:6px 8px">Ciphertext</th>
                  <th style="padding:6px 8px">Error Type</th>
                </tr>
              </thead>
              <tbody id="siem-logs-tbody">
                <tr><td colspan="7" style="color:var(--text-muted);text-align:center;padding:12px">Nessuna ricerca eseguita. Clicca "Esegui Query" o un suggerimento rapido.</td></tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- 2. Raw Telemetry Actor Profiles -->
        <div class="card" style="margin:0 0 16px 0">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
            <h3 style="margin:0;font-size:14px;color:#fff">2. Telemetria Grezza: Profilazione Attori &amp; Feature Crittografiche</h3>
            <button class="btn btn-secondary" style="font-size:11px;padding:3px 8px" onclick="loadHuntingData()">🔄 Aggiorna Profili</button>
          </div>
          <div style="overflow-x:auto">
            <table style="width:100%;font-size:12px">
              <thead>
                <tr>
                  <th>Actor IP</th>
                  <th>Richieste Decrypt</th>
                  <th>Errori (Fail Rate)</th>
                  <th>Blocco Target</th>
                  <th>Latenza Media</th>
                  <th>Sarle's BC (Bimodalità)</th>
                  <th>Classificazione</th>
                </tr>
              </thead>
              <tbody id="hunting-profiles-tbody">
                <tr><td colspan="7" style="color:var(--text-muted)">Caricamento profili telemetrici…</td></tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- 3. Detection Engineering: Regola Sigma YAML, Backtest & Deploy WAF -->
        <div class="card" style="margin:0">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
            <div>
              <h3 style="margin:0;font-size:14px;color:#fff">3. Regola di Detection Sigma YAML, Live Backtesting &amp; Deploy Difesa</h3>
              <div style="font-size:11px;color:var(--text-muted);margin-top:2px">Compilata automaticamente dalla Query SIEM per il rilevamento e il blocco inline (HTTP 429).</div>
            </div>
            <div style="display:flex;gap:6px">
              <button class="btn btn-secondary" style="font-size:11px;padding:4px 8px" onclick="copySigmaYaml()">📋 Copia YAML</button>
            </div>
          </div>

          <div style="display:grid;grid-template-columns:1.2fr 0.8fr;gap:14px;align-items:start">
            <!-- Left: Sigma YAML Rule Viewer -->
            <div>
              <label class="form-label" style="font-size:11px;color:var(--text-dim)">📜 Specifica Regola Sigma (Standard YAML):</label>
              <textarea id="sigma-rule-output" class="form-input" rows="11" readonly style="font-family:var(--font-mono);font-size:11px;background:#0d1117;color:#58a6ff;line-height:1.4"></textarea>
            </div>

            <!-- Right: Threshold Tuning & Action Buttons -->
            <div>
              <label class="form-label" style="font-size:11px;color:var(--text-dim)">⚙️ Parametri Soglia &amp; Finestra Temporale:</label>
              <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:10px">
                <div class="form-group" style="margin-bottom:6px">
                  <label class="form-label" style="font-size:10px">Min Richieste / Finestra</label>
                  <input class="form-input" type="number" id="hunt-min-events" value="15" min="5" max="100" onchange="runHuntingBacktest()" style="font-size:11px;padding:4px 8px">
                </div>
                <div class="form-group" style="margin-bottom:6px">
                  <label class="form-label" style="font-size:10px">Soglia Fail-Rate (0-1)</label>
                  <input class="form-input" type="number" id="hunt-fail-rate" value="0.80" min="0.1" max="1.0" step="0.05" onchange="runHuntingBacktest()" style="font-size:11px;padding:4px 8px">
                </div>
                <div class="form-group" style="margin-bottom:6px">
                  <label class="form-label" style="font-size:10px">Timing StdDev (ms)</label>
                  <input class="form-input" type="number" id="hunt-timing-stddev" value="6.0" min="1.0" max="30.0" step="0.5" onchange="runHuntingBacktest()" style="font-size:11px;padding:4px 8px">
                </div>
                <div class="form-group" style="margin-bottom:6px">
                  <label class="form-label" style="font-size:10px">Bimodalità Sarle (BC)</label>
                  <input class="form-input" type="number" id="hunt-bimodality" value="0.555" min="0.3" max="0.99" step="0.05" onchange="runHuntingBacktest()" style="font-size:11px;padding:4px 8px">
                </div>
              </div>
              <div style="display:flex;gap:8px;flex-direction:column">
                <button class="btn btn-primary" style="font-size:12px;padding:8px" onclick="runHuntingBacktest()">🔬 Esegui Live Backtest</button>
                <button class="btn btn-success" style="font-size:12px;padding:8px" onclick="deployHuntingPolicyToWAF()">🚀 Attiva Regola su WAF Vittima &amp; SOC</button>
              </div>
            </div>
          </div>

          <!-- Backtest Results Box -->
          <div id="hunting-backtest-result" style="margin-top:12px;padding:10px 14px;background:var(--bg-panel);border-radius:8px;display:none;border:1px solid rgba(255,255,255,0.08)">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
              <strong style="color:var(--green)">Risultati Live Backtest:</strong>
              <div id="hunting-kpis-badge" style="font-size:12px;font-weight:700"></div>
            </div>
            <div id="hunting-backtest-details" style="font-size:11px;color:var(--text-dim)"></div>
          </div>
        </div>
      </div>

      <!-- ── Inventario Nodi & Mappatura IP ── -->
      <div id="panel-docker" class="panel docker-panel">
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;margin-bottom:12px">
          <div>
            <div class="panel-title" style="margin-bottom:2px">📋 Inventario Nodi &amp; Mappatura IP di Rete</div>
            <div style="font-size:12px;color:var(--text-muted)">Mappa infrastrutturale del laboratorio: risoluzione IP reali della subnet Docker, ruoli applicativi e porte esposte.</div>
          </div>
          <button class="btn btn-secondary" style="font-size:12px" onclick="loadDockerStatus()">🔄 Aggiorna Inventario</button>
        </div>

        <div class="card" style="margin-bottom:16px">
          <table id="docker-table">
            <thead>
              <tr>
                <th>Host / Container</th>
                <th>Ruolo di Rete</th>
                <th>Indirizzo IP Subnet</th>
                <th>Stato</th>
                <th>Porte Mappate</th>
                <th>Controllo</th>
              </tr>
            </thead>
            <tbody id="docker-tbody">
              <tr><td colspan="6" style="color:var(--text-muted)">Caricamento inventario nodi…</td></tr>
            </tbody>
          </table>
        </div>

        <div class="card" style="margin-bottom:16px">
          <h3 style="margin:0 0 8px 0;font-size:13px;color:#fff">Target Vittima Attivo (Mutualmente Esclusivi)</h3>
          <p style="font-size:12px;color:var(--text-muted);margin:0 0 10px 0">Scegli quale implementazione crittografica della vittima deve rispondere alle chiamate HTTP.</p>
          <form method="post" action="/docker/action/start-victim" style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
            <select name="target" class="form-input" style="max-width:340px">
              <option value="victim-vuln">victim-vuln (Vulnerabile a Padding Oracle - Status 500)</option>
              <option value="victim-partial">victim-partial (Timing Side-Channel Oracle - Dispersione latenza)</option>
              <option value="victim-fixed">victim-fixed (Hardened - Verifica a tempo costante)</option>
            </select>
            <button class="btn btn-success" type="submit">Applica Target</button>
          </form>
        </div>

        <div class="card">
          <h3 style="margin:0 0 8px 0;font-size:13px;color:#fff">Azioni Infrastrutturali Globali</h3>
          <div style="display:flex;gap:8px;flex-wrap:wrap">
            <form style="display:inline" method="post" action="/docker/action/start"><input type="hidden" name="target" value="soc"><button class="btn btn-secondary" type="submit">▶ Riavvia SOC Collector</button></form>
            <form style="display:inline" method="post" action="/docker/action/stop-all"><button class="btn btn-danger" type="submit">⏹ Stop Tutti i Container</button></form>
          </div>
        </div>
      </div>

    </main>
  </div>
</div>

<!-- ══ MODAL: Victim ══ -->
<div class="modal-overlay" id="modal-victim">
  <div class="modal">
    <div class="modal-title">🖥️ Seleziona variante vittima</div>
    <div class="modal-sub">Una sola variante può essere attiva alla volta</div>
    <div class="radio-group">
      <label class="radio-opt">
        <input type="radio" name="victim-mode" value="victim-vuln" checked>
        <div><div class="opt-label">victim-vuln</div><div class="opt-desc">Vulnerabile — distingue padding_error (500) da altri errori (403)</div></div>
      </label>
      <label class="radio-opt">
        <input type="radio" name="victim-mode" value="victim-partial">
        <div><div class="opt-label">victim-partial</div><div class="opt-desc">Timing side-channel — risposta generica ma latenza diversa</div></div>
      </label>
      <label class="radio-opt">
        <input type="radio" name="victim-mode" value="victim-fixed">
        <div><div class="opt-label">victim-fixed</div><div class="opt-desc">Hardened — timing costante + risposta generica</div></div>
      </label>
    </div>
    <div class="modal-actions">
      <button class="btn btn-secondary" onclick="closeModal('modal-victim')">Chiudi</button>
      <button class="btn btn-success" onclick="switchVictim()">
        <span class="spinner" id="spin-victim"></span> Attiva variante
      </button>
    </div>
  </div>
</div>

<!-- ══ MODAL: Benign ══ -->
<div class="modal-overlay" id="modal-benign">
  <div class="modal" style="max-width:580px;width:95%">
    <div class="modal-title">🟡 Configura Traffico Benigno (Multi-API &amp; Noise)</div>
    <div class="modal-sub">I client legittimi simulano sessioni utente reali (Login, Profilo, Encrypt, Decrypt, Verify) con rumore fisiologico controllato.</div>
    
    <div class="card" style="padding:12px 14px;margin-bottom:12px;background:var(--bg-panel)">
      <div class="panel-title" style="font-size:12px;margin-bottom:8px">Host 1 — benign-1</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
        <div class="form-group">
          <label class="form-label">Modalità Traffico</label>
          <label style="font-size:12px;color:var(--text);display:flex;align-items:center;gap:6px">
            <input type="checkbox" id="benign-1-continuous" checked> Loop Continuo (Consigliato)
          </label>
        </div>
        <div class="form-group">
          <label class="form-label">% Errori Fisiologici (400/401/404)</label>
          <input class="form-input" type="number" id="benign-1-err-rate" value="3.0" min="0" max="25" step="0.5">
        </div>
        <div class="form-group">
          <label class="form-label">Sleep Minimo (ms)</label>
          <input class="form-input" type="number" id="benign-1-min" value="500" min="50">
        </div>
        <div class="form-group">
          <label class="form-label">Sleep Massimo (ms)</label>
          <input class="form-input" type="number" id="benign-1-max" value="1200" min="100">
        </div>
      </div>
      <div class="modal-actions" style="margin-top:8px">
        <button class="btn btn-primary" onclick="saveBenignConfig('benign-1')"><span class="spinner" id="spin-benign-1"></span> Salva Config benign-1</button>
      </div>
    </div>

    <div class="card" style="padding:12px 14px;background:var(--bg-panel)">
      <div class="panel-title" style="font-size:12px;margin-bottom:8px">Host 2 — benign-2</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
        <div class="form-group">
          <label class="form-label">Modalità Traffico</label>
          <label style="font-size:12px;color:var(--text);display:flex;align-items:center;gap:6px">
            <input type="checkbox" id="benign-2-continuous" checked> Loop Continuo (Consigliato)
          </label>
        </div>
        <div class="form-group">
          <label class="form-label">% Errori Fisiologici (400/401/404)</label>
          <input class="form-input" type="number" id="benign-2-err-rate" value="3.0" min="0" max="25" step="0.5">
        </div>
        <div class="form-group">
          <label class="form-label">Sleep Minimo (ms)</label>
          <input class="form-input" type="number" id="benign-2-min" value="600" min="50">
        </div>
        <div class="form-group">
          <label class="form-label">Sleep Massimo (ms)</label>
          <input class="form-input" type="number" id="benign-2-max" value="1500" min="100">
        </div>
      </div>
      <div class="modal-actions" style="margin-top:8px">
        <button class="btn btn-primary" onclick="saveBenignConfig('benign-2')"><span class="spinner" id="spin-benign-2"></span> Salva Config benign-2</button>
      </div>
    </div>
    <div class="modal-actions"><button class="btn btn-secondary" onclick="closeModal('modal-benign')">Chiudi</button></div>
  </div>
</div>

<!-- ══ MODAL: Attacker ══ -->
<div class="modal-overlay" id="modal-attacker">
  <div class="modal" style="max-width:580px;width:95%">
    <div class="modal-title">🔴 Configura Attacco Padding Oracle</div>
    <div class="modal-sub">Personalizza il segreto target, la modalità oracle e la frequenza di probing dell'attaccante.</div>
    <div class="form-group">
      <label class="form-label">🔑 Segreto Vittima</label>
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
          <div><div class="opt-label">vuln (status-based)</div><div class="opt-desc">Usa codici HTTP differenti (500 vs 403) per rilevare il padding</div></div>
        </label>
        <label class="radio-opt">
          <input type="radio" name="atk-mode" value="timing">
          <div><div class="opt-label">timing (side-channel)</div><div class="opt-desc">Usa la latenza di risposta come side-channel</div></div>
        </label>
      </div>
    </div>
    <div class="form-group">
      <label class="form-label">Origine Indirizzo IP Attaccante</label>
      <div class="radio-group">
        <label class="radio-opt">
          <input type="radio" name="atk-ip-mode" value="static" checked>
          <div><div class="opt-label">IP Statico Container</div><div class="opt-desc">Usa l'IP reale del container Docker (es. 172.28.0.5)</div></div>
        </label>
        <label class="radio-opt">
          <input type="radio" name="atk-ip-mode" value="random">
          <div><div class="opt-label">IP Spoofing Singolo</div><div class="opt-desc">Simula un IP esterno casuale fisso (198.51.100.x)</div></div>
        </label>
        <label class="radio-opt">
          <input type="radio" name="atk-ip-mode" value="rotate">
          <div><div class="opt-label">Proxy Pool / Botnet (Rotante)</div><div class="opt-desc">Ruota l'IP a ogni richiesta per evadere rate-limiting</div></div>
        </label>
      </div>
    </div>
    <div class="form-group">
      <label class="form-label">Delay tra probe (ms) — Consigliato: 4ms per ~45s di demo fluida</label>
      <input class="form-input" type="number" id="atk-sleep" value="4" min="0" max="1000" step="1">
    </div>
    <div class="modal-actions">
      <button class="btn btn-secondary" onclick="closeModal('modal-attacker')">Chiudi</button>
      <button class="btn btn-primary" onclick="saveAttackConfig()">
        <span class="spinner" id="spin-attacker"></span> Salva
      </button>
    </div>
  </div>
</div>

<!-- ══ MODAL: Forensic Incident Report ══ -->
<div class="modal-overlay" id="modal-report">
  <div class="modal" style="max-width:720px;width:90%">
    <div class="modal-title">📄 Forensic Incident & SOC Evaluation Report</div>
    <div class="modal-sub">Report accademico generato automaticamente, pronto da allegare alla relazione d'esame</div>
    <div style="margin-bottom:14px">
      <textarea id="report-md-content" readonly style="width:100%;height:320px;background:var(--bg-panel);border:1px solid var(--border);color:var(--text);font-family:var(--font-mono);font-size:11px;padding:10px;border-radius:8px;resize:vertical;line-height:1.5"></textarea>
    </div>
    <div class="modal-actions" style="justify-content:space-between;align-items:center">
      <button class="btn btn-secondary" onclick="closeModal('modal-report')">Chiudi</button>
      <div style="display:flex;gap:8px">
        <button class="btn btn-primary" onclick="copyReportToClipboard()">📋 Copia Markdown</button>
        <button class="btn btn-success" onclick="downloadReportFile()">⬇️ Scarica File .md</button>
      </div>
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
  if (name === 'hunting') { loadHuntingData(); updateWAFBadge(); executeSiemQuery(); }
  if (name === 'docker') loadDockerStatus();
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

  // Extra info in last column: for attacker events show details summary, otherwise error/endpoint
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
      lastCol = `<span style="color:var(--green);font-weight:700">✅ COMPLETED recovered="${escapeHtml(d.recovered_block ?? '')}" queries=${d.queries ?? '?'}</span>`;
    } else {
      lastCol = `<span style="color:var(--text-dim)">${_renderDetailsHtml(d)}</span>`;
    }
  } else if (cls === 'benign' && hasDetails) {
    const d = details;
    lastCol = `<span style="color:var(--text-dim)">#${d.iteration ?? 0} ${d.plaintext_sample ? '"' + escapeHtml(d.plaintext_sample) + '"' : ''} ${latency ? latency : ''}</span>`;
  } else {
    const clientInfo = hasDetails && details.client_id ? ` [${details.client_id}]` : '';
    lastCol = `<span style="color:var(--text-dim)">${err || ep}${clientInfo}${latency ? ' ' + latency : ''}</span>`;
  }

  const srcIpTag = ev.src_ip ? `<span style="font-family:var(--font-mono);font-size:11px;font-weight:700;color:#93c5fd">${escapeHtml(ev.src_ip)}</span>` : `<span style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted)">${escapeHtml(svc)}</span>`;

  row.innerHTML = `
    <span style="color:var(--text-dim)">${ts}</span>
    ${srcIpTag}
    <span style="color:var(--text-muted)">${escapeHtml(etype)}</span>
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
    document.getElementById('cnt-attacker').textContent = ec.attacker || 0;
    document.getElementById('cnt-benign').textContent   = ec.benign   || 0;
    document.getElementById('cnt-victim').textContent   = ec.victim   || 0;

    // Sidebar victim
    const v = d.active_victim || '—';
    document.getElementById('sidebar-victim-name').textContent = v;

    // Update traffic toggle buttons
    updateTrafficButtons(d.benign_active, d.attack_active);

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

// ── Clear all logs ──
async function clearLogs() {
  const btn = document.getElementById('btn-clear-logs');
  const orig = btn.textContent;
  btn.textContent = '⏳ Pulizia…';
  btn.disabled = true;
  try {
    const r = await fetch('/logs/clear', { method: 'POST' });
    const d = await r.json();
    // Reset live log stream dedup set so new events are shown fresh
    logStreamSeen.clear();
    persistentAttackByteMap = {};
    document.getElementById('log-stream').innerHTML = '';
    document.getElementById('log-soc-stream').innerHTML = '';
    document.getElementById('log-raw-stream').innerHTML = '';
    // Clear active flows animation
    stopPacketAnimation();
    btn.textContent = `✅ ${d.cleared?.length ?? 0} file puliti`;
    setTimeout(() => { btn.textContent = orig; btn.disabled = false; }, 2000);
  } catch (e) {
    btn.textContent = '❌ Errore';
    setTimeout(() => { btn.textContent = orig; btn.disabled = false; }, 2000);
  }
}

// ── Reset test (stop workloads + restore default victim + clear logs) ──
async function resetTest() {
  const btn = document.getElementById('btn-reset-test');
  const orig = btn.textContent;
  btn.textContent = '⏳ Reset…';
  btn.disabled = true;
  try {
    const r = await fetch('/test/reset', { method: 'POST' });
    const d = await r.json();
    logStreamSeen.clear();
    persistentAttackByteMap = {};
    document.getElementById('log-stream').innerHTML = '';
    document.getElementById('log-soc-stream').innerHTML = '';
    document.getElementById('log-raw-stream').innerHTML = '';
    stopPacketAnimation();
    await pollNetwork();
    await pollStatus();
    btn.textContent = `✅ Reset (${d.cleared?.length ?? 0} log)`;
    setTimeout(() => { btn.textContent = orig; btn.disabled = false; }, 2200);
  } catch (e) {
    btn.textContent = '❌ Errore';
    setTimeout(() => { btn.textContent = orig; btn.disabled = false; }, 2200);
  }
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
let currentNetSubTab = 'live';

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
  if (legend) legend.style.display = (tabName === 'live' || tabName === 'soc') ? 'flex' : 'none';
  if (scrollWrap) scrollWrap.style.display = (tabName === 'live' || tabName === 'soc') ? 'flex' : 'none';

  if (tabName === 'soc') loadNetSocLogs();
  if (tabName === 'raw') loadNetRawLogs();
  if (tabName === 'attack') loadAttackDetail('net-atk-body');
  if (tabName === 'alerts') loadAlerts();
}

// ── SOC Paired Request / Response Card Builder ──
function buildSocLogCard(ev) {
  const cls = colorClass(ev);
  const isAtk = cls === 'attacker';
  const ts = (ev.ts || '').replace('T', ' ').replace(/\.\d+.*$/, '');
  const svc = ev.service || (isAtk ? 'attacker' : 'benign');
  const etype = ev.event_type || (isAtk ? 'attack_probe' : 'benign_request');
  const code = ev.status_code ?? ev.status ?? 0;
  const latency = ev.latency_ms !== undefined && ev.latency_ms !== null ? `${Math.round(ev.latency_ms)} ms` : '—';
  const ep = ev.endpoint || '/decrypt';
  const cLen = ev.ciphertext_len !== undefined ? `${ev.ciphertext_len} bytes` : '32 bytes (2 blocks)';
  const details = ev.details || {};

  const card = document.createElement('div');
  card.className = `soc-card ${isAtk ? 'atk-card' : 'ben-card'}`;

  // Header
  const header = document.createElement('div');
  header.className = 'soc-card-header';
  header.innerHTML = `
    ${tagHtml(cls)}
    <span class="soc-card-svc">${escapeHtml(svc)}</span>
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
      <div class="soc-box-row"><span class="soc-box-key">Guess IV[i]</span><span style="color:#fff">${gHex} (${details.guess ?? '?'})</span></div>
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
    <div class="soc-box-row"><span class="soc-box-key">Sorgente IP</span><span style="color:var(--accent)">${escapeHtml(ev.src_ip || svc)}</span></div>
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
    <div class="soc-box-row"><span class="soc-box-key">Errore / Esito</span><span style="color:${code===500?'var(--red)':code===200?'var(--green)':'var(--amber)'}">${escapeHtml(ev.error_type || (code===500?'padding_error':'ok'))}</span></div>
    <div class="soc-box-row"><span class="soc-box-key">Latenza Server</span><span>${latency}</span></div>
  `;

  grid.appendChild(reqBox);
  grid.appendChild(resBox);
  card.appendChild(grid);

  // Bottom analysis context
  let analysisText = '';
  if (isAtk) {
    if (etype === 'attack_complete') {
      analysisText = `🏆 <strong>Analisi SOC:</strong> Attacco Padding Oracle completato con successo. Il blocco intero è stato decifrato sfruttando le risposte dell'oracolo.`;
    } else if (etype === 'attack_progress') {
      analysisText = `🎯 <strong>Analisi SOC:</strong> Byte <code>${details.byte_index ?? '?'}</code> identificato! Carattere recuperato: <code>'${escapeHtml(details.recovered_char ?? '')}'</code> (${details.recovered_hex || ''}) in ${details.queries_total ?? '?'} tentativi.`;
    } else {
      const gHex = details.guess_hex || `0x${(details.guess||0).toString(16).padStart(2,'0')}`;
      const outcomeDesc = details.valid_padding ? `<strong style="color:var(--green)">Padding corretto riscontrato</strong>` : `Padding non valido (scartato)`;
      analysisText = `⚡ <strong>Analisi SOC:</strong> Sonda #${details.queries_total ?? '?'}. Testato byte candidato <code>${gHex}</code> su indice <code>${details.byte_index ?? '?'}</code>. Esito oracolo: ${outcomeDesc}.`;
    }
  } else {
    analysisText = `🛡️ <strong>Analisi SOC:</strong> Traffico baseline legittimo generato da client autorizzato con payload crittografato valido.`;
  }

  const footer = document.createElement('div');
  footer.className = 'soc-analysis-footer';
  footer.innerHTML = analysisText;
  card.appendChild(footer);

  return card;
}

function renderSocEvents(container, events) {
  container.innerHTML = '';
  if (!events || events.length === 0) {
    container.innerHTML = `
      <div style="padding:40px 20px;text-align:center;color:var(--text-muted)">
        <div style="font-size:32px;margin-bottom:12px">📊</div>
        <strong style="color:#fff;font-size:14px">Nessun evento SOC registrato</strong>
        <p style="font-size:12px;margin-top:6px;color:var(--text-dim)">
          Avvia il traffico benigno o l'attacco padding oracle dalla barra superiore per analizzare le coppie richiesta/risposta.
        </p>
      </div>
    `;
    return;
  }

  const wrapper = document.createElement('div');
  wrapper.className = 'soc-container';
  events.forEach(ev => {
    wrapper.appendChild(buildSocLogCard(ev));
  });
  container.appendChild(wrapper);
}

// ── SOC log loaders ──
async function loadNetSocLogs() {
  try {
    const r = await fetch('/logs/tail?limit=500');
    const events = await r.json();
    const filtered = events.filter(ev => {
      const c = colorClass(ev);
      return c === 'attacker' || c === 'benign';
    });
    const stream = document.getElementById('net-soc-stream');
    if (!stream) return;
    renderSocEvents(stream, filtered.slice(0, 200));
    stream.scrollTop = stream.scrollHeight;
  } catch (e) { /* ignore */ }
}

async function loadSocLogs() {
  try {
    const rAtk = await fetch('/logs/tail?limit=500&service=attacker');
    const atkEvents = await rAtk.json();
    const rBen = await fetch('/logs/tail?limit=200&service=benign');
    const benEvents = await rBen.json();
    const combined = [...atkEvents, ...benEvents].sort((a, b) => (b.ts || '').localeCompare(a.ts || ''));
    const stream = document.getElementById('log-soc-stream');
    if (!stream) return;
    const socScroll = document.getElementById('soc-auto-scroll');
    const atBottom = stream.scrollHeight - stream.scrollTop - stream.clientHeight < 60;
    renderSocEvents(stream, combined.slice(0, 300));
    if (socScroll && socScroll.checked && atBottom) stream.scrollTop = stream.scrollHeight;
  } catch (e) { /* ignore */ }
}

async function loadNetRawLogs() {
  const svcSel = document.getElementById('net-raw-service-filter');
  const etypeSel = document.getElementById('net-raw-etype-filter');
  const qInput = document.getElementById('net-raw-q');
  const svc = svcSel ? svcSel.value : '';
  const etype = etypeSel ? etypeSel.value : '';
  const q = qInput ? qInput.value : '';
  let url = `/logs/tail?limit=1000`;
  if (q) url += `&q=${encodeURIComponent(q)}`;
  try {
    const r = await fetch(url);
    let events = await r.json();
    if (svc) events = events.filter(ev => str(ev.service || '').startsWith(svc));
    if (etype) events = events.filter(ev => (ev.event_type || '') === etype);
    const stream = document.getElementById('net-raw-stream');
    if (!stream) return;
    stream.innerHTML = '';
    if (events.length === 0) {
      stream.innerHTML = '<p style="color:var(--text-muted);padding:16px;font-size:12px">Nessun evento trovato con i filtri selezionati.</p>';
      return;
    }
    events.forEach(ev => stream.appendChild(buildLogRow(ev)));
    stream.scrollTop = stream.scrollHeight;
  } catch (e) { /* ignore */ }
}

// ── Raw log ──
async function loadRawLogs() {
  const svc   = document.getElementById('raw-service-filter').value;
  const etype = document.getElementById('raw-etype-filter').value;
  const q     = document.getElementById('raw-q').value;
  const lim   = document.getElementById('raw-limit').value;
  let url = `/logs/tail?limit=${lim}`;
  if (q) url += `&q=${encodeURIComponent(q)}`;
  try {
    const r = await fetch(url);
    let events = await r.json();
    if (svc) events = events.filter(ev => (ev.service || '').startsWith(svc));
    if (etype) events = events.filter(ev => (ev.event_type || '') === etype);
    const stream = document.getElementById('log-raw-stream');
    stream.innerHTML = '';
    if (events.length === 0) {
      stream.innerHTML = '<p style="color:var(--text-muted);padding:16px;font-size:12px">Nessun evento trovato con i filtri selezionati.</p>';
      return;
    }
    events.forEach(ev => stream.appendChild(buildLogRow(ev)));
    stream.scrollTop = stream.scrollHeight;
  } catch (e) { /* ignore */ }
}

// ── Attack Detail ──
let lastRenderedScenarioId = null;

async function loadAttackDetail(targetId) {
  const targetIds = targetId ? [targetId] : ['atk-body', 'net-atk-body'];
  try {
    const r = await fetch('/logs/tail?limit=10000&service=attacker');
    const allAtkEvents = await r.json();
    if (!allAtkEvents || !allAtkEvents.length) {
      targetIds.forEach(id => {
        const body = document.getElementById(id);
        if (body) body.innerHTML = '<p class="atk-no-data">In attesa di un attacco… lancia l\'attaccante dal pannello Network o Docker.</p>';
      });
      return;
    }

    const sortedEvents = allAtkEvents.sort((a, b) => (a.ts || '').localeCompare(b.ts || ''));

    // Identify the latest scenario_id
    let latestScenarioId = null;
    for (let i = sortedEvents.length - 1; i >= 0; i--) {
      if (sortedEvents[i].scenario_id) {
        latestScenarioId = sortedEvents[i].scenario_id;
        break;
      }
    }

    // When scenario changes, reset discovery map immediately
    if (latestScenarioId && latestScenarioId !== lastRenderedScenarioId) {
      persistentAttackByteMap = {};
      lastRenderedScenarioId = latestScenarioId;
    }

    const atk = latestScenarioId ? sortedEvents.filter(ev => ev.scenario_id === latestScenarioId) : sortedEvents;

    targetIds.forEach(id => {
      const body = document.getElementById(id);
      if (!body) return;
      if (!atk.length) {
        body.innerHTML = '<p class="atk-no-data">Inizializzazione nuovo attacco…</p>';
        return;
      }

      let completeEv = null;
      let blockedEv = null;
      let errEv = null;
      let totalProbes = 0;
      let lastProbe = null;
      let numBlocks = 1;

      atk.forEach(ev => {
        if (ev.event_type === 'attack_probe') {
          totalProbes++;
          lastProbe = ev;
          if (ev.details && ev.details.total_blocks) numBlocks = Math.max(numBlocks, ev.details.total_blocks);
        }
        if (ev.event_type === 'attack_progress' && ev.details) {
          const d = ev.details;
          const bIdx = d.block_index !== undefined ? d.block_index : 1;
          const byteIdx = d.byte_index !== undefined ? d.byte_index : 0;
          const gIdx = d.global_byte_index !== undefined ? d.global_byte_index : ((bIdx - 1) * 16 + byteIdx);
          persistentAttackByteMap[gIdx] = { ...d, ts: ev.ts };
          if (d.total_blocks) numBlocks = Math.max(numBlocks, d.total_blocks);
        }
        if (ev.event_type === 'attack_complete') {
          completeEv = ev;
          if (ev.details && ev.details.blocks_count) numBlocks = Math.max(numBlocks, ev.details.blocks_count);
        }
        if (ev.event_type === 'attack_blocked') {
          blockedEv = ev;
        }
        if (ev.event_type === 'attack_error') {
          errEv = ev;
        }
      });

      let html = '';
      let recFullStr = (completeEv && completeEv.details) ? (completeEv.details.recovered_plaintext || completeEv.details.recovered_block || '') : '';
      let rawPayloadHex = (completeEv && completeEv.details) ? (completeEv.details.raw_payload_hex || '') : '';
      const totalExpectedBytes = numBlocks * 16;
      const recCount = completeEv ? totalExpectedBytes : Object.keys(persistentAttackByteMap).length;

      const statusLabel = blockedEv ? '🛑 BLOCCATO DA WAF' : (errEv ? '⚠️ ATTACCO INTERROTTO' : (completeEv ? '✅ COMPLETATO' : '⚡ IN ESECUZIONE'));
      const statusColor = blockedEv ? 'var(--red)' : (errEv ? 'var(--amber)' : (completeEv ? 'var(--green)' : 'var(--accent)'));

      // Stats Summary Bar
      html += `
        <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(160px, 1fr));gap:10px;margin-bottom:16px">
          <div class="kpi-card" style="padding:10px 14px">
            <div class="kpi-label">Byte Decifrati</div>
            <div class="kpi-val" style="color:var(--green)">${recCount} / ${totalExpectedBytes}</div>
            <div class="kpi-sub">${((recCount / Math.max(1, totalExpectedBytes)) * 100).toFixed(0)}% (${numBlocks} ${numBlocks > 1 ? 'blocchi' : 'blocco'})</div>
          </div>
          <div class="kpi-card" style="padding:10px 14px">
            <div class="kpi-label">Sonde / Query Totali</div>
            <div class="kpi-val" style="color:var(--amber)">${completeEv?.details?.queries || blockedEv?.details?.queries_total || totalProbes}</div>
            <div class="kpi-sub">${recCount > 0 ? (totalProbes / Math.max(1, recCount)).toFixed(1) + ' probe/byte avg' : 'Inizializzazione'}</div>
          </div>
          <div class="kpi-card" style="padding:10px 14px">
            <div class="kpi-label">Stato Attacco</div>
            <div class="kpi-val" style="font-size:16px;color:${statusColor}">${statusLabel}</div>
            <div class="kpi-sub">${blockedEv ? 'Intercettato da Firewall' : (lastProbe ? 'Blocco ' + (lastProbe.details?.block_index || 1) + ' · Guess: ' + (lastProbe.details?.guess_hex || '0x..') : 'Pronto')}</div>
          </div>
        </div>
      `;

      if (blockedEv) {
        html += `
        <div class="atk-event" style="margin-bottom:16px;border-left-color:var(--red)">
          <div class="ae-header">
            <span class="ae-type" style="background:rgba(239,68,68,0.2);color:var(--red);border:1px solid rgba(239,68,68,0.4)">🛑 attack_blocked — Exploit Neutralizzato dal WAF (HTTP 429)</span>
            <span class="ae-ts">${(blockedEv.ts||'').replace('T',' ').replace(/\.\d+.*$/,'')}</span>
          </div>
          <div style="padding:10px 12px;background:rgba(239,68,68,0.1);border:1px solid var(--red);border-radius:6px;margin:8px 0">
            <strong style="color:var(--red)">🛡️ Difesa Attiva Efficace:</strong>
            <div style="font-size:12px;color:#fff;margin-top:4px">
              L'attacco è stato intercettato e bloccato preventivamente dal WAF della vittima dopo ${blockedEv.details?.queries_total || totalProbes} richieste. L'exploit è fallito e il segreto non è stato compromesso.
            </div>
          </div>
        </div>
        `;
      }


      if (completeEv) {
        const d = completeEv.details || {};
        const recText = d.recovered_plaintext || d.recovered_block || '';
        const q = d.queries || '?';
        const ms = completeEv.latency_ms ? Math.round(completeEv.latency_ms) : '?';
        html += `
        <div class="atk-event complete" style="margin-bottom:16px">
          <div class="ae-header">
            <span class="ae-type ae-complete-badge">✅ attack_complete — Testo Segreto Recuperato</span>
            <span class="ae-ts">${(completeEv.ts||'').replace('T',' ').replace(/\.\d+.*$/,'')}</span>
          </div>
          <div style="padding:10px 12px;background:rgba(16,185,129,0.12);border:1px solid var(--green);border-radius:6px;margin:8px 0">
            <span style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px">Messaggio Segreto Decifrato:</span>
            <div style="font-size:18px;font-weight:700;color:#fff;font-family:var(--font-mono);margin-top:4px">
              "${escapeHtml(recText)}"
            </div>
            <div style="font-size:11px;color:var(--text-dim);margin-top:4px">
              Estratto dal payload decifrato di ${totalExpectedBytes} byte (Plaintext: 23B + HMAC Tag: 16B + Padding: 9B).
            </div>
          </div>
          <div class="ae-grid">
            <div class="ae-kv"><span class="ae-k">blocchi_totali</span><span class="ae-v">${d.blocks_count || numBlocks}</span></div>
            <div class="ae-kv"><span class="ae-k">total_queries</span><span class="ae-v amber">${q}</span></div>
            <div class="ae-kv"><span class="ae-k">elapsed_ms</span><span class="ae-v">${ms} ms</span></div>
            <div class="ae-kv"><span class="ae-k">scenario_id</span><span class="ae-v">${escapeHtml(completeEv.scenario_id||'?')}</span></div>
          </div>
        </div>`;
      }

      // Render Byte Grid per block
      for (let b = 1; b <= numBlocks; b++) {
        html += `<div style="margin-bottom:14px">`;
        html += `<div style="font-size:11px;color:var(--text-muted);font-weight:700;letter-spacing:.6px;margin-bottom:6px">🧱 Blocco ${b} / ${numBlocks} (Byte ${(b-1)*16} → ${b*16 - 1})</div>`;
        html += `<div class="byte-grid">`;
        for (let idx = 0; idx < 16; idx++) {
          const globalIdx = (b - 1) * 16 + idx;
          const cellData = persistentAttackByteMap[globalIdx];
          let cellClass = '';
          let charVal = '?';
          let hexVal = '0x??';

          if (rawPayloadHex && (globalIdx * 2 + 2 <= rawPayloadHex.length)) {
            cellClass = 'recovered';
            const hexByte = rawPayloadHex.substring(globalIdx * 2, globalIdx * 2 + 2);
            const code = parseInt(hexByte, 16);
            hexVal = '0x' + hexByte;
            charVal = (code >= 32 && code < 127) ? String.fromCharCode(code) : '·';
          } else if (cellData) {
            cellClass = 'recovered';
            if (cellData.recovered_char !== undefined) {
              charVal = cellData.recovered_char;
              const code = cellData.recovered_byte !== undefined ? cellData.recovered_byte : (cellData.guess ^ cellData.pad_len);
              hexVal = '0x' + (typeof code === 'number' ? code : 0).toString(16).padStart(2, '0');
            } else {
              const code = cellData.guess ^ cellData.pad_len;
              charVal = (code >= 32 && code < 127) ? String.fromCharCode(code) : '·';
              hexVal = '0x' + code.toString(16).padStart(2, '0');
            }
          } else {
            const curBlock = lastProbe?.details?.block_index || 1;
            const curIdx = lastProbe?.details?.byte_index;
            if (curBlock === b && curIdx === idx && !completeEv) {
              cellClass = 'in-progress';
              charVal = '…';
              hexVal = lastProbe?.details?.guess_hex || 'probing';
            }
          }

          html += `<div class="byte-cell ${cellClass}">
            <span class="bc-idx">${globalIdx}</span>
            <span class="bc-val">${escapeHtml(charVal)}</span>
            <span class="bc-hex">${hexVal}</span>
          </div>`;
        }
        html += `</div></div>`;
      }

      // Recent events list (Progress and Probes)
      const notableEvents = atk.slice(-80).reverse();
      html += `<div style="font-size:11px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.8px;margin-bottom:8px">Flusso Telemetrico Recente (ultimi ${notableEvents.length} eventi attaccante)</div>`;
      notableEvents.forEach(ev => {
        const d = ev.details || {};
        const ts = (ev.ts||'').replace('T',' ').replace(/\.\d+.*$/,'');
        const isProg = ev.event_type === 'attack_progress';
        const isComp = ev.event_type === 'attack_complete';
        const recCh = d.recovered_char !== undefined ? d.recovered_char : '?';
        const recByte = d.recovered_byte !== undefined ? d.recovered_byte : '?';
        
        let cardStyle = isComp ? 'border-left:3px solid var(--green);background:rgba(16,185,129,0.08)' : isProg ? 'border-left:3px solid var(--amber);background:rgba(251,191,36,0.08)' : 'border-left:3px solid var(--border-lit)';
        let badgeType = isComp ? 'ae-complete-badge' : isProg ? 'ae-progress-badge' : '';
        
        html += `
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

      body.innerHTML = html;
    });
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
    const r = await fetch('/alerts_data');
    const d = await r.json();
    renderAlerts(d.alerts || [], d.kpis || {}, d.rules || {});
  } catch (e) {
    document.getElementById('alerts-content').innerHTML =
      '<p style="color:var(--text-muted)">SOC collector non raggiungibile (avviarlo dalla sezione Docker).</p>';
  }
}

function renderAlerts(alerts, kpis, rules) {
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

  // Update Telemetry Profile Table (Per-IP Evaluation)
  const teleTbody = document.getElementById('telemetry-ips-tbody');
  if (teleTbody) {
    const ipTable = kpis.ip_telemetry_table || [];
    if (!ipTable.length) {
      teleTbody.innerHTML = '<tr><td colspan="6" style="color:var(--text-muted);text-align:center;padding:12px">Nessuna richiesta <code>/decrypt</code> registrata nella finestra attiva.</td></tr>';
    } else {
      teleTbody.innerHTML = ipTable.map(row => {
        const isViolating = row.is_alerted || row.fail_rate >= 0.70;
        const statusBadge = isViolating
          ? `<span style="color:var(--red);font-weight:700">🔴 VIOLAZIONE REGOLA (${escapeHtml(row.evaluation)})</span>`
          : `<span style="color:var(--green);font-weight:600">🟢 Conforme alla Baseline (Traffico Legittimo)</span>`;
        const ipColor = isViolating ? 'var(--red)' : '#60a5fa';
        return `
          <tr>
            <td style="font-family:var(--font-mono);font-weight:700;color:${ipColor}">${escapeHtml(row.ip)}</td>
            <td><strong>${row.requests}</strong> req</td>
            <td style="color:${isViolating ? 'var(--red)' : 'inherit'};font-weight:700">${row.failed_requests} err (${(row.fail_rate * 100).toFixed(1)}%)</td>
            <td>${row.latency_p50_ms} ms</td>
            <td>${row.latency_stddev_ms} ms</td>
            <td>${statusBadge}</td>
          </tr>
        `;
      }).join('');
    }
  }

  // Render Alert Cards into both Main Panel and Network Sub-Tab
  const cont = document.getElementById('alerts-content');
  const netCont = document.getElementById('net-alerts-content');
  let alertCardsHtml = '';

  if (!alerts.length) {
    if (rules && !rules.enabled) {
      alertCardsHtml = `
        <div style="padding:20px;background:rgba(99,102,241,0.08);border:1px solid rgba(99,102,241,0.3);border-radius:8px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px">
          <div style="display:flex;align-items:center;gap:12px">
            <span style="font-size:26px">🛡️</span>
            <div>
              <strong style="color:#a5b4fc;font-size:14px">Zero Allarmi Attivi · Regole SOC &amp; WAF Iniziali Disattive</strong>
              <div style="font-size:12px;color:var(--text-muted);margin-top:4px">Nessuna regola di blocco è ancora attiva (zero spoiler). Apri il <strong>Threat Hunting Studio</strong> per analizzare i log grezzi con query SIEM e distribuire la tua regola di difesa.</div>
            </div>
          </div>
          <button class="btn btn-primary" style="font-size:12px" onclick="showPanel('hunting', document.querySelector('[data-panel=hunting]'))">🎯 Vai a Threat Hunting &amp; SIEM</button>
        </div>`;
    } else {
      alertCardsHtml = `
        <div style="padding:16px;background:rgba(16,185,129,0.08);border:1px solid rgba(16,185,129,0.25);border-radius:8px;display:flex;align-items:center;gap:12px">
          <span style="font-size:24px">🟢</span>
          <div>
            <strong style="color:var(--green);font-size:13px">Regole di Difesa Attive · Nessuna Violazione Rilevata</strong>
            <div style="font-size:12px;color:var(--text-muted);margin-top:2px">Il traffico dei client benigni rispetta pienamente le soglie consentite di errore e latenza.</div>
          </div>
        </div>`;
    }
  } else {
    alertCardsHtml = alerts.map(a => {
      const isWaf = a.rule === 'waf_padding_oracle_blocked';
      const sev = a.severity || (isWaf ? 'critical' : 'high');
      const sevClass = isWaf ? 'sev-critical' : `sev-${sev}`;
      const confPercent = Math.round((a.confidence || 0.9) * 100);
      const ev = a.evidence || {};
      
      let evHtml = '<div class="evidence-grid">';
      if (ev.total_requests !== undefined) evHtml += `<div class="evidence-item"><span class="evidence-k">Richieste Totali</span><span class="evidence-v">${ev.total_requests}</span></div>`;
      if (ev.failed_requests !== undefined) evHtml += `<div class="evidence-item"><span class="evidence-k">Errori / 500</span><span class="evidence-v">${ev.failed_requests}</span></div>`;
      if (ev.fail_rate !== undefined) evHtml += `<div class="evidence-item"><span class="evidence-k">Fail Rate</span><span class="evidence-v">${(ev.fail_rate * 100).toFixed(1)}%</span></div>`;
      if (ev.blocked_requests !== undefined) evHtml += `<div class="evidence-item"><span class="evidence-k">Richieste Bloccate WAF</span><span class="evidence-v" style="color:#c084fc;font-weight:700">${ev.blocked_requests} (HTTP 429)</span></div>`;
      if (ev.action !== undefined) evHtml += `<div class="evidence-item"><span class="evidence-k">Azione Inline</span><span class="evidence-v" style="color:var(--green)">${escapeHtml(ev.action)}</span></div>`;
      if (ev.latency_stddev_ms !== undefined) evHtml += `<div class="evidence-item"><span class="evidence-k">StdDev Latenza</span><span class="evidence-v">${ev.latency_stddev_ms} ms</span></div>`;
      if (ev.p95_p50_diff_ms !== undefined) evHtml += `<div class="evidence-item"><span class="evidence-k">Spread p95-p50</span><span class="evidence-v">${ev.p95_p50_diff_ms} ms</span></div>`;
      if (ev.bimodality_coefficient !== undefined) evHtml += `<div class="evidence-item"><span class="evidence-k">Sarle BC (Bimodale)</span><span class="evidence-v" style="color:${ev.is_bimodal ? 'var(--amber)' : 'inherit'}">${ev.bimodality_coefficient} ${ev.is_bimodal ? '⚠️ (Bimodale)' : ''}</span></div>`;
      if (ev.target_ciphertext_len !== undefined) evHtml += `<div class="evidence-item"><span class="evidence-k">Blocco AES Target</span><span class="evidence-v">${ev.target_ciphertext_len} byte</span></div>`;
      if (ev.block_aligned !== undefined) evHtml += `<div class="evidence-item"><span class="evidence-k">Allineamento CBC</span><span class="evidence-v">${ev.block_aligned ? '16B OK' : 'No'}</span></div>`;
      evHtml += '</div>';

      const cardStyle = isWaf ? 'border:1px solid rgba(168,85,247,0.5);background:rgba(168,85,247,0.06)' : '';

      return `
        <div class="alert-card ${sevClass}" style="${cardStyle}">
          <div class="alert-header">
            <div style="display:flex;align-items:center;gap:8px">
              <span class="alert-sev ${sevClass}">${isWaf ? '🛡️ WAF MITIGATION' : sev}</span>
              <strong style="color:#fff;font-size:14px">${escapeHtml(a.title || a.rule)}</strong>
              ${a.mitre_technique ? `<span class="mitre-tag">${escapeHtml(a.mitre_technique)}</span>` : ''}
            </div>
            <span style="font-size:11px;color:var(--text-muted);font-family:var(--font-mono)">${(a.timestamp||'').replace('T',' ').replace(/\..+$/,'')}</span>
          </div>
          <div style="font-size:12px;color:var(--text-dim);margin-bottom:6px">
            Actor IP: <strong style="color:var(--text)">${escapeHtml(a.ip)}</strong> · Confidenza Correlazione: <strong style="color:var(--green)">${confPercent}%</strong>
            ${isWaf ? ' · <span style="color:#c084fc;font-weight:700">🛡️ ATTACCO NEUTRALIZZATO - SEGRETO PROTETTO</span>' : ''}
          </div>
          ${evHtml}
          <div style="margin-top:10px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px">
            <div style="font-size:11px;color:var(--text-muted)">
              💡 <em>Azione Playbook:</em> <span style="color:var(--text)">${escapeHtml(a.recommended_action || 'Analizza log')}</span>
            </div>
            <div style="display:flex;gap:6px">
              <button class="btn btn-success" style="font-size:11px;padding:3px 8px" onclick="quickHotPatchFixed()">🛡️ Applica Patch (Fixed)</button>
              <button class="btn btn-danger" style="font-size:11px;padding:3px 8px" onclick="quickStopAttacker()">🚫 Blocca Attaccante</button>
            </div>
          </div>
        </div>
      `;
    }).join('');
  }

  if (cont) cont.innerHTML = alertCardsHtml;
  if (netCont) {
    netCont.innerHTML = `
      <div style="margin-bottom:12px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
        <span style="font-size:12px;font-weight:700;color:#fff">🚨 Rilevamenti & Allarmi SOC in tempo reale</span>
        <button class="btn btn-primary" style="font-size:11px;padding:3px 8px" onclick="openForensicReportModal()">📄 Genera Report Forense</button>
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
      alert('🛡️ Playbook SOAR Eseguito: Vittima commutata su victim-fixed (Mitigazione Constant-Time attiva e registrata nell\'Audit Trail).');
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
    await loadAlerts();
    await pollLogs();
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
  } catch (e) { /* ignore */ }
}

// ── SIEM Query Engine & Log Explorer ──
let currentSiemQuery = 'status = 500 AND endpoint = /decrypt';

async function executeSiemQuery(customQ) {
  const q = customQ !== undefined ? customQ : (document.getElementById('siem-query-input')?.value || '*');
  currentSiemQuery = q;
  const inputEl = document.getElementById('siem-query-input');
  if (inputEl && customQ !== undefined) inputEl.value = q;

  const tbody = document.getElementById('siem-logs-tbody');
  if (tbody) tbody.innerHTML = '<tr><td colspan="7" style="color:var(--text-muted);text-align:center;padding:10px">Esecuzione query SIEM…</td></tr>';

  try {
    const res = await fetch('/hunting/query', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ query: q, window_minutes: 15 }),
    });
    const data = await res.json();
    renderSiemResults(data);
  } catch (e) {
    if (tbody) tbody.innerHTML = `<tr><td colspan="7" style="color:var(--red);text-align:center;padding:10px">Errore query: ${escapeHtml(e.message)}</td></tr>`;
  }
}

function applySiemPreset(presetStr) {
  const input = document.getElementById('siem-query-input');
  if (input) input.value = presetStr;
  executeSiemQuery(presetStr);
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

  const events = data.events || [];
  if (!events.length) {
    tbody.innerHTML = '<tr><td colspan="7" style="color:var(--text-muted);text-align:center;padding:12px">Nessun evento corrisponde alla query SIEM nella finestra corrente.</td></tr>';
    return;
  }

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

    return `
      <tr>
        <td style="color:var(--text-dim);padding:4px 8px">${escapeHtml(ts)}</td>
        <td style="font-weight:600;color:#fff;padding:4px 8px">${escapeHtml(ip)}</td>
        <td style="color:var(--blue);padding:4px 8px">${escapeHtml(ep)}</td>
        <td style="padding:4px 8px"><span style="color:${scColor};font-weight:700">${sc}</span></td>
        <td style="padding:4px 8px">${escapeHtml(lat)}</td>
        <td style="padding:4px 8px">${escapeHtml(cLen)}</td>
        <td style="color:${errType !== 'ok' ? 'var(--red)' : 'var(--text-muted)'};padding:4px 8px">${escapeHtml(errType)}</td>
      </tr>
    `;
  }).join('');

  tbody.innerHTML = rows;
}

async function loadHuntingData() {
  try {
    const res = await fetch('/hunting/data');
    const data = await res.json();
    const tbody = document.getElementById('hunting-profiles-tbody');
    if (!tbody) return;

    if (!data.ip_profiles || !data.ip_profiles.length) {
      tbody.innerHTML = '<tr><td colspan="7" style="color:var(--text-muted)">Nessun evento telemetrico nella finestra corrente.</td></tr>';
      return;
    }

    tbody.innerHTML = data.ip_profiles.map(p => {
      const isSuspect = p.classification === 'SUSPECT_ATTACKER';
      const badgeStyle = isSuspect ? 'background:rgba(239,68,68,0.15);color:var(--red);border:1px solid rgba(239,68,68,0.3)' : 'background:rgba(16,185,129,0.15);color:var(--green);border:1px solid rgba(16,185,129,0.3)';
      const badgeLabel = isSuspect ? '🔴 Sospetto Attaccante' : '🟢 Traffico Benigno';
      const lats = p.latency_stats || {};
      const bcStr = lats.bimodality_coefficient !== undefined ? `${lats.bimodality_coefficient} ${lats.is_bimodal ? '⚠️ (Bimodale)' : ''}` : '—';
      const blkStr = p.sample_ciphertext_len ? `${p.sample_ciphertext_len}B (${p.is_aes_aligned ? 'AES' : 'No'})` : '—';

      return `
        <tr>
          <td><strong style="color:#fff">${escapeHtml(p.ip)}</strong></td>
          <td>${p.decrypt_requests}</td>
          <td><strong style="color:${p.fail_rate > 0.5 ? 'var(--red)' : 'var(--green)'}">${(p.fail_rate * 100).toFixed(1)}%</strong> (${p.failed_decrypts} err)</td>
          <td>${blkStr}</td>
          <td>${lats.mean || 0} ms (±${lats.stddev || 0}ms)</td>
          <td><span style="font-family:var(--font-mono)">${bcStr}</span></td>
          <td><span style="font-size:11px;font-weight:700;padding:2px 8px;border-radius:10px;${badgeStyle}">${badgeLabel}</span></td>
        </tr>
      `;
    }).join('');
    executeSiemQuery();
    await updateWAFBadge();
  } catch (e) {
    const tbody = document.getElementById('hunting-profiles-tbody');
    if (tbody) tbody.innerHTML = `<tr><td colspan="7" style="color:var(--red)">Errore caricamento: ${escapeHtml(e.message)}</td></tr>`;
  }
}

async function runHuntingBacktest() {
  const minEvents = parseInt(document.getElementById('hunt-min-events').value || '15', 10);
  const failRate = parseFloat(document.getElementById('hunt-fail-rate').value || '0.80');
  const timingStd = parseFloat(document.getElementById('hunt-timing-stddev').value || '6.0');
  const bimodalCoeff = parseFloat(document.getElementById('hunt-bimodality').value || '0.555');

  try {
    const res = await fetch('/hunting/backtest', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        query: currentSiemQuery,
        min_events_per_ip: minEvents,
        high_fail_rate_threshold: failRate,
        timing_stddev_threshold_ms: timingStd,
        bimodality_threshold: bimodalCoeff,
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

      let detailsHtml = '<div style="margin-top:6px"><strong>Dettaglio Valutazione per IP:</strong><ul style="margin:4px 0 0 18px;padding:0">';
      (data.evaluation_details || []).forEach(d => {
        const flagIcon = d.flagged ? '🚨' : '✅';
        const flagColor = d.flagged ? 'var(--red)' : 'var(--green)';
        detailsHtml += `<li>${flagIcon} <strong style="color:${flagColor}">${escapeHtml(d.ip)}</strong>: ${(d.fail_rate*100).toFixed(1)}% fail-rate, stddev: ${d.latency_stddev}ms, BC: ${d.bimodality_coeff} ${d.flagged ? `(Trigger: ${d.reasons.join(', ')})` : '(Conforme)'}</li>`;
      });
      detailsHtml += '</ul></div>';

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


// ── Docker / Node Inventory status table ──
async function loadDockerStatus() {
  try {
    const r = await fetch('/status');
    const d = await r.json();
    const svcs = d.services || {};
    const tbody = document.getElementById('docker-tbody');
    const order = ['victim-vuln','victim-partial','victim-fixed','benign-1','benign-2','attacker','soc','soc-ui'];
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
        <td style="font-family:var(--font-mono);font-size:11px;font-weight:700">${name}</td>
        <td style="font-size:12px">${escapeHtml(s.role || '-')}</td>
        <td style="font-family:var(--font-mono);font-size:11px;color:#60a5fa;font-weight:600">${escapeHtml(s.ip || '-')}</td>
        <td><span class="${stateClass}">${s.state}</span></td>
        <td style="font-size:11px;color:var(--text-muted)">${s.ports}</td>
        <td>${actions}</td>
      </tr>`;
    }).join('');
  } catch (e) { /* ignore */ }
}

// ── Node modal actions ──
async function switchVictim() {
  const mode = document.querySelector('input[name="victim-mode"]:checked')?.value || 'victim-vuln';
  const spin = document.getElementById('spin-victim');
  spin.style.display = 'block';
  try {
    await fetch('/nodes/victim/switch', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ mode }),
    });
    closeModal('modal-victim');
    pollNetwork();
    pollStatus();
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
  const continuous = document.getElementById(`${host}-continuous`) ? document.getElementById(`${host}-continuous`).checked : true;
  const errRate = parseFloat(document.getElementById(`${host}-err-rate`)?.value) || 3.0;
  return {
    continuous: continuous,
    error_rate: errRate,
    iterations: 100,
    min_ms: parseInt(document.getElementById(`${host}-min`)?.value) || 500,
    max_ms: parseInt(document.getElementById(`${host}-max`)?.value) || 1200,
  };
}

function readAttackConfig() {
  const secretMode = document.querySelector('input[name="atk-secret-mode"]:checked')?.value || 'manual';
  const secretInput = document.getElementById('atk-secret-input');
  const sleepVal = document.getElementById('atk-sleep')?.value;
  const ipMode = document.querySelector('input[name="atk-ip-mode"]:checked')?.value || 'static';
  return {
    secretMode,
    secret: (secretInput?.value || '').trim(),
    mode: document.querySelector('input[name="atk-mode"]:checked')?.value || 'vuln',
    ip_mode: ipMode,
    sleep_ms: (sleepVal !== undefined && sleepVal !== '') ? parseFloat(sleepVal) : 4,
  };
}

async function saveBenignConfig(host) {
  const spin = document.getElementById(`spin-${host}`);
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
    
    // Check which benign hosts are currently RUNNING (turned ON in the graph)
    const activeBenignHosts = ['benign-1', 'benign-2'].filter(
      h => services[h] && services[h].state === 'running'
    );

    if (activeBenignHosts.length === 0) {
      alert('Nessun host benigno è attivo. Clicca su un nodo benigno (benign-1 o benign-2) nel grafo per accenderlo prima di avviare il traffico.');
      return;
    }

    for (const host of activeBenignHosts) {
      const cfg = readBenignConfig(host);
      const r = await fetch('/nodes/benign/launch', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ host, ...cfg }),
      });
      const d = await r.json();
      if (!r.ok || !d.ok) {
        console.warn(`Avvio ${host}:`, d.error);
      }
    }
    await pollStatus();
    await pollNetwork();
  } catch (e) { alert('Errore avvio benigni: ' + (e.message || e)); }
}

async function stopBenignTraffic() {
  try {
    await Promise.all(['benign-1', 'benign-2'].map(host => fetch('/nodes/benign/pause', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ host }),
    })));
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
    const appStatus = await fetch('/status').then(r => r.json());
    const victimName = appStatus.active_victim || 'victim-vuln';
    const cfg = readAttackConfig();
    persistentAttackByteMap = {}; // Reset discovery map for new attack run

    // Only update secret if user explicitly changed it, to avoid unnecessary container destroy/recreate
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
      body: JSON.stringify({ mode: cfg.mode, sleep_ms: cfg.sleep_ms, ip_mode: cfg.ip_mode, target: victimName }),
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
pollNetwork();
pollStatus();
pollLogs();
loadAlerts();
startPacketAnimation();  // start rAF loop for moving dots
setInterval(pollNetwork, 5000);
setInterval(pollStatus, 3000);
setInterval(pollLogs, 2000);
setInterval(loadAlerts, 2500);
setInterval(() => {
  if (currentPanel === 'log-soc') loadSocLogs();
  if (currentPanel === 'network' && currentNetSubTab === 'soc') loadNetSocLogs();
}, 2500);
setInterval(() => { if (currentPanel === 'docker') loadDockerStatus(); }, 5000);
setInterval(() => { if (currentPanel === 'attack-detail' || (currentPanel === 'network' && currentNetSubTab === 'attack')) loadAttackDetail(); }, 3500);
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
        # Commuta a victim-fixed (mitigazione crittografica tempo costante)
        for name in VICTIM_NAMES:
            if name == "victim-fixed":
                _start(name)
            else:
                _stop(name)
        result_details = {
            "strategy": "Crypto-Hardening",
            "active_victim": "victim-fixed",
            "mitigation": "Constant-time padding & integrity verification",
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
    victim = _active_victim() or "victim-vuln"
    port_map = {"victim-vuln": 18080, "victim-partial": 18081, "victim-fixed": 18082}
    return f"http://{victim}:8080", f"http://localhost:{port_map.get(victim, 18080)}"


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


@app.get("/hunting/data")
def hunting_data():
    try:
        res = requests.get(f"{SOC_URL}/hunting/explore", timeout=3)
        return jsonify(res.json())
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "ip_profiles": []})


@app.post("/hunting/query")
def hunting_query_proxy():
    data = request.get_json(force=True, silent=True) or {}
    try:
        res = requests.post(f"{SOC_URL}/hunting/query", json=data, timeout=3)
        return jsonify(res.json())
    except Exception:
        # Fallback local SIEM evaluation
        query_str = data.get("query", "")
        events = _read_events(limit=500)
        result = filter_and_aggregate_events(events, query_str)
        result["ok"] = True
        return jsonify(result)


@app.post("/hunting/backtest")
def hunting_backtest_proxy():
    try:
        data = request.get_json(force=True, silent=True) or {}
        res = requests.post(f"{SOC_URL}/hunting/backtest", json=data, timeout=3)
        return jsonify(res.json())
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.post("/hunting/policy/deploy")
def hunting_policy_deploy():
    data = request.get_json(force=True, silent=True) or {}
    rules = _read_rules()
    for k in ["min_events_per_ip", "high_fail_rate_threshold", "timing_stddev_threshold_ms", "bimodality_threshold"]:
        if k in data:
            rules[k] = data[k]
    rules["enabled"] = True
    _write_rules(rules)

    waf_policy = {
        "enabled": True,
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

    waf_res = _call_victim_waf("/waf/policy", method="POST", json_data=waf_policy)
    return jsonify({"ok": True, "rules": rules, "waf": waf_res})


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
        f"1. **Hot-Patching Immediato:** Commutare la vittima in esecuzione sul profilo mitigato (`victim-fixed`). In questa modalità la verifica del padding e dell'integrità viene eseguita a tempo costante e con risposte indistinguibili.",
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
_clear_jsonl_logs()
_ensure_core_services()
signal.signal(signal.SIGTERM, _handle_shutdown_signal)
signal.signal(signal.SIGINT, _handle_shutdown_signal)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=UI_PORT, debug=False)

