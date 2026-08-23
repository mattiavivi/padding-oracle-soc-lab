import json
import os
import time
from datetime import datetime, timezone

from flask import Flask, jsonify, request

from common.crypto_utils import b64d, b64e, encrypt_token, verify_and_extract
from common.event_logger import emit_event


app = Flask(__name__)

MODE = os.getenv("VICTIM_MODE", "vuln").strip()
SCENARIO_ID = os.getenv("SCENARIO_ID", "default")
SECRET_MESSAGE = os.getenv("SECRET_MESSAGE", "PaddingOracle:TopSecret")

# ---------------------------------------------------------------------------
# Inline WAF Protection & Sliding-Window Inspection
# ---------------------------------------------------------------------------
WAF_POLICY_FILE = os.getenv(
    "WAF_POLICY_FILE",
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "control", "waf_policy.json"),
)


def _load_waf_policy() -> dict:
    default_policy = {
        "enabled": False,
        "min_requests_window": 15,
        "max_fail_rate": 0.80,
        "max_consecutive_errors": 12,
        "window_seconds": 60,
        "action": "429_too_many_requests",
    }
    if os.path.exists(WAF_POLICY_FILE):
        try:
            with open(WAF_POLICY_FILE, "r", encoding="utf-8") as f:
                saved = json.load(f)
                default_policy.update(saved)
        except Exception:
            pass
    return default_policy


def _save_waf_policy(policy: dict) -> None:
    try:
        os.makedirs(os.path.dirname(WAF_POLICY_FILE), exist_ok=True)
        with open(WAF_POLICY_FILE, "w", encoding="utf-8") as f:
            json.dump(policy, f, indent=2)
    except Exception:
        pass


WAF_POLICY = _load_waf_policy()

# In-memory sliding-window log per IP: list of (timestamp_float, is_error_bool)
WAF_STATE: dict[str, list[tuple[float, bool]]] = {}
WAF_BLOCKED_IPS: set[str] = set()


def _check_waf_block(ip: str) -> tuple[bool, str | None]:
    """Valuta la sliding-window dell'IP sorgente rispetto alla policy WAF attiva."""
    if not WAF_POLICY.get("enabled"):
        return False, None

    if ip in WAF_BLOCKED_IPS:
        return True, f"IP '{ip}' bloccato preventivamente dalla policy WAF"


    now = time.time()
    window_sec = float(WAF_POLICY.get("window_seconds", 60))
    history = WAF_STATE.get(ip, [])
    valid = [h for h in history if now - h[0] <= window_sec]
    WAF_STATE[ip] = valid

    total = len(valid)
    min_reqs = int(WAF_POLICY.get("min_requests_window", 15))
    max_rate = float(WAF_POLICY.get("max_fail_rate", 0.80))
    max_consec = int(WAF_POLICY.get("max_consecutive_errors", 12))

    if total >= min_reqs:
        errors = sum(1 for h in valid if h[1])
        fail_rate = errors / total
        if fail_rate >= max_rate:
            WAF_BLOCKED_IPS.add(ip)
            return True, f"Fail-rate anomalo ({fail_rate*100:.1f}% >= {max_rate*100:.1f}%)"

    consec = 0
    for _, is_err in reversed(valid):
        if is_err:
            consec += 1
        else:
            break
    if consec >= max_consec:
        WAF_BLOCKED_IPS.add(ip)
        return True, f"Errori crittografici consecutivi ({consec} >= {max_consec})"

    return False, None


def _record_waf_outcome(ip: str, is_error: bool) -> None:
    if ip not in WAF_STATE:
        WAF_STATE[ip] = []
    WAF_STATE[ip].append((time.time(), is_error))


def _client_ip() -> str:
    client_id = request.headers.get("X-Client-ID") or request.headers.get("X-Client-Role")
    if client_id:
        return client_id.strip()
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _log_request(
    endpoint: str,
    status_code: int,
    latency_ms: float,
    ciphertext_len: int,
    error_type: str,
    extra_details: dict | None = None,
) -> None:
    details = {
        "server_time": datetime.now(timezone.utc).isoformat(),
        "client_role": request.headers.get("X-Client-Role", "unknown"),
        "client_id": request.headers.get("X-Client-ID", _client_ip()),
    }
    if extra_details:
        details.update(extra_details)

    emit_event(
        "victim",
        {
            "event_type": "http_request",
            "scenario_id": SCENARIO_ID,
            "src_ip": _client_ip(),
            "endpoint": endpoint,
            "status_code": status_code,
            "latency_ms": round(latency_ms, 3),
            "ciphertext_len": ciphertext_len,
            "error_type": error_type,
            "mode": MODE,
            "details": details,
        },
    )


@app.get("/health")
def health():
    return jsonify({"status": "ok", "mode": MODE, "waf_enabled": WAF_POLICY.get("enabled", False)})


@app.get("/waf/status")
def waf_status():
    return jsonify({
        "policy": WAF_POLICY,
        "blocked_ips": list(WAF_BLOCKED_IPS),
        "tracked_ips_count": len(WAF_STATE),
    })


@app.post("/waf/policy")
def waf_set_policy():
    data = request.get_json(force=True, silent=True) or {}
    for k in ["enabled", "min_requests_window", "max_fail_rate", "max_consecutive_errors", "window_seconds", "action"]:
        if k in data:
            WAF_POLICY[k] = data[k]
    _save_waf_policy(WAF_POLICY)
    return jsonify({"ok": True, "policy": WAF_POLICY})



@app.post("/waf/reset")
def waf_reset():
    WAF_BLOCKED_IPS.clear()
    WAF_STATE.clear()
    return jsonify({"ok": True, "message": "WAF memory state reset"})


@app.get("/sample_token")
def sample_token():
    token = encrypt_token(SECRET_MESSAGE.encode("utf-8"))
    return jsonify({"token": b64e(token), "mode": MODE})


@app.post("/encrypt")
def encrypt():
    body = request.get_json(force=True, silent=True) or {}
    plaintext = str(body.get("plaintext", "hello")).encode("utf-8")
    token = encrypt_token(plaintext)
    return jsonify({"token": b64e(token), "length": len(token)})


@app.post("/decrypt")
def decrypt():
    start = time.perf_counter()
    ip = _client_ip()

    # --- Fast-Path: WAF Pre-Inspection ---
    is_blocked, block_reason = _check_waf_block(ip)
    if is_blocked:
        latency_ms = (time.perf_counter() - start) * 1000
        _log_request("/decrypt", 429, latency_ms, 0, "waf_blocked", extra_details={"waf_reason": block_reason})
        return jsonify({
            "error": "WAF_PREVENTIVE_BLOCK",
            "message": "Access denied by Cryptographic Threat Detection WAF",
            "reason": block_reason,
            "src_ip": ip,
        }), 429

    body = request.get_json(force=True, silent=True) or {}
    token_b64 = body.get("token")
    if not isinstance(token_b64, str):
        latency_ms = (time.perf_counter() - start) * 1000
        _record_waf_outcome(ip, is_error=True)
        _log_request("/decrypt", 400, latency_ms, 0, "bad_request")
        return jsonify({"result": "invalid_request"}), 400

    try:
        token = b64d(token_b64)
    except Exception:
        latency_ms = (time.perf_counter() - start) * 1000
        _record_waf_outcome(ip, is_error=True)
        _log_request("/decrypt", 400, latency_ms, 0, "bad_b64")
        return jsonify({"result": "invalid_request"}), 400

    plaintext, outcome = verify_and_extract(token)
    status = 200
    response = {"result": "ok"}
    error_type = "ok"
    is_crypto_error = outcome != "ok"

    if MODE == "vuln":
        if outcome == "padding_error":
            status = 500
            response = {"result": "padding_error"}
            error_type = "padding_error"
        elif outcome == "integrity_error":
            status = 403
            response = {"result": "integrity_error"}
            error_type = "integrity_error"
    elif MODE == "partial":
        if outcome == "padding_error":
            time.sleep(0.03)
        elif outcome == "integrity_error":
            time.sleep(0.005)
        if outcome != "ok":
            status = 403
            response = {"result": "request_denied"}
            error_type = outcome
    elif MODE == "fixed":
        if outcome != "ok":
            time.sleep(0.015)
            status = 403
            response = {"result": "request_denied"}
            error_type = "generic_error"
    else:
        if outcome != "ok":
            status = 403
            response = {"result": "request_denied"}
            error_type = "generic_error"

    # Record outcome in WAF state for subsequent requests
    _record_waf_outcome(ip, is_error=is_crypto_error)

    latency_ms = (time.perf_counter() - start) * 1000
    _log_request("/decrypt", status, latency_ms, len(token), error_type)
    if plaintext is None:
        return jsonify(response), status
    return jsonify({"result": "ok", "plaintext": plaintext.decode("utf-8", errors="ignore")})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)

