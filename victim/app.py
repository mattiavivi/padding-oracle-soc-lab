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


@app.post("/mode")
@app.post("/api/v1/mode")
def set_mode():
    global MODE
    data = request.get_json(force=True, silent=True) or {}
    new_mode = data.get("mode", "").strip()
    if new_mode in ("vuln", "partial", "fixed"):
        MODE = new_mode
        return jsonify({"ok": True, "mode": MODE, "message": f"Victim mode switched to {MODE}"})
    return jsonify({"ok": False, "error": "Invalid mode. Choose vuln, partial, or fixed"}), 400


# ---------------------------------------------------------------------------
# Inline WAF Protection & Sliding-Window Inspection
# ---------------------------------------------------------------------------
WAF_POLICY_FILE = os.getenv(
    "WAF_POLICY_FILE",
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "control", "waf_policy.json"),
)


def _default_waf_rules() -> list[dict]:
    return [
        {
            "id": "waf_rate_limit_flooding",
            "name": "WAF-01: Padding Error Flooding & High Fail-Rate Ban",
            "description": "Blocca IP quando il fail-rate supera la soglia con burst di richieste",
            "endpoint": "/decrypt",
            "enabled": True,
            "min_requests_window": 15,
            "max_fail_rate": 0.80,
            "max_consecutive_errors": 12,
            "window_seconds": 60,
            "ban_ttl_seconds": 120,
        },
        {
            "id": "waf_consecutive_probing",
            "name": "WAF-02: Consecutive CBC Byte-Probing Mitigation",
            "description": "Blocca IP immediatamente dopo una sequenza ininterrotta di errori crittografici",
            "endpoint": "/decrypt",
            "enabled": True,
            "min_requests_window": 8,
            "max_fail_rate": 0.90,
            "max_consecutive_errors": 8,
            "window_seconds": 60,
            "ban_ttl_seconds": 180,
        },
        {
            "id": "waf_login_bruteforce_defense",
            "name": "WAF-03: Login Brute-Force & Credential Spraying Shield",
            "description": "Blocca tentativi ripetuti di autenticazione fallita (HTTP 401)",
            "endpoint": "/api/v1/auth/login",
            "enabled": True,
            "min_requests_window": 5,
            "max_fail_rate": 0.80,
            "max_consecutive_errors": 5,
            "window_seconds": 60,
            "ban_ttl_seconds": 120,
        }
    ]


def _load_waf_policy() -> dict:
    default_policy = {
        "enabled": False,
        "min_requests_window": 15,
        "max_fail_rate": 0.80,
        "max_consecutive_errors": 12,
        "window_seconds": 60,
        "ban_ttl_seconds": 120,
        "action": "429_too_many_requests",
        "rules": _default_waf_rules(),
    }
    if os.path.exists(WAF_POLICY_FILE):
        try:
            with open(WAF_POLICY_FILE, "r", encoding="utf-8") as f:
                saved = json.load(f)
                default_policy.update(saved)
                if "rules" not in saved or not isinstance(saved["rules"], list):
                    default_policy["rules"] = _default_waf_rules()
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


class WafBlockList:
    """Thread-safe and TTL-aware IP Block table compatible with set[str] interface and per-endpoint scoping."""

    def __init__(self):
        self._blocked: dict[tuple[str, str | None], float] = {}

    def add(self, ip: str, ttl_seconds: float = 0.0, endpoint: str | None = "/decrypt") -> None:
        expire_ts = (time.time() + ttl_seconds) if ttl_seconds > 0 else 0.0
        self._blocked[(ip, endpoint)] = expire_ts

    def block(self, ip: str, ttl_seconds: float = 0.0, endpoint: str | None = "/decrypt") -> None:
        self.add(ip, ttl_seconds, endpoint)

    def remove(self, ip: str, endpoint: str | None = None) -> None:
        if endpoint is not None:
            self._blocked.pop((ip, endpoint), None)
        else:
            to_del = [k for k in self._blocked if k[0] == ip]
            for k in to_del:
                del self._blocked[k]

    def discard(self, ip: str) -> None:
        self.remove(ip)

    def clear(self) -> None:
        self._blocked.clear()

    def is_blocked(self, ip: str, endpoint: str | None = "/decrypt") -> bool:
        now = time.time()
        for (b_ip, b_ep), exp in list(self._blocked.items()):
            if exp > 0.0 and now > exp:
                del self._blocked[(b_ip, b_ep)]
                continue
            if b_ip == ip:
                if b_ep is None or endpoint is None:
                    return True
                if b_ep in endpoint or endpoint in b_ep:
                    return True
        return False

    def __contains__(self, ip: str) -> bool:
        now = time.time()
        for (b_ip, b_ep), exp in list(self._blocked.items()):
            if exp > 0.0 and now > exp:
                del self._blocked[(b_ip, b_ep)]
                continue
            if b_ip == ip:
                return True
        return False

    def __iter__(self):
        now = time.time()
        valid_ips = set()
        for (b_ip, b_ep), exp in list(self._blocked.items()):
            if exp <= 0.0 or exp > now:
                valid_ips.add(b_ip)
        return iter(valid_ips)

    def __len__(self) -> int:
        now = time.time()
        valid_ips = set()
        for (b_ip, b_ep), exp in list(self._blocked.items()):
            if exp <= 0.0 or exp > now:
                valid_ips.add(b_ip)
        return len(valid_ips)

    def get_ttl(self, ip: str, endpoint: str | None = None) -> float | None:
        now = time.time()
        matching_ttls = []
        for (b_ip, b_ep), exp in list(self._blocked.items()):
            if exp <= 0.0:
                continue
            if b_ip == ip:
                if endpoint is None or b_ep is None or b_ep in endpoint or endpoint in b_ep:
                    if exp > now:
                        matching_ttls.append(exp - now)
        return max(matching_ttls) if matching_ttls else None

    def to_list(self) -> list[str]:
        return list(self)


# In-memory sliding-window log per IP: list of (timestamp_float, is_error_bool, endpoint_str)
WAF_STATE: dict[str, list[tuple[float, bool, str]]] = {}
WAF_BLOCKED_IPS: WafBlockList = WafBlockList()


def _check_waf_block(ip: str, endpoint: str = "/decrypt") -> tuple[bool, str | None]:
    """Valuta la sliding-window dell'IP sorgente rispetto alle policy WAF attive con scoping per endpoint."""
    if not WAF_POLICY.get("enabled"):
        return False, None

    if WAF_BLOCKED_IPS.is_blocked(ip, endpoint):
        remaining_ttl = WAF_BLOCKED_IPS.get_ttl(ip, endpoint)
        ttl_info = f" (TTL rimanente: {int(remaining_ttl)}s)" if remaining_ttl is not None else ""
        return True, f"IP '{ip}' bloccato preventivamente dalla policy WAF su '{endpoint}'{ttl_info}"

    now = time.time()
    history = WAF_STATE.get(ip, [])

    rules_list = WAF_POLICY.get("rules")
    if not isinstance(rules_list, list) or not rules_list:
        # Fallback a singola regola retrocompatibile
        rules_list = [{
            "id": "default_padding_oracle_block",
            "name": "Default Padding Oracle & Burst Block",
            "endpoint": "/decrypt",
            "enabled": True,
            "min_requests_window": WAF_POLICY.get("min_requests_window", 15),
            "max_fail_rate": WAF_POLICY.get("max_fail_rate", 0.80),
            "max_consecutive_errors": WAF_POLICY.get("max_consecutive_errors", 12),
            "window_seconds": WAF_POLICY.get("window_seconds", 60),
            "ban_ttl_seconds": WAF_POLICY.get("ban_ttl_seconds", 120),
        }]

    # Pulizia storia oltre la finestra massima attiva
    max_window = max([float(r.get("window_seconds", 60)) for r in rules_list if r.get("enabled", True)] or [60.0])
    valid_global = [h for h in history if now - h[0] <= max_window]
    WAF_STATE[ip] = valid_global

    # Itera su ciascuna regola attiva
    for rule in rules_list:
        if not rule.get("enabled", True):
            continue

        rule_endpoint = rule.get("endpoint", "/decrypt")
        is_endpoint_match = (
            not rule_endpoint
            or rule_endpoint in ("*", "/")
            or not endpoint
            or (rule_endpoint in endpoint or endpoint in rule_endpoint)
        )
        if not is_endpoint_match:
            continue

        window_sec = float(rule.get("window_seconds", WAF_POLICY.get("window_seconds", 60)))
        ban_ttl = float(rule.get("ban_ttl_seconds", WAF_POLICY.get("ban_ttl_seconds", 120)))
        
        # Filtra la storia considerando solo gli eventi pertinenti all'endpoint della regola
        valid = []
        for h in valid_global:
            if now - h[0] <= window_sec:
                h_ep = h[2] if len(h) >= 3 else "/decrypt"
                if (
                    not rule_endpoint
                    or rule_endpoint in ("*", "/")
                    or (rule_endpoint in h_ep or h_ep in rule_endpoint)
                ):
                    valid.append(h)

        total = len(valid)
        min_reqs = int(rule.get("min_requests_window", WAF_POLICY.get("min_requests_window", 15)))
        max_rate = float(rule.get("max_fail_rate", WAF_POLICY.get("max_fail_rate", 0.80)))
        max_consec = int(min(rule.get("max_consecutive_errors", 12), WAF_POLICY.get("max_consecutive_errors", 12)))
        rule_name = rule.get("name", rule.get("id", "WAF Rule"))

        if total >= min_reqs:
            errors = sum(1 for h in valid if h[1])
            fail_rate = errors / total
            if fail_rate >= max_rate:
                WAF_BLOCKED_IPS.add(ip, ttl_seconds=ban_ttl, endpoint=rule_endpoint)
                return True, f"[{rule_name}] Fail-rate anomalo ({fail_rate*100:.1f}% >= {max_rate*100:.1f}%) su {rule_endpoint} [Auto-ban {int(ban_ttl)}s]"

        consec = 0
        for h in reversed(valid):
            if h[1]:
                consec += 1
            else:
                break
        if consec >= max_consec:
            WAF_BLOCKED_IPS.add(ip, ttl_seconds=ban_ttl, endpoint=rule_endpoint)
            return True, f"[{rule_name}] Errori consecutivi ({consec} >= {max_consec}) su {rule_endpoint} [Auto-ban {int(ban_ttl)}s]"

    return False, None


def _record_waf_outcome(ip: str, is_error: bool, endpoint: str = "/decrypt") -> None:
    if ip not in WAF_STATE:
        WAF_STATE[ip] = []
    WAF_STATE[ip].append((time.time(), is_error, endpoint))


EXEMPT_WAF_PATHS = ("/health", "/api/v1/health", "/mode", "/api/v1/mode", "/metrics")


@app.before_request
def waf_inbound_filter():
    """Middleware WAF Layer 7 universale: ispezione preventiva trasparente per tutte le route applicative."""
    request._waf_start_time = time.perf_counter()
    if not WAF_POLICY.get("enabled"):
        return None

    # Escludi endpoint di diagnostica, gestione o statici
    if request.path in EXEMPT_WAF_PATHS or request.path.startswith("/waf/"):
        return None

    ip = _client_ip()
    is_blocked, block_reason = _check_waf_block(ip, endpoint=request.path)
    if is_blocked:
        latency_ms = (time.perf_counter() - request._waf_start_time) * 1000
        _log_request(
            request.path,
            429,
            latency_ms,
            0,
            "waf_blocked",
            extra_details={"waf_reason": block_reason},
        )
        return jsonify({
            "error": "WAF_PREVENTIVE_BLOCK",
            "message": "Access denied by Cryptographic Threat Detection WAF",
            "reason": block_reason,
            "endpoint": request.path,
            "src_ip": ip,
        }), 429
    return None


@app.after_request
def waf_outbound_recorder(response):
    """Middleware WAF Layer 7 universale: registrazione automatica dell'esito nella sliding-window dell'endpoint."""
    if not WAF_POLICY.get("enabled"):
        return response

    if request.path in EXEMPT_WAF_PATHS or request.path.startswith("/waf/"):
        return response

    # Se la richiesta è già stata bloccata dal WAF con 429, non incrementare ulteriormente
    if response.status_code == 429:
        return response

    ip = _client_ip()
    is_error = response.status_code >= 400
    _record_waf_outcome(ip, is_error=is_error, endpoint=request.path)
    return response


def _client_ip() -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    remote = request.remote_addr
    if remote and remote not in ("127.0.0.1", "localhost", "::1", ""):
        return remote.strip()
    client_id = request.headers.get("X-Client-ID") or request.headers.get("X-Client-Role")
    if client_id:
        return client_id.strip()
    return remote or "127.0.0.1"


def _log_request(
    endpoint: str,
    status_code: int,
    latency_ms: float,
    ciphertext_len: int,
    error_type: str,
    extra_details: dict | None = None,
    crypto_time_ns: int | None = None,
) -> None:
    details = {
        "server_time": datetime.now(timezone.utc).isoformat(),
        "client_role": request.headers.get("X-Client-Role", "unknown"),
        "client_id": request.headers.get("X-Client-ID", _client_ip()),
    }
    if crypto_time_ns is not None:
        details["crypto_time_ns"] = crypto_time_ns
        details["crypto_time_ms"] = round(crypto_time_ns / 1_000_000.0, 4)
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
            "crypto_time_ns": crypto_time_ns or 0,
            "ciphertext_len": ciphertext_len,
            "error_type": error_type,
            "mode": MODE,
            "details": details,
        },
    )


@app.get("/health")
@app.get("/api/v1/health")
def health():
    return jsonify({"status": "ok", "mode": MODE, "waf_enabled": WAF_POLICY.get("enabled", False)})


@app.post("/api/v1/auth/login")
def auth_login():
    start = time.perf_counter()
    ip = _client_ip()
    body = request.get_json(force=True, silent=True) or {}
    username = body.get("username", "")
    password = body.get("password", "")

    # Real authentication check against CorporateSecret2026!
    if not username or password != "CorporateSecret2026!":
        latency_ms = (time.perf_counter() - start) * 1000
        _log_request("/api/v1/auth/login", 401, latency_ms, 0, "unauthorized", {"reason": "invalid_credentials"})
        return jsonify({"error": "unauthorized", "message": "Invalid username or password"}), 401

    scheme = "etm" if MODE == "fixed" else "mte"
    session_token = b64e(encrypt_token(f"session:{username}:{int(time.time())}".encode("utf-8"), scheme=scheme))
    latency_ms = (time.perf_counter() - start) * 1000
    _log_request("/api/v1/auth/login", 200, latency_ms, len(session_token), "ok", {"username": username})
    return jsonify({"token_type": "Bearer", "access_token": session_token, "expires_in": 3600})


@app.get("/api/v1/user/profile")
def user_profile():
    start = time.perf_counter()
    ip = _client_ip()
    auth_header = request.headers.get("Authorization", "")
    if not auth_header or not auth_header.startswith("Bearer "):
        latency_ms = (time.perf_counter() - start) * 1000
        _log_request("/api/v1/user/profile", 401, latency_ms, 0, "unauthorized", {"reason": "missing_token"})
        return jsonify({"error": "unauthorized", "message": "Authentication required"}), 401

    token_b64 = auth_header[7:].strip()
    try:
        token = b64d(token_b64)
        scheme = "etm" if MODE == "fixed" else "mte"
        _, outcome = verify_and_extract(token, scheme=scheme)
        if outcome != "ok":
            latency_ms = (time.perf_counter() - start) * 1000
            _log_request("/api/v1/user/profile", 401, latency_ms, len(token), "token_expired")
            return jsonify({"error": "token_expired", "message": "Session token signature invalid"}), 401
    except Exception:
        latency_ms = (time.perf_counter() - start) * 1000
        _log_request("/api/v1/user/profile", 400, latency_ms, 0, "bad_token")
        return jsonify({"error": "bad_request", "message": "Malformed authorization token"}), 400

    latency_ms = (time.perf_counter() - start) * 1000
    _log_request("/api/v1/user/profile", 200, latency_ms, 0, "ok")
    return jsonify({
        "user_id": f"usr-{ip.replace('.', '')[-4:]}",
        "roles": ["standard_user", "crypto_client"],
        "algorithm": "AES-128-CBC",
        "key_version": "v1.2",
    })


@app.post("/api/v1/token/verify")
def token_verify():
    start = time.perf_counter()
    body = request.get_json(force=True, silent=True) or {}
    token_b64 = body.get("token")
    if not isinstance(token_b64, str):
        latency_ms = (time.perf_counter() - start) * 1000
        _log_request("/api/v1/token/verify", 400, latency_ms, 0, "bad_request")
        return jsonify({"valid": False, "reason": "missing_token"}), 400

    try:
        token = b64d(token_b64)
        scheme = "etm" if MODE == "fixed" else "mte"
        _, outcome = verify_and_extract(token, scheme=scheme)
        is_valid = (outcome == "ok")
        status = 200 if is_valid else 400
        err_type = "ok" if is_valid else "verification_failed"
        latency_ms = (time.perf_counter() - start) * 1000
        _log_request("/api/v1/token/verify", status, latency_ms, len(token), err_type)
        return jsonify({"valid": is_valid, "outcome": outcome}), status
    except Exception:
        latency_ms = (time.perf_counter() - start) * 1000
        _log_request("/api/v1/token/verify", 400, latency_ms, 0, "bad_b64")
        return jsonify({"valid": False, "reason": "invalid_base64"}), 400


@app.get("/waf/status")
def waf_status():
    return jsonify({
        "policy": WAF_POLICY,
        "blocked_ips": list(WAF_BLOCKED_IPS),
        "blocked_details": [
            {
                "ip": ip,
                "ttl_remaining_s": (
                    round(WAF_BLOCKED_IPS.get_ttl(ip), 1)
                    if WAF_BLOCKED_IPS.get_ttl(ip) is not None
                    else None
                ),
            }
            for ip in list(WAF_BLOCKED_IPS)
        ],
        "tracked_ips_count": len(WAF_STATE),
    })


@app.post("/waf/policy")
def waf_set_policy():
    data = request.get_json(force=True, silent=True) or {}
    for k in ["enabled", "min_requests_window", "max_fail_rate", "max_consecutive_errors", "window_seconds", "ban_ttl_seconds", "action", "rules"]:
        if k in data:
            WAF_POLICY[k] = data[k]
    _save_waf_policy(WAF_POLICY)
    return jsonify({"ok": True, "policy": WAF_POLICY})


@app.post("/waf/rules/toggle")
def waf_rules_toggle():
    data = request.get_json(force=True, silent=True) or {}
    rule_id = data.get("rule_id")
    rules = WAF_POLICY.get("rules")
    if not isinstance(rules, list):
        rules = _default_waf_rules()
        WAF_POLICY["rules"] = rules

    if rule_id == "all":
        target_state = not WAF_POLICY.get("enabled", True) if "enabled" not in data else bool(data["enabled"])
        WAF_POLICY["enabled"] = target_state
        for r in rules:
            r["enabled"] = target_state
    else:
        for r in rules:
            if r.get("id") == rule_id:
                new_enabled = not r.get("enabled", True) if "enabled" not in data else bool(data["enabled"])
                r["enabled"] = new_enabled
                break
    _save_waf_policy(WAF_POLICY)
    return jsonify({"ok": True, "policy": WAF_POLICY})


@app.post("/waf/rules/update")
def waf_rules_update():
    data = request.get_json(force=True, silent=True) or {}
    rule_id = data.get("rule_id")
    updates = data.get("updates", {})
    rules = WAF_POLICY.get("rules")
    if not isinstance(rules, list):
        rules = _default_waf_rules()
        WAF_POLICY["rules"] = rules

    updated = False
    for r in rules:
        if r.get("id") == rule_id:
            for k, v in updates.items():
                if k in ("name", "endpoint", "min_requests_window", "max_fail_rate", "max_consecutive_errors", "window_seconds", "ban_ttl_seconds", "enabled"):
                    if k == "window_seconds":
                        try:
                            v = max(5, min(86400, int(v)))
                        except (ValueError, TypeError):
                            v = 60
                    r[k] = v
            updated = True
            break
    if updated:
        _save_waf_policy(WAF_POLICY)
    return jsonify({"ok": updated, "policy": WAF_POLICY})


@app.post("/waf/rules/add")
def waf_rules_add():
    data = request.get_json(force=True, silent=True) or {}
    new_rule = data.get("rule") or {}
    if not new_rule.get("id"):
        new_rule["id"] = f"waf_custom_{int(time.time())}"
    if not new_rule.get("name"):
        new_rule["name"] = "Regola WAF Personalizzata"
    new_rule.setdefault("endpoint", "/decrypt")
    new_rule.setdefault("enabled", True)
    new_rule.setdefault("min_requests_window", 15)
    new_rule.setdefault("max_fail_rate", 0.80)
    new_rule.setdefault("max_consecutive_errors", 12)
    try:
        new_rule["window_seconds"] = max(5, min(86400, int(new_rule.get("window_seconds", 60))))
    except (ValueError, TypeError):
        new_rule["window_seconds"] = 60
    new_rule.setdefault("ban_ttl_seconds", 120)

    rules = WAF_POLICY.get("rules")
    if not isinstance(rules, list):
        rules = _default_waf_rules()
        WAF_POLICY["rules"] = rules

    # Rimuovi eventuale duplicato per ID
    WAF_POLICY["rules"] = [r for r in rules if r.get("id") != new_rule["id"]] + [new_rule]
    _save_waf_policy(WAF_POLICY)
    return jsonify({"ok": True, "policy": WAF_POLICY, "rule": new_rule})


@app.post("/waf/rules/delete")
def waf_rules_delete():
    data = request.get_json(force=True, silent=True) or {}
    rule_id = data.get("rule_id")
    rules = WAF_POLICY.get("rules")
    if not isinstance(rules, list):
        rules = _default_waf_rules()
        WAF_POLICY["rules"] = rules

    original_len = len(rules)
    WAF_POLICY["rules"] = [r for r in rules if r.get("id") != rule_id]
    deleted = len(WAF_POLICY["rules"]) < original_len
    if deleted:
        _save_waf_policy(WAF_POLICY)
    return jsonify({"ok": deleted, "policy": WAF_POLICY, "deleted_id": rule_id})



@app.post("/waf/reset")
def waf_reset():
    WAF_BLOCKED_IPS.clear()
    WAF_STATE.clear()
    return jsonify({"ok": True, "message": "WAF memory state reset"})


@app.post("/waf/block_ip")
def waf_block_ip():
    data = request.get_json(force=True, silent=True) or {}
    ip = data.get("ip")
    ttl_seconds = float(data.get("ttl_seconds", 0) or 0)
    endpoint = data.get("endpoint")
    if endpoint in ("*", "/"):
        endpoint = None
    if ip:
        WAF_BLOCKED_IPS.add(ip, ttl_seconds=ttl_seconds, endpoint=endpoint)
    return jsonify({
        "ok": True,
        "blocked_ips": list(WAF_BLOCKED_IPS),
        "ip": ip,
        "endpoint": endpoint,
        "ttl_seconds": ttl_seconds,
    })


@app.post("/waf/unblock_ip")
def waf_unblock_ip():
    data = request.get_json(force=True, silent=True) or {}
    ip = data.get("ip")
    endpoint = data.get("endpoint")
    if endpoint in ("*", "/"):
        endpoint = None
    if ip and ip in WAF_BLOCKED_IPS:
        WAF_BLOCKED_IPS.remove(ip, endpoint=endpoint)
    return jsonify({"ok": True, "blocked_ips": list(WAF_BLOCKED_IPS)})



@app.get("/sample_token")
def sample_token():
    scheme = "etm" if MODE == "fixed" else "mte"
    token = encrypt_token(SECRET_MESSAGE.encode("utf-8"), scheme=scheme)
    return jsonify({"token": b64e(token), "mode": MODE})


@app.post("/encrypt")
@app.post("/api/v1/crypto/encrypt")
def encrypt():
    start = time.perf_counter()
    body = request.get_json(force=True, silent=True) or {}
    plaintext = str(body.get("plaintext", "hello")).encode("utf-8")
    t_crypto_start = time.perf_counter_ns()
    scheme = "etm" if MODE == "fixed" else "mte"
    token = encrypt_token(plaintext, scheme=scheme)
    crypto_time_ns = time.perf_counter_ns() - t_crypto_start
    latency_ms = (time.perf_counter() - start) * 1000
    _log_request(request.path, 200, latency_ms, len(token), "ok", crypto_time_ns=crypto_time_ns)
    return jsonify({"token": b64e(token), "length": len(token)})


@app.post("/decrypt")
@app.post("/api/v1/crypto/decrypt")
def decrypt():
    start = time.perf_counter()
    ip = _client_ip()

    body = request.get_json(force=True, silent=True) or {}
    token_b64 = body.get("token")
    if not isinstance(token_b64, str):
        latency_ms = (time.perf_counter() - start) * 1000
        _log_request(request.path, 400, latency_ms, 0, "bad_request")
        return jsonify({"result": "invalid_request"}), 400

    try:
        token = b64d(token_b64)
    except Exception:
        latency_ms = (time.perf_counter() - start) * 1000
        _log_request(request.path, 400, latency_ms, 0, "bad_b64")
        return jsonify({"result": "invalid_request"}), 400

    t_crypto_start = time.perf_counter_ns()
    scheme = "etm" if MODE == "fixed" else "mte"
    plaintext, outcome = verify_and_extract(token, scheme=scheme)
    crypto_time_ns = time.perf_counter_ns() - t_crypto_start

    status = 200
    response = {"result": "ok"}
    error_type = "ok"

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
        # Encrypt-then-MAC: HMAC integrity is verified in constant time before decryption.
        # Any tampering fails HMAC immediately without ever touching AES decryption or PKCS#7 unpadding.
        if outcome != "ok":
            status = 403
            response = {"result": "request_denied"}
            error_type = "integrity_error"
    else:
        if outcome != "ok":
            status = 403
            response = {"result": "request_denied"}
            error_type = "generic_error"

    latency_ms = (time.perf_counter() - start) * 1000
    _log_request(request.path, status, latency_ms, len(token), error_type, crypto_time_ns=crypto_time_ns)
    if plaintext is None:
        return jsonify(response), status
    return jsonify({"result": "ok", "plaintext": plaintext.decode("utf-8", errors="ignore")})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)


