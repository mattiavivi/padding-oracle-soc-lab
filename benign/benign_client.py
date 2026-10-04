import argparse
import random
import socket
import sys
import threading
import time
import requests

from common.event_logger import emit_event


def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def generate_ip_pool(count: int, base_subnet: str = "192.168.1") -> list[str]:
    """Genera un pool di IP virtuali realistici per simulare workstation aziendali."""
    count = max(1, min(count, 200))
    return [f"{base_subnet}.{10 + i}" for i in range(count)]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Enterprise Multi-IP Parallel Benign Client Workload Generator")
    p.add_argument("--target", default="http://victim:8080", help="Target victim server URL")
    p.add_argument("--name", default="benign", help="Service worker name")
    p.add_argument("--scenario-id", default="enterprise-baseline", help="Scenario ID")
    p.add_argument("--iterations", type=int, default=100, help="Total iterations per host (if not continuous)")
    p.add_argument("--continuous", action="store_true", help="Run indefinitely in background")
    p.add_argument("--virtual-ips", type=int, default=10, help="Number of virtual client IPs / parallel threads to simulate")
    p.add_argument("--min-sleep-ms", type=int, default=300, help="Minimum delay between requests in ms")
    p.add_argument("--max-sleep-ms", type=int, default=1000, help="Maximum delay between requests in ms")
    p.add_argument("--error-rate-pct", type=float, default=3.0, help="Physiological error rate percentage (2-5%)")
    return p.parse_args()


def run_workstation_worker(cur_ip: str, args: argparse.Namespace) -> None:
    """Worker thread dedicato a un singolo IP virtuale (workstation)."""
    client_data = {
        "session": requests.Session(),
        "username": f"user_{cur_ip.replace('.', '_')}",
        "token": "",
        "active": True,
        "requests_count": 0,
    }
    s = client_data["session"]
    username = client_data["username"]

    headers = {
        "X-Client-Role": "benign",
        "X-Client-ID": f"workstation-{cur_ip.split('.')[-1]}",
        "X-Forwarded-For": cur_ip,
    }
    s.headers.update(headers)

    iteration = 0
    while True:
        if not args.continuous and iteration >= args.iterations:
            break

        iteration += 1
        inject_error = random.random() < (args.error_rate_pct / 100.0)
        client_data["requests_count"] += 1

        try:
            action_roll = random.random()

            if action_roll < 0.20 or not client_data.get("token"):
                # --- Flow 1: Authentic User Login (HTTP 200 o raro 401) ---
                auth_payload = {
                    "username": username,
                    "password": "invalid_pass" if (inject_error and random.random() < 0.5) else "CorporateSecret2026!",
                }
                start = time.perf_counter()
                r = s.post(f"{args.target}/api/v1/auth/login", json=auth_payload, timeout=5)
                lat = (time.perf_counter() - start) * 1000

                if r.status_code == 200:
                    token_val = r.json().get("access_token", "")
                    client_data["token"] = token_val
                    s.headers["Authorization"] = f"Bearer {token_val}"

                emit_event(
                    args.name,
                    {
                        "event_type": "benign_auth",
                        "scenario_id": args.scenario_id,
                        "src_ip": cur_ip,
                        "endpoint": "/api/v1/auth/login",
                        "status_code": r.status_code,
                        "latency_ms": round(lat, 3),
                        "error_type": "ok" if r.status_code == 200 else "unauthorized",
                        "details": {
                            "iteration": iteration,
                            "client_ip": cur_ip,
                            "username": username,
                            "action": "user_login",
                            "auth_method": "password_auth",
                            "result": "success" if r.status_code == 200 else "invalid_credentials",
                        },
                    },
                )

            elif action_roll < 0.45:
                # --- Flow 2: User Profile Request (HTTP 200 o raro 401) ---
                start = time.perf_counter()
                r = s.get(f"{args.target}/api/v1/user/profile", timeout=5)
                lat = (time.perf_counter() - start) * 1000
                emit_event(
                    args.name,
                    {
                        "event_type": "benign_profile",
                        "scenario_id": args.scenario_id,
                        "src_ip": cur_ip,
                        "endpoint": "/api/v1/user/profile",
                        "status_code": r.status_code,
                        "latency_ms": round(lat, 3),
                        "error_type": "ok" if r.status_code == 200 else "profile_error",
                        "details": {
                            "iteration": iteration,
                            "client_ip": cur_ip,
                            "username": username,
                            "action": "query_profile",
                            "department": f"dept_{int(cur_ip.split('.')[-1]) % 4 + 1}",
                        },
                    },
                )

            elif action_roll < 0.70:
                # --- Flow 3: Cryptographic Token Encrypt (HTTP 200) ---
                msg = f"Doc-{username}-{int(time.time()*1000)}"
                start = time.perf_counter()
                r = s.post(f"{args.target}/api/v1/crypto/encrypt", json={"plaintext": msg}, timeout=5)
                lat = (time.perf_counter() - start) * 1000
                token_out = ""
                if r.status_code == 200:
                    token_out = r.json().get("token", "")
                    client_data["last_crypto_token"] = token_out

                emit_event(
                    args.name,
                    {
                        "event_type": "benign_encrypt",
                        "scenario_id": args.scenario_id,
                        "src_ip": cur_ip,
                        "endpoint": "/api/v1/crypto/encrypt",
                        "status_code": r.status_code,
                        "latency_ms": round(lat, 3),
                        "ciphertext_len": len(token_out),
                        "error_type": "ok" if r.status_code == 200 else "encrypt_error",
                        "details": {
                            "iteration": iteration,
                            "client_ip": cur_ip,
                            "username": username,
                            "action": "encrypt_doc",
                            "doc_id": msg,
                            "ciphertext_bytes": len(token_out),
                            "plaintext_sample": msg[:18],
                        },
                    },
                )

            else:
                # --- Flow 4: Cryptographic Token Decrypt (HTTP 200 o raro errore) ---
                token_to_decrypt = client_data.get("last_crypto_token") or client_data.get("token")
                if not token_to_decrypt:
                    sample_r = s.get(f"{args.target}/sample_token", timeout=5)
                    if sample_r.status_code == 200:
                        token_to_decrypt = sample_r.json().get("token", "")
                        client_data["last_crypto_token"] = token_to_decrypt

                if token_to_decrypt:
                    if inject_error and random.random() < 0.4:
                        corrupted = token_to_decrypt[:-4] + "AAAA"
                    else:
                        corrupted = token_to_decrypt

                    start = time.perf_counter()
                    r = s.post(f"{args.target}/api/v1/crypto/decrypt", json={"token": corrupted}, timeout=5)
                    lat = (time.perf_counter() - start) * 1000
                    emit_event(
                        args.name,
                        {
                            "event_type": "benign_request",
                            "scenario_id": args.scenario_id,
                            "src_ip": cur_ip,
                            "endpoint": "/api/v1/crypto/decrypt",
                            "status_code": r.status_code,
                            "latency_ms": round(lat, 3),
                            "ciphertext_len": len(corrupted),
                            "error_type": "ok" if r.status_code == 200 else "unexpected_error",
                            "details": {
                                "iteration": iteration,
                                "client_ip": cur_ip,
                                "username": username,
                                "action": "decrypt_payload",
                                "token_prefix": (corrupted[:12] + "...") if corrupted else "",
                                "valid_padding": r.status_code == 200,
                                "ciphertext_bytes": len(corrupted),
                            },
                        },
                    )

        except Exception:
            pass

        min_s = max(1, args.min_sleep_ms)
        max_s = max(min_s, args.max_sleep_ms)
        sleep_sec = random.randint(min_s, max_s) / 1000.0
        time.sleep(sleep_sec)


def main() -> int:
    args = parse_args()
    ip_pool = generate_ip_pool(args.virtual_ips)

    print(f"[*] Avvio Generatore Benigno: target={args.target}, {len(ip_pool)} thread worker paralleli (IP subnet 192.168.1.10+), sleep={args.min_sleep_ms}-{args.max_sleep_ms}ms, errore={args.error_rate_pct}%")

    threads = []
    for ip in ip_pool:
        t = threading.Thread(target=run_workstation_worker, args=(ip, args), daemon=True, name=f"WorkstationWorker-{ip}")
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        sys.exit(0)
