import argparse
import random
import socket
import sys
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


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Benign client workload generator with multi-API support")
    p.add_argument("--target", default="http://victim-vuln:8080")
    p.add_argument("--name", default="benign-1")
    p.add_argument("--scenario-id", default="baseline")
    p.add_argument("--iterations", type=int, default=100)
    p.add_argument("--continuous", action="store_true", help="Run indefinitely in a background loop")
    p.add_argument("--min-sleep-ms", type=int, default=100)
    p.add_argument("--max-sleep-ms", type=int, default=600)
    p.add_argument("--error-rate-pct", type=float, default=3.0, help="Percentage of requests with physiological errors")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    local_ip = get_local_ip()
    headers = {"X-Client-Role": "benign", "X-Client-ID": args.name, "X-Forwarded-For": local_ip}
    
    session = requests.Session()
    session.headers.update(headers)
    
    iteration = 0
    while True:
        if not args.continuous and iteration >= args.iterations:
            break
        
        iteration += 1
        msg = f"{args.name}-msg-{iteration}-{int(time.time()*1000)}"
        inject_error = random.random() < (args.error_rate_pct / 100.0)

        try:
            # 1. Authentic User Login flow
            auth_payload = {
                "username": f"user_{args.name}",
                "password": "invalid_pass" if (inject_error and random.random() < 0.3) else "secret123",
            }
            start_auth = time.perf_counter()
            r_auth = session.post(f"{args.target}/api/v1/auth/login", json=auth_payload, timeout=5)
            lat_auth = (time.perf_counter() - start_auth) * 1000
            
            bearer_token = ""
            if r_auth.status_code == 200:
                bearer_token = r_auth.json().get("access_token", "")
                session.headers["Authorization"] = f"Bearer {bearer_token}"
            
            emit_event(
                args.name,
                {
                    "event_type": "benign_auth",
                    "scenario_id": args.scenario_id,
                    "src_ip": local_ip,
                    "endpoint": "/api/v1/auth/login",
                    "status_code": r_auth.status_code,
                    "latency_ms": round(lat_auth, 3),
                    "error_type": "ok" if r_auth.status_code == 200 else "unauthorized",
                }
            )

            # 2. User Profile fetch
            start_prof = time.perf_counter()
            r_prof = session.get(f"{args.target}/api/v1/user/profile", timeout=5)
            lat_prof = (time.perf_counter() - start_prof) * 1000
            emit_event(
                args.name,
                {
                    "event_type": "benign_profile",
                    "scenario_id": args.scenario_id,
                    "src_ip": local_ip,
                    "endpoint": "/api/v1/user/profile",
                    "status_code": r_prof.status_code,
                    "latency_ms": round(lat_prof, 3),
                    "error_type": "ok" if r_prof.status_code == 200 else "profile_error",
                }
            )

            # 3. Cryptographic Token Encrypt
            start_enc = time.perf_counter()
            r_enc = session.post(f"{args.target}/api/v1/crypto/encrypt", json={"plaintext": msg}, timeout=5)
            lat_enc = (time.perf_counter() - start_enc) * 1000
            
            token = ""
            if r_enc.status_code == 200:
                token = r_enc.json().get("token", "")

            emit_event(
                args.name,
                {
                    "event_type": "benign_encrypt",
                    "scenario_id": args.scenario_id,
                    "src_ip": local_ip,
                    "endpoint": "/api/v1/crypto/encrypt",
                    "status_code": r_enc.status_code,
                    "latency_ms": round(lat_enc, 3),
                    "ciphertext_len": len(token),
                    "error_type": "ok" if r_enc.status_code == 200 else "encrypt_error",
                }
            )

            # 4. Cryptographic Decrypt
            if token:
                # If physiological error, corrupt token
                dec_token = token if not (inject_error and random.random() < 0.5) else token[:-4] + "AAAA"
                start_dec = time.perf_counter()
                r_dec = session.post(f"{args.target}/api/v1/crypto/decrypt", json={"token": dec_token}, timeout=5)
                lat_dec = (time.perf_counter() - start_dec) * 1000
                emit_event(
                    args.name,
                    {
                        "event_type": "benign_request",
                        "scenario_id": args.scenario_id,
                        "src_ip": local_ip,
                        "endpoint": "/decrypt",
                        "status_code": r_dec.status_code,
                        "latency_ms": round(lat_dec, 3),
                        "ciphertext_len": len(dec_token),
                        "error_type": "ok" if r_dec.status_code == 200 else "unexpected_error",
                    }
                )

            # 5. Token Verify
            if token:
                start_ver = time.perf_counter()
                r_ver = session.post(f"{args.target}/api/v1/token/verify", json={"token": token}, timeout=5)
                lat_ver = (time.perf_counter() - start_ver) * 1000
                emit_event(
                    args.name,
                    {
                        "event_type": "benign_verify",
                        "scenario_id": args.scenario_id,
                        "src_ip": local_ip,
                        "endpoint": "/api/v1/token/verify",
                        "status_code": r_ver.status_code,
                        "latency_ms": round(lat_ver, 3),
                        "error_type": "ok" if r_ver.status_code == 200 else "verify_error",
                    }
                )

        except Exception as e:
            pass

        # Jitter sleep
        sleep_sec = random.randint(args.min_sleep_ms, args.max_sleep_ms) / 1000.0
        time.sleep(sleep_sec)

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        sys.exit(0)
