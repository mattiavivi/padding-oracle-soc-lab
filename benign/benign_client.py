import argparse
import random
import time

import requests

from common.event_logger import emit_event


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--target", default="http://victim-vuln:8080")
    p.add_argument("--name", default="benign-1")
    p.add_argument("--scenario-id", default="baseline")
    p.add_argument("--iterations", type=int, default=100)
    p.add_argument("--min-sleep-ms", type=int, default=100)
    p.add_argument("--max-sleep-ms", type=int, default=600)
    return p.parse_args()


def main() -> int:
    args = parse_args()
    headers = {"X-Client-Role": "benign", "X-Client-ID": args.name}
    for i in range(args.iterations):
        msg = f"{args.name}-message-{i}"
        try:
            enc = requests.post(f"{args.target}/encrypt", json={"plaintext": msg}, headers=headers, timeout=5)
            if enc.status_code == 200:
                token = enc.json().get("token", "")
                if token:
                    started = time.perf_counter()
                    dec = requests.post(f"{args.target}/decrypt", json={"token": token}, headers=headers, timeout=5)
                    latency = (time.perf_counter() - started) * 1000
                    emit_event(
                        args.name,
                        {
                            "event_type": "benign_request",
                            "scenario_id": args.scenario_id,
                            "src_ip": args.name,
                            "endpoint": "/decrypt",
                            "status_code": dec.status_code,
                            "latency_ms": round(latency, 3),
                            "ciphertext_len": len(token),
                            "error_type": "ok" if dec.status_code == 200 else "unexpected_error",
                            "details": {
                                "iteration": i,
                                "plaintext_sample": msg,
                            },
                        },
                    )
        except Exception:
            pass
        time.sleep(random.randint(args.min_sleep_ms, args.max_sleep_ms) / 1000)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
