import argparse

from common.crypto_utils import b64d


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--token-b64", required=True, help="Token base64 (IV+ciphertext)")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    token = b64d(args.token_b64)
    if len(token) < 32 or len(token) % 16 != 0:
        raise SystemExit("Token is not a valid CBC payload")

    blocks = [token[i : i + 16] for i in range(0, len(token), 16)]
    print("=== CBC Layout ===")
    print(f"Total bytes: {len(token)}")
    print(f"Blocks: {len(blocks)} (block size = 16)")
    print(f"IV : {blocks[0].hex()}")
    for i, b in enumerate(blocks[1:], start=1):
        print(f"C{i}: {b.hex()}")
    print("\nByte positions in IV useful for oracle on first ciphertext block:")
    for idx in range(16):
        print(f"- mutate IV[{idx:02d}] to influence P1[{idx:02d}]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
