import base64
import hashlib
import hmac
import os

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


BLOCK_SIZE = 16


def _pkcs7_pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes) -> bytes | None:
    if not data:
        return None
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        return None
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        return None
    return data[:-pad_len]


def _get_key_material() -> tuple[bytes, bytes]:
    enc_key_hex = os.getenv("LAB_ENC_KEY_HEX", "00112233445566778899aabbccddeeff")
    mac_key_hex = os.getenv("LAB_MAC_KEY_HEX", "ffeeddccbbaa99887766554433221100")
    return bytes.fromhex(enc_key_hex), bytes.fromhex(mac_key_hex)


def _tag(plaintext: bytes, mac_key: bytes) -> bytes:
    return hmac.new(mac_key, plaintext, hashlib.sha256).digest()[:16]


def encrypt_token(plaintext: bytes) -> bytes:
    enc_key, mac_key = _get_key_material()
    iv = get_random_bytes(BLOCK_SIZE)
    payload = plaintext + _tag(plaintext, mac_key)
    cipher = AES.new(enc_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(_pkcs7_pad(payload))
    return iv + ciphertext


def decrypt_token_raw(token: bytes) -> bytes | None:
    enc_key, _ = _get_key_material()
    if len(token) < 2 * BLOCK_SIZE or len(token) % BLOCK_SIZE != 0:
        return None
    iv = token[:BLOCK_SIZE]
    ciphertext = token[BLOCK_SIZE:]
    cipher = AES.new(enc_key, AES.MODE_CBC, iv)
    padded = cipher.decrypt(ciphertext)
    return pkcs7_unpad(padded)


def verify_and_extract(token: bytes) -> tuple[bytes | None, str]:
    _, mac_key = _get_key_material()
    unpadded = decrypt_token_raw(token)
    if unpadded is None:
        return None, "padding_error"
    if len(unpadded) < 16:
        return None, "integrity_error"
    plaintext = unpadded[:-16]
    recv_tag = unpadded[-16:]
    expected = _tag(plaintext, mac_key)
    if not hmac.compare_digest(recv_tag, expected):
        return None, "integrity_error"
    return plaintext, "ok"


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))
