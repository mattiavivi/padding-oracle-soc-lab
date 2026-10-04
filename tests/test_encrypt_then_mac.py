import unittest
from common.crypto_utils import (
    encrypt_token,
    verify_and_extract,
    encrypt_token_etm,
    verify_and_extract_etm,
    encrypt_token_mte,
    verify_and_extract_mte,
    b64e,
    b64d,
)
from victim.app import app as victim_app, MODE


class TestEncryptThenMac(unittest.TestCase):
    def test_etm_round_trip(self):
        secret = b"ConfidentialPayload12345"
        token = encrypt_token_etm(secret)
        plaintext, outcome = verify_and_extract_etm(token)
        self.assertEqual(outcome, "ok")
        self.assertEqual(plaintext, secret)

    def test_etm_iv_tamper_rejected_before_decryption(self):
        secret = b"ConfidentialPayload12345"
        token = bytearray(encrypt_token_etm(secret))
        # Tamper with first byte of IV
        token[0] ^= 0xFF
        plaintext, outcome = verify_and_extract_etm(bytes(token))
        self.assertIsNone(plaintext)
        self.assertEqual(outcome, "integrity_error")

    def test_etm_ciphertext_tamper_rejected(self):
        secret = b"ConfidentialPayload12345"
        token = bytearray(encrypt_token_etm(secret))
        # Tamper with a byte inside ciphertext (offset 20: after 16-byte IV)
        token[20] ^= 0x42
        plaintext, outcome = verify_and_extract_etm(bytes(token))
        self.assertIsNone(plaintext)
        self.assertEqual(outcome, "integrity_error")

    def test_etm_tag_tamper_rejected(self):
        secret = b"ConfidentialPayload12345"
        token = bytearray(encrypt_token_etm(secret))
        # Tamper with the HMAC tag (last byte)
        token[-1] ^= 0x01
        plaintext, outcome = verify_and_extract_etm(bytes(token))
        self.assertIsNone(plaintext)
        self.assertEqual(outcome, "integrity_error")

    def test_victim_fixed_mode_api(self):
        client = victim_app.test_client()
        # Switch victim to fixed mode
        r = client.post("/mode", json={"mode": "fixed"})
        self.assertEqual(r.status_code, 200)

        # Get sample token generated in fixed mode (EtM)
        token_resp = client.get("/sample_token")
        self.assertEqual(token_resp.status_code, 200)
        token_data = token_resp.get_json()
        self.assertEqual(token_data["mode"], "fixed")
        token_bytes = bytearray(b64d(token_data["token"]))

        # Valid decryption
        dec_resp = client.post("/decrypt", json={"token": b64e(bytes(token_bytes))})
        self.assertEqual(dec_resp.status_code, 200)
        self.assertIn("plaintext", dec_resp.get_json())

        # Tampered ciphertext: must return 403 request_denied with no timing leak
        token_bytes[0] ^= 0xAA
        tampered_resp = client.post("/decrypt", json={"token": b64e(bytes(token_bytes))})
        self.assertEqual(tampered_resp.status_code, 403)
        self.assertEqual(tampered_resp.get_json()["result"], "request_denied")

        # Switch back to vuln mode
        client.post("/mode", json={"mode": "vuln"})


if __name__ == "__main__":
    unittest.main()
