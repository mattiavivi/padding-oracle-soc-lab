import unittest
import json
import attacker.attack as attacker_mod
from attacker.attack import (
    get_attack_ip,
    padding_oracle_attack_block,
    GLOBAL_IP_MODE,
)
from victim.app import app as victim_app, WAF_POLICY, WAF_STATE, WAF_BLOCKED_IPS, _default_waf_rules
from common.crypto_utils import encrypt_token, b64e


class TestIpRotationPerQuery(unittest.TestCase):

    def setUp(self):
        self.client = victim_app.test_client()
        WAF_BLOCKED_IPS.clear()
        WAF_STATE.clear()
        WAF_POLICY["enabled"] = False
        WAF_POLICY["max_consecutive_errors"] = 6
        WAF_POLICY["min_requests_window"] = 8
        WAF_POLICY["max_fail_rate"] = 0.80
        WAF_POLICY["rules"] = _default_waf_rules()

    def tearDown(self):
        attacker_mod.GLOBAL_IP_MODE = "static"

    def test_per_query_ip_generator_uniqueness(self):
        attacker_mod.GLOBAL_IP_MODE = "per-query"
        attacker_mod.GLOBAL_PER_QUERY_COUNTER = 0

        generated_ips = [get_attack_ip() for _ in range(4096)]
        unique_ips = set(generated_ips)

        # Ensure all 4,096 generated IPs are distinct
        self.assertEqual(len(unique_ips), 4096)
        # Ensure all IPs belong to the documentation/virtual range 203.0.x.y
        for ip in generated_ips:
            self.assertTrue(ip.startswith("203.0."))

    def test_waf_per_api_scoping_and_isolation(self):
        """Verify that blocking an IP on /decrypt does NOT block /health or auth."""
        WAF_POLICY["enabled"] = True
        WAF_POLICY["max_consecutive_errors"] = 3

        bad_ip = "198.51.100.99"

        # 3 consecutive bad decrypt requests to trigger WAF
        for _ in range(3):
            r = self.client.post("/decrypt", json={"token": "invalid"}, headers={"X-Forwarded-For": bad_ip})
            self.assertEqual(r.status_code, 400)

        # 4th decrypt request from bad_ip must be blocked (HTTP 429)
        r4 = self.client.post("/decrypt", json={"token": "invalid"}, headers={"X-Forwarded-For": bad_ip})
        self.assertEqual(r4.status_code, 429)
        self.assertEqual(r4.json.get("error"), "WAF_PREVENTIVE_BLOCK")

        # BUT health check from the exact same bad_ip must succeed (HTTP 200)
        r_health = self.client.get("/health", headers={"X-Forwarded-For": bad_ip})
        self.assertEqual(r_health.status_code, 200)

        # AND login check from the exact same bad_ip must process normally
        r_login = self.client.post(
            "/api/v1/auth/login",
            json={"username": "analyst_test", "password": "CorporateSecret2026!"},
            headers={"X-Forwarded-For": bad_ip},
        )
        self.assertEqual(r_login.status_code, 200)

    def test_per_query_ip_rotation_evades_waf_completely(self):
        """Verify that per-query rotation allows full attack without triggering per-IP WAF thresholds."""
        WAF_POLICY["enabled"] = True
        WAF_POLICY["max_consecutive_errors"] = 6
        WAF_POLICY["min_requests_window"] = 8
        WAF_POLICY["max_fail_rate"] = 0.80

        attacker_mod.GLOBAL_IP_MODE = "per-query"
        attacker_mod.GLOBAL_PER_QUERY_COUNTER = 0

        # Simulate 20 requests with unique per-query IPs on /decrypt with bad tokens
        statuses = []
        for _ in range(20):
            cur_ip = get_attack_ip()
            r = self.client.post(
                "/decrypt",
                json={"token": "invalid"},
                headers={"X-Forwarded-For": cur_ip},
            )
            statuses.append(r.status_code)

        # Every request returned 400 (bad token) and NONE was blocked with 429
        self.assertTrue(all(s == 400 for s in statuses))
        self.assertEqual(len(WAF_BLOCKED_IPS), 0)

    def test_botnet_reuse_mode_is_blocked_by_waf_rule_2(self):
        """Verify that rotate mode (with node reuse) triggers Rule 2 (6 consecutive errors) and gets banned."""
        WAF_POLICY["enabled"] = True
        WAF_POLICY["max_consecutive_errors"] = 6
        WAF_POLICY["min_requests_window"] = 8
        WAF_POLICY["max_fail_rate"] = 0.80

        reused_ip = "203.0.113.42"

        # 6 consecutive bad decrypt requests from the same reused botnet node
        for _ in range(6):
            r = self.client.post(
                "/decrypt",
                json={"token": "invalid"},
                headers={"X-Forwarded-For": reused_ip},
            )
            self.assertEqual(r.status_code, 400)

        # 7th request from the same node is intercepted and dropped by WAF (Rule 2 Early Ban)
        r_drop = self.client.post(
            "/decrypt",
            json={"token": "invalid"},
            headers={"X-Forwarded-For": reused_ip},
        )
        self.assertEqual(r_drop.status_code, 429)
        self.assertEqual(r_drop.json.get("error"), "WAF_PREVENTIVE_BLOCK")
        self.assertIn(reused_ip, WAF_BLOCKED_IPS)


if __name__ == "__main__":
    unittest.main()
