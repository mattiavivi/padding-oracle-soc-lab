import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

from soc.collector import (
    _calc_latency_stats,
    _build_alerts,
    _default_siem_rules,
    _event_matches_endpoint,
    _trigger_soar_mitigation,
)
from soc.dashboard import app as dashboard_app, _default_siem_rules as dash_default_rules
from victim.app import app as victim_app, WAF_POLICY, WAF_STATE, WAF_BLOCKED_IPS


class TestEndpointScopedSiemRules(unittest.TestCase):

    def setUp(self):
        WAF_BLOCKED_IPS.clear()
        WAF_STATE.clear()
        WAF_POLICY["enabled"] = False
        self.dash_client = dashboard_app.test_client()
        self.victim_client = victim_app.test_client()

    def tearDown(self):
        WAF_BLOCKED_IPS.clear()
        WAF_STATE.clear()

    def test_default_rules_have_endpoints(self):
        collector_rules = _default_siem_rules()
        dash_rules = dash_default_rules()
        
        self.assertTrue(len(collector_rules) >= 4)
        for r in collector_rules:
            self.assertIn("endpoint", r, f"Rule {r.get('id')} in collector must specify an endpoint")
            self.assertTrue(r["endpoint"].startswith("/") or r["endpoint"] == "*")

        for r in dash_rules:
            self.assertIn("endpoint", r, f"Rule {r.get('id')} in dashboard must specify an endpoint")

        rule_ids = [r["id"] for r in collector_rules]
        self.assertIn("rule_error_flooding", rule_ids)
        self.assertIn("rule_timing_oracle", rule_ids)
        self.assertIn("rule_byte_probing", rule_ids)
        self.assertIn("rule_auth_bruteforce", rule_ids)

    def test_event_matches_endpoint_logic(self):
        # Exact match
        ev1 = {"endpoint": "/api/v1/crypto/decrypt"}
        self.assertTrue(_event_matches_endpoint(ev1, "/api/v1/crypto/decrypt"))

        # Decrypt alias match
        ev_legacy = {"endpoint": "/decrypt"}
        self.assertTrue(_event_matches_endpoint(ev_legacy, "/api/v1/crypto/decrypt"))
        self.assertTrue(_event_matches_endpoint(ev1, "/decrypt"))

        # Wildcard match
        self.assertTrue(_event_matches_endpoint(ev1, "*"))
        self.assertTrue(_event_matches_endpoint(ev1, None))
        self.assertTrue(_event_matches_endpoint(ev1, "/"))

        # Auth login endpoint
        ev_login = {"endpoint": "/api/v1/auth/login"}
        self.assertTrue(_event_matches_endpoint(ev_login, "/api/v1/auth/login"))
        self.assertFalse(_event_matches_endpoint(ev_login, "/api/v1/crypto/decrypt"))
        self.assertFalse(_event_matches_endpoint(ev1, "/api/v1/auth/login"))

    def test_auth_bruteforce_alert_generation_and_isolation(self):
        now = datetime.now(timezone.utc)
        # 10 failed login requests on /api/v1/auth/login
        login_events = []
        for i in range(10):
            login_events.append({
                "ts": (now - timedelta(seconds=10 - i)).isoformat(),
                "service": "victim",
                "endpoint": "/api/v1/auth/login",
                "src_ip": "198.51.100.77",
                "status_code": 401,
                "error_type": "generic_error",
                "latency_ms": 5.0,
            })

        alerts = _build_alerts(login_events, custom_rules={"enabled": True})
        
        # Must trigger auth_bruteforce_detected
        auth_alerts = [a for a in alerts if a.get("rule") == "auth_bruteforce_detected"]
        self.assertEqual(len(auth_alerts), 1)
        self.assertEqual(auth_alerts[0]["ip"], "198.51.100.77")
        self.assertEqual(auth_alerts[0]["endpoint"], "/api/v1/auth/login")

        # Must NOT trigger crypto padding oracle rule
        crypto_alerts = [a for a in alerts if a.get("rule") == "high_fail_rate_padding_oracle"]
        self.assertEqual(len(crypto_alerts), 0)

    def test_crypto_padding_oracle_alert_isolation_from_auth(self):
        now = datetime.now(timezone.utc)
        # 20 failed decrypt requests
        decrypt_events = []
        for i in range(20):
            decrypt_events.append({
                "ts": (now - timedelta(seconds=20 - i)).isoformat(),
                "service": "victim",
                "endpoint": "/api/v1/crypto/decrypt",
                "src_ip": "198.51.100.88",
                "status_code": 500,
                "error_type": "padding_error",
                "ciphertext_len": 48,
                "latency_ms": 2.0,
            })

        alerts = _build_alerts(decrypt_events, custom_rules={"enabled": True})
        
        crypto_alerts = [a for a in alerts if a.get("rule") == "high_fail_rate_padding_oracle"]
        self.assertEqual(len(crypto_alerts), 1)
        self.assertEqual(crypto_alerts[0]["ip"], "198.51.100.88")
        self.assertEqual(crypto_alerts[0]["endpoint"], "/api/v1/crypto/decrypt")

        # Must NOT trigger auth bruteforce
        auth_alerts = [a for a in alerts if a.get("rule") == "auth_bruteforce_detected"]
        self.assertEqual(len(auth_alerts), 0)

    def test_custom_rule_endpoint_filtering(self):
        now = datetime.now(timezone.utc)
        events = []
        # 15 errors on /api/v1/tokens
        for i in range(15):
            events.append({
                "ts": (now - timedelta(seconds=15 - i)).isoformat(),
                "service": "victim",
                "endpoint": "/api/v1/tokens",
                "src_ip": "198.51.100.99",
                "status_code": 403,
                "error_type": "forbidden",
                "latency_ms": 3.0,
            })

        custom_rules = {
            "enabled": True,
            "rules": [
                {
                    "id": "rule_token_abuse",
                    "name": "Token Abuse Detector",
                    "endpoint": "/api/v1/tokens",
                    "enabled": True,
                    "min_events": 10,
                    "fail_rate": 0.80,
                },
                {
                    "id": "rule_user_profile_abuse",
                    "name": "User Profile Abuse",
                    "endpoint": "/api/v1/user/profile",
                    "enabled": True,
                    "min_events": 5,
                    "fail_rate": 0.50,
                }
            ]
        }

        alerts = _build_alerts(events, custom_rules=custom_rules)
        
        token_alerts = [a for a in alerts if a.get("rule") == "rule_token_abuse"]
        self.assertEqual(len(token_alerts), 1)
        self.assertEqual(token_alerts[0]["endpoint"], "/api/v1/tokens")

        # /api/v1/user/profile rule must NOT trigger
        profile_alerts = [a for a in alerts if a.get("rule") == "rule_user_profile_abuse"]
        self.assertEqual(len(profile_alerts), 0)

    def test_victim_waf_scoped_block_endpoint(self):
        """Test that victim /waf/block_ip accepts endpoint and isolates access."""
        WAF_POLICY["enabled"] = True
        
        # Block attacker IP only on /api/v1/auth/login
        res = self.victim_client.post("/waf/block_ip", json={
            "ip": "192.168.1.200",
            "endpoint": "/api/v1/auth/login",
            "ttl_seconds": 60,
        })
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json.get("endpoint"), "/api/v1/auth/login")

        # Request on /api/v1/auth/login should be blocked by WAF (HTTP 429)
        login_res = self.victim_client.post(
            "/api/v1/auth/login",
            json={"username": "test", "password": "pwd"},
            headers={"X-Client-ID": "192.168.1.200"}
        )
        self.assertEqual(login_res.status_code, 429)
        self.assertEqual(login_res.json.get("error"), "WAF_PREVENTIVE_BLOCK")

        # Request from same IP on /decrypt should NOT be blocked (returns 400 for bad token)
        decrypt_res = self.victim_client.post(
            "/decrypt",
            json={"token": "bad_token"},
            headers={"X-Client-ID": "192.168.1.200"}
        )
        self.assertNotEqual(decrypt_res.status_code, 429)
        self.assertIn(decrypt_res.status_code, (400, 500))

    def test_dashboard_siem_rules_api_with_endpoint(self):
        # Test adding rule with endpoint
        res = self.dash_client.post("/siem/rules/add", json={
            "rule": {
                "id": "custom_scoped_test_rule",
                "name": "Custom Scoped Test Rule",
                "endpoint": "/api/v1/user/profile",
                "min_events": 8,
                "fail_rate": 0.75,
            }
        })
        self.assertEqual(res.status_code, 200)
        data = res.json
        self.assertTrue(data.get("ok"))
        self.assertEqual(data.get("rule", {}).get("endpoint"), "/api/v1/user/profile")

        # Verify rule is returned in status
        status_res = self.dash_client.get("/siem/rules/status")
        self.assertEqual(status_res.status_code, 200)
        rules = status_res.json.get("rules", {}).get("rules", [])
        added_rule = next((r for r in rules if r.get("id") == "custom_scoped_test_rule"), None)
        self.assertIsNotNone(added_rule)
        self.assertEqual(added_rule.get("endpoint"), "/api/v1/user/profile")

        # Clean up
        del_res = self.dash_client.post("/siem/rules/delete", json={"rule_id": "custom_scoped_test_rule"})
        self.assertTrue(del_res.json.get("ok"))


if __name__ == "__main__":
    unittest.main()
