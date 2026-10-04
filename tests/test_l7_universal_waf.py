import unittest
import json
from datetime import datetime, timezone
from victim.app import app as victim_app, WAF_POLICY, WAF_STATE, WAF_BLOCKED_IPS
from soc.collector import app as soc_app, _MEMORY_LOG_BUFFER, _LOG_SYNC_LOCK


import copy

class TestL7UniversalWAF(unittest.TestCase):

    def setUp(self):
        self.victim_client = victim_app.test_client()
        self.soc_client = soc_app.test_client()

        # Reset Victim WAF state
        WAF_BLOCKED_IPS.clear()
        WAF_STATE.clear()
        from victim.app import _default_waf_rules
        WAF_POLICY["enabled"] = False
        WAF_POLICY["max_consecutive_errors"] = 5
        WAF_POLICY["min_requests_window"] = 10
        WAF_POLICY["max_fail_rate"] = 0.80
        WAF_POLICY["rules"] = _default_waf_rules()

    def tearDown(self):
        WAF_BLOCKED_IPS.clear()
        WAF_STATE.clear()
        from victim.app import _default_waf_rules
        WAF_POLICY["enabled"] = False
        WAF_POLICY["rules"] = _default_waf_rules()

    def test_universal_waf_intercepts_login_without_route_changes(self):
        """Zero-touch test: requests on /api/v1/auth/login are inspected at L7 by @app.before_request."""
        WAF_POLICY["enabled"] = True
        WAF_POLICY["rules"] = [
            {
                "id": "waf_login_bruteforce_defense",
                "name": "Login Brute-Force Rate Limiting",
                "endpoint": "/api/v1/auth/login",
                "enabled": True,
                "min_requests_window": 5,
                "max_fail_rate": 0.80,
                "max_consecutive_errors": 5,
                "window_seconds": 60,
                "ban_ttl_seconds": 120,
            }
        ]

        test_ip = "192.168.1.99"
        # 5 consecutive failed logins return 401 Unauthorized
        for i in range(5):
            res = self.victim_client.post(
                "/api/v1/auth/login",
                json={"username": "admin", "password": f"wrong_{i}"},
                headers={"X-Client-ID": test_ip}
            )
            self.assertEqual(res.status_code, 401, f"Attempt {i+1} should return 401")

        # 6th request should be blocked at Layer 7 before route handler with HTTP 429
        blocked_res = self.victim_client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "wrong_final"},
            headers={"X-Client-ID": test_ip}
        )
        self.assertEqual(blocked_res.status_code, 429)
        self.assertEqual(blocked_res.json.get("error"), "WAF_PREVENTIVE_BLOCK")
        self.assertIn("Login Brute-Force Rate Limiting", blocked_res.json.get("reason", ""))

    def test_endpoint_isolation_login_vs_decrypt(self):
        """Verify endpoint isolation: an IP blocked on /api/v1/auth/login remains unblocked on /decrypt, and vice versa."""
        WAF_POLICY["enabled"] = True
        WAF_POLICY["rules"] = [
            {
                "id": "waf_login_defense",
                "endpoint": "/api/v1/auth/login",
                "enabled": True,
                "max_consecutive_errors": 3,
                "window_seconds": 60,
                "ban_ttl_seconds": 120,
            },
            {
                "id": "waf_decrypt_defense",
                "endpoint": "/api/v1/crypto/decrypt",
                "enabled": True,
                "max_consecutive_errors": 3,
                "window_seconds": 60,
                "ban_ttl_seconds": 120,
            }
        ]

        test_ip = "192.168.1.150"

        # Trigger ban on /api/v1/auth/login with 3 bad requests
        for _ in range(3):
            r = self.victim_client.post(
                "/api/v1/auth/login",
                json={"username": "root", "password": "bad"},
                headers={"X-Client-ID": test_ip}
            )
            self.assertEqual(r.status_code, 401)

        # 4th request on login is 429
        r_blocked = self.victim_client.post(
            "/api/v1/auth/login",
            json={"username": "root", "password": "bad"},
            headers={"X-Client-ID": test_ip}
        )
        self.assertEqual(r_blocked.status_code, 429)

        # But request on /api/v1/crypto/decrypt (or /decrypt) MUST NOT be blocked by WAF!
        r_decrypt = self.victim_client.post(
            "/decrypt",
            json={"token": "invalid_token_b64"},
            headers={"X-Client-ID": test_ip}
        )
        # Should return 400 (application error), NOT 429 (WAF block)
        self.assertEqual(r_decrypt.status_code, 400)

    def test_waf_disabled_permits_continuous_failures(self):
        """When WAF is disabled, requests pass through without 429 blocking."""
        WAF_POLICY["enabled"] = False
        test_ip = "192.168.1.200"

        for i in range(10):
            res = self.victim_client.post(
                "/api/v1/auth/login",
                json={"username": "user", "password": f"guess_{i}"},
                headers={"X-Client-ID": test_ip}
            )
            self.assertEqual(res.status_code, 401)

    def test_threat_hunting_query_scoping_and_metrics(self):
        """Test that /hunting/explore scopes actor metrics and telemetry based on SIEM query."""
        now_ts = datetime.now(timezone.utc).isoformat()
        
        with _LOG_SYNC_LOCK:
            _MEMORY_LOG_BUFFER.clear()
            # Inject login events for 192.168.1.50
            for i in range(6):
                _MEMORY_LOG_BUFFER.append({
                    "service": "victim",
                    "src_ip": "192.168.1.50",
                    "endpoint": "/api/v1/auth/login",
                    "status_code": 401 if i > 0 else 200,
                    "error_type": "auth_failure" if i > 0 else "ok",
                    "latency_ms": 3.0,
                    "ts": now_ts,
                })
            # Inject decrypt events for 198.51.100.77
            for i in range(10):
                _MEMORY_LOG_BUFFER.append({
                    "service": "victim",
                    "src_ip": "198.51.100.77",
                    "endpoint": "/api/v1/crypto/decrypt",
                    "status_code": 500,
                    "error_type": "padding_error",
                    "ciphertext_len": 48,
                    "latency_ms": 2.0,
                    "ts": now_ts,
                })

        # Query scoped to /api/v1/auth/login
        res = self.soc_client.get("/hunting/explore?query=endpoint%20%3D%20%2Fapi%2Fv1%2Fauth%2Flogin")
        self.assertEqual(res.status_code, 200)
        data = res.json
        self.assertTrue(data.get("ok"))

        # Verify scope stats reflect only login traffic
        scope_stats = data.get("scope_stats", {})
        self.assertEqual(scope_stats.get("total_events"), 6)
        self.assertIn("/api/v1/auth/login", scope_stats.get("endpoints", []))
        self.assertNotIn("/api/v1/crypto/decrypt", scope_stats.get("endpoints", []))

        # Verify IP profiles only contain 192.168.1.50
        profiles = data.get("ip_profiles", [])
        ips = [p.get("ip") for p in profiles]
        self.assertIn("192.168.1.50", ips)
        self.assertNotIn("198.51.100.77", ips)

        login_profile = next(p for p in profiles if p.get("ip") == "192.168.1.50")
        self.assertEqual(login_profile.get("total_requests"), 6)
        self.assertEqual(login_profile.get("failed_requests"), 5)

    def test_hunting_backtest_with_endpoint_candidate(self):
        """Test that /hunting/backtest respects candidate endpoint and generates appropriate Sigma rule."""
        payload = {
            "query": "endpoint = /api/v1/auth/login",
            "endpoint": "/api/v1/auth/login",
            "min_events_per_ip": 5,
            "high_fail_rate_threshold": 0.70,
        }
        res = self.soc_client.post("/hunting/backtest", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json
        self.assertTrue(data.get("ok"))
        self.assertIn("/api/v1/auth/login", data.get("sigma_rule_yaml", ""))


if __name__ == "__main__":
    unittest.main()
