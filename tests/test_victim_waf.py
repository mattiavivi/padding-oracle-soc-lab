import unittest
import json
from victim.app import app, WAF_POLICY, WAF_STATE, WAF_BLOCKED_IPS


class TestVictimWAF(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        WAF_BLOCKED_IPS.clear()
        WAF_STATE.clear()
        WAF_POLICY["enabled"] = False
        WAF_POLICY["max_consecutive_errors"] = 5
        WAF_POLICY["min_requests_window"] = 10
        WAF_POLICY["max_fail_rate"] = 0.80

    def test_waf_disabled_allows_traffic(self):
        WAF_POLICY["enabled"] = False
        res = self.client.post("/decrypt", json={"token": "invalid_token_b64"}, headers={"X-Client-ID": "test-ip-1"})
        self.assertEqual(res.status_code, 400)

    def test_waf_policy_activation_and_blocking(self):
        WAF_POLICY["enabled"] = True
        WAF_POLICY["max_consecutive_errors"] = 3
        
        # 3 consecutive bad requests from test-ip-2
        for _ in range(3):
            r = self.client.post("/decrypt", json={"token": "invalid"}, headers={"X-Client-ID": "test-ip-2"})
            self.assertEqual(r.status_code, 400)
            
        # 4th request must be blocked by WAF with HTTP 429
        r4 = self.client.post("/decrypt", json={"token": "invalid"}, headers={"X-Client-ID": "test-ip-2"})
        self.assertEqual(r4.status_code, 429)
        self.assertEqual(r4.json.get("error"), "WAF_PREVENTIVE_BLOCK")
        self.assertIn("test-ip-2", WAF_BLOCKED_IPS)

    def test_waf_status_and_reset_endpoints(self):
        WAF_POLICY["enabled"] = True
        WAF_BLOCKED_IPS.add("blocked-actor")
        
        res = self.client.get("/waf/status")
        self.assertEqual(res.status_code, 200)
        self.assertIn("blocked-actor", res.json.get("blocked_ips", []))
        
        reset_res = self.client.post("/waf/reset")
        self.assertEqual(reset_res.status_code, 200)
        self.assertEqual(len(WAF_BLOCKED_IPS), 0)


if __name__ == "__main__":
    unittest.main()
