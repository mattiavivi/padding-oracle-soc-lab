import unittest
import time
from datetime import datetime, timezone
from victim.app import app as victim_app, WAF_BLOCKED_IPS, WAF_POLICY
from soc.collector import app as collector_app, _calc_latency_stats, _build_alerts
from common.siem_query import evaluate_event_query, filter_and_aggregate_events


class TestAdvancedSocImprovements(unittest.TestCase):

    def setUp(self):
        self.victim_client = victim_app.test_client()
        self.collector_client = collector_app.test_client()
        WAF_BLOCKED_IPS.clear()
        WAF_POLICY["enabled"] = True

    def test_http_event_ingestion_endpoint(self):
        test_ev = {
            "service": "test_service",
            "event_type": "unit_test_event",
            "src_ip": "198.51.100.99",
            "endpoint": "/api/test",
            "status_code": 200,
            "latency_ms": 1.25,
            "crypto_time_ns": 45000,
        }
        res = self.collector_client.post("/api/v1/events", json=test_ev)
        self.assertEqual(res.status_code, 201)
        self.assertTrue(res.json.get("ok"))
        self.assertIn("event_id", res.json)

    def test_crypto_time_tracking_in_victim(self):
        # 1. Test Encrypt endpoint
        enc_res = self.victim_client.post("/encrypt", json={"plaintext": "SecretPayload123"})
        self.assertEqual(enc_res.status_code, 200)
        token_b64 = enc_res.json.get("token")
        self.assertIsNotNone(token_b64)

        # 2. Test Decrypt endpoint
        dec_res = self.victim_client.post("/decrypt", json={"token": token_b64})
        self.assertEqual(dec_res.status_code, 200)
        self.assertEqual(dec_res.json.get("plaintext"), "SecretPayload123")

    def test_waf_ttl_auto_expiration(self):
        # Block IP with a very short TTL (0.15s)
        WAF_BLOCKED_IPS.add("192.0.2.77", ttl_seconds=0.15)
        self.assertIn("192.0.2.77", WAF_BLOCKED_IPS)

        # Immediate request should be blocked
        res_blocked = self.victim_client.post(
            "/decrypt",
            json={"token": "dGVzdA=="},
            headers={"X-Client-ID": "192.0.2.77"}
        )
        self.assertEqual(res_blocked.status_code, 429)
        self.assertEqual(res_blocked.json.get("error"), "WAF_PREVENTIVE_BLOCK")

        # Wait for TTL to expire
        time.sleep(0.25)
        self.assertNotIn("192.0.2.77", WAF_BLOCKED_IPS)

    def test_sarles_bimodality_with_iqr(self):
        # Strict bimodal latency distribution
        lats = [4.5, 4.6, 4.8, 5.0, 5.1, 4.9, 4.7, 5.2] * 4 + [35.0, 36.0, 34.5, 35.5]
        stats = _calc_latency_stats(lats)
        self.assertTrue(stats["is_bimodal"])
        self.assertGreater(stats["bimodality_coefficient"], 0.555)
        self.assertGreater(stats["iqr"], 0.0)
        self.assertGreater(stats["stddev"], 5.0)

    def test_siem_query_crypto_time_fields(self):
        sample = {
            "service": "victim",
            "endpoint": "/decrypt",
            "status_code": 200,
            "latency_ms": 5.2,
            "crypto_time_ns": 85000,
            "src_ip": "10.0.0.1",
        }
        self.assertTrue(evaluate_event_query(sample, "crypto_time_ns > 50000"))
        self.assertFalse(evaluate_event_query(sample, "crypto_time_ns > 100000"))
        self.assertTrue(evaluate_event_query(sample, "crypto_time_ms > 0.05"))

    def test_waf_rule_delete_endpoint(self):
        # 1. Add rule
        add_res = self.victim_client.post("/waf/rules/add", json={
            "rule": {
                "id": "waf_test_delete_me",
                "name": "Test Delete Rule",
                "enabled": True,
            }
        })
        self.assertEqual(add_res.status_code, 200)
        self.assertTrue(add_res.json.get("ok"))
        self.assertTrue(any(r["id"] == "waf_test_delete_me" for r in add_res.json["policy"]["rules"]))

        # 2. Delete rule
        del_res = self.victim_client.post("/waf/rules/delete", json={
            "rule_id": "waf_test_delete_me"
        })
        self.assertEqual(del_res.status_code, 200)
        self.assertTrue(del_res.json.get("ok"))
        self.assertFalse(any(r["id"] == "waf_test_delete_me" for r in del_res.json["policy"]["rules"]))

    def test_siem_rule_add_and_delete_endpoints(self):
        from soc.dashboard import app as dash_app
        dash_client = dash_app.test_client()

        # 1. Add SIEM rule
        add_res = dash_client.post("/siem/rules/add", json={
            "rule": {
                "id": "siem_test_custom_rule",
                "name": "Unit Test Custom SIEM Rule",
                "mitre": "T1110.001",
                "min_events": 10,
                "fail_rate": 0.70,
                "enabled": True,
            }
        })
        self.assertEqual(add_res.status_code, 200)
        self.assertTrue(add_res.json.get("ok"))
        self.assertTrue(any(r["id"] == "siem_test_custom_rule" for r in add_res.json["rules"]["rules"]))

        # 2. Toggle SIEM rule
        tog_res = dash_client.post("/siem/rules/toggle", json={"rule_key": "siem_test_custom_rule"})
        self.assertEqual(tog_res.status_code, 200)
        self.assertTrue(tog_res.json.get("ok"))
        toggled_rule = next(r for r in tog_res.json["rules"]["rules"] if r["id"] == "siem_test_custom_rule")
        self.assertFalse(toggled_rule["enabled"])

        # 3. Delete SIEM rule
        del_res = dash_client.post("/siem/rules/delete", json={"rule_id": "siem_test_custom_rule"})
        self.assertEqual(del_res.status_code, 200)
        self.assertTrue(del_res.json.get("ok"))
        self.assertFalse(any(r["id"] == "siem_test_custom_rule" for r in del_res.json["rules"]["rules"]))


if __name__ == "__main__":
    unittest.main()

