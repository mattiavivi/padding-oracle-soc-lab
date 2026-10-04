import unittest
import json
from datetime import datetime, timezone, timedelta
from soc.collector import app, _generate_sigma_rule


class TestSocThreatHunting(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()

    def test_sigma_rule_generation(self):
        rule_params = {
            "min_events_per_ip": 15,
            "high_fail_rate_threshold": 0.85,
            "min_timing_events_per_ip": 20,
            "timing_stddev_threshold_ms": 6.0,
            "bimodality_threshold": 0.555,
        }
        yaml_out = _generate_sigma_rule(rule_params)
        self.assertIn("title: AES-CBC Cryptographic Padding Oracle", yaml_out)
        self.assertIn("t1110.001", yaml_out)
        self.assertIn("t1595.002", yaml_out)
        self.assertIn("timeframe: 60s", yaml_out)
        self.assertIn("condition_error_rate", yaml_out)
        self.assertIn("failure_rate >= 0.85", yaml_out)

    def test_sigma_rule_generation_custom_timeframe(self):
        rule_params = {
            "min_events_per_ip": 15,
            "high_fail_rate_threshold": 0.85,
            "window_seconds": 300,
        }
        yaml_out = _generate_sigma_rule(rule_params)
        self.assertIn("timeframe: 300s", yaml_out)


    def test_hunting_backtest_endpoint(self):
        payload = {
            "min_events_per_ip": 5,
            "high_fail_rate_threshold": 0.80,
            "window_seconds": 120,
        }
        res = self.client.post("/hunting/backtest", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json
        self.assertTrue(data.get("ok"))
        self.assertIn("sigma_rule_yaml", data)
        self.assertIn("timeframe: 120s", data["sigma_rule_yaml"])
        self.assertIn("true_positive_rate", data)
        self.assertIn("false_positive_rate", data)

    def test_hunting_explore_endpoint(self):
        res = self.client.get("/hunting/explore")
        self.assertEqual(res.status_code, 200)
        data = res.json
        self.assertTrue(data.get("ok"))
        self.assertIn("ip_profiles", data)

    def test_waf_drop_alert_schema(self):
        from soc.collector import _build_alerts
        mock_events = [
            {
                "service": "victim",
                "src_ip": "198.51.100.50",
                "status_code": 429,
                "error_type": "waf_blocked",
                "details": {"reason": "Test block", "queries_total": 20},
                "ts": datetime.now(timezone.utc).isoformat(),
            }
        ]
        alerts = _build_alerts(mock_events)
        self.assertTrue(len(alerts) >= 1)
        waf_alert = next((a for a in alerts if a.get("rule") == "waf_padding_oracle_blocked"), None)
        self.assertIsNotNone(waf_alert)
        self.assertEqual(waf_alert.get("ip"), "198.51.100.50")
        self.assertEqual(waf_alert.get("src_ip"), "198.51.100.50")
        self.assertEqual(waf_alert.get("severity"), "critical")
        self.assertIn("blocked_requests", waf_alert.get("evidence", {}))

    def test_siem_query_aliases_endpoint(self):
        res = self.client.post("/hunting/query", json={"query": "client_ip = attacker AND status_code != 200"})
        self.assertEqual(res.status_code, 200)
        data = res.json
        self.assertTrue(data.get("ok"))
        self.assertIn("events", data)

    def test_no_double_counting_ephemeral_ip_rotation(self):
        from soc.collector import _MEMORY_LOG_BUFFER, _LOG_SYNC_LOCK
        now_ts = datetime.now(timezone.utc).isoformat()
        ephemeral_ip = "203.0.113.88"

        # Simulate 1 query with 1 IP = 1 Query: 1 event from victim + 1 event from attacker
        victim_event = {
            "service": "victim",
            "src_ip": ephemeral_ip,
            "endpoint": "/api/v1/crypto/decrypt",
            "status_code": 500,
            "error_type": "padding_error",
            "ciphertext_len": 48,
            "latency_ms": 2.5,
            "ts": now_ts,
            "details": {"client_role": "attacker"},
        }
        attacker_event = {
            "service": "attacker",
            "event_type": "attack_probe",
            "src_ip": ephemeral_ip,
            "endpoint": "/api/v1/crypto/decrypt",
            "status_code": 500,
            "error_type": "padding_error",
            "ciphertext_len": 48,
            "latency_ms": 2.5,
            "ts": now_ts,
            "details": {"byte_index": 0, "guess": 42},
        }

        with _LOG_SYNC_LOCK:
            _MEMORY_LOG_BUFFER.append(victim_event)
            _MEMORY_LOG_BUFFER.append(attacker_event)

        res = self.client.get("/hunting/explore")
        self.assertEqual(res.status_code, 200)
        profiles = res.json.get("ip_profiles", [])
        ephemeral_profile = next((p for p in profiles if p["ip"] == ephemeral_ip), None)
        self.assertIsNotNone(ephemeral_profile)

        # Must be exactly 1 request and 1 failed decrypt (no double count!)
        self.assertEqual(ephemeral_profile["total_events"], 1)
        self.assertEqual(ephemeral_profile["decrypt_requests"], 1)
        self.assertEqual(ephemeral_profile["failed_decrypts"], 1)
        self.assertEqual(ephemeral_profile["fail_rate"], 1.0)
        self.assertTrue(ephemeral_profile["is_attacker_origin"])


if __name__ == "__main__":
    unittest.main()

