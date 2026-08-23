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
        self.assertIn("condition_error_rate", yaml_out)
        self.assertIn("failure_rate >= 0.85", yaml_out)


    def test_hunting_backtest_endpoint(self):
        payload = {
            "min_events_per_ip": 5,
            "high_fail_rate_threshold": 0.80,
        }
        res = self.client.post("/hunting/backtest", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json
        self.assertTrue(data.get("ok"))
        self.assertIn("sigma_rule_yaml", data)
        self.assertIn("true_positive_rate", data)
        self.assertIn("false_positive_rate", data)

    def test_hunting_explore_endpoint(self):
        res = self.client.get("/hunting/explore")
        self.assertEqual(res.status_code, 200)
        data = res.json
        self.assertTrue(data.get("ok"))
        self.assertIn("ip_profiles", data)


if __name__ == "__main__":
    unittest.main()
