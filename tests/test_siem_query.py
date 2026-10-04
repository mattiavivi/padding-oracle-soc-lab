import unittest
from common.siem_query import evaluate_event_query, filter_and_aggregate_events


class TestSiemQuery(unittest.TestCase):

    def setUp(self):
        self.sample_events = [
            {"service": "victim", "endpoint": "/decrypt", "src_ip": "attacker", "status_code": 500, "error_type": "padding_error", "latency_ms": 2.4, "ciphertext_len": 48},
            {"service": "victim", "endpoint": "/decrypt", "src_ip": "attacker", "status_code": 403, "error_type": "integrity_error", "latency_ms": 1.9, "ciphertext_len": 48},
            {"service": "victim", "endpoint": "/decrypt", "src_ip": "attacker", "status_code": 200, "error_type": "ok", "latency_ms": 2.1, "ciphertext_len": 48},
            {"service": "victim", "endpoint": "/decrypt", "src_ip": "benign-1", "status_code": 200, "error_type": "ok", "latency_ms": 2.0, "ciphertext_len": 32},
            {"service": "victim", "endpoint": "/decrypt", "src_ip": "benign-2", "status_code": 200, "error_type": "ok", "latency_ms": 1.8, "ciphertext_len": 32},
            {"service": "victim", "endpoint": "/encrypt", "src_ip": "benign-1", "status_code": 200, "error_type": "ok", "latency_ms": 1.1, "ciphertext_len": 16},
        ]

    def test_single_field_query(self):
        self.assertTrue(evaluate_event_query(self.sample_events[0], "status = 500"))
        self.assertFalse(evaluate_event_query(self.sample_events[1], "status = 500"))
        self.assertTrue(evaluate_event_query(self.sample_events[0], "endpoint = /decrypt"))

    def test_logical_and_query(self):
        q = "status = 500 AND endpoint = /decrypt"
        self.assertTrue(evaluate_event_query(self.sample_events[0], q))
        self.assertFalse(evaluate_event_query(self.sample_events[1], q))
        self.assertFalse(evaluate_event_query(self.sample_events[3], q))

    def test_logical_or_query(self):
        q = "status = 500 OR status = 403"
        self.assertTrue(evaluate_event_query(self.sample_events[0], q))
        self.assertTrue(evaluate_event_query(self.sample_events[1], q))
        self.assertFalse(evaluate_event_query(self.sample_events[2], q))

    def test_latency_comparison(self):
        self.assertTrue(evaluate_event_query(self.sample_events[0], "latency > 2.2"))
        self.assertFalse(evaluate_event_query(self.sample_events[1], "latency > 2.2"))

    def test_filter_and_aggregate(self):
        result = filter_and_aggregate_events(self.sample_events, "endpoint = /decrypt AND status != 200")
        self.assertEqual(result["total_matched"], 2)
        self.assertIn("500", result["status_distribution"])
        self.assertIn("403", result["status_distribution"])
        
        # Attacker summary should show 2 fails out of 2 matched
        attacker_summary = next(s for s in result["ip_summaries"] if s["ip"] == "attacker")
        self.assertEqual(attacker_summary["total_requests"], 2)
        self.assertEqual(attacker_summary["padding_errors"], 1)

    def test_group_by_and_having_clause(self):
        q = "endpoint = /decrypt | GROUP BY src_ip | HAVING COUNT(*) >= 2 AND FAIL_RATE > 0.50"
        result = filter_and_aggregate_events(self.sample_events, q)
        self.assertEqual(result["group_by"], "src_ip")
        
        matched_summaries = [s for s in result["ip_summaries"] if s["matches_aggregation"]]
        self.assertEqual(len(matched_summaries), 1)
        self.assertEqual(matched_summaries[0]["key"], "attacker")
        self.assertEqual(matched_summaries[0]["total_requests"], 3)
        self.assertGreater(matched_summaries[0]["fail_rate"], 0.50)


if __name__ == "__main__":
    unittest.main()

