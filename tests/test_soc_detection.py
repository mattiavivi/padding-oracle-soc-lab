import unittest
from datetime import datetime, timezone, timedelta
from soc.collector import _calc_latency_stats, _build_alerts, _compute_soc_kpis


class TestSocDetectionEngine(unittest.TestCase):

    def test_latency_statistics(self):
        latencies = [5.0, 5.2, 4.8, 5.1, 35.0, 34.8]
        stats = _calc_latency_stats(latencies)
        self.assertEqual(stats["count"], 6)
        self.assertGreater(stats["stddev"], 10.0)
        self.assertGreater(stats["p95_p50_diff"], 20.0)

    def test_default_zero_alerts_when_rules_disabled(self):
        # 30 attack events with default disabled rules -> 0 alerts (clean slate)
        events = []
        now = datetime.now(timezone.utc)
        for i in range(30):
            events.append({
                "ts": (now - timedelta(seconds=30 - i)).isoformat(),
                "service": "victim",
                "endpoint": "/decrypt",
                "src_ip": "attacker",
                "status_code": 500 if i < 28 else 200,
                "error_type": "padding_error" if i < 28 else "ok",
                "ciphertext_len": 48,
                "latency_ms": 2.5,
            })
        alerts = _build_alerts(events, custom_rules={"enabled": False})
        self.assertEqual(len(alerts), 0, "No alerts should be triggered when rules are disabled")

    def test_error_rate_padding_oracle_detection(self):
        # 30 events with 28 padding errors from attacker IP
        events = []
        now = datetime.now(timezone.utc)
        for i in range(30):
            events.append({
                "ts": (now - timedelta(seconds=30 - i)).isoformat(),
                "service": "victim",
                "endpoint": "/decrypt",
                "src_ip": "attacker",
                "status_code": 500 if i < 28 else 200,
                "error_type": "padding_error" if i < 28 else "ok",
                "ciphertext_len": 48,
                "latency_ms": 2.5,
            })

        alerts = _build_alerts(events, custom_rules={"enabled": True, "min_events_per_ip": 15})
        self.assertTrue(any(a["rule"] == "high_fail_rate_padding_oracle" for a in alerts))
        self.assertTrue(any(a["severity"] == "critical" for a in alerts))

    def test_timing_side_channel_oracle_detection(self):
        # 25 events on victim-partial: generic 403 status but 23 fast (5ms) and 2 delayed (35ms)
        events = []
        now = datetime.now(timezone.utc)
        for i in range(25):
            lat = 35.0 if i in (5, 18) else 5.0
            events.append({
                "ts": (now - timedelta(seconds=25 - i)).isoformat(),
                "service": "victim",
                "endpoint": "/decrypt",
                "src_ip": "attacker",
                "status_code": 403,
                "error_type": "generic_error",
                "ciphertext_len": 32,
                "latency_ms": lat,
            })

        alerts = _build_alerts(events, custom_rules={"enabled": True, "min_timing_events_per_ip": 20})
        self.assertTrue(any(a["rule"] == "timing_side_channel_oracle" for a in alerts))
        self.assertEqual(alerts[0]["severity"], "high")
        self.assertIn("T1595.002", alerts[0]["mitre_technique"])

    def test_waf_blocked_alert_generation(self):
        now = datetime.now(timezone.utc)
        events = [
            {
                "ts": now.isoformat(),
                "service": "victim",
                "endpoint": "/decrypt",
                "src_ip": "attacker",
                "status_code": 429,
                "error_type": "waf_blocked",
                "latency_ms": 0.5,
                "ciphertext_len": 0,
            }
        ]
        alerts = _build_alerts(events)
        self.assertTrue(any(a["rule"] == "waf_padding_oracle_blocked" for a in alerts))
        self.assertEqual(alerts[0]["severity"], "critical")

    def test_benign_traffic_no_false_positives(self):
        # 50 benign requests (status 200, latency ~2ms)
        events = []
        now = datetime.now(timezone.utc)
        for i in range(50):
            events.append({
                "ts": (now - timedelta(seconds=50 - i)).isoformat(),
                "service": "victim",
                "endpoint": "/decrypt",
                "src_ip": "benign-1",
                "status_code": 200,
                "error_type": "ok",
                "ciphertext_len": 32,
                "latency_ms": 2.1,
            })

        alerts = _build_alerts(events)
        self.assertEqual(len(alerts), 0, "Benign traffic must not trigger security alerts")

        kpis = _compute_soc_kpis(events, alerts)
        self.assertEqual(kpis["false_positive_rate"], 0.0)
        self.assertEqual(kpis["baseline_profile"]["benign_requests"], 50)

    def test_sarles_bimodality_coefficient(self):
        # Unimodal normal-like traffic: BC should be close to 0.333
        unimodal_lats = [5.0, 5.1, 4.9, 5.2, 5.0, 4.8, 5.1, 5.0, 4.9, 5.2]
        unimodal_stats = _calc_latency_stats(unimodal_lats)
        self.assertFalse(unimodal_stats["is_bimodal"])
        self.assertLess(unimodal_stats["bimodality_coefficient"], 0.555)

        # Bimodal side-channel traffic (fast error probes + slow valid padding probes)
        bimodal_lats = [5.0] * 20 + [35.0] * 3
        bimodal_stats = _calc_latency_stats(bimodal_lats)
        self.assertTrue(bimodal_stats["is_bimodal"])
        self.assertGreater(bimodal_stats["bimodality_coefficient"], 0.555)

    def test_mttd_calculation(self):
        now = datetime.now(timezone.utc)
        events = [
            {"ts": (now - timedelta(seconds=20)).isoformat(), "service": "attacker", "event_type": "attack_progress"},
            {"ts": (now - timedelta(seconds=15)).isoformat(), "service": "victim", "endpoint": "/decrypt", "src_ip": "attacker", "status_code": 500, "error_type": "padding_error"},
        ]
        alerts = [
            {
                "rule": "high_fail_rate_padding_oracle",
                "ip": "attacker",
                "timestamp": (now - timedelta(seconds=12)).isoformat(),
            }
        ]
        kpis = _compute_soc_kpis(events, alerts)
        self.assertIsNotNone(kpis["mttd_seconds"])
        self.assertEqual(kpis["mttd_seconds"], 8.0)


if __name__ == "__main__":
    unittest.main()

