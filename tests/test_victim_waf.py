import unittest
import json
from victim.app import app, WAF_POLICY, WAF_STATE, WAF_BLOCKED_IPS


class TestVictimWAF(unittest.TestCase):

    @classmethod
    def tearDownClass(cls):
        from victim.app import WAF_POLICY_FILE, WAF_POLICY, _default_waf_rules
        clean_json = {
            "enabled": False,
            "min_requests_window": 15,
            "max_fail_rate": 0.8,
            "max_consecutive_errors": 12,
            "window_seconds": 60,
            "action": "429_too_many_requests"
        }
        try:
            with open(WAF_POLICY_FILE, "w", encoding="utf-8") as f:
                json.dump(clean_json, f, indent=2)
        except Exception:
            pass
        WAF_POLICY.clear()
        WAF_POLICY.update(clean_json)
        WAF_POLICY["rules"] = _default_waf_rules()

    def setUp(self):
        self.client = app.test_client()
        WAF_BLOCKED_IPS.clear()
        WAF_STATE.clear()
        from victim.app import _default_waf_rules
        WAF_POLICY["enabled"] = False
        WAF_POLICY["max_consecutive_errors"] = 5
        WAF_POLICY["min_requests_window"] = 10
        WAF_POLICY["max_fail_rate"] = 0.80
        WAF_POLICY["rules"] = _default_waf_rules()

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

    def test_waf_rules_catalog_toggle_and_update(self):
        # Aggiungi una regola WAF personalizzata
        add_res = self.client.post("/waf/rules/add", json={
            "rule": {
                "id": "custom_test_rule",
                "name": "Custom Test Rule",
                "enabled": True,
                "min_requests_window": 5,
                "max_fail_rate": 0.50,
                "max_consecutive_errors": 4,
                "window_seconds": 30,
                "ban_ttl_seconds": 60,
            }
        })
        self.assertEqual(add_res.status_code, 200)
        rules = add_res.json.get("policy", {}).get("rules", [])
        self.assertTrue(any(r["id"] == "custom_test_rule" for r in rules))

        # Toggle della regola
        toggle_res = self.client.post("/waf/rules/toggle", json={"rule_id": "custom_test_rule"})
        self.assertEqual(toggle_res.status_code, 200)
        rules = toggle_res.json.get("policy", {}).get("rules", [])
        matched = next(r for r in rules if r["id"] == "custom_test_rule")
        self.assertFalse(matched["enabled"])

        # Update parametri regola
        upd_res = self.client.post("/waf/rules/update", json={
            "rule_id": "custom_test_rule",
            "updates": {"max_fail_rate": 0.65, "window_seconds": 300}
        })
        self.assertEqual(upd_res.status_code, 200)
        rules = upd_res.json.get("policy", {}).get("rules", [])
        matched = next(r for r in rules if r["id"] == "custom_test_rule")
        self.assertEqual(matched["max_fail_rate"], 0.65)
        self.assertEqual(matched["window_seconds"], 300)

    def test_waf_custom_window_seconds_dilation(self):
        import time
        from victim.app import _check_waf_block

        # Abilita WAF policy globale
        WAF_POLICY["enabled"] = True
        WAF_BLOCKED_IPS.clear()
        test_ip = "192.0.2.77"

        # Scenario A: Regola con finestra a 60 secondi
        WAF_POLICY["rules"] = [{
            "id": "waf_fast_window",
            "name": "Fast 60s Window",
            "endpoint": "/decrypt",
            "enabled": True,
            "min_requests_window": 5,
            "max_fail_rate": 0.80,
            "max_consecutive_errors": 10,
            "window_seconds": 60,
            "ban_ttl_seconds": 60,
        }]

        # Simula attacco lento: 5 richieste distanziate di 20s l'una dall'altra (arco temporale di 80 secondi)
        now = time.time()
        WAF_STATE[test_ip] = [
            (now - 80, True, "/decrypt"),
            (now - 60.5, True, "/decrypt"),
            (now - 40, True, "/decrypt"),
            (now - 20, True, "/decrypt"),
            (now, True, "/decrypt"),
        ]

        # Con finestra 60s, i primi due eventi sono fuori finestra: solo 3 eventi validi (< 5) -> NON bloccato
        blocked, _ = _check_waf_block(test_ip, "/decrypt")
        self.assertFalse(blocked)

        # Scenario B: Regola riconfigurata con finestra dilatata a 300 secondi (anti slow attack)
        WAF_POLICY["rules"] = [{
            "id": "waf_dilated_window",
            "name": "Dilated 300s Anti-Slow Window",
            "endpoint": "/decrypt",
            "enabled": True,
            "min_requests_window": 5,
            "max_fail_rate": 0.80,
            "max_consecutive_errors": 10,
            "window_seconds": 300,
            "ban_ttl_seconds": 60,
        }]

        WAF_STATE[test_ip] = [
            (now - 80, True, "/decrypt"),
            (now - 60.5, True, "/decrypt"),
            (now - 40, True, "/decrypt"),
            (now - 20, True, "/decrypt"),
            (now, True, "/decrypt"),
        ]

        # Con finestra 300s, tutti e 5 gli eventi sono validi (5 >= 5 e fail_rate 100% >= 80%) -> BLOCCATO!
        blocked, msg = _check_waf_block(test_ip, "/decrypt")
        self.assertTrue(blocked)
        self.assertIn("Dilated 300s Anti-Slow Window", msg)


if __name__ == "__main__":
    unittest.main()

