import unittest
import os
import json
import time
import requests
from pathlib import Path

BASE_UI_URL = os.getenv("TEST_UI_URL", "http://localhost:18091")
if "UI_PORT" in os.environ:
    BASE_UI_URL = f"http://localhost:{os.environ['UI_PORT']}"
BASE_SOC_URL = os.getenv("TEST_SOC_URL", "http://soc:8090" if "UI_PORT" in os.environ else "http://localhost:18090")
LOG_DIR = Path(__file__).resolve().parents[1] / "runtime-logs"


class TestLabScenarios(unittest.TestCase):

    def setUp(self):
        # Reset test state before each test if UI is responsive
        try:
            r = requests.get(f"{BASE_UI_URL}/status", timeout=2)
            if r.status_code != 200:
                self.skipTest(f"SOC UI returned status {r.status_code} on {BASE_UI_URL}")
        except Exception as e:
            self.skipTest(f"Live SOC UI container not reachable on {BASE_UI_URL}: {e}")


    def test_01_victim_switch(self):
        """Test switching active victim mode to vuln."""
        res = requests.post(f"{BASE_UI_URL}/nodes/victim/switch", json={"mode": "vuln"}, timeout=5)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data.get("ok"))
        self.assertEqual(data.get("mode"), "vuln")

    def test_02_benign_traffic_logging(self):
        """Test launching benign traffic and verifying log emission."""
        res = requests.post(f"{BASE_UI_URL}/nodes/benign/launch", json={"iterations": 15, "min_ms": 10, "max_ms": 30, "virtual_ips": 5}, timeout=5)
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.json().get("ok"))
        
        # Wait briefly for execution
        time.sleep(2)
        
        # Verify status endpoint returns updated counts or services status
        status_res = requests.get(f"{BASE_UI_URL}/status", timeout=5).json()
        self.assertIn("active_victim", status_res)

    def test_03_attacker_oracle_vuln_mode(self):
        """Test launching Padding Oracle attack in vuln (status-based) mode."""
        # Ensure victim is in vuln mode
        requests.post(f"{BASE_UI_URL}/nodes/victim/switch", json={"mode": "vuln"}, timeout=5)
        
        # Launch attack
        res = requests.post(f"{BASE_UI_URL}/nodes/attacker/launch", json={"mode": "vuln", "sleep_ms": 0, "target": "victim"}, timeout=5)
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.json().get("ok"))


    def test_04_soc_collector_alerts(self):
        """Test SOC collector endpoint returns alert list."""
        res = requests.get(f"{BASE_SOC_URL}/alerts", timeout=5)
        self.assertEqual(res.status_code, 200)
        self.assertIn("alerts", res.json())

    def test_05_victim_secret_management(self):
        """Test reading and setting custom victim secret message via API."""
        get_res = requests.get(f"{BASE_UI_URL}/nodes/victim/secret", timeout=5)
        self.assertEqual(get_res.status_code, 200)
        self.assertIn("secret", get_res.json())

        new_secret = "TestCustomSecret1"
        set_res = requests.post(f"{BASE_UI_URL}/nodes/victim/secret", json={"secret": new_secret}, timeout=10)
        self.assertEqual(set_res.status_code, 200)
        self.assertEqual(set_res.json().get("secret"), new_secret)

if __name__ == "__main__":
    unittest.main()
