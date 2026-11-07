"""End-to-end regression: real attack traffic -> real access log -> collector -> ingest -> shipped web model -> alerts."""
import importlib.util
import unittest

from app.config import ROOT_DIR

SCRIPT = ROOT_DIR / "scripts" / "verify_connector_pipeline.py"


@unittest.skipUnless((ROOT_DIR / "models" / "web" / "web_model.joblib").exists() and SCRIPT.exists(), "shipped web model or script missing")
class TestLabPipeline(unittest.TestCase):
    def test_every_attack_type_is_detected_from_real_traffic(self):
        spec = importlib.util.spec_from_file_location("verify", SCRIPT)
        mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
        res = mod.run(verbose=False)
        self.assertTrue(mod.EXPECTED <= set(res["alerts"]), set(res["alerts"]))
        ph = res["phases"]
        self.assertEqual(res["browsing_threats"], 0)
        self.assertGreaterEqual(ph["sqli"].get("SQL Injection", 0), 8)
        self.assertGreaterEqual(ph["xss"].get("XSS", 0), 6)
        self.assertGreaterEqual(ph["traversal"].get("Path Traversal", 0), 5)
        self.assertGreaterEqual(ph["cmdi"].get("Command Injection", 0), 5)
        self.assertGreaterEqual(ph["brute"].get("Brute Force", 0), 30)
        self.assertGreaterEqual(ph["scan"].get("Web Reconnaissance", 0), 30)
        self.assertGreaterEqual(ph["flood"].get("DDoS", 0), 200)
        # an attack from one address must not be mislabelled as another type (the regression this test was written for)
        self.assertEqual(set(ph["scan"]) - {"benign", "Web Reconnaissance", "Brute Force"}, set())
        self.assertEqual(set(ph["flood"]) - {"benign", "DDoS", "SQL Injection"}, set())   # SQL Injection = the sqlmap User-Agent request


if __name__ == "__main__":
    unittest.main()
