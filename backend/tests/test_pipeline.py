import unittest

from app.services.detection.pipeline import DetectionPipeline, normalize_event
from app.services.detection.severity import risk_label, score_risk
from tests.helpers import get_bundle


class TestSeverity(unittest.TestCase):
    def test_monotonic_and_bounds(self):
        lo, _ = score_risk("DDoS", 0.5)
        hi, _ = score_risk("DDoS", 0.99)
        self.assertLess(lo, hi)
        s, lab = score_risk("Malware", 1.0, "10.0.0.10", ["10.0.0.10"], 1000, True)
        self.assertLessEqual(s, 100)
        self.assertEqual(lab, "Critical")

    def test_context_raises_score(self):
        base, _ = score_risk("Brute Force", 0.9)
        self.assertGreater(score_risk("Brute Force", 0.9, "10.0.0.10", ["10.0.0.10"])[0], base)

    def test_labels(self):
        self.assertEqual([risk_label(x) for x in (10, 45, 65, 90)], ["Low", "Medium", "High", "Critical"])


class TestPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.p = DetectionPipeline(get_bundle(), ["10.0.0.10"])

    def test_sqli_payload_detected(self):
        d = self.p.analyze(normalize_event({"src_ip": "198.51.100.5", "payload_sample": "/x?id=1' UNION SELECT a,b FROM users--"}))
        self.assertEqual((d["verdict"], d["attack_type"]), ("threat", "SQL Injection"))
        self.assertTrue(any(s.startswith("signature:") for s in d["sources"]))
        self.assertTrue(d["explanation"])

    def test_client_cannot_hide_injection_by_zeroing_features(self):
        d = self.p.analyze(normalize_event({"sql_kw_count": 0, "script_tag_count": 0, "payload_sample": "<script>alert(1)</script>"}))
        self.assertEqual(d["attack_type"], "XSS")

    def test_plain_request_is_benign(self):
        d = self.p.analyze(normalize_event({"src_ip": "192.168.1.5", "payload_sample": "/search?q=wireless+mouse"}))
        self.assertEqual(d["verdict"], "benign")

    def test_bad_ips_are_neutralised(self):
        ev = normalize_event({"src_ip": "1.2.3.4; DROP TABLE", "dst_ip": "<script>"})
        self.assertEqual((ev["src_ip"], ev["dst_ip"]), ("0.0.0.0", "0.0.0.0"))

    def test_empty_csv_cells_are_not_a_payload(self):
        # pandas reads an empty payload cell as NaN, which is truthy: it must not become the text "nan"
        ev = normalize_event({"payload_sample": float("nan"), "src_ip": float("nan")})
        self.assertEqual((ev["payload_sample"], ev["features"]["payload_len"]), ("", 0.0))

    def test_cache_hits(self):
        ev = normalize_event({"src_ip": "198.51.100.5", "src_bytes": 123, "dst_port": 8080})
        self.p.analyze(ev)
        before = self.p.cache_stats()["hits"]
        self.p.analyze(ev)
        self.assertGreater(self.p.cache_stats()["hits"], before)

    def test_batch_equals_single(self):
        evs = [normalize_event({"src_bytes": 100 * i, "failed_logins": i}) for i in range(1, 6)]
        batch = [d["attack_type"] for d in self.p.analyze_many(evs)]
        single = [self.p.analyze(e)["attack_type"] for e in evs]
        self.assertEqual(batch, single)


if __name__ == "__main__":
    unittest.main()
