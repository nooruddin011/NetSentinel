import unittest

import numpy as np
import pandas as pd

from app.detectors.signature import SignatureEngine
from app.ml.payload import payload_features
from app.ml.schema import FEATURES, RAW_FEATURES, engineer
from app.ml.synthetic import generate_dataset
from app.models.attacks import resolve_attack


class TestPayload(unittest.TestCase):
    def test_sqli_encoded_is_decoded(self):
        f = payload_features("/s?q=%27%20UNION%20SELECT%20a,b%20FROM%20t--")
        self.assertGreaterEqual(f["sql_kw_count"], 2)

    def test_benign_clean(self):
        f = payload_features("/search?q=wireless+mouse")
        self.assertEqual((f["sql_kw_count"], f["script_tag_count"]), (0, 0))

    def test_empty(self):
        self.assertEqual(payload_features("")["payload_len"], 0)


class TestSchema(unittest.TestCase):
    def test_paths_identical(self):
        df = generate_dataset(300, seed=1).drop(columns="label")
        self.assertTrue(np.allclose(engineer(df), engineer(df.to_dict("records"))))
        self.assertEqual(engineer(df).shape[1], len(FEATURES))

    def test_bad_values_are_sanitised(self):
        X = engineer([{"src_bytes": "abc", "duration": float("nan"), "syn_ratio": 9, "protocol": "udp", "dst_port": -5}])
        self.assertTrue(np.isfinite(X).all())

    def test_missing_columns_dataframe(self):
        X = engineer(pd.DataFrame({"src_bytes": [1, 2]}))
        self.assertEqual(X.shape, (2, len(FEATURES)))


class TestSignatures(unittest.TestCase):
    sig = SignatureEngine()

    def types(self, **ev):
        return {h.attack_type for h in self.sig.scan(ev)}

    def test_sqli_xss(self):
        self.assertIn("SQL Injection", self.types(payload_sample="id=1 OR 1=1"))
        self.assertIn("SQL Injection", self.types(payload_sample="id=1%27%20UNION%20SELECT%20x%20FROM%20y"))
        self.assertIn("XSS", self.types(payload_sample="<script>alert(1)</script>"))

    def test_benign_text_with_sql_words(self):
        self.assertEqual(self.types(payload_sample="/search?q=select+your+size+and+update+profile"), set())

    def test_behavioural_rules(self):
        self.assertIn("Brute Force", self.types(failed_logins=30, dst_port=22))
        self.assertIn("Port Scanning", self.types(distinct_dst_ports=100, error_rate=0.8))
        self.assertIn("DDoS", self.types(src_pkts=20000, dst_pkts=0, duration=1, conn_count_src=500))
        self.assertIn("Ransomware", self.types(smb_write_rate=300, payload_entropy=7.9))
        self.assertEqual(self.types(), set())


class TestAliases(unittest.TestCase):
    def test_resolve(self):
        self.assertEqual(resolve_attack("what is sqli"), "SQL Injection")
        self.assertIsNone(resolve_attack("both of them"))


if __name__ == "__main__":
    unittest.main()
