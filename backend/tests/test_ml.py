import tempfile
import unittest
from pathlib import Path

import numpy as np

from app.ml.registry import BUNDLE_FILE, load_bundle, save_bundle
from app.ml.smote import smote
from app.ml.synthetic import generate_dataset
from tests.helpers import get_bundle


class TestSmote(unittest.TestCase):
    def test_balances_only_minorities_and_rounds_flags(self):
        rng = np.random.default_rng(0)
        X = np.vstack([rng.normal(0, 1, (200, 3)), rng.normal(5, 1, (10, 3))])
        X[:, 2] = (X[:, 2] > 0).astype(float)
        y = np.array([0] * 200 + [1] * 10)
        Xs, ys = smote(X, y, ratio=0.5, round_columns=[2])
        self.assertEqual((ys == 0).sum(), 200)
        self.assertEqual((ys == 1).sum(), 100)
        self.assertTrue(set(np.unique(Xs[:, 2])) <= {0.0, 1.0})

    def test_single_sample_class(self):
        X = np.random.default_rng(0).normal(size=(30, 2)); y = np.array([0] * 29 + [1])
        _, ys = smote(X, y, ratio=0.5)
        self.assertGreater((ys == 1).sum(), 1)


class TestDataset(unittest.TestCase):
    def test_shape_and_zero_day_excluded(self):
        df = generate_dataset(2000, seed=1)
        self.assertNotIn("Zero-Day", set(df.label))
        self.assertEqual(df.label.nunique(), 12)
        self.assertTrue(np.isfinite(df.drop(columns="label").to_numpy()).all())


class TestTraining(unittest.TestCase):
    def test_report_sane(self):
        r = get_bundle().report
        e = r["models"]["ensemble"]
        self.assertGreater(e["accuracy"], 0.85)
        self.assertLess(e["false_positive_rate"], 0.05)
        for k in ("roc", "confusion_matrix", "anomaly", "hybrid", "decision", "dataset"):
            self.assertIn(k, r)
        self.assertTrue(r["dataset"]["synthetic"])
        self.assertAlmostEqual(sum(r["decision"]["weights"].values()), 1.0, places=2)
        self.assertGreater(r["hybrid"]["zero_day_detected_as_threat"], 0.5)

    def test_save_load_and_tamper(self):
        b = get_bundle()
        with tempfile.TemporaryDirectory() as d:
            save_bundle(b, d)
            b2 = load_bundle(d)
            X = np.zeros((1, len(b.baseline)))
            self.assertTrue(np.allclose(b.ensemble.predict_proba(X), b2.ensemble.predict_proba(X)))
            with open(Path(d) / BUNDLE_FILE, "ab") as f:
                f.write(b"x")
            with self.assertRaises(ValueError):
                load_bundle(d)

    def test_missing_bundle(self):
        with tempfile.TemporaryDirectory() as d, self.assertRaises(FileNotFoundError):
            load_bundle(d)


if __name__ == "__main__":
    unittest.main()
