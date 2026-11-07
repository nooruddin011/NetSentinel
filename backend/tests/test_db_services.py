import io
import tempfile
import time
import unittest

import numpy as np
import pandas as pd

from app.db.database import Database
from app.db.repository import Repository
from app.services import reports
from app.services.alerting import EmailNotifier
from app.services.analytics import holt_forecast
from app.services.detection.pipeline import normalize_event
from app.services.ingestion import loader
from app.services.recommendation import PLAYBOOKS, Recommender, apply_mitigation, render_rule
from tests.helpers import get_bundle, make_ctx, make_settings

DET = dict(verdict="threat", attack_type="Brute Force", confidence=0.9, severity="High", risk_score=70.0, sources=["ensemble"], explanation=None)


def ev(ip="198.51.100.7", ts=None):
    e = normalize_event({"src_ip": ip, "dst_ip": "10.0.0.10"})
    e["ts"] = ts or time.time()
    return e


class TestRepository(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        self.db = Database(f"{d}/t.db"); self.db.init(); self.r = Repository(self.db)

    def test_alert_dedupe_and_severity_upgrade(self):
        a = self.r.record_detection(ev(), DET)
        b = self.r.record_detection(ev(), dict(DET, severity="Critical", risk_score=95.0))
        self.assertTrue(a["alert_is_new"]); self.assertFalse(b["alert_is_new"])
        self.assertEqual(a["alert_id"], b["alert_id"])
        al = self.r.get_alert(a["alert_id"])
        self.assertEqual((al["count"], al["severity"], al["risk_score"]), (2, "Critical", 95.0))
        c = self.r.record_detection(ev("198.51.100.8"), DET)
        self.assertNotEqual(c["alert_id"], a["alert_id"])

    def test_dedupe_window_respected(self):
        a = self.r.record_detection(ev(ts=1000.0), DET, dedupe_window=60)
        b = self.r.record_detection(ev(ts=2000.0), DET, dedupe_window=60)
        self.assertNotEqual(a["alert_id"], b["alert_id"])

    def test_benign_creates_no_alert(self):
        r = self.r.record_detection(ev(), dict(DET, verdict="benign", attack_type=None))
        self.assertIsNone(r["alert_id"])

    def test_filters_status_search_and_wildcard_escape(self):
        self.r.record_detection(ev("198.51.100.7"), DET)
        rows, total = self.r.list_alerts(q="198.51"); self.assertEqual(total, 1)
        _, none = self.r.list_alerts(q="%"); self.assertEqual(none, 0)          # LIKE wildcard is escaped
        _, inj = self.r.list_alerts(q="x' OR '1'='1"); self.assertEqual(inj, 0)  # parameterised
        self.assertTrue(self.r.update_alert_status(rows[0]["id"], "resolved", "bob"))
        self.assertEqual(self.r.list_alerts(status="open")[1], 0)
        with self.assertRaises(ValueError):
            self.r.update_alert_status(rows[0]["id"], "bogus", "bob")

    def test_blocklist_marks_events(self):
        self.r.block_ip("198.51.100.7", "test", None, "bob")
        self.assertTrue(self.r.record_detection(ev(), DET)["blocked"])
        self.assertTrue(self.r.unblock_ip("198.51.100.7"))

    def test_overview_timeline_heatmap(self):
        for i in range(5):
            self.r.record_detection(ev(f"198.51.100.{i}"), DET)
        self.r.record_detection(ev(), dict(DET, verdict="benign", attack_type=None, severity=None))
        o = self.r.overview(24)
        self.assertEqual((o["total_events"], o["threats"], o["unique_attackers"]), (6, 5, 5))
        self.assertEqual(o["by_attack"][0]["name"], "Brute Force")
        self.assertEqual(sum(p["threats"] for p in self.r.timeline(24)), 5)
        self.assertTrue(self.r.heatmap()); self.assertTrue(self.r.top_sources())

    def test_bulk_single_transaction(self):
        items = [(ev(f"198.51.100.{i % 3}"), DET) for i in range(50)]
        n_alerts, n_new = self.r.record_bulk(items)
        self.assertEqual((n_alerts, n_new), (50, 3))

    def test_purge_keeps_open_alerts(self):
        a = self.r.record_detection(ev(ts=time.time() - 40 * 86400), DET)
        self.r.purge_older_than(14)
        self.assertIsNotNone(self.r.get_alert(a["alert_id"]))
        self.r.update_alert_status(a["alert_id"], "resolved", "x")
        self.r.purge_older_than(14)
        self.assertIsNone(self.r.get_alert(a["alert_id"]))

    def test_users_unique_case_insensitive(self):
        import sqlite3
        self.r.create_user("Alice", "h", "viewer")
        with self.assertRaises(sqlite3.IntegrityError):
            self.r.create_user("alice", "h", "viewer")


class TestRecommendation(unittest.TestCase):
    def test_every_attack_has_playbook_and_measured_options(self):
        rec = Recommender(lambda: get_bundle().report)
        for name in ("DDoS", "SQL Injection", "XSS", "Phishing", "Brute Force", "Malware", "Ransomware", "Botnet",
                     "Port Scanning", "Insider Threat", "MITM", "Zero-Day"):
            r = rec.for_attack(name)
            self.assertGreaterEqual(len(r["mitigation_options"]), 3, name)
            self.assertTrue(r["detection_options"], name)
        d = rec.for_attack("DDoS")["detection_options"]
        self.assertTrue(all(o["measured"] for o in d if o["id"] not in ("signature", "web_behaviour")))
        self.assertTrue(all(0 <= o["accuracy"] <= 1 for o in d if o.get("accuracy") is not None))

    def test_rule_rendering_is_injection_safe(self):
        r = render_rule("iptables -I INPUT -s {src_ip} -p tcp --dport {port} -j DROP", "1.2.3.4; rm -rf /", "x", "22; evil")
        self.assertEqual(r, "iptables -I INPUT -s 0.0.0.0 -p tcp --dport 0 -j DROP")
        self.assertEqual(render_rule("x {src_ip}", "10.1.1.1", "10.0.0.1", 99999).strip(), "x 10.1.1.1")

    def test_apply_mitigation_blocks_and_updates_status(self):
        ctx = make_ctx()
        out = ctx.processor.process({"src_ip": "198.51.100.77", "failed_logins": 60, "dst_port": 22, "conn_count_src": 200})
        alert = ctx.repo.get_alert(out["alert_id"])
        opt = next(o for o in PLAYBOOKS[alert["attack_type"]] if o["blocks_ip"])
        res = apply_mitigation(ctx.repo, alert, opt["id"], "tester")
        self.assertTrue(res["simulated"])
        self.assertEqual(ctx.repo.get_alert(alert["id"])["status"], "mitigated")
        self.assertIn("198.51.100.77", [b["ip"] for b in ctx.repo.list_blocklist()])
        with self.assertRaises(KeyError):
            apply_mitigation(ctx.repo, alert, "nope", "tester")


class TestChatReportsAnalytics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ctx = make_ctx()
        for _ in range(60):
            e = cls.ctx.simulator.next_event()
            cls.ctx.processor.process(e)
        from app.ml.synthetic import generate_event
        cls.ctx.processor.process(generate_event("SQL Injection", np.random.default_rng(17)))

    def test_chat_intents(self):
        c = self.ctx.chat
        self.assertEqual(c.reply("hello")["intent"], "help")
        self.assertEqual(c.reply("what is sqli?")["intent"], "explain")
        self.assertEqual(c.reply("how do i stop brute force")["intent"], "mitigation")
        self.assertEqual(c.reply("which model has the best accuracy")["intent"], "models")
        self.assertEqual(c.reply("give me a status summary")["intent"], "status")
        self.assertEqual(c.reply("asdf qwer")["intent"], "unknown")
        self.assertIn("simulated", c.reply("model accuracy")["reply"])  # synthetic data is disclosed

    def test_pdf_and_csv(self):
        r = self.ctx.repo
        pdf = reports.build_pdf(r.overview(24), r.iter_alerts_for_export(), r.top_sources(24), get_bundle().report, 24)
        self.assertEqual(pdf[:4], b"%PDF")
        evil = [{"id": 1, "attack_type": "=HYPERLINK(\"http://x\")", "src_ip": "+cmd", "status": "open"}]
        line = reports.alerts_csv(evil).splitlines()[1]
        self.assertIn("'=HYPERLINK", line); self.assertIn("'+cmd", line)

    def test_pdf_escapes_markup_from_data(self):
        r = self.ctx.repo
        alerts = [dict(id=1, severity="High", attack_type="<b>x</b><img src=x>", src_ip="1.1.1.1", risk_score=1, count=1, status="open")]
        self.assertEqual(reports.build_pdf(r.overview(24), alerts, [], {}, 24)[:4], b"%PDF")  # would raise on bad markup

    def test_forecast(self):
        f = holt_forecast([1, 2, 3, 4, 5, 6, 7, 8], 3)
        self.assertEqual(len(f["forecast"]), 3); self.assertGreater(f["forecast"][0], 8)
        self.assertEqual(holt_forecast([1], 2)["method"], "insufficient-data")
        self.assertTrue(all(v >= 0 for v in holt_forecast([9, 7, 5, 3, 1, 0, 0], 4)["forecast"]))


class TestNotifier(unittest.TestCase):
    def test_threshold_and_header_safety(self):
        sent = []
        s = make_settings(tempfile.mkdtemp(), smtp_host="smtp.test", alert_email_to=["soc@example.com"])
        n = EmailNotifier(s, send_fn=sent.append)
        base = dict(attack_type="DDoS\r\nBcc: evil@x.com", src_ip="1.1.1.1", dst_ip="2.2.2.2", confidence=0.9, risk_score=80, sources=["ensemble"])
        self.assertFalse(n.notify(dict(base, severity="Low"), blocking=True))
        self.assertTrue(n.notify(dict(base, severity="Critical"), blocking=True))
        self.assertNotIn("\n", sent[0]["Subject"]); self.assertNotIn("evil@x.com", sent[0]["To"])
        self.assertFalse(EmailNotifier(make_settings(tempfile.mkdtemp())).enabled)


class TestIngestion(unittest.TestCase):
    def test_upload_and_evaluation_end_to_end(self):
        ctx = make_ctx()
        from app.ml.synthetic import generate_dataset
        df = generate_dataset(400, seed=11)
        df["src_ip"] = [f"203.0.113.{i % 50 + 1}" for i in range(len(df))]
        csv = df.to_csv(index=False).encode()
        data = loader.read_upload(csv, 10000)
        job = ctx.repo.create_job("t.csv", "tester")
        s = ctx.processor.process_dataframe(data, job)
        self.assertEqual(s["rows"], 400)
        self.assertGreater(s["flagged"], 50)
        self.assertGreater(s["evaluation"]["accuracy"], 0.8)
        self.assertGreater(ctx.repo.list_alerts()[1], 0)

    def test_rejects_bad_files(self):
        for bad in (b"", b"a,b\n", b"foo,bar\n1,2\n", b"src_ip,dst_ip,bytes\n" + b"1.1.1.1,2.2.2.2,5\n" * 20):
            try:
                loader.read_upload(bad, 10)
                raised = False
            except loader.UploadError:
                raised = True
            self.assertTrue(raised, bad[:20])

    def test_cicids_headers_and_ms_timestamps(self):
        csv = (" Destination Port, Flow Duration, Total Fwd Packets, Total Backward Packets, Total Length of Fwd Packets,"
               " Total Length of Bwd Packets, Label\n80,2000000,5,4,500,900,BENIGN\n")
        df = loader.read_upload(csv.encode(), 100)
        self.assertAlmostEqual(df["duration"].iloc[0], 2.0)
        self.assertEqual(loader.map_label("Web Attack – XSS"), "XSS")
        self.assertIsNone(loader.map_label("???"))
        ts = loader.parse_timestamps(pd.DataFrame({"ts": [1_700_000_000_000]}), 0)
        self.assertEqual(int(ts[0]), 1_700_000_000)

    def test_window_enrichment(self):
        df = pd.DataFrame({"src_ip": ["1.1.1.1"] * 5 + ["2.2.2.2"], "dst_ip": list("abcde") + ["z"], "dst_port": [1, 2, 3, 4, 5, 80]})
        out = loader.enrich_windows(df, np.zeros(6))
        self.assertEqual(out["conn_count_src"].tolist(), [5] * 5 + [1])
        self.assertEqual(out["distinct_dst_ports"].iloc[0], 5)

    def test_nslkdd_adapter(self):
        rows = []
        for lab in ("normal", "neptune", "portsweep", "warezclient"):
            rec = {c: "0" for c in loader.NSLKDD_COLUMNS}
            rec.update(protocol_type="tcp", service="http", flag="SF", src_bytes="100", dst_bytes="200", count="5",
                       serror_rate="0.0", rerror_rate="0.0", diff_srv_rate="0.1", label=lab, difficulty="20")
            rows.append(",".join(rec[c] for c in loader.NSLKDD_COLUMNS))
        p = tempfile.mkdtemp() + "/k.txt"
        open(p, "w").write("\n".join(rows))
        df = loader.load_nslkdd(p)
        self.assertEqual(sorted(df["label"]), ["Benign", "DDoS", "Port Scanning"])
        self.assertEqual(df.attrs["dropped"], 1)


if __name__ == "__main__":
    unittest.main()
