"""Connector layer: API keys, rate limiting, sources, de-duplication, scopes, schema migration."""
import tempfile
import time
import unittest

from app.db.database import Database
from app.db.repository import Repository
from app.security.apikeys import generate_key, hash_key, looks_like_key
from app.security.ratelimit import TokenBucket
from app.services.detection.pipeline import normalize_event

DET = dict(verdict="threat", attack_type="SQL Injection", confidence=0.95, severity="Critical", risk_score=88.0, sources=["signature:x"], explanation=None)


def ev(ip="198.51.100.7", **extra):
    e = normalize_event({"src_ip": ip})
    e["ts"] = time.time()
    e.update(extra)
    return e


class TestApiKeys(unittest.TestCase):
    def test_generate_and_verify(self):
        full, prefix, h = generate_key()
        self.assertTrue(looks_like_key(full))
        self.assertTrue(full.startswith(prefix))
        self.assertEqual(h, hash_key(full))
        self.assertNotEqual(generate_key()[0], full)
        self.assertNotIn(full, h)

    def test_rejects_malformed(self):
        for bad in ("", "abc", "agk_short", "agk_" + "!" * 40, "Bearer agk_x"):
            self.assertFalse(looks_like_key(bad), bad)


class TestRateLimit(unittest.TestCase):
    def test_bucket(self):
        b = TokenBucket(capacity=10, refill_per_second=5)
        self.assertTrue(b.allow("k", 10))
        self.assertFalse(b.allow("k", 1))
        self.assertTrue(b.allow("other", 10))      # independent per key
        time.sleep(0.45)
        self.assertTrue(b.allow("k", 2))           # refilled ~2 tokens
        self.assertGreaterEqual(b.retry_after("k", 50), 1)


class TestSources(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        self.db = Database(f"{d}/t.db"); self.db.init(); self.r = Repository(self.db)

    def _make(self, name="Shop"):
        full, prefix, h = generate_key()
        sid = self.r.create_source(name, "web_access_log", prefix, h, {"exclude_paths": ["/health"]}, "admin")
        return sid, full, h

    def test_lookup_never_exposes_hash(self):
        sid, full, h = self._make()
        s = self.r.get_source_by_key_hash(hash_key(full))
        self.assertEqual((s["id"], s["name"], s["policy"]["exclude_paths"]), (sid, "Shop", ["/health"]))
        self.assertNotIn("key_hash", s)
        self.assertNotIn("key_hash", self.r.list_sources()[0])
        self.assertIsNone(self.r.get_source_by_key_hash(hash_key("agk_" + "x" * 43)))

    def test_rotate_revoke_delete(self):
        sid, full, h = self._make()
        self.assertTrue(self.r.revoke_source(sid))
        self.assertFalse(self.r.revoke_source(sid))
        self.assertIsNotNone(self.r.get_source(sid)["revoked_at"])
        nfull, nprefix, nh = generate_key()
        self.r.set_source_key(sid, nprefix, nh)  # rotation re-activates and kills the old key
        self.assertIsNone(self.r.get_source(sid)["revoked_at"])
        self.assertIsNone(self.r.get_source_by_key_hash(hash_key(full)))
        self.assertEqual(self.r.get_source_by_key_hash(hash_key(nfull))["id"], sid)
        self.assertTrue(self.r.delete_source(sid))
        self.assertIsNone(self.r.get_source(sid))

    def test_touch_counters_and_heartbeat(self):
        sid, *_ = self._make()
        self.r.touch_source(sid, events=10, threats=2, rejected=1)
        self.r.touch_source(sid, heartbeat=True, info={"version": "1.0"})
        s = self.r.get_source(sid)
        self.assertEqual((s["events_total"], s["threats_total"], s["rejected_total"]), (10, 2, 1))
        self.assertIsNotNone(s["last_seen"]); self.assertIsNotNone(s["last_heartbeat"])
        self.assertEqual(s["info"]["version"], "1.0")

    def test_idempotent_event_ids(self):
        sid, *_ = self._make()
        self.r.record_detection(ev(source_id=sid, eid="abc"), DET, origin="connector")
        self.assertEqual(self.r.known_eids(sid, ["abc", "zzz", None]), {"abc"})
        self.assertEqual(self.r.known_eids(sid + 1, ["abc"]), set())

    def test_alert_and_event_carry_source(self):
        sid, *_ = self._make("Prod web")
        ids = self.r.record_detection(ev(source_id=sid, eid="e1"), DET, origin="connector")
        a = self.r.get_alert(ids["alert_id"])
        self.assertEqual((a["source_name"], a["source_kind"]), ("Prod web", "web_access_log"))
        rows, _ = self.r.list_alerts()
        self.assertEqual(rows[0]["source_name"], "Prod web")
        self.r.delete_source(sid)  # events/alerts survive a deleted source
        self.assertIsNone(self.r.get_alert(ids["alert_id"])["source_name"])

    def test_scopes_separate_live_from_demo(self):
        self.r.record_detection(ev("198.51.100.1"), DET, origin="connector")
        self.r.record_detection(ev("198.51.100.2"), DET, origin="stream")
        self.r.record_detection(ev("198.51.100.3"), DET, origin="seed")
        self.r.record_detection(ev("198.51.100.4"), DET, origin="upload")
        n = lambda scope: self.r.overview(24, scope)["threats"]  # noqa: E731
        self.assertEqual((n("all"), n("live"), n("demo"), n("upload")), (4, 1, 2, 1))
        self.assertEqual(len(self.r.list_alerts(scope="live")[0]), 1)
        self.assertEqual(self.r.list_alerts(scope="demo")[1], 2)
        self.assertEqual(sum(p["threats"] for p in self.r.timeline(24, "live")), 1)
        self.assertEqual(len(self.r.top_sources(24, 10, "live")), 1)
        self.assertEqual(len(self.r.recent_events(10, False, "demo")), 2)
        self.assertEqual(self.r.overview(24, "bogus")["threats"], 4)  # unknown scope = no filter, never SQL


class TestMigrationV22(unittest.TestCase):
    def test_events_get_new_columns(self):
        import sqlite3
        d = tempfile.mkdtemp(); path = f"{d}/old.db"
        con = sqlite3.connect(path)
        # the events/alerts tables exactly as shipped in v2.0/v2.1 (before connectors existed)
        con.execute("CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, src_ip TEXT, dst_ip TEXT, dst_port INTEGER, "
                    "protocol TEXT, bytes_total REAL, features_json TEXT, payload_sample TEXT, verdict TEXT NOT NULL, attack_type TEXT, "
                    "confidence REAL, risk_score REAL, severity TEXT, sources_json TEXT, origin TEXT NOT NULL DEFAULT 'stream', "
                    "job_id INTEGER, alert_id INTEGER, blocked INTEGER NOT NULL DEFAULT 0)")
        con.execute("CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, event_id INTEGER, first_seen REAL NOT NULL, last_seen REAL NOT NULL, "
                    "count INTEGER NOT NULL DEFAULT 1, attack_type TEXT NOT NULL, severity TEXT NOT NULL, risk_score REAL NOT NULL, confidence REAL NOT NULL, "
                    "src_ip TEXT, dst_ip TEXT, status TEXT NOT NULL DEFAULT 'open', explanation_json TEXT, sources_json TEXT, "
                    "origin TEXT NOT NULL DEFAULT 'stream', job_id INTEGER, handled_by TEXT, updated_at REAL NOT NULL)")
        con.execute("INSERT INTO events(ts,verdict,src_ip) VALUES(1,'benign','1.1.1.1')")
        con.commit(); con.close()
        db = Database(path); db.init()
        with db.connect() as c:
            self.assertTrue({"source_id", "eid"} <= {r[1] for r in c.execute("PRAGMA table_info(events)")})
            self.assertIn("source_id", {r[1] for r in c.execute("PRAGMA table_info(alerts)")})
            self.assertEqual(c.execute("SELECT COUNT(*) FROM events").fetchone()[0], 1)  # existing data preserved


if __name__ == "__main__":
    unittest.main()
