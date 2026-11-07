"""Account, ownership and migration logic (repository/security level - no web framework needed)."""
import sqlite3
import tempfile
import time
import unittest

from app.db.database import Database
from app.db.repository import Repository
from app.security.passwords import hash_password, password_problems, password_version


class TestPasswordPolicy(unittest.TestCase):
    def test_rules(self):
        self.assertEqual(password_problems("Str0ngPassw0rd"), [])
        self.assertTrue(password_problems("short1A"))
        self.assertTrue(password_problems("alllowercase123"))
        self.assertTrue(password_problems("NoDigitsHereAtAll"))

    def test_common_and_username(self):
        self.assertIn("is too common", password_problems("Password123!"))
        self.assertIn("must not contain your username", password_problems("Maria-Secret99x", "maria"))
        self.assertEqual(password_problems("Maria-Secret99x", "bob"), [])

    def test_version_changes_with_hash(self):
        a, b = hash_password("Str0ngPassw0rd"), hash_password("Str0ngPassw0rd")
        self.assertNotEqual(password_version(a), password_version(b))
        self.assertEqual(password_version(a), password_version(a))


class TestUsersAndJobs(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        self.db = Database(f"{d}/t.db"); self.db.init(); self.r = Repository(self.db)

    def test_user_lifecycle(self):
        uid = self.r.create_user("Maria", "h", "viewer", "Maria Lopez")
        u = self.r.get_user(uid)
        self.assertEqual((u["full_name"], u["last_login"]), ("Maria Lopez", None))
        self.r.touch_login(uid)
        self.assertIsNotNone(self.r.get_user(uid)["last_login"])
        self.r.update_user(uid, role="analyst", full_name="  M. Lopez ")
        self.assertEqual((self.r.get_user(uid)["role"], self.r.get_user(uid)["full_name"]), ("analyst", "M. Lopez"))
        self.assertTrue(self.r.delete_user(uid))
        self.assertIsNone(self.r.get_user(uid))
        self.assertFalse(self.r.delete_user(uid))

    def test_job_visibility_and_delete(self):
        a, b = self.r.create_job("a.csv", "alice"), self.r.create_job("b.csv", "bob")
        self.assertEqual({j["created_by"] for j in self.r.list_jobs(created_by="alice")}, {"alice"})
        self.assertEqual(len(self.r.list_jobs()), 2)  # Admin view
        self.assertEqual(self.r.delete_job(a), dict(alerts_deleted=0, events_deleted=0))
        self.assertIsNone(self.r.delete_job(a))
        self.assertEqual([j["id"] for j in self.r.list_jobs()], [b])

    def test_delete_job_with_findings(self):
        from app.services.detection.pipeline import normalize_event
        job = self.r.create_job("x.csv", "alice")
        ev = normalize_event({"src_ip": "198.51.100.1"}); ev["ts"] = time.time()
        det = dict(verdict="threat", attack_type="DDoS", confidence=0.9, severity="High", risk_score=70.0, sources=["ensemble"], explanation=None)
        ids = self.r.record_detection(ev, det, origin="upload", job_id=job)
        keep = self.r.create_job("y.csv", "alice")
        res = self.r.delete_job(job, delete_findings=True)
        self.assertEqual((res["alerts_deleted"], res["events_deleted"]), (1, 1))
        self.assertIsNone(self.r.get_alert(ids["alert_id"]))
        # without the flag the findings stay but are detached from the deleted log
        ev2 = normalize_event({"src_ip": "198.51.100.2"}); ev2["ts"] = time.time()
        ids2 = self.r.record_detection(ev2, det, origin="upload", job_id=keep)
        self.r.delete_job(keep, delete_findings=False)
        self.assertIsNotNone(self.r.get_alert(ids2["alert_id"]))


class TestMigration(unittest.TestCase):
    def test_old_database_is_upgraded_in_place(self):
        d = tempfile.mkdtemp(); path = f"{d}/old.db"
        con = sqlite3.connect(path)  # schema as shipped in v2.0 (no full_name / last_login)
        con.execute("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE, "
                    "password_hash TEXT NOT NULL, role TEXT NOT NULL, is_active INTEGER NOT NULL DEFAULT 1, created_at REAL NOT NULL)")
        con.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES('admin','h','admin',1)")
        con.commit(); con.close()
        db = Database(path); db.init(); db.init()  # idempotent
        r = Repository(db)
        u = r.get_user_by_name("admin")
        self.assertEqual((u["role"], u["full_name"], u["last_login"]), ("admin", None, None))
        r.create_user("new", "h", "viewer", "New User")
        self.assertEqual(len(r.list_users()), 2)


if __name__ == "__main__":
    unittest.main()
