"""HTTP-level integration tests (need `pip install fastapi httpx python-multipart`; skipped otherwise)."""
import io
import tempfile
import unittest

try:
    from fastapi.testclient import TestClient
    HAVE = True
except Exception:  # fastapi/httpx not installed
    HAVE = False

from tests.helpers import get_bundle, make_settings

PW = "Admin-Passw0rd!"


@unittest.skipUnless(HAVE, "fastapi/httpx not installed")
class TestAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from app.factory import create_app
        cls.app = create_app(make_settings(tempfile.mkdtemp()), bundle=get_bundle(), background=False)
        cls.cm = TestClient(cls.app)
        cls.c = cls.cm.__enter__()
        cls.tok = cls.login("admin", PW)
        cls.c.post("/api/auth/users", json={"username": "vera", "password": "Viewer-Passw0rd1", "role": "viewer"}, headers=cls.h())
        cls.vtok = cls.login("vera", "Viewer-Passw0rd1")

    @classmethod
    def tearDownClass(cls):
        cls.cm.__exit__(None, None, None)

    @classmethod
    def login(cls, u, p):
        r = cls.c.post("/api/auth/login", json={"username": u, "password": p})
        assert r.status_code == 200, r.text
        return r.json()["access_token"]

    @classmethod
    def h(cls, tok=None):
        return {"Authorization": f"Bearer {tok or cls.tok}"}

    def test_auth_required_everywhere(self):
        for path in ("/api/alerts", "/api/stats/overview", "/api/models/active", "/api/reports/summary.pdf", "/api/admin/audit"):
            self.assertEqual(self.c.get(path).status_code, 401, path)
        self.assertEqual(self.c.get("/api/alerts", headers={"Authorization": "Bearer junk"}).status_code, 401)

    def test_health_is_public_and_security_headers(self):
        r = self.c.get("/api/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers["x-content-type-options"], "nosniff")
        self.assertEqual(r.headers["x-frame-options"], "DENY")

    def test_login_wrong_password(self):
        self.assertEqual(self.c.post("/api/auth/login", json={"username": "admin", "password": "nope"}).status_code, 401)

    def test_rbac(self):
        v = self.h(self.vtok)
        self.assertEqual(self.c.get("/api/alerts", headers=v).status_code, 200)
        self.assertEqual(self.c.post("/api/detect/event", json={"payload_sample": "x"}, headers=v).status_code, 403)
        self.assertEqual(self.c.get("/api/admin/audit", headers=v).status_code, 403)
        self.assertEqual(self.c.post("/api/models/retrain", json={}, headers=v).status_code, 403)

    def test_detect_alert_mitigate_flow(self):
        r = self.c.post("/api/detect/event", headers=self.h(), json={
            "src_ip": "198.51.100.200", "dst_ip": "10.0.0.10", "payload_sample": "/x?id=1' UNION SELECT a FROM b--"})
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(body["attack_type"], "SQL Injection")
        aid = body["alert_id"]
        d = self.c.get(f"/api/alerts/{aid}", headers=self.h()).json()
        self.assertTrue(d["explanation"])
        recs = self.c.get(f"/api/alerts/{aid}/recommendations", headers=self.h()).json()
        sol = recs["mitigation_options"][0]["id"]
        m = self.c.post(f"/api/alerts/{aid}/mitigate", json={"solution_id": sol}, headers=self.h())
        self.assertEqual(m.status_code, 200)
        self.assertTrue(m.json()["simulated"])
        self.assertEqual(self.c.get(f"/api/alerts/{aid}", headers=self.h()).json()["status"], "mitigated")

    def test_validation(self):
        h = self.h()
        self.assertEqual(self.c.post("/api/detect/event", json={"payload_sample": "x" * 5000}, headers=h).status_code, 422)
        self.assertEqual(self.c.post("/api/lab/simulate", json={"scenario": "NotAnAttack"}, headers=h).status_code, 422)
        self.assertEqual(self.c.get("/api/alerts?limit=9999", headers=h).status_code, 422)
        self.assertEqual(self.c.get("/api/alerts?severity=Bogus", headers=h).status_code, 422)
        self.assertEqual(self.c.get("/api/alerts/99999999", headers=h).status_code, 404)

    def test_upload(self):
        from app.ml.synthetic import generate_dataset
        csv = generate_dataset(200, seed=9).assign(src_ip="203.0.113.5").to_csv(index=False)
        r = self.c.post("/api/detect/upload", headers=self.h(), files={"file": ("t.csv", io.BytesIO(csv.encode()), "text/csv")})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["rows"], 200)
        bad = self.c.post("/api/detect/upload", headers=self.h(), files={"file": ("t.txt", io.BytesIO(b"x"), "text/plain")})
        self.assertEqual(bad.status_code, 415)

    def test_reports(self):
        self.assertEqual(self.c.get("/api/reports/summary.pdf", headers=self.h()).content[:4], b"%PDF")
        self.assertTrue(self.c.get("/api/reports/alerts.csv", headers=self.h()).text.startswith("id,"))

    def test_websocket_auth(self):
        with self.c.websocket_connect("/ws/stream") as ws:
            ws.send_json({"type": "auth", "token": self.tok})
            self.assertEqual(ws.receive_json()["type"], "hello")
        from starlette.websockets import WebSocketDisconnect
        with self.assertRaises(WebSocketDisconnect):
            with self.c.websocket_connect("/ws/stream") as ws:
                ws.send_json({"type": "auth", "token": "bad"})
                ws.receive_json()

    def test_websocket_receives_published_events(self):
        with self.c.websocket_connect("/ws/stream") as ws:
            ws.send_json({"type": "auth", "token": self.tok})
            ws.receive_json()
            self.c.post("/api/lab/simulate", json={"scenario": "DDoS"}, headers=self.h())
            msg = ws.receive_json()
            self.assertEqual(msg["type"], "event")


    # ---- accounts, registration, ownership (added in v2.1)
    def _register(self, name, pw="Zx-Secret-Pass99"):
        return self.c.post("/api/auth/register", json={"username": name, "password": pw, "full_name": "Test User"})

    def test_public_config_and_minimal_health(self):
        cfg = self.c.get("/api/auth/config").json()
        self.assertTrue(cfg["registration_enabled"])
        self.assertEqual(set(self.c.get("/api/health").json()), {"status", "uptime_seconds"})
        self.assertEqual(self.c.get("/api/admin/system", headers=self.h(self.vtok)).status_code, 403)
        self.assertIn("model_members", self.c.get("/api/admin/system", headers=self.h()).json())

    def test_register_creates_viewer_only(self):
        r = self._register("selfreg1")
        self.assertEqual(r.status_code, 201, r.text)
        self.assertEqual(r.json()["user"]["role"], "viewer")
        r2 = self.c.post("/api/auth/register", json={"username": "selfreg2", "password": "Zx-Secret-Pass99", "role": "admin"})
        self.assertEqual(r2.json()["user"]["role"], "viewer")  # extra field is ignored: no self-promotion
        self.assertEqual(self._register("SELFREG1").status_code, 409)
        self.assertEqual(self._register("bad name").status_code, 422)
        self.assertEqual(self._register("weakpw", "short").status_code, 422)
        tok = r.json()["access_token"]
        self.assertEqual(self.c.get("/api/alerts", headers=self.h(tok)).status_code, 200)
        self.assertEqual(self.c.post("/api/lab/simulate", json={"scenario": "DDoS"}, headers=self.h(tok)).status_code, 403)

    def test_admin_can_create_viewer_and_analyst(self):
        for name, role in (("mk.viewer", "viewer"), ("mk.analyst", "analyst"), ("mk@mail.example", "viewer")):
            r = self.c.post("/api/auth/users", headers=self.h(), json={"username": name, "password": "Zx-Secret-Pass99", "role": role})
            self.assertEqual(r.status_code, 201, r.text)

    def test_disabled_account_message_and_session_end(self):
        r = self._register("tobedisabled")
        uid = next(u["id"] for u in self.c.get("/api/auth/users", headers=self.h()).json()["users"] if u["username"] == "tobedisabled")
        self.c.patch(f"/api/auth/users/{uid}", json={"is_active": False}, headers=self.h())
        ok = self.c.post("/api/auth/login", json={"username": "tobedisabled", "password": "Zx-Secret-Pass99"})
        self.assertEqual(ok.status_code, 403)
        self.assertIn("disabled", ok.json()["detail"])
        bad = self.c.post("/api/auth/login", json={"username": "tobedisabled", "password": "wrong"})
        self.assertEqual(bad.status_code, 401)  # wrong password never reveals the account state
        self.assertEqual(self.c.get("/api/alerts", headers=self.h(r.json()["access_token"])).status_code, 401)

    def test_password_change_ends_other_sessions(self):
        first = self._register("pwchanger").json()["access_token"]
        r = self.c.post("/api/auth/change-password", headers=self.h(first),
                        json={"current_password": "Zx-Secret-Pass99", "new_password": "Another-Passw0rd77"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self.c.get("/api/auth/me", headers=self.h(first)).status_code, 401)
        self.assertEqual(self.c.get("/api/auth/me", headers=self.h(r.json()["access_token"])).status_code, 200)

    def test_user_safeguards(self):
        me = self.c.get("/api/auth/me", headers=self.h()).json()
        self.assertEqual(self.c.delete(f"/api/auth/users/{me['id']}", headers=self.h()).status_code, 409)
        self.assertEqual(self.c.patch(f"/api/auth/users/{me['id']}", json={"role": "viewer"}, headers=self.h()).status_code, 409)

    def test_upload_history_is_private_and_deletable(self):
        from app.ml.synthetic import generate_dataset
        csv = generate_dataset(120, seed=5).assign(src_ip="203.0.113.7").to_csv(index=False).encode()
        self.c.post("/api/auth/users", headers=self.h(), json={"username": "ana1", "password": "Zx-Secret-Pass99", "role": "analyst"})
        self.c.post("/api/auth/users", headers=self.h(), json={"username": "ana2", "password": "Zx-Secret-Pass99", "role": "analyst"})
        t1, t2 = self.login("ana1", "Zx-Secret-Pass99"), self.login("ana2", "Zx-Secret-Pass99")
        up = lambda tok: self.c.post("/api/detect/upload", headers=self.h(tok), files={"file": ("d.csv", io.BytesIO(csv), "text/csv")}).json()["job_id"]
        j1, j2 = up(t1), up(t2)
        self.assertEqual({j["id"] for j in self.c.get("/api/detect/jobs", headers=self.h(t1)).json()["jobs"]}, {j1})
        self.assertEqual(self.c.get(f"/api/detect/jobs/{j2}", headers=self.h(t1)).status_code, 404)
        self.assertEqual(self.c.delete(f"/api/detect/jobs/{j2}", headers=self.h(t1)).status_code, 404)
        admin_ids = {j["id"] for j in self.c.get("/api/detect/jobs", headers=self.h()).json()["jobs"]}
        self.assertTrue({j1, j2} <= admin_ids)
        self.assertEqual(self.c.delete(f"/api/detect/jobs/{j1}", headers=self.h(t1)).status_code, 200)
        self.assertEqual(self.c.delete(f"/api/detect/jobs/{j2}?delete_findings=true", headers=self.h()).status_code, 200)

    def test_login_lockout(self):
        for _ in range(5):
            self.c.post("/api/auth/login", json={"username": "ghost", "password": "x"})
        r = self.c.post("/api/auth/login", json={"username": "ghost", "password": "x"})
        self.assertEqual(r.status_code, 429)
        self.assertIn("retry-after", r.headers)


if __name__ == "__main__":
    unittest.main()
