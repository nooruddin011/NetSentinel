"""The collector program: parsing, privacy, tailing (rotation, restart, partial lines), delivery guarantees, HTTP, end-to-end."""
import importlib.util
import json
import os
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from app.config import ROOT_DIR

_spec = importlib.util.spec_from_file_location("argus_collector", ROOT_DIR / "collector" / "argus_collector.py")
C = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(C)


def line(ip="203.0.113.9", path="/", query="", status=200, ua="Mozilla/5.0", method="GET", t="10/Oct/2023:13:55:36 +0000"):
    target = path + (("?" + query) if query else "")
    return f'{ip} - - [{t}] "{method} {target} HTTP/1.1" {status} 512 "-" "{ua}"\n'


class FakeTransport:
    def __init__(self):
        self.sent, self.script, self.calls, self.heartbeats = [], [], 0, []
        self.policy_body = {}

    def send_events(self, events):
        self.calls += 1
        if self.script:
            code, body = self.script.pop(0)
            if code != 200:
                return code, body
        self.sent.extend(events)
        return 200, {"accepted": len(events), "duplicates": 0}

    def heartbeat(self, info):
        self.heartbeats.append(info)
        return 200, {"policy": self.policy_body}

    def policy(self):
        return 200, {"policy": self.policy_body, "name": "t"}


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.log = os.path.join(self.dir, "access.log")
        self.statef = os.path.join(self.dir, "state.json")
        self.tp = FakeTransport()

    def append(self, *lines, path=None):
        with open(path or self.log, "a", encoding="utf-8", newline="") as f:
            f.write("".join(lines))

    def make(self, from_start=False, **kw):
        self.col = C.Collector([self.log], self.tp, kw.pop("privacy", C.Privacy()), C.State(self.statef), "auto", kw.pop("batch_size", 200), from_start,
                               sleep=lambda s: None, **kw)
        return self.col

    def drain(self, col=None):
        col = col or self.col
        col._last_discovery = 0
        while col.step():
            pass

    def paths(self):
        return [e["path"] for e in self.tp.sent]


class TestParsing(unittest.TestCase):
    def test_combined_variants(self):
        ev = C.parse_line(line(path="/vulnerabilities/sqli/", query="id=1%27+OR+%271%27%3D%271&Submit=Submit"), "auto")
        self.assertEqual((ev["src_ip"], ev["method"], ev["path"], ev["status"], ev["bytes"]), ("203.0.113.9", "GET", "/vulnerabilities/sqli/", 200, 512))
        self.assertTrue(ev["query"].startswith("id=1%27+OR"))
        self.assertEqual(int(C.parse_line(line(t="01/Jan/2024:00:00:01 +0530"), "auto")["ts"]), 1704047401)  # time zones honoured
        self.assertEqual(C.parse_line(line(ip="2001:db8::1"), "auto")["src_ip"], "2001:db8::1")

    def test_escapes_and_odd_requests(self):
        ev = C.parse_line('1.1.1.1 - - [10/Oct/2023:13:55:36 +0000] "GET /a\\x22b HTTP/2.0" 404 0 "-" "\\xE4\\xBD\\xA0 agent"', "auto")
        self.assertEqual((ev["path"], ev["ua"]), ('/a"b', "你 agent"))
        self.assertEqual(C.parse_line('1.1.1.1 - - [10/Oct/2023:13:55:36 +0000] "GET /a b?x=1 HTTP/1.1" 200 5', "auto")["path"], "/a b")   # no referer/UA, space in target
        ev = C.parse_line('1.1.1.1 - - [10/Oct/2023:13:55:36 +0000] "GET http://shop.example/p?q=1 HTTP/1.1" 200 5 "-" "-"', "auto")
        self.assertEqual((ev["host"], ev["path"], ev["query"], ev["ua"]), ("shop.example", "/p", "q=1", ""))

    def test_garbage_is_rejected_not_crashed(self):
        for bad in ("", "   ", "garbage", "{broken json", '- - - [10/Oct/2023:13:55:36 +0000] "GET / HTTP/1.1" 200 1',
                    '1.1.1.1 - - [10/Oct/2023:13:55:36 +0000] "-" 400 0 "-" "-"', "[]", "123"):
            self.assertIsNone(C.parse_line(bad, "auto"), bad)
        self.assertIsNone(C.parse_line("x" * 100000, "combined"))   # no catastrophic regex backtracking
        ev = C.parse_line('1.1.1.1 - - [bad time] "GET /x HTTP/1.1" 200 1', "auto")   # unparseable time: keep the request, the collector stamps "now"
        self.assertEqual((ev["path"], ev["ts"]), ("/x", None))

    def test_json_formats(self):
        flat = json.dumps({"remote_addr": "1.2.3.4", "request_method": "GET", "request_uri": "/s?q=1", "status": "200", "body_bytes_sent": "55",
                           "http_user_agent": "ua", "time_iso8601": "2024-05-01T10:00:00+00:00", "host": "shop"})
        ev = C.parse_line(flat, "auto")
        self.assertEqual((ev["path"], ev["query"], ev["status"], ev["bytes"], ev["host"], int(ev["ts"])), ("/s", "q=1", 200, 55, "shop", 1714557600))
        caddy = json.dumps({"ts": 1714557600.5, "request": {"remote_ip": "5.6.7.8", "method": "POST", "uri": "/login?u=a", "host": "x.io",
                                                           "headers": {"User-Agent": ["Mozilla"]}}, "status": 302, "size": 0})
        ev = C.parse_line(caddy, "auto")
        self.assertEqual((ev["src_ip"], ev["method"], ev["path"], ev["ua"], ev["ts"]), ("5.6.7.8", "POST", "/login", "Mozilla", 1714557600.5))
        xff = C.parse_line(json.dumps({"remote_addr": "1.1.1.1, 2.2.2.2", "request": "GET /z?a=1 HTTP/1.1", "status": 200}), "json")
        self.assertEqual((xff["src_ip"], xff["path"]), ("1.1.1.1", "/z"))


class TestPrivacy(unittest.TestCase):
    def ev(self, **kw):
        d = dict(path="/a", query="", src_ip="203.0.113.9"); d.update(kw); return d

    def test_exclude_and_redact(self):
        p = C.Privacy(["healthz", "/admin"], C.DEFAULT_REDACT)
        self.assertIsNone(p.apply(self.ev(path="/healthz/live")))
        self.assertIsNone(p.apply(self.ev(path="/admin/users")))
        out = p.apply(self.ev(query="user=bob&Password=hunter2&user_token=abc&q=1"))
        self.assertEqual(out["query"], f"user=bob&Password={C.REDACTED}&user_token={C.REDACTED}&q=1")

    def test_pseudonyms_are_stable_private_and_in_cgnat_range(self):
        p = C.Privacy(pseudonymize=True, salt=b"s" * 32)
        a, b = p.pseudonym("203.0.113.9"), p.pseudonym("203.0.113.10")
        self.assertEqual(a, p.pseudonym("203.0.113.9"))
        self.assertNotEqual(a, b)
        self.assertNotIn("203.0.113", a)
        o = [int(x) for x in a.split(".")]
        self.assertEqual(o[0], 100); self.assertTrue(64 <= o[1] <= 127)           # 100.64.0.0/10
        self.assertNotEqual(a, C.Privacy(pseudonymize=True, salt=b"t" * 32).pseudonym("203.0.113.9"))  # different salt, different pseudonym
        self.assertEqual(p.apply(self.ev())["src_ip"], a)

    def test_server_policy_is_merged_with_local_flags(self):
        local = C.Privacy(["/a"], ["x"])
        m = local.merged({"exclude_paths": ["/b"], "redact_params": ["y"], "pseudonymize_ips": True})
        self.assertEqual((set(m.exclude), m.redact, m.pseudonymize), ({"/a", "/b"}, {"x", "y"}, True))
        self.assertEqual(local.merged(None).exclude, ["/a"])

    def test_salt_file_created_private_and_reused(self):
        path = os.path.join(tempfile.mkdtemp(), "salt")
        s1 = C.load_salt(path); s2 = C.load_salt(path)
        self.assertEqual(s1, s2); self.assertGreaterEqual(len(s1), 32)
        if os.name == "posix":
            self.assertEqual(os.stat(path).st_mode & 0o077, 0)


class TestTailing(Base):
    def test_default_ignores_history_and_follows_new_lines(self):
        self.append(line(path="/old1"), line(path="/old2"))
        self.make(); self.drain()
        self.assertEqual(self.paths(), [])
        self.append(line(path="/new1"), line(path="/new2"))
        self.drain()
        self.assertEqual(self.paths(), ["/new1", "/new2"])

    def test_from_start_reads_everything(self):
        self.append(line(path="/a"), line(path="/b"))
        self.make(from_start=True); self.drain()
        self.assertEqual(self.paths(), ["/a", "/b"])

    def test_partial_last_line_waits_until_complete(self):
        self.make(from_start=True)
        self.append(line(path="/whole"))
        full = line(path="/split")
        self.append(full[:30])
        self.drain(); self.assertEqual(self.paths(), ["/whole"])
        self.append(full[30:])
        self.drain(); self.assertEqual(self.paths(), ["/whole", "/split"])

    def test_oversize_and_malformed_lines_are_skipped_not_fatal(self):
        self.append(line(path="/a"), "x" * (C.MAX_LINE_BYTES * 3) + "\n", "not a log line\n", line(path="/b"))
        col = self.make(from_start=True); self.drain()
        self.assertEqual(self.paths(), ["/a", "/b"])
        self.assertEqual(col.stats["skipped"], 2)

    def test_event_ids_are_stable_and_unique(self):
        self.append(line(path="/a"), line(path="/a"), line(path="/b"))
        self.make(from_start=True); self.drain()
        ids = [e["eid"] for e in self.tp.sent]
        self.assertEqual(len(set(ids)), 3)                      # identical lines at different positions differ
        self.tp.sent.clear(); os.remove(self.statef) if os.path.exists(self.statef) else None
        self.make(from_start=True); self.drain()
        self.assertEqual([e["eid"] for e in self.tp.sent], ids)  # same file -> same ids: the server can de-duplicate

    def test_batches_respect_batch_size(self):
        self.append(*[line(path=f"/p{i}") for i in range(25)])
        self.make(from_start=True, batch_size=10); self.drain()
        self.assertEqual((len(self.tp.sent), self.tp.calls), (25, 3))

    def test_logrotate_rename_does_not_lose_lines(self):
        self.append(line(path="/a1"), line(path="/a2"))
        self.make(from_start=True); self.drain()
        self.append(line(path="/a3"))                           # written just before rotation
        os.rename(self.log, self.log + ".1")
        self.append(line(path="/b1"), line(path="/b2"))          # new file at the same path
        self.drain()
        self.assertEqual(self.paths(), ["/a1", "/a2", "/a3", "/b1", "/b2"])

    def test_copytruncate_restarts_from_the_top(self):
        self.append(line(path="/a1"), line(path="/a2"))
        self.make(from_start=True); self.drain()
        with open(self.log, "w") as f:
            f.write(line(path="/n1"))                            # truncated in place, then written again
        self.drain()
        self.assertEqual(self.paths(), ["/a1", "/a2", "/n1"])

    def test_missing_file_is_waited_for(self):
        self.make(from_start=True); self.drain()
        self.assertEqual(self.paths(), [])
        self.append(line(path="/late"))
        self.drain()
        self.assertEqual(self.paths(), ["/late"])

    def test_new_files_matching_a_glob_are_read_from_their_first_byte(self):
        col = C.Collector([os.path.join(self.dir, "*.log")], self.tp, C.Privacy(), C.State(self.statef), "auto", 200, False, sleep=lambda s: None)
        self.append(line(path="/hist"), path=self.log)
        col._last_discovery = 0; col.step()                      # first sighting: history ignored
        second = os.path.join(self.dir, "other.log")
        self.append(line(path="/fresh"), path=second)
        col._last_discovery = 0
        while col.step():
            pass
        self.assertEqual(self.paths(), ["/fresh"])


class TestDeliveryGuarantees(Base):
    def test_nothing_is_lost_or_duplicated_when_the_server_fails(self):
        self.append(*[line(path=f"/p{i}") for i in range(6)])
        col = self.make(from_start=True, batch_size=3)
        self.tp.script = [(503, {"detail": "down"}), (0, {"detail": "refused"}), (429, {"detail": "slow"})]
        for _ in range(12):          # the real run loop keeps retrying after a failed step (it just sleeps first)
            col.step()
        self.assertEqual(self.paths(), [f"/p{i}" for i in range(6)])         # eventually all, in order, once
        self.assertEqual(col._backoff, 0.0)                                   # reset after success

    def test_position_is_saved_only_after_the_server_acknowledges(self):
        self.append(line(path="/a"))
        col = self.make(from_start=True)
        self.tp.script = [(500, {})]
        col.step()
        self.assertFalse(os.path.exists(self.statef))                         # failed batch: nothing committed
        self.drain(col)
        self.assertEqual(json.load(open(self.statef))[os.path.abspath(self.log)]["offset"], os.path.getsize(self.log))

    def test_crash_and_restart_resumes_exactly(self):
        self.append(line(path="/a"), line(path="/b"))
        self.make(from_start=True); self.drain()
        self.append(line(path="/c"))                                          # arrives while the collector is "down"
        self.make(from_start=False); self.drain()                             # restart: saved position wins over "start at end"
        self.append(line(path="/d")); self.drain()
        self.assertEqual(self.paths(), ["/a", "/b", "/c", "/d"])

    def test_rotation_while_down_is_detected(self):
        self.append(line(path="/a"))
        self.make(from_start=True); self.drain()
        os.rename(self.log, self.log + ".1"); self.append(line(path="/b"))
        self.make(); self.drain()
        self.assertEqual(self.paths(), ["/a", "/b"])

    def test_413_splits_the_batch(self):
        self.append(*[line(path=f"/p{i}") for i in range(8)])
        col = self.make(from_start=True)
        self.tp.script = [(413, {"detail": "big"})]
        self.drain(col)
        self.assertEqual(self.paths(), [f"/p{i}" for i in range(8)])

    def test_auth_failure_keeps_lines_and_flags_it(self):
        self.append(line(path="/a"))
        col = self.make(from_start=True)
        self.tp.script = [(401, {"detail": "Invalid, revoked or missing API key"})]
        col.step()
        self.assertTrue(col.fatal_auth); self.assertEqual(self.paths(), [])
        self.drain(col)                                                        # key fixed (rotated): the same line is delivered
        self.assertEqual(self.paths(), ["/a"]); self.assertFalse(col.fatal_auth)

    def test_backoff_grows_and_is_capped(self):
        self.append(line(path="/a"))
        col = self.make(from_start=True)
        seen = []
        for _ in range(9):
            self.tp.script = [(503, {})]
            col.step(); seen.append(col._backoff)
        self.assertEqual(seen[:4], [1.0, 2.0, 4.0, 8.0]); self.assertEqual(max(seen), 60.0)

    def test_malformed_batch_rejected_by_server_is_dropped_not_retried_forever(self):
        self.append(line(path="/a"), line(path="/b"))
        col = self.make(from_start=True)
        self.tp.script = [(422, {"detail": "bad"})]
        self.drain(col)
        self.assertEqual(col.stats["events_failed"], 2); self.assertEqual(self.tp.calls, 1)

    def test_heartbeat_applies_dashboard_policy(self):
        self.tp.policy_body = {"exclude_paths": ["/secret"], "redact_params": ["sid"]}
        col = self.make(from_start=True, heartbeat_interval=0)
        self.append(line(path="/secret/x"), line(path="/ok", query="sid=abc&q=1"))
        col._heartbeat_if_due(force=True); self.drain(col)
        self.assertEqual(self.paths(), ["/ok"])
        self.assertEqual(self.tp.sent[0]["query"], f"sid={C.REDACTED}&q=1")
        self.assertIn("version", self.tp.heartbeats[0])

    def test_dry_run_sends_nothing(self):
        self.append(line(path="/a"))
        col = self.make(from_start=True, dry_run=True); self.drain(col)
        self.assertEqual(self.tp.calls, 0)


class _Handler(BaseHTTPRequestHandler):
    seen, code = [], 200
    def log_message(self, *a): pass
    def _reply(self, code, body):
        raw = json.dumps(body).encode()
        self.send_response(code); self.send_header("Content-Length", str(len(raw))); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(raw)
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); body = json.loads(self.rfile.read(n) or b"{}")
        _Handler.seen.append((self.path, self.headers.get("X-Argus-Key"), self.headers.get("Content-Type"), body))
        if self.headers.get("X-Argus-Key") != "agk_" + "k" * 43:
            return self._reply(401, {"detail": "Invalid"})
        self._reply(_Handler.code, {"accepted": len(body.get("events", [])), "policy": {}})
    def do_GET(self):
        _Handler.seen.append((self.path, self.headers.get("X-Argus-Key"), None, None))
        self._reply(200, {"policy": {}, "name": "T"})


class TestHttpTransport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def test_headers_body_and_status_mapping(self):
        _Handler.seen.clear()
        tp = C.HttpTransport(f"http://127.0.0.1:{self.port}", "agk_" + "k" * 43)
        code, body = tp.send_events([{"src_ip": "1.1.1.1", "path": "/"}])
        self.assertEqual((code, body["accepted"]), (200, 1))
        path, key, ctype, sent = _Handler.seen[-1]
        self.assertEqual((path, key, ctype), ("/api/ingest/events", "agk_" + "k" * 43, "application/json"))
        self.assertEqual(sent["events"][0]["path"], "/")
        self.assertEqual(tp.policy()[1]["name"], "T")
        self.assertEqual(C.HttpTransport(f"http://127.0.0.1:{self.port}", "wrong").send_events([])[0], 401)

    def test_unreachable_server_returns_code_zero(self):
        code, body = C.HttpTransport("http://127.0.0.1:1", "k", timeout=2).send_events([])
        self.assertEqual(code, 0); self.assertIn("detail", body)

    def test_collector_through_real_http(self):
        d = tempfile.mkdtemp(); log = os.path.join(d, "a.log")
        open(log, "w").write(line(path="/x") + line(path="/y"))
        col = C.Collector([log], C.HttpTransport(f"http://127.0.0.1:{self.port}", "agk_" + "k" * 43), C.Privacy(), C.State(os.path.join(d, "s.json")), "auto", 200, True, sleep=lambda s: None)
        _Handler.seen.clear()
        while col.step():
            pass
        self.assertEqual(col.stats["events_sent"], 2)
        self.assertTrue(any(p == "/api/ingest/events" for p, *_ in _Handler.seen))


class TestEndToEndWithBackend(Base):
    """A real log file -> collector -> ingest service -> detector -> database -> alerts."""

    def bridge(self):
        from app.security.apikeys import generate_key
        from app.services.connectors.ingest import IngestService
        from app.services.connectors.webevent import normalize_policy
        from app.services.detection.web_pipeline import WebDetectionPipeline
        from tests.helpers import get_web_model, make_settings
        from app.db.database import Database
        from app.db.repository import Repository
        db = Database(os.path.join(self.dir, "t.db")); db.init(); repo = Repository(db)
        _, p, h = generate_key()
        sid = repo.create_source("Lab", "web_access_log", p, h, normalize_policy({}), "a")
        svc = IngestService(repo, WebDetectionPipeline(get_web_model()), make_settings(self.dir))

        class Bridge:
            def send_events(_s, events):
                self.last = svc.ingest_web(repo.get_source(sid), json.loads(json.dumps(events)))   # JSON round trip like the wire
                return 200, self.last
            def heartbeat(_s, info): return 200, {"policy": {}}
            def policy(_s): return 200, {"policy": {}}
        return repo, Bridge()

    def test_real_log_to_alerts_and_restart_is_idempotent(self):
        repo, bridge = self.bridge()
        now = time.strftime("%d/%b/%Y:%H:%M:%S +0000", time.gmtime())
        lines = [line(ip="192.168.1.5", path="/", t=now), line(ip="192.168.1.5", path="/search", query="q=women%27s+shoes", t=now),
                 line(ip="203.0.113.50", path="/vulnerabilities/sqli/", query="id=1%27+OR+%271%27%3D%271&Submit=Submit", t=now),
                 line(ip="203.0.113.51", path="/vulnerabilities/xss_r/", query="name=%3Cscript%3Ealert(1)%3C%2Fscript%3E", t=now),
                 line(ip="203.0.113.52", path="/download", query="file=..%2f..%2f..%2fetc%2fpasswd", t=now),
                 line(ip="203.0.113.53", path="/ping", query="ip=127.0.0.1%3Bcat+%2Fetc%2Fpasswd", t=now),
                 line(ip="203.0.113.54", path="/.env", status=404, t=now)]
        lines += [line(ip="198.51.100.77", path="/vulnerabilities/brute/", query=f"username=admin&password=pw{i}&Login=Login", t=now) for i in range(30)]
        self.append(*lines)
        col = C.Collector([self.log], bridge, C.Privacy([], C.DEFAULT_REDACT), C.State(self.statef), "auto", 200, True, sleep=lambda s: None)
        while col.step():
            pass
        found = {(a["attack_type"], a["src_ip"]) for a in repo.list_alerts(scope="live")[0]}
        for expected in [("SQL Injection", "203.0.113.50"), ("XSS", "203.0.113.51"), ("Path Traversal", "203.0.113.52"),
                         ("Command Injection", "203.0.113.53"), ("Web Reconnaissance", "203.0.113.54"), ("Brute Force", "198.51.100.77")]:
            self.assertIn(expected, found)
        self.assertFalse(any(ip == "192.168.1.5" for _t, ip in found))        # normal visitors raise nothing
        total = repo.overview(24, "live")["total_events"]
        self.assertEqual(total, len(lines))
        with repo.db.connect() as c:                                            # secrets never reach the database
            self.assertEqual(c.execute("SELECT COUNT(*) FROM events WHERE payload_sample LIKE '%pw1%'").fetchone()[0], 0)
        # restart with a brand-new state file: everything is re-sent, the server stores nothing twice
        os.remove(self.statef)
        col2 = C.Collector([self.log], bridge, C.Privacy([], C.DEFAULT_REDACT), C.State(self.statef), "auto", 200, True, sleep=lambda s: None)
        while col2.step():
            pass
        self.assertEqual(self.last["accepted"], 0); self.assertEqual(self.last["duplicates"], len(lines))
        self.assertEqual(repo.overview(24, "live")["total_events"], total)


if __name__ == "__main__":
    unittest.main()
