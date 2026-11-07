"""Web detector: event format, signature rules, behaviour tracking, fusion, pipeline, ingestion and source health."""
import tempfile
import time
import unittest

from app.config import ROOT_DIR
from app.db.database import Database
from app.db.repository import Repository
from app.detectors.webrules import scan
from app.models.coverage import compute_coverage
from app.security.apikeys import generate_key
from app.services.connectors.behaviour import BehaviourConfig, BehaviourTracker
from app.services.connectors.ingest import IngestService
from app.services.connectors.sources import live_connected, source_status
from app.services.connectors.webevent import is_pseudonymised, normalize_policy, normalize_web_event, redact_query
from app.services.detection.web_pipeline import WebDetectionPipeline
from app.services.detection.webfuse import fuse
from tests.helpers import get_web_model, make_settings

POL = normalize_policy({})


def mk(ip="203.0.113.9", path="/", query="", status=200, ts=None, method="GET", ua="Mozilla/5.0", eid=None, **kw):
    raw = dict(src_ip=ip, path=path, query=query, status=status, ts=ts if ts is not None else time.time(), method=method, ua=ua, eid=eid, **kw)
    return normalize_web_event(raw, POL)[0]


class TestWebEvent(unittest.TestCase):
    def test_validation_and_bounds(self):
        self.assertEqual(normalize_web_event({"src_ip": "bad", "path": "/"}, POL), (None, "invalid"))
        self.assertEqual(normalize_web_event("junk", POL), (None, "invalid"))
        ev = mk(path="x\x00y\n/z", query="a=" + "b" * 9000, ua="\x1b[31m" + "u" * 500, method="WEIRD", ts=9e12)
        self.assertEqual((ev["path"], ev["method"]), ("/xy/z", "OTHER"))
        self.assertEqual(len(ev["query"]), 4096)
        self.assertLessEqual(len(ev["ua"]), 300)
        self.assertLess(abs(ev["ts"] - time.time()), 5)  # absurd future timestamps become "now"

    def test_ipv6_and_iso_time_and_millis(self):
        self.assertEqual(mk(ip="2001:db8::1")["src_ip"], "2001:db8::1")
        self.assertEqual(int(mk(ts="2024-05-01T10:00:00Z")["ts"]), 1714557600)
        self.assertEqual(int(mk(ts=1714557600000)["ts"]), 1714557600)

    def test_privacy_policy_enforced_server_side(self):
        pol = normalize_policy({"exclude_paths": ["health"], "redact_params": ["Password", "x_key"]})
        self.assertEqual(normalize_web_event({"src_ip": "1.2.3.4", "path": "/health/live"}, pol), (None, "excluded"))
        ev = normalize_web_event({"src_ip": "1.2.3.4", "path": "/l", "query": "u=bob&PASSWORD=hunter2&X_KEY=k&z=1"}, pol)[0]
        self.assertEqual(ev["query"], "u=bob&PASSWORD=[REDACTED]&X_KEY=[REDACTED]&z=1")
        self.assertNotIn("hunter2", ev["request_line"])
        self.assertEqual(redact_query("a=1", []), "a=1")
        self.assertEqual(normalize_policy({"protected_ip": "nope"})["protected_ip"], "")
        self.assertTrue(is_pseudonymised("100.100.1.2")); self.assertFalse(is_pseudonymised("8.8.8.8"))

    def test_default_policy_redacts_csrf_style_tokens(self):
        ev = mk(query="user_token=abc123&csrf_token=zzz&q=ok")
        self.assertIn("user_token=[REDACTED]", ev["query"]); self.assertIn("q=ok", ev["query"])


ATTACKS = [
    ("SQL Injection", "/vulnerabilities/sqli/", "id=1' OR '1'='1&Submit=Submit"),
    ("SQL Injection", "/s", "q=1%27%20UNION%20SELECT%20user,password%20FROM%20users--"),
    ("SQL Injection", "/s", "q=1 UNION/**/SELECT/**/1,2"),
    ("SQL Injection", "/s", "q=1%20uNiOn%0aSeLeCt%201,2"),
    ("SQL Injection", "/item", "id=1) AND 5870=5870 AND (4953=4953"),
    ("XSS", "/x", "name=<script>alert(1)</script>"),
    ("XSS", "/x", "n=%3Cimg%20src=x%20onerror=alert(1)%3E"),
    ("XSS", "/x", "n=<svg/onload=alert`1`>"),
    ("Path Traversal", "/download", "file=../../../../etc/passwd"),
    ("Path Traversal", "/download", "f=..%2f..%2fwindows%2fwin.ini"),
    ("Command Injection", "/ping", "h=127.0.0.1|whoami"),
    ("Command Injection", "/ping", "h=$(id)"),
    ("Command Injection", "/ping", "h=`uname -a`"),
    ("Command Injection", "/ping", "h=1.1.1.1%0aid"),
    ("Web Reconnaissance", "/.env", ""),
    ("Web Reconnaissance", "/phpmyadmin/index.php", ""),
]
BENIGN = [
    ("/search", "q=women%27s+shoes"), ("/search", "q=select+your+size+and+update+profile"), ("/product/42", "color=red&size=M"),
    ("/blog/2024/wait...what", ""), ("/report..final.pdf", ""), ("/search", "q=O%27Brien"), ("/api/items", "page=2&sort=price;desc"),
    ("/redirect", "url=https://example.com/a/b?c=d"), ("/docs/rm-guide", ""), ("/search", "q=how+to+use+curl+or+wget"), ("/search", "q=cat+food+and+id+cards"),
    ("/vulnerabilities/sqli/", "id=1&Submit=Submit"), ("/vulnerabilities/exec/", "ip=8.8.8.8&Submit=Submit"), ("/vulnerabilities/fi/", "page=include.php"),
    ("/vulnerabilities/brute/", "username=admin&password=[REDACTED]&Login=Login"), ("/js/app.js", "q=`hello`"),
]


class TestSignatures(unittest.TestCase):
    def test_every_attack_is_detected_with_the_right_type(self):
        for attack, path, query in ATTACKS:
            types = {h.attack_type for h in scan(mk(path=path, query=query))}
            self.assertIn(attack, types, f"{attack}: {path}?{query} -> {types}")

    def test_no_signature_fires_on_tricky_benign_requests(self):
        for path, query in BENIGN:
            self.assertEqual(scan(mk(path=path, query=query)), [], f"{path}?{query}")

    def test_tool_user_agents(self):
        self.assertEqual({h.attack_type for h in scan(mk(ua="sqlmap/1.7.2#stable"))}, {"SQL Injection"})
        self.assertEqual({h.attack_type for h in scan(mk(ua="Mozilla/5.0 (compatible; Nikto/2.5.0)"))}, {"Web Reconnaissance"})
        self.assertEqual({h.attack_type for h in scan(mk(ua="Mozilla/5.0 (Windows NT 10.0) Chrome/120"))}, set())

    def test_evidence_is_captured(self):
        h = scan(mk(path="/x", query="a=<script>alert(1)</script>"))[0]
        self.assertIn("<script", h.evidence.lower())


class TestBehaviour(unittest.TestCase):
    def run_pattern(self, events):
        tr, fired = BehaviourTracker(), {}
        for e in events:
            for h in tr.observe(1, e):
                fired[h.rule_id] = fired.get(h.rule_id, 0) + 1
        return fired

    def test_normal_patterns_are_silent(self):
        t = 1000.0
        self.assertEqual(self.run_pattern([mk(ip="9.9.9.9", path=f"/p/{i}", ts=t + i * 10) for i in range(30)]), {})
        self.assertEqual(self.run_pattern([mk(ip="9.9.9.9", path=f"/static/a{i}.js", ts=t + i * 0.03) for i in range(80)]), {})  # a page load
        self.assertEqual(self.run_pattern([mk(ip="9.9.9.9", path="/login", status=401, method="POST", ts=t + i * 5) for i in range(3)]), {})
        self.assertEqual(self.run_pattern([mk(ip="9.9.9.9", path="/missing.html", status=404, ts=t + i * 2) for i in range(20)]), {})

    def test_attack_patterns_fire(self):
        t = 1000.0
        self.assertIn("WEB-BEH-BRUTE", self.run_pattern([mk(ip="6.6.6.6", path="/vulnerabilities/brute/", query=f"username=admin&password=p{i}&Login=Login", ts=t + i * .5) for i in range(40)]))
        self.assertIn("WEB-BEH-BRUTE", self.run_pattern([mk(ip="6.6.6.6", path="/login", status=401, method="POST", ts=t + i) for i in range(10)]))
        self.assertIn("WEB-BEH-FLOOD", self.run_pattern([mk(ip="5.5.5.5", path="/", ts=t + i * .0125) for i in range(400)]))
        self.assertIn("WEB-BEH-SCAN", self.run_pattern([mk(ip="4.4.4.4", path=f"/d{i}/x", status=404, ts=t + i * .2) for i in range(60)]))

    def test_a_verdict_is_attached_only_to_events_that_contribute_to_it(self):
        t = 1000.0
        tr = BehaviourTracker()
        for i in range(30):                                               # a brute-force burst ...
            tr.observe(1, mk(ip="6.6.6.6", path="/login", status=401, method="POST", ts=t + i * .1))
        after = tr.observe(1, mk(ip="6.6.6.6", path="/about", ts=t + 4))     # ... must not taint an unrelated page view from the same client
        self.assertEqual([h.rule_id for h in after], [])
        for i in range(40):                                               # a directory scan ...
            tr.observe(1, mk(ip="4.4.4.4", path=f"/x{i}/", status=404, ts=t + i * .1))
        self.assertEqual(tr.observe(1, mk(ip="4.4.4.4", path="/", status=200, ts=t + 5)), [])   # ... does not taint a successful request
        self.assertEqual([h.rule_id for h in tr.observe(1, mk(ip="4.4.4.4", path="/y/", status=404, ts=t + 5))], ["WEB-BEH-SCAN"])

    def test_clients_and_sources_are_isolated(self):
        tr = BehaviourTracker(BehaviourConfig(brute_attempts=5, brute_failures=99))
        for i in range(4):
            self.assertEqual(tr.observe(1, mk(ip="7.7.7.7", path="/login", ts=1000 + i)), [])
            self.assertEqual(tr.observe(2, mk(ip="7.7.7.7", path="/login", ts=1000 + i)), [])  # same IP, other source: separate counters
        self.assertTrue(tr.observe(1, mk(ip="7.7.7.7", path="/login", ts=1005)))
        self.assertEqual(tr.observe(1, mk(ip="8.8.8.8", path="/login", ts=1005)), [])

    def test_memory_is_bounded(self):
        tr = BehaviourTracker(BehaviourConfig(max_clients=50))
        for i in range(500):
            tr.observe(1, mk(ip=f"10.0.{i // 250}.{i % 250}", ts=1000 + i))
        self.assertLessEqual(len(tr._clients), 50)


class TestFusion(unittest.TestCase):
    def test_strong_signature_alone_alerts_weak_alone_does_not(self):
        strong = scan(mk(query="q=<script>alert(1)</script>"))
        self.assertEqual(fuse(strong, None)["attack_type"], "XSS")
        weak = scan(mk(query="id=5'"))
        self.assertIsNone(fuse(weak, None))
        self.assertIsNone(fuse([], ("SQL Injection", 0.6)))          # model alone below threshold
        self.assertEqual(fuse([], ("SQL Injection", 0.9))["attack_type"], "SQL Injection")
        self.assertIsNone(fuse([], ("SQL Injection", 0.3)))

    def test_independent_evidence_strengthens(self):
        sig_only = fuse(scan(mk(query="id=1 AND 5=5")), None)
        both = fuse(scan(mk(query="id=1 AND 5=5")), ("SQL Injection", 0.9))
        self.assertGreater(both["confidence"], sig_only["confidence"])
        self.assertTrue(both["corroborated"]); self.assertFalse(sig_only["corroborated"])

    def test_more_severe_wins_near_ties_but_not_big_gaps(self):
        e = mk(path="/ping", query="h=1;cat /etc/passwd")      # path traversal (0.97) AND command injection (0.92)
        self.assertEqual(fuse(scan(e), ("Command Injection", 0.95))["attack_type"], "Command Injection")
        e2 = mk(path="/x", query="n=<svg/onload=alert`1`>")      # XSS must not lose to the backtick rule
        self.assertEqual(fuse(scan(e2), ("XSS", 0.9))["attack_type"], "XSS")


class TestPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pipe = WebDetectionPipeline(get_web_model(), ["10.0.0.10"])

    def test_batch_verdicts_and_explanations(self):
        evs = [mk(path="/", ts=1), mk(path="/vulnerabilities/sqli/", query="id=1' OR '1'='1&Submit=Submit", ts=2),
               mk(path="/search", query="q=women%27s+shoes", ts=3), mk(path="/dl", query="f=../../etc/passwd", ts=4)]
        d = self.pipe.analyze_batch(evs, 1, "10.0.0.10")
        self.assertEqual([x["verdict"] for x in d], ["benign", "threat", "benign", "threat"])
        self.assertEqual((d[1]["attack_type"], d[3]["attack_type"]), ("SQL Injection", "Path Traversal"))
        self.assertTrue(any(s.startswith("signature:") for s in d[1]["sources"]))
        self.assertTrue(d[1]["explanation"] and d[1]["explanation"][0]["factor"])
        self.assertAlmostEqual(sum(x["share"] for x in d[1]["explanation"]), 1.0, places=1)
        self.assertGreater(d[1]["risk_score"], 60)

    def test_critical_asset_raises_risk(self):
        e = [mk(path="/x", query="a=;cat /etc/hosts", ts=1)]
        hi = self.pipe.analyze_batch(e, 1, "10.0.0.10")[0]["risk_score"]
        lo = self.pipe.analyze_batch(e, 1, "")[0]["risk_score"]
        self.assertGreater(hi, lo)

    def test_results_follow_input_order_even_if_unsorted_in_time(self):
        evs = [mk(ip="3.3.3.3", path="/login", status=401, method="POST", ts=100 + i) for i in range(12)]
        pipe = WebDetectionPipeline(get_web_model())
        d = pipe.analyze_batch(evs[::-1], 1)
        self.assertEqual(len(d), 12)
        self.assertTrue(any(x["attack_type"] == "Brute Force" for x in d))   # time ordering is applied internally

    def test_shipped_model_independent_probes(self):
        model_dir = ROOT_DIR / "models" / "web"
        if not (model_dir / "web_model.joblib").exists():
            self.skipTest("shipped web model not present")
        from app.ml.webregistry import load_web_model
        model, rep = load_web_model(model_dir)
        pipe = WebDetectionPipeline(model)
        probes = [("SQL Injection", "/item", "id=1) AND 5870=5870 AND (4953=4953"), ("SQL Injection", "/p", "id=-1' UNION ALL SELECT NULL,CONCAT(0x7171,user(),0x7171),NULL-- -"),
                  ("XSS", "/x", "q=\"><script>alert(String.fromCharCode(88,83,83))</script>"), ("XSS", "/x", "q=<iframe srcdoc=\"<script>alert(1)</script>\">"),
                  ("Path Traversal", "/dl", "f=....//....//....//etc/shadow"), ("Path Traversal", "/dl", "f=..%5c..%5c..%5cwindows%5cwin.ini"),
                  ("Command Injection", "/ping", "h=localhost && id"), ("Command Injection", "/p", "a=$(cat /etc/hosts)")]
        got = [pipe.analyze_batch([mk(path=p, query=q)], 1)[0]["attack_type"] for _a, p, q in probes]
        self.assertEqual(got, [a for a, _p, _q in probes])
        for path, query in [("/vulnerabilities/sqli/", "id=2&Submit=Submit&user_token=0123456789abcdef0123456789abcdef"), ("/vulnerabilities/xss_r/", "name=Bob+Smith"),
                            ("/vulnerabilities/exec/", "ip=google.com&Submit=Submit"), ("/vulnerabilities/fi/", "page=file1.php"), ("/login.php", ""), ("/security.php", "")]:
            self.assertEqual(pipe.analyze_batch([mk(path=path, query=query)], 1)[0]["verdict"], "benign", f"{path}?{query}")
        self.assertLess(rep["leak_audit"]["structure_only_auc"], 0.65)
        self.assertGreater(rep["held_out_families"]["combined"]["detection_rate"], 0.85)
        self.assertLess(rep["held_out_families"]["combined"]["false_positive_rate"], 0.01)


class FakeHub:
    def __init__(self): self.msgs = []
    def publish(self, m): self.msgs.append(m)


class FakeNotifier:
    def __init__(self): self.sent = []
    def notify(self, alert): self.sent.append(alert)


class TestIngest(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        self.db = Database(f"{d}/t.db"); self.db.init(); self.repo = Repository(self.db)
        full, prefix, h = generate_key()
        self.sid = self.repo.create_source("Shop", "web_access_log", prefix, h, normalize_policy({"exclude_paths": ["/health"], "protected_ip": "10.0.0.10"}), "admin")
        self.hub, self.notifier = FakeHub(), FakeNotifier()
        self.svc = IngestService(self.repo, WebDetectionPipeline(get_web_model(), ["10.0.0.10"]), make_settings(d), self.hub, self.notifier)

    def src(self): return self.repo.get_source(self.sid)

    def raw(self, **kw):
        base = dict(src_ip="203.0.113.9", method="GET", path="/", query="", status=200, bytes=100, ua="Mozilla/5.0", ts=time.time())
        base.update(kw); return base

    def test_end_to_end_batch(self):
        batch = [self.raw(eid="a"), self.raw(eid="b", path="/vulnerabilities/sqli/", query="id=1' OR '1'='1&Submit=Submit"),
                 self.raw(eid="c", path="/health/live"), self.raw(src_ip="not-an-ip"), self.raw(eid="d", path="/x", query="u=bob&password=hunter2")]
        r = self.svc.ingest_web(self.src(), batch)
        self.assertEqual((r["accepted"], r["excluded"], r["rejected"], r["threats"]), (3, 1, 1, 1))
        ov = self.repo.overview(24, "live")
        self.assertEqual((ov["total_events"], ov["threats"]), (3, 1))
        alert = self.repo.list_alerts(scope="live")[0][0]
        self.assertEqual((alert["attack_type"], alert["source_name"], alert["dst_ip"]), ("SQL Injection", "Shop", "10.0.0.10"))
        with self.db.connect() as c:   # the password value never reaches the database
            self.assertEqual(c.execute("SELECT COUNT(*) FROM events WHERE payload_sample LIKE '%hunter2%'").fetchone()[0], 0)
            self.assertEqual(c.execute("SELECT COUNT(*) FROM events WHERE payload_sample LIKE '%[REDACTED]%'").fetchone()[0], 1)
        s = self.src()
        self.assertEqual((s["events_total"], s["threats_total"], s["rejected_total"]), (3, 1, 1))
        self.assertEqual(len(self.notifier.sent), 1)                      # one new alert -> one notification
        threats = [m for m in self.hub.msgs if m["verdict"] == "threat"]
        self.assertEqual((len(threats), threats[0]["source"], threats[0]["origin"]), (1, "Shop", "connector"))

    def test_resending_the_same_batch_is_harmless(self):
        batch = [self.raw(eid=f"e{i}", path="/p", query=f"id={i}") for i in range(5)] + [self.raw(eid="evil", path="/s", query="q=<script>alert(1)</script>")]
        first = self.svc.ingest_web(self.src(), batch)
        again = self.svc.ingest_web(self.src(), batch)
        self.assertEqual((first["accepted"], again["accepted"], again["duplicates"]), (6, 0, 6))
        self.assertEqual(self.repo.overview(24, "live")["total_events"], 6)
        self.assertEqual(self.repo.list_alerts(scope="live")[1], 1)

    def test_duplicate_ids_inside_one_batch(self):
        r = self.svc.ingest_web(self.src(), [self.raw(eid="x"), self.raw(eid="x")])
        self.assertEqual((r["accepted"], r["duplicates"]), (1, 1))

    def test_repeated_attacks_become_one_alert_with_a_counter(self):
        batch = [self.raw(eid=f"s{i}", path="/s", query="q=<script>alert(1)</script>", ts=time.time() + i) for i in range(10)]
        self.svc.ingest_web(self.src(), batch)
        rows, total = self.repo.list_alerts(scope="live")
        self.assertEqual((total, rows[0]["count"]), (1, 10))

    def test_live_feed_is_not_flooded_with_benign_events(self):
        self.svc.ingest_web(self.src(), [self.raw(eid=f"n{i}", path=f"/page/{i}") for i in range(50)])
        self.assertLessEqual(len(self.hub.msgs), 3)

    def test_empty_and_garbage_batches(self):
        self.assertEqual(self.svc.ingest_web(self.src(), [])["accepted"], 0)
        r = self.svc.ingest_web(self.src(), ["x", 5, None, {}, {"src_ip": "1.1.1.1"}])
        self.assertEqual(r["rejected"], 4)
        self.assertEqual(r["accepted"], 1)     # a bare event with a valid IP defaults to "GET /"


class TestSourceHealth(unittest.TestCase):
    def test_status_transitions(self):
        now = time.time()
        self.assertEqual(source_status({"revoked_at": 1}, 150, now), "revoked")
        self.assertEqual(source_status({}, 150, now), "waiting")
        self.assertEqual(source_status({"last_heartbeat": now - 20}, 150, now), "connected")
        self.assertEqual(source_status({"last_seen": now - 400, "last_heartbeat": now - 400}, 150, now), "silent")
        self.assertEqual(source_status({"last_seen": now - 400, "last_heartbeat": now - 5}, 150, now), "connected")  # quiet site, collector alive

    def test_live_connected_and_coverage(self):
        d = tempfile.mkdtemp(); repo = Repository(Database(f"{d}/t.db")); repo.db.init()
        _, p, h = generate_key(); sid = repo.create_source("Shop", "web_access_log", p, h, {}, "a")
        self.assertFalse(live_connected(repo, 150))
        repo.touch_source(sid, heartbeat=True)
        self.assertTrue(live_connected(repo, 150))
        repo.revoke_source(sid)
        self.assertFalse(live_connected(repo, 150))

    def test_coverage_is_honest(self):
        srcs = [dict(kind="web_access_log", name="Shop", status="connected")]
        by = {i["attack_type"]: i for i in compute_coverage(srcs, demo_active=False)["items"]}
        for covered in ("SQL Injection", "XSS", "Brute Force", "Path Traversal", "Command Injection", "Web Reconnaissance", "DDoS"):
            self.assertEqual(by[covered]["status"], "covered", covered)
        for blind in ("Ransomware", "Malware", "Phishing", "Botnet", "Insider Threat", "MITM", "Port Scanning", "Zero-Day"):
            self.assertEqual(by[blind]["status"], "uncovered", blind)
            self.assertTrue(by[blind]["needs"])
        self.assertIn("HTTP", by["DDoS"]["note"])
        silent = {i["attack_type"]: i["status"] for i in compute_coverage([dict(kind="web_access_log", name="Shop", status="silent")], False)["items"]}
        self.assertEqual(silent["SQL Injection"], "silent")
        self.assertTrue(all(i["status"] == "demo" for i in compute_coverage([], demo_active=True)["items"]))
        waiting = {i["attack_type"]: i["status"] for i in compute_coverage([dict(kind="web_access_log", name="S", status="waiting")], False)["items"]}
        self.assertEqual(waiting["XSS"], "waiting")
        self.assertEqual(compute_coverage([dict(kind="web_access_log", name="S", status="revoked")], False)["summary"]["covered"], 0)

    def test_coverage_names_only_sources_that_are_delivering_data(self):
        mixed = [dict(kind="web_access_log", name="Good", status="connected"), dict(kind="web_access_log", name="Quiet", status="silent"),
                 dict(kind="web_access_log", name="New", status="waiting")]
        by = {i["attack_type"]: i for i in compute_coverage(mixed, False)["items"]}
        self.assertEqual((by["XSS"]["status"], by["XSS"]["via"]), ("covered", ["Good"]))
        only_quiet = {i["attack_type"]: i for i in compute_coverage(mixed[1:2], False)["items"]}
        self.assertEqual((only_quiet["XSS"]["status"], only_quiet["XSS"]["via"]), ("silent", ["Quiet"]))


if __name__ == "__main__":
    unittest.main()
