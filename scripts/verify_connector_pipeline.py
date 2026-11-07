#!/usr/bin/env python3
"""Prove the live-detection chain works on THIS machine, without Docker.

    python scripts/verify_connector_pipeline.py

What it does (everything stays on localhost, nothing is installed):
  1. starts a throwaway web server that writes a real nginx-style access log,
  2. runs lab/attack_demo.py against it (real HTTP requests: SQLi, XSS, path traversal, command injection, brute force,
     directory scan, HTTP flood, sqlmap User-Agent),
  3. feeds that log file through the real collector -> ingest -> detector -> database,
  4. checks that each attack was detected with the right type, and that normal browsing raised nothing.
"""
import http.client
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter, defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

EXPECTED = {"SQL Injection", "XSS", "Path Traversal", "Command Injection", "Brute Force", "Web Reconnaissance", "DDoS"}


def _load_collector():
    spec = importlib.util.spec_from_file_location("argus_collector", ROOT / "collector" / "argus_collector.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run(model=None, report=None, verbose=True) -> dict:
    from app.config import Settings
    from app.db.database import Database
    from app.db.repository import Repository
    from app.ml.webregistry import load_web_model
    from app.security.apikeys import generate_key
    from app.services.connectors.ingest import IngestService
    from app.services.connectors.webevent import normalize_policy
    from app.services.detection.web_pipeline import WebDetectionPipeline

    C = _load_collector()
    work = tempfile.mkdtemp()
    logf, lock = os.path.join(work, "access.log"), threading.Lock()

    class Target(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            path = self.path.split("?")[0]
            status = 200 if (path in ("/", "/login.php", "/index.php") or path.startswith("/vulnerabilities/")) else 404
            self.send_response(status); self.send_header("Content-Length", "0"); self.end_headers()
            stamp = time.strftime("%d/%b/%Y:%H:%M:%S +0000", time.gmtime())
            with lock, open(logf, "a") as f:
                f.write(f'127.0.0.1 - - [{stamp}] "GET {self.path} HTTP/1.1" {status} 0 "-" "{self.headers.get("User-Agent", "-")}"\n')

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Target)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        # normal browsing first: must raise nothing
        for p in ["/", "/index.php", "/vulnerabilities/sqli/?id=1&Submit=Submit", "/vulnerabilities/xss_r/?name=Alice", "/login.php"]:
            c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=10)
            c.request("GET", p, headers={"User-Agent": "Mozilla/5.0 Firefox/120"}); c.getresponse().read(); c.close()
        subprocess.run([sys.executable, str(ROOT / "lab" / "attack_demo.py"), "--target", f"http://127.0.0.1:{srv.server_address[1]}"],
                       capture_output=True, text=True, timeout=300, check=True)
    finally:
        srv.shutdown(); srv.server_close()

    if model is None:
        model, report = load_web_model(ROOT / "models" / "web")
    db = Database(os.path.join(work, "t.db")); db.init(); repo = Repository(db)
    _, prefix, h = generate_key()
    sid = repo.create_source("Lab", "web_access_log", prefix, h, normalize_policy({}), "verify")
    svc = IngestService(repo, WebDetectionPipeline(model, report=report), Settings())

    class Bridge:  # in-process stand-in for the HTTP hop (the real hop is covered by tests/test_collector.py)
        def send_events(self, events):
            return 200, svc.ingest_web(repo.get_source(sid), json.loads(json.dumps(events)))

        def heartbeat(self, info):
            return 200, {"policy": {}}

    col = C.Collector([logf], Bridge(), C.Privacy([], C.DEFAULT_REDACT), C.State(os.path.join(work, "state.json")), "auto", 200, True, sleep=lambda s: None)
    t0 = time.time()
    while col.step():
        pass
    elapsed = max(time.time() - t0, 1e-6)
    rows, _ = repo.list_alerts(scope="live", limit=100)
    phases = defaultdict(Counter)
    with db.connect() as conn:
        for request, attack in conn.execute("SELECT payload_sample, attack_type FROM events"):
            path = request.split(" ", 1)[1].split("?")[0]
            phase = ("sqli" if "/sqli/" in path else "xss" if "/xss_r/" in path else "traversal" if "/fi/" in path else "cmdi" if "/exec/" in path
                     else "brute" if "/brute/" in path else "flood" if path == "/" else "scan")
            phases[phase][attack or "benign"] += 1
        first = [r[0] for r in conn.execute("SELECT verdict FROM events ORDER BY id LIMIT 5")]  # the five ordinary page views
    result = dict(browsing_threats=sum(1 for v in first if v == "threat"), events=col.stats["events_sent"],
                  events_per_second=round(col.stats["events_sent"] / elapsed), alerts={a["attack_type"]: a for a in rows},
                  phases={k: dict(v) for k, v in phases.items()}, log_lines=sum(1 for _ in open(logf)))
    if verbose:
        print(f"{result['log_lines']} real requests -> {result['events']} events analysed at {result['events_per_second']} events/s\n")
        for a in sorted(rows, key=lambda r: -r["risk_score"]):
            print(f"  {a['severity']:8s} {a['attack_type']:20s} x{a['count']:<4d} risk {a['risk_score']:5.1f}")
    return result


def main():
    res = run()
    ph = res["phases"]
    checks = [
        ("every attack type produced an alert", EXPECTED <= set(res["alerts"])),
        ("SQL injection: all 8 payloads detected", ph["sqli"].get("SQL Injection", 0) >= 8),
        ("XSS: all 6 payloads detected", ph["xss"].get("XSS", 0) >= 6),
        ("path traversal: all 5 detected", ph["traversal"].get("Path Traversal", 0) >= 5),
        ("command injection: all 5 detected", ph["cmdi"].get("Command Injection", 0) >= 5),
        ("brute force detected after the first few guesses", ph["brute"].get("Brute Force", 0) >= 30),
        ("directory scan detected", ph["scan"].get("Web Reconnaissance", 0) >= 30),
        ("HTTP flood detected", ph["flood"].get("DDoS", 0) >= 200),
        ("normal browsing raised no alert", res["browsing_threats"] == 0),
    ]
    print()
    bad = 0
    for name, ok in checks:
        print(("  PASS  " if ok else "  FAIL  ") + name)
        bad += not ok
    print("\nAll checks passed: the live detection chain works on this machine." if not bad else f"\n{bad} check(s) failed.")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
