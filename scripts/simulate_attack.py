#!/usr/bin/env python3
"""Inject simulated attacks into a running platform through its API (stdlib only).

  python scripts/simulate_attack.py --password '...' --scenario DDoS --count 3
  python scripts/simulate_attack.py --password '...' --payload "' OR 1=1 --"
"""
import argparse
import json
import urllib.error
import urllib.request


def call(url, body=None, token=None):
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json", **({"Authorization": f"Bearer {token}"} if token else {})})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        raise SystemExit(f"HTTP {e.code}: {e.read().decode()[:300]}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--password", required=True)
    ap.add_argument("--scenario", help="e.g. DDoS, 'SQL Injection', Ransomware, Zero-Day")
    ap.add_argument("--count", type=int, default=1)
    ap.add_argument("--payload", help="send a raw request payload for inspection instead of a scenario")
    a = ap.parse_args()
    token = call(f"{a.url}/api/auth/login", {"username": a.user, "password": a.password})["access_token"]
    if a.payload:
        r = call(f"{a.url}/api/detect/event", {"payload_sample": a.payload, "src_ip": "198.51.100.77"}, token)
        print(f"{r['verdict']}: {r['attack_type']} {r['severity']} risk={r['risk_score']} via {r['sources']}")
        return
    for _ in range(a.count):
        r = call(f"{a.url}/api/lab/simulate", {"scenario": a.scenario or "DDoS"}, token)
        print(f"injected {r['injected_scenario']:15s} -> detected {str(r['attack_type']):15s} {r['severity']} risk={r['risk_score']} correct={r['correct']}")


if __name__ == "__main__":
    main()
