"""Signature rules for web requests.

Operates on the URL path + query string (URL-decoded twice so simple encoding tricks do not hide an attack)
and on the User-Agent header. Each rule has a confidence: strong rules are precise enough to alert on their own;
weak rules only contribute evidence that the text model or the behaviour tracker can corroborate.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from app.detectors.signature import _SQL_STRONG, _XSS_STRONG
from app.ml.payload import decode_payload, sql_hits, xss_hits


@dataclass
class WebHit:
    attack_type: str
    rule_id: str
    confidence: float
    description: str
    evidence: str = ""
    kind: str = "signature"  # signature | behaviour


_I = re.I
_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_WS = re.compile(r"[\r\n\t\f\v]+")
_TAUTOLOGY = re.compile(r"\b(and|or)\b\s*\(*\s*['\"]?(\w{1,12})['\"]?\s*=\s*['\"]?\2\b", re.I)

_TRAVERSAL = [
    ("WEB-TRAV-002", 0.97, "Request for a well-known system file", re.compile(r"(/etc/(passwd|shadow|hosts)|/proc/self/|boot\.ini|win\.ini|c:\\+windows|/windows/system32|\.\./\.\./)", _I)),
    ("WEB-TRAV-001", 0.93, "Directory traversal sequence (../)", re.compile(r"(\.\./|\.\.\\|\.\.%2f|%2e%2e[/%\\])", _I)),
]
_CMD_WORDS = r"(cat|ls|id|whoami|uname|pwd|wget|curl|nc|ncat|netcat|bash|sh|zsh|python\d?|perl|php|ruby|powershell|cmd|ping|nslookup|echo|rm|chmod|touch|sleep)"
_CMDI = [
    ("WEB-CMDI-001", 0.92, "Shell metacharacter followed by a command", re.compile(r"[;|&`]\s*" + _CMD_WORDS + r"(\s|$|\+|[/\\])", _I)),
    ("WEB-CMDI-002", 0.92, "Command substitution $( ) or backticks around a command",
     re.compile(r"(\$\(\s*|`\s*)(/[\w./-]+/)?" + _CMD_WORDS + r"\b[^`)]{0,100}[`)]", _I)),
    ("WEB-CMDI-003", 0.95, "Reverse-shell or shell-path fragment", re.compile(r"(/bin/(ba|z)?sh\b|/dev/tcp/|nc\s+-[a-z]*e|bash\s+-i|powershell\s+-)", _I)),
    ("WEB-CMDI-004", 0.80, "Newline-separated command", re.compile(r"[\r\n]\s*" + _CMD_WORDS + r"(\s|$|[&;|])", _I)),
]
_RECON_PATHS = re.compile(
    r"(/\.env\b|/\.git(/|$)|/\.svn|/\.hg|/\.htaccess|/\.htpasswd|/\.aws/|/\.ssh/|/\.DS_Store|/wp-config\.php|/config\.php\.(bak|old|save)|"
    r"/phpinfo\.php|/phpmyadmin|/pma/|/server-status|/server-info|/actuator/(env|heapdump)|/cgi-bin/|/vendor/phpunit|/shell\.php|/c99\.php|"
    r"/backup\.(zip|sql|tar\.gz|tgz|rar)|/dump\.sql|/database\.sql|/\.well-known/security\.txt\.bak|/etc/passwd)", _I)
_UA_TOOLS = [  # (regex, attack type it indicates, label)
    (re.compile(r"sqlmap", _I), "SQL Injection", "sqlmap"),
    (re.compile(r"(hydra|medusa|patator|ncrack)", _I), "Brute Force", "password-guessing tool"),
    (re.compile(r"(nikto|nmap|masscan|dirbuster|gobuster|dirb\b|wfuzz|ffuf|feroxbuster|acunetix|nessus|openvas|nuclei|whatweb|zgrab|wpscan|burpcollaborator|jaeles)", _I), "Web Reconnaissance", "scanner"),
]


def inspect_text(ev: dict) -> str:
    """Decoded path+query, with SQL comments neutralised so `UN/**/ION` style obfuscation is visible."""
    return decode_payload(ev["path"] + (("?" + ev["query"]) if ev["query"] else ""))


def scan(ev: dict) -> list:
    hits = []
    text = inspect_text(ev)
    plain = _WS.sub(" ", _COMMENT.sub(" ", text))  # `UNION/**/SELECT` and `UNION%0aSELECT` both become `UNION SELECT`

    # --- SQL injection
    for p in _SQL_STRONG:
        m = p.search(plain)
        if m:
            hits.append(WebHit("SQL Injection", "WEB-SQLI-001", 0.96, "Classic SQL injection construct", m.group(0)))
            break
    else:
        taut = _TAUTOLOGY.search(plain)
        n = sql_hits(plain)
        if taut:
            hits.append(WebHit("SQL Injection", "WEB-SQLI-004", 0.90, "Always-true condition (e.g. AND 5870=5870), typical of automated SQL injection", taut.group(0)))
        elif n >= 2:
            hits.append(WebHit("SQL Injection", "WEB-SQLI-002", 0.88, "Several SQL keywords/operators in the request", plain[:80]))
        elif n == 1 and re.search(r"['\"]", plain):
            hits.append(WebHit("SQL Injection", "WEB-SQLI-003", 0.60, "Single SQL fragment next to a quote (weak)", plain[:80]))

    # --- XSS
    for p in _XSS_STRONG:
        m = p.search(text)
        if m:
            hits.append(WebHit("XSS", "WEB-XSS-001", 0.96, "Script / event-handler injection", m.group(0)))
            break
    else:
        if xss_hits(text) >= 2:
            hits.append(WebHit("XSS", "WEB-XSS-002", 0.86, "Several scripting indicators in the request", text[:80]))

    # --- path traversal / command injection
    for rid, conf, desc, rx in _TRAVERSAL:
        m = rx.search(text) or rx.search(ev["path"] + "?" + ev["query"])
        if m:
            hits.append(WebHit("Path Traversal", rid, conf, desc, m.group(0)))
            break
    for rid, conf, desc, rx in _CMDI:
        m = rx.search(text)
        if m:
            hits.append(WebHit("Command Injection", rid, conf, desc, m.group(0)))
            break

    # --- reconnaissance by sensitive path, and attack-tool User-Agents
    m = _RECON_PATHS.search(decode_payload(ev["path"]))
    if m:
        hits.append(WebHit("Web Reconnaissance", "WEB-RECON-001", 0.82 if ev["status"] in (200, 301, 302, 403) else 0.78,  # probing for secrets is intent even when the file is absent
                           "Probe for a sensitive or administrative file", m.group(0)))
    ua = ev.get("ua") or ""
    for rx, attack, label in _UA_TOOLS:
        m = rx.search(ua)
        if m:
            hits.append(WebHit(attack, "WEB-TOOL-001", 0.95, f"Attack tool in User-Agent ({label})", m.group(0)))
            break
    return hits
