"""Domain knowledge: the 12 attack types, their base severity, MITRE ATT&CK mapping (indicative)
and plain-language descriptions. This is reference data, not model output."""
from __future__ import annotations

import re

BENIGN = "Benign"

SEVERITY_ORDER = ["Low", "Medium", "High", "Critical"]
SEVERITY_BASE_SCORE = {"Low": 25, "Medium": 45, "High": 70, "Critical": 90}

ATTACKS = {
    "DDoS": dict(severity="High", mitre="T1498", aliases=["ddos", "dos", "flood", "denial of service"],
                 description="Flooding a service with traffic from one or many sources to exhaust bandwidth or connection capacity.",
                 indicators=["very high packet rate", "tiny packets", "high SYN ratio", "little or no response data"]),
    "SQL Injection": dict(severity="Critical", mitre="T1190", aliases=["sql injection", "sqli", "sql", "injection"],
                          description="Malicious SQL fragments in request parameters that manipulate or exfiltrate database content.",
                          indicators=["SQL keywords in payload", "quotes/comment tokens", "UNION/OR 1=1 patterns"]),
    "XSS": dict(severity="Medium", mitre="T1189", aliases=["xss", "cross-site scripting", "cross site scripting", "script injection"],
                description="Injection of client-side script into pages viewed by other users.",
                indicators=["<script> tags", "event-handler attributes", "javascript: URIs"]),
    "Phishing": dict(severity="Medium", mitre="T1566", aliases=["phishing", "credential theft", "fake login"],
                     description="Deceptive pages or messages that harvest credentials.",
                     indicators=["very young domain", "long/obfuscated URL", "IP literal in URL", "certificate mismatch"]),
    "Brute Force": dict(severity="High", mitre="T1110", aliases=["brute force", "bruteforce", "password guessing", "credential stuffing"],
                        description="Repeated authentication attempts to guess valid credentials.",
                        indicators=["many failed logins", "high connection count from one source", "login ports (22/3389/21)"]),
    "Malware": dict(severity="Critical", mitre="T1204", aliases=["malware", "trojan", "virus"],
                    description="Malicious software delivered to or running on a host.",
                    indicators=["high-entropy (packed) payload", "unusual destination", "off-hours activity"]),
    "Ransomware": dict(severity="Critical", mitre="T1486", aliases=["ransomware", "crypto locker", "encryption attack"],
                       description="Malware that encrypts files and demands payment, often spreading over SMB.",
                       indicators=["bulk SMB writes", "very high payload entropy", "lateral spread to many hosts"]),
    "Botnet": dict(severity="High", mitre="T1071", aliases=["botnet", "c2", "command and control", "bot"],
                   description="Infected hosts beaconing to a command-and-control server.",
                   indicators=["highly regular beaconing", "elevated DNS rate", "rare external destination"]),
    "Port Scanning": dict(severity="Low", mitre="T1046", aliases=["port scan", "port scanning", "portscan", "recon", "reconnaissance", "nmap"],
                          description="Probing many ports or hosts to map exposed services.",
                          indicators=["many distinct ports", "tiny packets", "high error/RST ratio"]),
    "Insider Threat": dict(severity="High", mitre="T1567", aliases=["insider", "insider threat", "data exfiltration", "exfiltration"],
                           description="Authorised users abusing access, typically bulk data transfer to unusual destinations.",
                           indicators=["off-hours activity", "very large outbound volume", "unusual destination"]),
    "MITM": dict(severity="High", mitre="T1557", aliases=["mitm", "man in the middle", "man-in-the-middle", "arp spoofing"],
                 description="An attacker silently relaying or altering traffic between two parties.",
                 indicators=["certificate mismatch", "latency inflation vs. baseline"]),
    "Path Traversal": dict(severity="High", mitre="T1190", aliases=["path traversal", "directory traversal", "dot dot slash", "lfi", "local file inclusion"],
                           description="Requests that use ../ sequences or absolute paths to read files outside the web root (for example /etc/passwd).",
                           indicators=["../ or encoded %2e%2e sequences", "references to system files", "unusual file extensions in parameters"]),
    "Command Injection": dict(severity="Critical", mitre="T1059", aliases=["command injection", "os command injection", "shell injection", "rce", "remote code execution"],
                              description="Input that makes the server run operating-system commands (for example ; cat /etc/passwd or $(id)).",
                              indicators=["shell metacharacters ; | && ` $( )", "commands such as cat, wget, curl, id, whoami", "reverse-shell fragments"]),
    "Web Reconnaissance": dict(severity="Low", mitre="T1595", aliases=["web reconnaissance", "web recon", "web scan", "directory enumeration", "vulnerability scan", "scanner"],
                               description="Automated probing of a website for hidden or sensitive files and known-vulnerable software.",
                               indicators=["requests for /.env, /.git, /phpmyadmin, backups", "many 404 responses from one source", "scanner tools in the User-Agent (sqlmap, nikto, nmap)"]),
    "Zero-Day": dict(severity="High", mitre="N/A", aliases=["zero-day", "zero day", "0day", "unknown attack", "novel"],
                     description="Traffic that matches no known attack class but is statistically abnormal (flagged by the anomaly detector).",
                     indicators=["high autoencoder reconstruction error", "low classifier confidence"]),
}

# Attack types found only by the web-request detector (rules + text model + behaviour), not by the flow classifier.
WEB_ONLY_ATTACKS = ["Path Traversal", "Command Injection", "Web Reconnaissance"]

# Classes the supervised flow models are trained on (this list must not change without retraining).
# Zero-Day is intentionally NOT a trained class: a supervised model cannot learn what it has never seen,
# so it is handled by anomaly detection.
KNOWN_ATTACKS = [a for a in ATTACKS if a != "Zero-Day" and a not in WEB_ONLY_ATTACKS]
CLASSES = [BENIGN] + KNOWN_ATTACKS


def resolve_attack(text: str):
    """Map free text ('what is sqli?') to a canonical attack name, or None."""
    t = text.lower()
    best, best_len = None, 0
    for name, meta in ATTACKS.items():
        for alias in meta["aliases"] + [name.lower()]:
            if len(alias) > best_len and re.search(r"(?<![a-z0-9])" + re.escape(alias) + r"(?![a-z0-9])", t):
                best, best_len = name, len(alias)
    return best
