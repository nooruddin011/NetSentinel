"""What each kind of data source can (and cannot) see.

Honesty is the point: a web-server log can reveal web attacks, but it cannot reveal ransomware on a laptop.
The dashboard uses this table to tell the client exactly which attack types are covered by the sources they
have connected, which are not, and what additional source would cover them.
"""
from __future__ import annotations

from app.models.attacks import ATTACKS, KNOWN_ATTACKS, WEB_ONLY_ATTACKS

# kind -> metadata. `available` = a connector exists today.  `live` = it streams in real time.
SOURCE_KINDS = {
    "web_access_log": dict(
        label="Web server access log", available=True, live=True,
        description="Nginx / Apache (combined format) or JSON access logs, streamed live by the Argus collector.",
        covers=["SQL Injection", "XSS", "Brute Force", "DDoS", "Path Traversal", "Command Injection", "Web Reconnaissance"],
        partial={"DDoS": "HTTP-level floods only (not network-layer floods)",
                 "Brute Force": "web login attempts only (not SSH / RDP / database logins)"}),
    "flow_upload": dict(
        label="Network flow records (file upload)", available=True, live=False,
        description="CSV exports of network flows (CICIDS / NSL-KDD style), analysed on upload. Not real-time.",
        covers=list(KNOWN_ATTACKS) + ["Zero-Day"], partial={}),
    "honeypot": dict(label="Honeypot (decoy server)", available=False, live=True,
                     description="A decoy SSH/web server that records real attackers. Planned.",
                     covers=["Brute Force", "Botnet", "Malware", "Port Scanning"], partial={}),
    "auth_log": dict(label="Authentication logs", available=False, live=True,
                     description="SSH / Windows / identity-provider sign-in events. Planned.",
                     covers=["Brute Force", "Insider Threat"], partial={}),
    "endpoint": dict(label="Endpoint (EDR) logs", available=False, live=True,
                     description="Process and file events from laptops and servers. Planned.",
                     covers=["Malware", "Ransomware", "Insider Threat"], partial={}),
    "network_flow": dict(label="Network flow / firewall logs", available=False, live=True,
                         description="NetFlow / Zeek / firewall logs streamed live. Planned.",
                         covers=list(KNOWN_ATTACKS) + ["Zero-Day"], partial={}),
    "email_gateway": dict(label="Email gateway logs", available=False, live=True,
                          description="Inbound mail metadata and URLs. Planned.", covers=["Phishing"], partial={}),
}

# What a client would need to connect to cover an attack that none of their current sources can see.
NEEDS = {
    "Malware": "Endpoint (EDR) logs", "Ransomware": "Endpoint or file-server logs", "Botnet": "Network flow or DNS logs",
    "Port Scanning": "Network flow or firewall logs", "Insider Threat": "Authentication and data-access logs",
    "MITM": "Network / TLS logs", "Phishing": "Email gateway logs", "Zero-Day": "Network flow logs (anomaly detection)",
    "DDoS": "Web or network flow logs", "Brute Force": "Web or authentication logs",
    "SQL Injection": "Web server logs", "XSS": "Web server logs", "Path Traversal": "Web server logs",
    "Command Injection": "Web server logs", "Web Reconnaissance": "Web server logs",
}

# Order shown in the UI: the attacks a web-log source covers first, then the rest.
ATTACK_ORDER = ["SQL Injection", "XSS", "Brute Force", "Path Traversal", "Command Injection", "Web Reconnaissance", "DDoS"] + \
               [a for a in ATTACKS if a not in ("SQL Injection", "XSS", "Brute Force", "Path Traversal", "Command Injection",
                                                "Web Reconnaissance", "DDoS")]


def source_kind(kind: str) -> dict:
    return SOURCE_KINDS.get(kind, {})


def compute_coverage(sources: list, demo_active: bool) -> dict:
    """sources: dicts with `kind`, `name`, `status` ('connected'|'silent'|'revoked'|'waiting').

    Returns per-attack coverage. Only *live* sources count towards coverage; revoked ones are ignored."""
    live = [s for s in sources if s.get("status") != "revoked" and source_kind(s["kind"]).get("live")]
    items = []
    for attack in ATTACK_ORDER:
        via = [s for s in live if attack in source_kind(s["kind"]).get("covers", [])]
        healthy = [s for s in via if s["status"] == "connected"]
        waiting = [s for s in via if s["status"] == "waiting"]
        if healthy:
            status = "covered"
        elif waiting:
            status = "waiting"
        elif via:
            status = "silent"
        elif demo_active:
            status = "demo"
        else:
            status = "uncovered"
        notes = [source_kind(s["kind"]).get("partial", {}).get(attack) for s in via]
        shown = healthy if healthy else via        # name only sources that are delivering data; if none are, name the ones that should be
        items.append(dict(attack_type=attack, status=status, via=[s["name"] for s in shown],
                          severity=ATTACKS[attack]["severity"], note=next((n for n in notes if n), None),
                          needs=None if via else NEEDS.get(attack),
                          web_only=attack in WEB_ONLY_ATTACKS))
    n = lambda st: sum(1 for i in items if i["status"] == st)  # noqa: E731
    return dict(items=items, summary=dict(total=len(items), covered=n("covered"), silent=n("silent"), waiting=n("waiting"),
                                          uncovered=n("uncovered"), demo=n("demo")))
