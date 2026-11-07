"""Recommendation engine.

Two kinds of advice per attack type:
  * detection_options  -- which detector (Random Forest, XGBoost, ensemble, autoencoder, signature rules...)
    performs best for this attack. Every number comes from the active training run's hold-out evaluation;
    nothing is invented. Models that were not trained are simply absent.
  * mitigation_options -- response actions (block, rate-limit, isolate, patch...) with qualitative
    effectiveness / disruption / time-to-apply. Choosing one runs a *simulation*: rule text is generated
    and recorded, nothing is executed against any real system.
"""
from __future__ import annotations

from app.models.attacks import ATTACKS
from app.utils.net import safe_ip

S = lambda **kw: kw  # noqa: E731  (compact dict literal helper)

PLAYBOOKS = {
    "DDoS": [
        S(id="ddos_ratelimit", title="Rate-limit per source", kind="network", effectiveness="High", disruption="Low", time_to_apply="Minutes", blocks_ip=False,
          description="Cap new connections per source at the edge firewall / load balancer.",
          rule="iptables -A INPUT -p tcp --dport {port} -m hashlimit --hashlimit-above 200/sec --hashlimit-mode srcip --hashlimit-name flood -j DROP"),
        S(id="ddos_scrub", title="Divert to upstream scrubbing / CDN", kind="network", effectiveness="Very High", disruption="Low", time_to_apply="Hours", blocks_ip=False,
          description="Route traffic through a scrubbing provider that absorbs volumetric floods.", rule=None),
        S(id="ddos_block", title="Block offending source", kind="network", effectiveness="Medium", disruption="Low", time_to_apply="Seconds", blocks_ip=True,
          description="Drop traffic from this source. Weak against distributed floods but cheap.", rule="iptables -I INPUT -s {src_ip} -j DROP")],
    "SQL Injection": [
        S(id="sqli_waf", title="Enable WAF SQLi rule", kind="application", effectiveness="High", disruption="Low", time_to_apply="Minutes", blocks_ip=False,
          description="Block requests matching SQL injection patterns in front of the application.",
          rule='SecRule ARGS "@detectSQLi" "id:942100,phase:2,deny,status:403,log,msg:\'SQL injection blocked\'"'),
        S(id="sqli_param", title="Fix with parameterised queries", kind="application", effectiveness="Very High", disruption="Medium", time_to_apply="Days", blocks_ip=False,
          description="Root-cause fix: use prepared statements / an ORM; enforce least-privilege DB accounts.", rule=None),
        S(id="sqli_block", title="Block source IP", kind="network", effectiveness="Medium", disruption="Low", time_to_apply="Seconds", blocks_ip=True,
          description="Stop this attacker; does not fix the vulnerable endpoint.", rule="iptables -I INPUT -s {src_ip} -j DROP")],
    "XSS": [
        S(id="xss_csp", title="Deploy strict Content-Security-Policy", kind="application", effectiveness="High", disruption="Medium", time_to_apply="Hours", blocks_ip=False,
          description="Prevents injected inline scripts from executing in browsers.",
          rule="Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'"),
        S(id="xss_encode", title="Contextual output encoding + input validation", kind="application", effectiveness="Very High", disruption="Medium", time_to_apply="Days", blocks_ip=False,
          description="Root-cause fix in templates and API serialisers.", rule=None),
        S(id="xss_waf", title="Enable WAF XSS rule", kind="application", effectiveness="High", disruption="Low", time_to_apply="Minutes", blocks_ip=False,
          description="Virtual patch while the code fix is prepared.",
          rule='SecRule ARGS "@detectXSS" "id:941100,phase:2,deny,status:403,log,msg:\'XSS blocked\'"')],
    "Phishing": [
        S(id="phish_block", title="Block URL/domain at proxy and DNS", kind="network", effectiveness="High", disruption="Low", time_to_apply="Minutes", blocks_ip=True,
          description="Sinkhole the phishing host so no further users can reach it.", rule="# DNS sinkhole / proxy deny for host at {src_ip}"),
        S(id="phish_reset", title="Force credential reset + enforce MFA for exposed users", kind="identity", effectiveness="Very High", disruption="Medium", time_to_apply="Hours", blocks_ip=False,
          description="Neutralises stolen passwords.", rule=None),
        S(id="phish_train", title="Targeted awareness notice", kind="process", effectiveness="Medium", disruption="Low", time_to_apply="Hours", blocks_ip=False,
          description="Warn users with the indicators seen in this campaign.", rule=None)],
    "Brute Force": [
        S(id="bf_lockout", title="Temporary lockout / fail2ban jail", kind="identity", effectiveness="High", disruption="Low", time_to_apply="Minutes", blocks_ip=True,
          description="Ban sources after repeated failures.", rule="fail2ban-client set sshd banip {src_ip}"),
        S(id="bf_mfa", title="Require MFA on exposed login", kind="identity", effectiveness="Very High", disruption="Medium", time_to_apply="Days", blocks_ip=False,
          description="Makes guessed passwords useless.", rule=None),
        S(id="bf_block", title="Block source IP", kind="network", effectiveness="Medium", disruption="Low", time_to_apply="Seconds", blocks_ip=True,
          description="Immediate containment of this source.", rule="iptables -I INPUT -s {src_ip} -j DROP")],
    "Malware": [
        S(id="mal_isolate", title="Isolate affected host (EDR quarantine)", kind="host", effectiveness="Very High", disruption="Medium", time_to_apply="Minutes", blocks_ip=False,
          description="Cut the host off from the network while preserving memory for forensics.", rule="# EDR: network-isolate host {dst_ip}"),
        S(id="mal_egress", title="Block C2 / download destination", kind="network", effectiveness="High", disruption="Low", time_to_apply="Minutes", blocks_ip=True,
          description="Deny egress to the delivering/controlling endpoint.", rule="iptables -I OUTPUT -d {src_ip} -j DROP"),
        S(id="mal_reimage", title="Full scan and reimage", kind="host", effectiveness="High", disruption="High", time_to_apply="Hours", blocks_ip=False,
          description="Only way to be sure persistence is removed.", rule=None)],
    "Ransomware": [
        S(id="ran_isolate", title="Isolate host and segment SMB", kind="host", effectiveness="Very High", disruption="High", time_to_apply="Minutes", blocks_ip=False,
          description="Stop encryption spreading laterally.", rule="# EDR: network-isolate host {dst_ip}; block TCP/445 between VLANs"),
        S(id="ran_disable", title="Disable compromised accounts and sessions", kind="identity", effectiveness="High", disruption="Medium", time_to_apply="Minutes", blocks_ip=False,
          description="Remove the attacker's access path.", rule=None),
        S(id="ran_restore", title="Restore from offline backups", kind="process", effectiveness="Very High", disruption="High", time_to_apply="Hours", blocks_ip=False,
          description="Recovery without paying; verify backups are clean first.", rule=None)],
    "Botnet": [
        S(id="bot_sinkhole", title="Sinkhole / block C2 domain and IP", kind="network", effectiveness="High", disruption="Low", time_to_apply="Minutes", blocks_ip=True,
          description="Breaks the beacon channel.", rule="iptables -I OUTPUT -d {src_ip} -j DROP"),
        S(id="bot_isolate", title="Isolate infected host", kind="host", effectiveness="Very High", disruption="Medium", time_to_apply="Minutes", blocks_ip=False,
          description="Stops participation in attacks and further spread.", rule="# EDR: network-isolate host {dst_ip}"),
        S(id="bot_egress", title="Default-deny egress filtering", kind="network", effectiveness="High", disruption="Medium", time_to_apply="Days", blocks_ip=False,
          description="Long-term control: only allow known outbound destinations.", rule=None)],
    "Port Scanning": [
        S(id="scan_block", title="Block scanning source", kind="network", effectiveness="High", disruption="Low", time_to_apply="Seconds", blocks_ip=True,
          description="Recon is cheap to stop at the perimeter.", rule="iptables -I INPUT -s {src_ip} -j DROP"),
        S(id="scan_close", title="Close unused ports (default-deny)", kind="network", effectiveness="Very High", disruption="Low", time_to_apply="Hours", blocks_ip=False,
          description="Reduces what a scan can find.", rule=None),
        S(id="scan_watch", title="Raise monitoring on scanned hosts", kind="process", effectiveness="Medium", disruption="Low", time_to_apply="Minutes", blocks_ip=False,
          description="Scans often precede exploitation.", rule=None)],
    "Insider Threat": [
        S(id="ins_suspend", title="Suspend account pending review", kind="identity", effectiveness="High", disruption="High", time_to_apply="Minutes", blocks_ip=False,
          description="Contain possible exfiltration; involve HR/legal per policy.", rule=None),
        S(id="ins_dlp", title="Apply DLP rule on the destination", kind="network", effectiveness="High", disruption="Medium", time_to_apply="Hours", blocks_ip=True,
          description="Block bulk uploads to unsanctioned destinations.", rule="# DLP: deny bulk outbound to {src_ip}"),
        S(id="ins_audit", title="Review access logs and entitlements", kind="process", effectiveness="Medium", disruption="Low", time_to_apply="Hours", blocks_ip=False,
          description="Establish what was accessed and tighten least privilege.", rule=None)],
    "MITM": [
        S(id="mitm_hsts", title="Enforce HSTS + certificate validation", kind="application", effectiveness="High", disruption="Low", time_to_apply="Hours", blocks_ip=False,
          description="Browsers refuse downgraded or forged connections.", rule="Strict-Transport-Security: max-age=31536000; includeSubDomains"),
        S(id="mitm_dai", title="Dynamic ARP inspection on the switch", kind="network", effectiveness="High", disruption="Low", time_to_apply="Hours", blocks_ip=False,
          description="Stops ARP spoofing on the local segment.", rule=None),
        S(id="mitm_vpn", title="Force VPN for affected users", kind="network", effectiveness="Medium", disruption="Medium", time_to_apply="Hours", blocks_ip=False,
          description="Protects traffic on untrusted networks.", rule=None)],
    "Path Traversal": [
        S(id="trav_waf", title="Enable WAF path-traversal rule", kind="application", effectiveness="High", disruption="Low", time_to_apply="Minutes", blocks_ip=False,
          description="Block requests containing ../ sequences or system-file names before they reach the application.",
          rule='SecRule REQUEST_URI|ARGS "@rx (\\.\\./|%2e%2e|/etc/passwd)" "id:930100,phase:2,deny,status:403,log,msg:\'Path traversal blocked\'"'),
        S(id="trav_fix", title="Validate and canonicalise file paths in code", kind="application", effectiveness="Very High", disruption="Medium", time_to_apply="Days", blocks_ip=False,
          description="Root-cause fix: resolve the path, check it stays inside the allowed directory, or use an ID-to-file map instead of file names. Run the app with least privilege.", rule=None),
        S(id="trav_block", title="Block source IP", kind="network", effectiveness="Medium", disruption="Low", time_to_apply="Seconds", blocks_ip=True,
          description="Stop this attacker; does not fix the vulnerable endpoint.", rule="iptables -I INPUT -s {src_ip} -j DROP")],
    "Command Injection": [
        S(id="cmdi_waf", title="Enable WAF command-injection rule", kind="application", effectiveness="High", disruption="Low", time_to_apply="Minutes", blocks_ip=False,
          description="Virtual patch: block shell metacharacters followed by commands while the code is fixed.",
          rule='SecRule ARGS "@rx [;|`]\\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh)\\b" "id:932100,phase:2,deny,status:403,log,msg:\'Command injection blocked\'"'),
        S(id="cmdi_fix", title="Stop passing user input to a shell", kind="application", effectiveness="Very High", disruption="Medium", time_to_apply="Days", blocks_ip=False,
          description="Use library functions instead of shell commands; if unavoidable, pass arguments as a list with a strict allow-list. Treat the server as potentially compromised: check for new files, accounts and outbound connections.", rule=None),
        S(id="cmdi_block", title="Block source IP and review the host", kind="network", effectiveness="Medium", disruption="Low", time_to_apply="Seconds", blocks_ip=True,
          description="Contain the attacker immediately, then investigate the server for signs of execution.", rule="iptables -I INPUT -s {src_ip} -j DROP")],
    "Web Reconnaissance": [
        S(id="recon_block", title="Block the scanning source", kind="network", effectiveness="High", disruption="Low", time_to_apply="Seconds", blocks_ip=True,
          description="Automated scanners are cheap to stop at the edge.", rule="iptables -I INPUT -s {src_ip} -j DROP"),
        S(id="recon_hide", title="Remove or protect sensitive files and admin pages", kind="application", effectiveness="Very High", disruption="Low", time_to_apply="Hours", blocks_ip=False,
          description="Delete backups, .env and .git from the web root; restrict admin interfaces by IP or VPN.", rule=None),
        S(id="recon_ratelimit", title="Rate-limit repeated 404 / 403 responses", kind="network", effectiveness="High", disruption="Low", time_to_apply="Minutes", blocks_ip=False,
          description="Slow down directory enumeration with a per-client limit.", rule="limit_req_zone $binary_remote_addr zone=scan:10m rate=5r/s;")],
    "Zero-Day": [
        S(id="zd_isolate", title="Isolate target and capture traffic (PCAP)", kind="host", effectiveness="High", disruption="Medium", time_to_apply="Minutes", blocks_ip=False,
          description="Preserve evidence for analysis of the unknown behaviour.", rule="# capture: tcpdump -w zeroday.pcap host {src_ip}"),
        S(id="zd_virtual", title="Virtual patch via WAF/IPS", kind="application", effectiveness="Medium", disruption="Low", time_to_apply="Hours", blocks_ip=False,
          description="Block the observed pattern while a vendor patch is awaited.", rule=None),
        S(id="zd_block", title="Block source and escalate to threat hunting", kind="network", effectiveness="Medium", disruption="Low", time_to_apply="Seconds", blocks_ip=True,
          description="Contain, then hunt for related activity.", rule="iptables -I INPUT -s {src_ip} -j DROP")],
}

# trained-model key -> report entry; the signature engine and autoencoder are described separately
SIGNATURE_COVERED = {"SQL Injection", "XSS", "Phishing", "Brute Force", "Port Scanning", "DDoS", "Ransomware"}


def effectiveness_label(f1):
    if f1 is None:
        return "n/a"
    return "Very High" if f1 >= 0.97 else "High" if f1 >= 0.93 else "Moderate" if f1 >= 0.85 else "Low"


WEB_TEXT_CLASSES = ("SQL Injection", "XSS", "Path Traversal", "Command Injection")
WEB_BEHAVIOUR = {"Brute Force": "more than 8 login-like requests (or 5 rejected logins) from one client within 60 s",
                 "DDoS": "more than 120 page requests from one client within 10 s",
                 "Web Reconnaissance": "15+ not-found/forbidden answers on 10+ different paths within 60 s, sensitive-file probes, scanner User-Agents"}


class Recommender:
    def __init__(self, report_provider, web_report_provider=None):
        self._report = report_provider  # callable -> training report dict
        self._web_report = web_report_provider or (lambda: {})

    def detection_options(self, attack_type: str) -> list:
        rep = self._report() or {}
        info = rep.get("model_info", {})
        dataset = (rep.get("dataset") or {}).get("name", "n/a")
        out = self._web_options(attack_type)
        if attack_type == "Zero-Day":
            an = rep.get("anomaly") or {}
            if "autoencoder_auc_vs_benign" in an:
                out.append(dict(id="autoencoder", model="Autoencoder", approach=info.get("autoencoder", {}).get("approach", "Anomaly detection"),
                                complexity=info.get("autoencoder", {}).get("complexity", ""), dataset=dataset, measured=True,
                                roc_auc=an["autoencoder_auc_vs_benign"], recall=an.get("novel_flag_rate"),
                                false_positive_rate=an.get("benign_flag_rate"), effectiveness=effectiveness_label(an["autoencoder_auc_vs_benign"]),
                                note="Evaluated on a held-out novel attack family never seen in training."))
            if "isolation_forest_auc_vs_benign" in an:
                out.append(dict(id="isolation_forest", model="Isolation Forest (baseline)", approach="Anomaly detection (unsupervised)",
                                complexity="Train O(t·ψ·log ψ) · Infer O(t·log ψ)", dataset=dataset, measured=True,
                                roc_auc=an["isolation_forest_auc_vs_benign"], effectiveness=effectiveness_label(an["isolation_forest_auc_vs_benign"]),
                                note="Baseline for comparison with the autoencoder."))
            return out
        for key, m in (rep.get("models") or {}).items():
            if attack_type not in ((m.get("per_class") or {})):
                continue  # web-only attack types are not classes of the flow models
            pc = (m.get("per_class") or {}).get(attack_type, {})
            meta = info.get(key, {})
            out.append(dict(id=key, model=meta.get("display", key), approach=meta.get("approach", ""), complexity=meta.get("complexity", ""),
                            dataset=dataset, measured=True, accuracy=m.get("accuracy"), precision=m.get("precision"), recall=m.get("recall"),
                            f1=m.get("f1"), roc_auc=m.get("roc_auc"), false_positive_rate=m.get("false_positive_rate"),
                            infer_ms=m.get("infer_ms"), class_precision=pc.get("precision"), class_recall=pc.get("recall"),
                            class_f1=pc.get("f1"), effectiveness=effectiveness_label(pc.get("f1"))))
        if attack_type in SIGNATURE_COVERED:
            out.append(dict(id="signature", model="Signature rules", approach="Signature-based (regex / threshold rules)",
                            complexity="O(rules × payload length)", dataset="n/a (hand-written rules)", measured=False,
                            infer_ms=0.1, effectiveness="High (precise, but only known patterns)",
                            note="No trained metrics: rules fire only on known patterns. Used together with the ML ensemble."))
        out.sort(key=lambda o: (o.get("class_f1") or 0, o.get("f1") or 0), reverse=True)
        return out

    def _web_options(self, attack_type: str) -> list:
        """Detectors that work on web-server logs. Numbers come from the web model's held-out-family evaluation."""
        wr = self._web_report() or {}
        held = wr.get("held_out_families") or {}
        out = []
        ds = "generated web-request corpus; payload families held out of training"
        if attack_type in WEB_TEXT_CLASSES and held:
            for key, label, approach, cx in (
                    ("signatures_only", "Web signature rules", "Signature-based (regex on decoded path + query)", "O(rules x request length)"),
                    ("text_model_only", "Web text model", "Learned (character n-gram TF-IDF + logistic regression)", "Train O(n x features) / Infer O(features)"),
                    ("combined", "Web combined detector", "Hybrid (rules + text model, noisy-OR fusion)", "Sum of both")):
                m = held.get(key) or {}
                pc = (m.get("per_class") or {}).get(attack_type)
                if not pc:
                    continue
                out.append(dict(id=f"web_{key}", model=label, approach=approach, complexity=cx, dataset=ds, measured=True, accuracy=m.get("accuracy"),
                                false_positive_rate=m.get("false_positive_rate"), recall=m.get("detection_rate"),
                                class_precision=pc["precision"], class_recall=pc["recall"], class_f1=pc["f1"], effectiveness=effectiveness_label(pc["f1"]),
                                note="Evaluated on payload styles never seen in training. Generated data: indicative, not a real-world benchmark."))
        elif attack_type in WEB_TEXT_CLASSES:  # model present but no evaluation report: say so instead of showing nothing
            out.append(dict(id="web_combined", model="Web combined detector", approach="Hybrid (rules + text model)", complexity="Sum of both",
                            dataset="n/a", measured=False, effectiveness="n/a", note="No evaluation report is available for the web model."))
        elif attack_type in WEB_BEHAVIOUR:
            out.append(dict(id="web_behaviour", model="Behaviour rules (sliding window)", approach="Rule-based behaviour analysis", complexity="O(1) per request",
                            dataset="n/a (thresholds)", measured=False, effectiveness="High for obvious bursts",
                            note=f"Fires on: {WEB_BEHAVIOUR[attack_type]}. Thresholds are configurable; no trained metrics."))
        return out

    @staticmethod
    def mitigation_options(attack_type: str) -> list:
        opts = PLAYBOOKS.get(attack_type, PLAYBOOKS["Zero-Day"])
        return [{k: v for k, v in o.items() if k != "rule"} | {"has_rule": o["rule"] is not None} for o in opts]

    def for_attack(self, attack_type: str) -> dict:
        meta = ATTACKS.get(attack_type, ATTACKS["Zero-Day"])
        return dict(attack_type=attack_type, description=meta["description"], base_severity=meta["severity"], mitre=meta["mitre"],
                    indicators=meta["indicators"], detection_options=self.detection_options(attack_type),
                    mitigation_options=self.mitigation_options(attack_type))


def render_rule(template, src_ip, dst_ip, port) -> str | None:
    """Fill a rule template. Only validated IPs and a bounded integer port can enter the text."""
    if template is None:
        return None
    try:
        p = max(0, min(65535, int(port)))
    except (TypeError, ValueError):
        p = 0
    return template.format(src_ip=safe_ip(src_ip), dst_ip=safe_ip(dst_ip), port=p)


def apply_mitigation(repo, alert: dict, solution_id: str, username: str) -> dict:
    """Simulate applying a mitigation: record it, update blocklist/alert state, return the generated rule."""
    opt = next((o for o in PLAYBOOKS.get(alert["attack_type"], PLAYBOOKS["Zero-Day"]) if o["id"] == solution_id), None)
    if opt is None:
        raise KeyError(solution_id)
    port = (alert.get("event") or {}).get("dst_port") or 0
    rule = render_rule(opt["rule"], alert.get("src_ip"), alert.get("dst_ip"), port)
    mid = repo.add_mitigation(alert["id"], solution_id, opt["title"], rule, username, {"kind": opt["kind"]})
    if opt["blocks_ip"] and alert.get("src_ip"):
        repo.block_ip(safe_ip(alert["src_ip"]), f"{opt['title']} (alert #{alert['id']})", alert["id"], username)
    repo.update_alert_status(alert["id"], "mitigated", username)
    return dict(mitigation_id=mid, solution_id=solution_id, title=opt["title"], rule_text=rule, simulated=True,
                blocked_ip=safe_ip(alert["src_ip"]) if opt["blocks_ip"] else None,
                message="Simulation only: the rule was generated and recorded; nothing was executed on any system.")
