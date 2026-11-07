"""Security assistant. Deterministic and grounded: every figure in a reply is read from the database or
the active model report -- it never invents numbers. (No external LLM calls; swap one in behind `reply`
if desired.)"""
from __future__ import annotations

import re
import time

from app.branding import APP_NAME
from app.models.attacks import ATTACKS, resolve_attack
from app.models.coverage import compute_coverage
from app.services.analytics import holt_forecast
from app.services.connectors.sources import list_described

HELP = ("I can help with: **status** (how are we doing?), **latest/critical alerts**, **top attackers**, "
        "**explain <attack>** (e.g. 'what is SQL injection?'), **mitigation for <attack>**, **model accuracy / best model**, "
        "and **forecast**.")


class ChatEngine:
    def __init__(self, repo, recommender, report_provider, silent_after=150):
        self.repo, self.rec, self.report, self.silent_after = repo, recommender, report_provider, silent_after

    def reply(self, message: str) -> dict:
        msg = (message or "").strip()[:500]
        low = msg.lower()
        attack = resolve_attack(low)
        if not msg or re.fullmatch(r"(hi|hello|hey|help|\?)\W*", low):
            return self._r("help", "Hi, I'm the Argus assistant. " + HELP)
        if attack and re.search(r"mitigat|fix|stop|prevent|respond|solution|remediat|defen|how (do|to|can)", low):
            return self._mitigation(attack)
        if attack and re.search(r"what|explain|about|describe|define|mean|tell", low):
            return self._explain(attack)
        if re.search(r"cover|what can you (see|detect)|blind spot|connected source|which attacks", low):
            return self._coverage()
        if re.search(r"accura|model|f1|precision|recall|roc|best detector|performance", low):
            return self._models()
        if re.search(r"forecast|predict|trend|next hour|expect", low):
            return self._forecast()
        if re.search(r"attacker|top source|top ip|offender|who is attacking|source ip", low):
            return self._attackers()
        if re.search(r"critical|latest|recent|newest|last alert|open alert", low):
            return self._latest("critical" in low)
        if re.search(r"status|summary|overview|how (are|is)|report|incident|today|situation", low):
            return self._status()
        if attack:
            return self._explain(attack)
        return self._r("unknown", "I didn't catch that. " + HELP)

    @staticmethod
    def _r(intent, text, data=None):
        return dict(reply=text, intent=intent, data=data)

    def _status(self):
        o = self.repo.overview(24)
        if not o["total_events"]:
            return self._r("status", "No traffic has been analysed in the last 24 hours yet.")
        top = ", ".join(f"{a['name']} ({a['value']})" for a in o["by_attack"][:3]) or "none"
        rate = 100 * o["threats"] / max(o["total_events"], 1)
        return self._r("status", f"Last 24h: {o['total_events']} events analysed, {o['threats']} flagged as threats ({rate:.1f}%) "
                       f"from {o['unique_attackers']} distinct sources. {o['open_alerts']} alerts are open, "
                       f"{o['critical_open']} of them Critical. Most frequent: {top}. Average risk score {o['avg_risk']}/100.", o)

    def _latest(self, critical_only):
        rows, _ = self.repo.list_alerts(status="open", severity="Critical" if critical_only else None, limit=5)
        if not rows:
            return self._r("alerts", "There are no matching open alerts." if critical_only else "There are no open alerts.")
        lines = [f"#{r['id']} {r['severity']} {r['attack_type']} from {r['src_ip']} (risk {r['risk_score']}, x{r['count']})" for r in rows]
        return self._r("alerts", "Open alerts, newest first: " + "; ".join(lines) + ".", rows)

    def _attackers(self):
        rows = self.repo.top_sources(24, 5)
        if not rows:
            return self._r("attackers", "No attacking sources recorded in the last 24 hours.")
        txt = "; ".join(f"{r['src_ip']} - {r['events']} events, mostly {r['top_attack']}{' (blocked)' if r['blocked'] else ''}" for r in rows)
        return self._r("attackers", "Top sources in the last 24h: " + txt + ".", rows)

    def _explain(self, a):
        m = ATTACKS[a]
        return self._r("explain", f"**{a}** (MITRE {m['mitre']}, base severity {m['severity']}): {m['description']} "
                       f"Typical indicators: {', '.join(m['indicators'])}.")

    def _mitigation(self, a):
        opts = self.rec.mitigation_options(a)
        txt = "; ".join(f"{o['title']} ({o['effectiveness']} effectiveness, {o['disruption'].lower()} disruption, ~{o['time_to_apply'].lower()})" for o in opts)
        return self._r("mitigation", f"Recommended responses for {a}: {txt}. Open an alert of this type to simulate applying one.", opts)

    def _coverage(self):
        srcs = list_described(self.repo, self.silent_after)
        live = [s for s in srcs if s["live"] and s["status"] != "revoked"]
        if not live:
            return self._r("coverage", "No live source is connected, so the dashboard is in Demo mode (simulated traffic). Connect a web-server log under Sources to monitor a real system.")
        cov = compute_coverage([dict(kind=s["kind"], name=s["name"], status=s["status"]) for s in live], False)
        ok = [i["attack_type"] for i in cov["items"] if i["status"] == "covered"]
        blind = [i["attack_type"] for i in cov["items"] if i["status"] == "uncovered"]
        silent = [s["name"] for s in live if s["status"] == "silent"]
        names = lambda st: [x["name"] for x in live if x["status"] == st]  # noqa: E731
        ok_src = names("connected")
        txt = (f"{', '.join(ok_src)} {'is' if len(ok_src) == 1 else 'are'} connected and cover{'s' if len(ok_src) == 1 else ''} {len(ok) } of {len(cov['items'])} attack types: {', '.join(ok)}. " if ok_src
               else "No live source is currently delivering data. ")
        txt += f"Not covered: {', '.join(blind)} (these need other kinds of logs)." if blind else "All attack types are covered."
        if names("silent"):
            txt += f" Warning: {', '.join(names('silent'))} has gone silent."
        if names("waiting"):
            txt += f" Waiting for the first event from: {', '.join(names('waiting'))}."
        return self._r("coverage", txt, cov["summary"])

    def _models(self):
        rep = self.report() or {}
        ms = rep.get("models") or {}
        if not ms:
            return self._r("models", "No trained model report is available yet.")
        best = max(ms.items(), key=lambda kv: kv[1].get("f1", 0))
        e = ms.get("ensemble", best[1])
        syn = " Note: these figures come from simulated data, not a real-world benchmark." if (rep.get("dataset") or {}).get("synthetic") else ""
        return self._r("models", f"Best model by macro-F1: {best[0]} ({best[1]['f1']:.3f}). The ensemble reaches accuracy {e['accuracy']:.3f}, "
                       f"macro-F1 {e['f1']:.3f}, detection rate {e['detection_rate']:.3f} at a false-positive rate of {e['false_positive_rate']:.3f}, "
                       f"measured on a hold-out set.{syn}", {k: v.get("f1") for k, v in ms.items()})

    def _forecast(self):
        series = [t["threats"] for t in self.repo.timeline(48)]
        f = holt_forecast(series, 6)
        if f["method"] == "insufficient-data" or sum(series) == 0:
            return self._r("forecast", "Not enough history yet to forecast.")
        return self._r("forecast", f"Expected threats per hour over the next 6 hours: {', '.join(str(round(v)) for v in f['forecast'])} "
                       f"(recent hourly average {sum(series[-12:]) / max(len(series[-12:]), 1):.1f}).", f)
