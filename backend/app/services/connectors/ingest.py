"""IngestService: validates a batch from a connector, detects, stores, publishes and updates source health."""
from __future__ import annotations

import logging

from app.services.connectors.webevent import normalize_policy, normalize_web_event, to_record
from app.services.detection.processor import EventProcessor

log = logging.getLogger(__name__)
LIVE_FEED_BENIGN_PER_BATCH = 3  # keep the dashboard feed lively without flooding sockets with every normal request


class IngestService:
    def __init__(self, repo, web_pipeline, settings, hub=None, notifier=None):
        self.repo, self.pipeline, self.settings, self.hub, self.notifier = repo, web_pipeline, settings, hub, notifier

    def ingest_web(self, source: dict, raw_events: list) -> dict:
        policy = normalize_policy(source.get("policy"))
        events, invalid, excluded, dups = [], 0, 0, 0
        seen = set()
        for raw in raw_events:
            ev, why = normalize_web_event(raw, policy)
            if ev is None:
                invalid += why == "invalid"
                excluded += why == "excluded"
                continue
            if ev["eid"]:
                if ev["eid"] in seen:
                    dups += 1
                    continue
                seen.add(ev["eid"])
            events.append(ev)
        if events:
            known = self.repo.known_eids(source["id"], [e["eid"] for e in events])
            if known:
                dups += sum(1 for e in events if e["eid"] in known)
                events = [e for e in events if e["eid"] not in known]
        threats = 0
        if events:
            repeat = {ip: self.repo.recent_alert_count(ip, max(e["ts"] for e in events) - 3600) for ip in {e["src_ip"] for e in events}}
            dets = self.pipeline.analyze_batch(events, source["id"], policy["protected_ip"], repeat)
            items = [(to_record(e, source["id"], policy["protected_ip"]), d) for e, d in zip(events, dets)]
            results = self.repo.record_many(items, origin="connector", dedupe_window=self.settings.dedupe_window_seconds)
            threats = sum(1 for _, d in items if d["verdict"] == "threat")
            self._publish(source, items, results)
        self.repo.touch_source(source["id"], events=len(events), threats=threats, rejected=invalid)
        return dict(accepted=len(events), duplicates=dups, excluded=excluded, rejected=invalid, threats=threats)

    def _publish(self, source, items, results):
        benign_sent = 0
        for (rec, det), ids in zip(items, results):
            if det["verdict"] != "threat":
                if benign_sent >= LIVE_FEED_BENIGN_PER_BATCH:
                    continue
                benign_sent += 1
            if self.hub is not None:
                out = EventProcessor.public_event(rec, det, ids, "connector")
                out["source"] = source["name"]
                self.hub.publish(dict(type="event", **out))
            if ids["alert_is_new"] and self.notifier:
                self.notifier.notify(dict(det, src_ip=rec["src_ip"], dst_ip=rec["dst_ip"]))
