"""Repository: every SQL statement in the application lives here (parameterised, never string-built
from user input except for fixed, whitelisted column names)."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from app.db.database import Database
from app.models.attacks import SEVERITY_ORDER

_SEV_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}
ALERT_STATUSES = ("open", "acknowledged", "mitigated", "resolved", "false_positive")
_ALERT_SORT = {"time": "last_seen", "risk": "risk_score", "count": "count"}

# Which events/alerts count as "live" (real data from a connected source) versus "demo" (simulated).
SCOPES = {"live": "origin = 'connector'", "demo": "origin IN ('stream','seed','lab')", "upload": "origin = 'upload'"}


def scope_sql(scope, prefix="origin"):
    """SQL fragment (starting with ' AND ') for a scope name; '' for 'all'/unknown. Fixed whitelist, never user text."""
    frag = SCOPES.get(scope)
    return f" AND {frag.replace('origin', prefix)}" if frag else ""


def _row(r):
    return dict(r) if r is not None else None


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _loads(s, default=None):
    if not s:
        return default
    try:
        return json.loads(s)
    except (TypeError, ValueError):
        return default


class Repository:
    def __init__(self, db: Database):
        self.db = db

    # ------------------------------------------------------------------ users
    def create_user(self, username, password_hash, role, full_name=None):
        with self.db.connect() as c:
            cur = c.execute("INSERT INTO users(username,password_hash,role,created_at,full_name) VALUES(?,?,?,?,?)",
                            (username, password_hash, role, time.time(), (full_name or None)))
            return cur.lastrowid

    def get_user_by_name(self, username):
        with self.db.connect() as c:
            return _row(c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone())

    def get_user(self, user_id):
        with self.db.connect() as c:
            return _row(c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone())

    def list_users(self):
        with self.db.connect() as c:
            return [dict(r) for r in c.execute(
                "SELECT id,username,full_name,role,is_active,created_at,last_login FROM users ORDER BY id")]

    def update_user(self, user_id, role=None, is_active=None, password_hash=None, full_name=None):
        sets, vals = [], []
        if full_name is not None:
            sets.append("full_name=?"); vals.append(full_name.strip() or None)
        if role is not None:
            sets.append("role=?"); vals.append(role)
        if is_active is not None:
            sets.append("is_active=?"); vals.append(1 if is_active else 0)
        if password_hash is not None:
            sets.append("password_hash=?"); vals.append(password_hash)
        if not sets:
            return
        with self.db.connect() as c:
            c.execute(f"UPDATE users SET {', '.join(sets)} WHERE id=?", (*vals, user_id))  # fixed column names

    def delete_user(self, user_id) -> bool:
        with self.db.connect() as c:
            return c.execute("DELETE FROM users WHERE id=?", (user_id,)).rowcount > 0

    def touch_login(self, user_id):
        with self.db.connect() as c:
            c.execute("UPDATE users SET last_login=? WHERE id=?", (time.time(), user_id))

    def count_admins(self):
        with self.db.connect() as c:
            return c.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND is_active=1").fetchone()[0]

    def count_users(self):
        with self.db.connect() as c:
            return c.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    # ------------------------------------------------------------------ audit
    def audit(self, username, action, target=None, detail=None, ip=None):
        with self.db.connect() as c:
            c.execute("INSERT INTO audit_log(ts,username,action,target,detail,ip) VALUES(?,?,?,?,?,?)",
                      (time.time(), username, action, target, (detail or "")[:500], ip))

    def list_audit(self, limit=100, offset=0):
        with self.db.connect() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset))]

    # ------------------------------------------------------------------ events & alerts
    def record_detection(self, ev: dict, det: dict, origin="stream", job_id=None, dedupe_window=300,
                         include_explanation=True):
        """Persist one analysed event; for threats also create or bump an alert.

        Returns dict(event_id, alert_id, alert_is_new, blocked)."""
        with self.db.connect() as c:
            return self._record(c, ev, det, origin, job_id, dedupe_window, include_explanation)

    def record_bulk(self, items, origin="upload", job_id=None, dedupe_window=300, store_benign=False):
        """Persist many (event, detection) pairs in ONE transaction. Benign rows are skipped unless asked."""
        n_alerts = n_new = 0
        with self.db.connect() as c:
            for ev, det in items:
                if det["verdict"] != "threat" and not store_benign:
                    continue
                r = self._record(c, ev, det, origin, job_id, dedupe_window, True)
                if r["alert_id"]:
                    n_alerts += 1
                    n_new += 1 if r["alert_is_new"] else 0
        return n_alerts, n_new

    def record_many(self, items, origin="connector", dedupe_window=300):
        """Persist (event, detection) pairs in one transaction; returns one result dict per pair (input order)."""
        with self.db.connect() as c:
            return [self._record(c, ev, det, origin, None, dedupe_window, True) for ev, det in items]

    def _record(self, c, ev, det, origin, job_id, dedupe_window, include_explanation):
        is_threat = det["verdict"] == "threat"
        blocked = 0
        if is_threat and ev.get("src_ip"):
            blocked = 1 if c.execute("SELECT 1 FROM blocklist WHERE ip=?", (ev["src_ip"],)).fetchone() else 0
        feats = ev.get("features", {})
        cur = c.execute(
            "INSERT INTO events(ts,src_ip,dst_ip,dst_port,protocol,bytes_total,features_json,payload_sample,verdict,"
            "attack_type,confidence,risk_score,severity,sources_json,origin,job_id,blocked,source_id,eid) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (ev["ts"], ev.get("src_ip"), ev.get("dst_ip"), int(feats.get("dst_port", 0)), ev.get("protocol"),
             float(feats.get("src_bytes", 0)) + float(feats.get("dst_bytes", 0)), json.dumps(feats),
             (ev.get("payload_sample") or "")[:500], det["verdict"], det.get("attack_type"), det.get("confidence"),
             det.get("risk_score"), det.get("severity"), json.dumps(det.get("sources", [])), origin, job_id, blocked,
             ev.get("source_id"), ev.get("eid")))
        event_id = cur.lastrowid
        alert_id, is_new = None, False
        if is_threat:
            alert_id, is_new = self._upsert_alert(c, event_id, ev, det, origin, job_id, dedupe_window, include_explanation)
            c.execute("UPDATE events SET alert_id=? WHERE id=?", (alert_id, event_id))
        return dict(event_id=event_id, alert_id=alert_id, alert_is_new=is_new, blocked=bool(blocked))

    def _upsert_alert(self, c, event_id, ev, det, origin, job_id, window, include_explanation):
        ts = ev["ts"]
        row = c.execute(
            "SELECT id,count,risk_score,severity FROM alerts WHERE src_ip IS ? AND attack_type=? "
            "AND status IN ('open','acknowledged') AND last_seen>=? AND last_seen<=? ORDER BY last_seen DESC LIMIT 1",
            (ev.get("src_ip"), det["attack_type"], ts - window, ts + window)).fetchone()
        if row:
            sev = det["severity"] if _SEV_RANK.get(det["severity"], 0) > _SEV_RANK.get(row["severity"], 0) else row["severity"]
            c.execute("UPDATE alerts SET count=count+1,last_seen=MAX(last_seen,?),risk_score=MAX(risk_score,?),severity=?,updated_at=? WHERE id=?",
                      (ts, det["risk_score"], sev, time.time(), row["id"]))
            return row["id"], False
        expl = json.dumps(det.get("explanation")) if include_explanation and det.get("explanation") else None
        cur = c.execute(
            "INSERT INTO alerts(event_id,first_seen,last_seen,count,attack_type,severity,risk_score,confidence,src_ip,dst_ip,"
            "explanation_json,sources_json,origin,job_id,updated_at,source_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (event_id, ts, ts, 1, det["attack_type"], det["severity"], det["risk_score"], det["confidence"],
             ev.get("src_ip"), ev.get("dst_ip"), expl, json.dumps(det.get("sources", [])), origin, job_id, time.time(),
             ev.get("source_id")))
        return cur.lastrowid, True

    def get_alert(self, alert_id):
        with self.db.connect() as c:
            a = _row(c.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone())
            if not a:
                return None
            a["explanation"] = _loads(a.pop("explanation_json"), None)
            a["sources"] = _loads(a.pop("sources_json"), [])
            ev = _row(c.execute("SELECT * FROM events WHERE id=?", (a["event_id"],)).fetchone()) if a["event_id"] else None
            if ev:
                ev["features"] = _loads(ev.pop("features_json"), {})
                ev["sources"] = _loads(ev.pop("sources_json"), [])
            a["event"] = ev
            src = c.execute("SELECT name,kind FROM sources WHERE id=?", (a.get("source_id"),)).fetchone() if a.get("source_id") else None
            a["source_name"], a["source_kind"] = (src["name"], src["kind"]) if src else (None, None)
            a["mitigations"] = [dict(r) for r in c.execute(
                "SELECT id,solution_id,title,rule_text,status,applied_by,applied_at FROM mitigations WHERE alert_id=? ORDER BY id DESC",
                (alert_id,))]
            return a

    def set_alert_explanation(self, alert_id, explanation):
        with self.db.connect() as c:
            c.execute("UPDATE alerts SET explanation_json=? WHERE id=?", (json.dumps(explanation), alert_id))

    def list_alerts(self, status=None, severity=None, attack_type=None, q=None, since=None, sort="time",
                    limit=50, offset=0, scope="all"):
        where, vals = [], []
        if scope in SCOPES:
            where.append(SCOPES[scope])
        if status:
            where.append("status=?"); vals.append(status)
        if severity:
            where.append("severity=?"); vals.append(severity)
        if attack_type:
            where.append("attack_type=?"); vals.append(attack_type)
        if since:
            where.append("last_seen>=?"); vals.append(since)
        if q:
            where.append("(src_ip LIKE ? ESCAPE '\\' OR dst_ip LIKE ? ESCAPE '\\' OR attack_type LIKE ? ESCAPE '\\')")
            vals += [_like(q)] * 3
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        order = _ALERT_SORT.get(sort, "last_seen")  # whitelist -> safe to interpolate
        with self.db.connect() as c:
            total = c.execute(f"SELECT COUNT(*) FROM alerts {clause}", vals).fetchone()[0]
            rows = [dict(r) for r in c.execute(
                f"SELECT id,first_seen,last_seen,count,attack_type,severity,risk_score,confidence,src_ip,dst_ip,status,origin,handled_by,source_id,"
                f"(SELECT name FROM sources WHERE sources.id=alerts.source_id) AS source_name "
                f"FROM alerts {clause} ORDER BY {order} DESC, id DESC LIMIT ? OFFSET ?", (*vals, limit, offset))]
        return rows, total

    def update_alert_status(self, alert_id, status, username):
        if status not in ALERT_STATUSES:
            raise ValueError("invalid status")
        with self.db.connect() as c:
            cur = c.execute("UPDATE alerts SET status=?,handled_by=?,updated_at=? WHERE id=?",
                            (status, username, time.time(), alert_id))
            return cur.rowcount > 0

    def recent_alert_count(self, src_ip, since):
        with self.db.connect() as c:
            return c.execute("SELECT COALESCE(SUM(count),0) FROM alerts WHERE src_ip=? AND last_seen>=?",
                             (src_ip, since)).fetchone()[0]

    def recent_events(self, limit=50, threats_only=False, scope="all"):
        sql = ("SELECT id,ts,src_ip,dst_ip,protocol,bytes_total,verdict,attack_type,severity,risk_score,confidence,blocked,alert_id,origin,"
               "(SELECT name FROM sources WHERE sources.id=events.source_id) AS source_name FROM events WHERE 1=1")
        if threats_only:
            sql += " AND verdict='threat'"
        sql += scope_sql(scope)
        with self.db.connect() as c:
            return [dict(r) for r in c.execute(sql + " ORDER BY id DESC LIMIT ?", (limit,))]

    def iter_alerts_for_export(self, since=None, limit=50000, scope="all"):
        with self.db.connect() as c:
            sql = ("SELECT id,first_seen,last_seen,count,attack_type,severity,risk_score,confidence,src_ip,dst_ip,status,origin,handled_by "
                   "FROM alerts WHERE 1=1")
            vals = []
            if since:
                sql += " AND last_seen>=?"; vals.append(since)
            sql += scope_sql(scope)
            return [dict(r) for r in c.execute(sql + " ORDER BY last_seen DESC LIMIT ?", (*vals, limit))]

    # ------------------------------------------------------------------ analytics
    def overview(self, hours=24, scope="all"):
        since = time.time() - hours * 3600
        sc, sa = scope_sql(scope), scope_sql(scope, "a.origin")
        with self.db.connect() as c:
            tot = c.execute("SELECT COUNT(*), COALESCE(SUM(verdict='threat'),0), COALESCE(SUM(bytes_total),0), "
                            "COUNT(DISTINCT CASE WHEN verdict='threat' THEN src_ip END), COALESCE(SUM(blocked),0) "
                            f"FROM events WHERE ts>=?{sc}", (since,)).fetchone()
            by_sev = {r[0]: r[1] for r in c.execute(
                f"SELECT severity,COUNT(*) FROM events WHERE verdict='threat' AND ts>=?{sc} GROUP BY severity", (since,))}
            by_type = [dict(name=r[0], value=r[1]) for r in c.execute(
                f"SELECT attack_type,COUNT(*) FROM events WHERE verdict='threat' AND ts>=?{sc} GROUP BY attack_type ORDER BY 2 DESC", (since,))]
            by_proto = [dict(name=r[0] or "OTHER", value=r[1]) for r in c.execute(
                f"SELECT protocol,COUNT(*) FROM events WHERE ts>=?{sc} GROUP BY protocol ORDER BY 2 DESC", (since,))]
            open_alerts = c.execute(f"SELECT COUNT(*) FROM alerts WHERE status IN ('open','acknowledged'){sc}").fetchone()[0]
            crit_open = c.execute(f"SELECT COUNT(*) FROM alerts WHERE status='open' AND severity='Critical'{sc}").fetchone()[0]
            mitig = c.execute(f"SELECT COUNT(*) FROM mitigations m JOIN alerts a ON a.id=m.alert_id WHERE m.applied_at>=?{sa}", (since,)).fetchone()[0]
            avg_risk = c.execute(f"SELECT AVG(risk_score) FROM events WHERE verdict='threat' AND ts>=?{sc}", (since,)).fetchone()[0]
        return dict(window_hours=hours, scope=scope, total_events=tot[0], threats=int(tot[1]), bytes_total=float(tot[2]),
                    unique_attackers=tot[3], blocked_events=int(tot[4]), open_alerts=open_alerts,
                    critical_open=crit_open, mitigations_applied=mitig, avg_risk=round(avg_risk or 0, 1),
                    by_severity={s: by_sev.get(s, 0) for s in reversed(SEVERITY_ORDER)}, by_attack=by_type,
                    by_protocol=by_proto)

    def timeline(self, hours=24, scope="all"):
        now = time.time()
        end = int(now // 3600)
        start = end - hours + 1
        with self.db.connect() as c:
            rows = {r[0]: (r[1], r[2]) for r in c.execute(
                f"SELECT CAST(ts/3600 AS INTEGER) b, COUNT(*), COALESCE(SUM(verdict='threat'),0) FROM events "
                f"WHERE ts>=?{scope_sql(scope)} GROUP BY b", (start * 3600,))}
        out = []
        for b in range(start, end + 1):
            t, th = rows.get(b, (0, 0))
            out.append(dict(ts=b * 3600, hour=datetime.fromtimestamp(b * 3600, tz=timezone.utc).strftime("%H:00"),
                            total=t, threats=int(th)))
        return out

    def heatmap(self, hours=24 * 7, scope="all"):
        since = time.time() - hours * 3600
        with self.db.connect() as c:
            return [dict(attack_type=r[0], hour=r[1], count=r[2]) for r in c.execute(
                f"SELECT attack_type, CAST(strftime('%H', ts, 'unixepoch') AS INTEGER) h, COUNT(*) FROM events "
                f"WHERE verdict='threat' AND ts>=?{scope_sql(scope)} GROUP BY attack_type, h", (since,))]

    def top_sources(self, hours=24, limit=10, scope="all"):
        since = time.time() - hours * 3600
        sc = scope_sql(scope)
        with self.db.connect() as c:
            rows = [dict(r) for r in c.execute(
                f"SELECT src_ip, COUNT(*) AS events, ROUND(MAX(risk_score),1) AS max_risk FROM events "
                f"WHERE verdict='threat' AND ts>=?{sc} GROUP BY src_ip ORDER BY events DESC LIMIT ?", (since, limit))]
            for r in rows:
                t = c.execute(f"SELECT attack_type FROM events WHERE src_ip=? AND verdict='threat' AND ts>=?{sc} "
                              "GROUP BY attack_type ORDER BY COUNT(*) DESC LIMIT 1", (r["src_ip"], since)).fetchone()
                r["top_attack"] = t[0] if t else None
                r["blocked"] = bool(c.execute("SELECT 1 FROM blocklist WHERE ip=?", (r["src_ip"],)).fetchone())
            return rows

    # ------------------------------------------------------------------ mitigations & blocklist
    def add_mitigation(self, alert_id, solution_id, title, rule_text, username, details=None):
        with self.db.connect() as c:
            cur = c.execute("INSERT INTO mitigations(alert_id,solution_id,title,rule_text,applied_by,applied_at,details_json) "
                            "VALUES(?,?,?,?,?,?,?)",
                            (alert_id, solution_id, title, rule_text, username, time.time(), json.dumps(details or {})))
            return cur.lastrowid

    def list_mitigations(self, limit=100):
        with self.db.connect() as c:
            return [dict(r) for r in c.execute(
                "SELECT m.id,m.alert_id,m.solution_id,m.title,m.status,m.applied_by,m.applied_at,a.attack_type,a.src_ip "
                "FROM mitigations m JOIN alerts a ON a.id=m.alert_id ORDER BY m.id DESC LIMIT ?", (limit,))]

    def block_ip(self, ip, reason, alert_id, username):
        with self.db.connect() as c:
            c.execute("INSERT OR REPLACE INTO blocklist(ip,reason,alert_id,created_by,created_at) VALUES(?,?,?,?,?)",
                      (ip, reason[:200], alert_id, username, time.time()))

    def unblock_ip(self, ip):
        with self.db.connect() as c:
            return c.execute("DELETE FROM blocklist WHERE ip=?", (ip,)).rowcount > 0

    def list_blocklist(self):
        with self.db.connect() as c:
            return [dict(r) for r in c.execute("SELECT * FROM blocklist ORDER BY created_at DESC")]

    # ------------------------------------------------------------------ upload jobs
    def create_job(self, filename, username):
        with self.db.connect() as c:
            return c.execute("INSERT INTO upload_jobs(filename,created_by,created_at,status) VALUES(?,?,?,'running')",
                             (filename[:200], username, time.time())).lastrowid

    def finish_job(self, job_id, status, rows_total=0, rows_flagged=0, summary=None, error=None):
        with self.db.connect() as c:
            c.execute("UPDATE upload_jobs SET status=?,rows_total=?,rows_flagged=?,summary_json=?,error=? WHERE id=?",
                      (status, rows_total, rows_flagged, json.dumps(summary) if summary is not None else None, error, job_id))

    def get_job(self, job_id):
        with self.db.connect() as c:
            j = _row(c.execute("SELECT * FROM upload_jobs WHERE id=?", (job_id,)).fetchone())
        if j:
            j["summary"] = _loads(j.pop("summary_json"), None)
        return j

    def list_jobs(self, limit=20, created_by=None):
        """Upload history. `created_by=None` returns everyone's (Admin view); otherwise only that user's."""
        sql = "SELECT id,filename,created_by,created_at,status,rows_total,rows_flagged FROM upload_jobs"
        vals = []
        if created_by is not None:
            sql += " WHERE created_by=?"; vals.append(created_by)
        with self.db.connect() as c:
            return [dict(r) for r in c.execute(sql + " ORDER BY id DESC LIMIT ?", (*vals, limit))]

    def delete_job(self, job_id, delete_findings=False):
        """Remove an upload log. With delete_findings, also remove the events/alerts that upload produced."""
        with self.db.connect() as c:
            if not c.execute("SELECT 1 FROM upload_jobs WHERE id=?", (job_id,)).fetchone():
                return None
            n_alerts = n_events = 0
            if delete_findings:
                n_events = c.execute("DELETE FROM events WHERE job_id=?", (job_id,)).rowcount
                n_alerts = c.execute("DELETE FROM alerts WHERE job_id=?", (job_id,)).rowcount  # mitigations cascade
            else:
                c.execute("UPDATE events SET job_id=NULL WHERE job_id=?", (job_id,))
                c.execute("UPDATE alerts SET job_id=NULL WHERE job_id=?", (job_id,))
            c.execute("DELETE FROM upload_jobs WHERE id=?", (job_id,))
            return dict(alerts_deleted=n_alerts, events_deleted=n_events)

    # ------------------------------------------------------------------ model runs
    def add_model_run(self, report: dict, artifact_path: str, activate=True):
        with self.db.connect() as c:
            if activate:
                c.execute("UPDATE model_runs SET is_active=0")
            return c.execute("INSERT INTO model_runs(created_at,dataset,is_active,artifact_path,report_json) VALUES(?,?,?,?,?)",
                             (time.time(), (report.get("dataset") or {}).get("name"), 1 if activate else 0, artifact_path,
                              json.dumps(report))).lastrowid

    def get_active_run(self):
        with self.db.connect() as c:
            r = _row(c.execute("SELECT * FROM model_runs WHERE is_active=1 ORDER BY id DESC LIMIT 1").fetchone())
        if r:
            r["report"] = _loads(r.pop("report_json"), {})
        return r

    def list_runs(self, limit=20):
        with self.db.connect() as c:
            rows = [dict(r) for r in c.execute("SELECT id,created_at,dataset,is_active,report_json FROM model_runs ORDER BY id DESC LIMIT ?", (limit,))]
        out = []
        for r in rows:
            rep = _loads(r.pop("report_json"), {})
            ens = (rep.get("models") or {}).get("ensemble", {})
            r.update(accuracy=ens.get("accuracy"), f1=ens.get("f1"), false_positive_rate=ens.get("false_positive_rate"))
            out.append(r)
        return out

    # ------------------------------------------------------------------ connectors (sources)
    @staticmethod
    def _src(r):
        d = dict(r)
        d["policy"] = _loads(d.pop("policy_json"), {})
        d["info"] = _loads(d.pop("info_json", None), {})
        d.pop("key_hash", None)  # never leaves the repository
        return d

    def create_source(self, name, kind, key_prefix, key_hash, policy, created_by):
        with self.db.connect() as c:
            return c.execute("INSERT INTO sources(name,kind,key_prefix,key_hash,policy_json,created_by,created_at) VALUES(?,?,?,?,?,?,?)",
                             (name, kind, key_prefix, key_hash, json.dumps(policy), created_by, time.time())).lastrowid

    def get_source(self, source_id):
        with self.db.connect() as c:
            r = c.execute("SELECT * FROM sources WHERE id=?", (source_id,)).fetchone()
        return self._src(r) if r else None

    def get_source_by_key_hash(self, key_hash):
        with self.db.connect() as c:
            r = c.execute("SELECT * FROM sources WHERE key_hash=?", (key_hash,)).fetchone()
        return self._src(r) if r else None

    def list_sources(self):
        with self.db.connect() as c:
            return [self._src(r) for r in c.execute("SELECT * FROM sources ORDER BY id")]

    def update_source(self, source_id, name=None, policy=None):
        sets, vals = [], []
        if name is not None:
            sets.append("name=?"); vals.append(name)
        if policy is not None:
            sets.append("policy_json=?"); vals.append(json.dumps(policy))
        if sets:
            with self.db.connect() as c:
                c.execute(f"UPDATE sources SET {', '.join(sets)} WHERE id=?", (*vals, source_id))  # fixed column names

    def set_source_key(self, source_id, key_prefix, key_hash):
        """Rotate: the old key stops working immediately; also re-activates a revoked source."""
        with self.db.connect() as c:
            c.execute("UPDATE sources SET key_prefix=?,key_hash=?,revoked_at=NULL WHERE id=?", (key_prefix, key_hash, source_id))

    def revoke_source(self, source_id):
        with self.db.connect() as c:
            return c.execute("UPDATE sources SET revoked_at=? WHERE id=? AND revoked_at IS NULL", (time.time(), source_id)).rowcount > 0

    def delete_source(self, source_id):
        """Remove the source and its key. Already-recorded events/alerts are kept (shown as a deleted source)."""
        with self.db.connect() as c:
            c.execute("UPDATE events SET source_id=NULL WHERE source_id=?", (source_id,))
            c.execute("UPDATE alerts SET source_id=NULL WHERE source_id=?", (source_id,))
            return c.execute("DELETE FROM sources WHERE id=?", (source_id,)).rowcount > 0

    def touch_source(self, source_id, events=0, threats=0, rejected=0, info=None, heartbeat=False):
        with self.db.connect() as c:
            now = time.time()
            c.execute("UPDATE sources SET events_total=events_total+?, threats_total=threats_total+?, rejected_total=rejected_total+?, "
                      "last_seen=CASE WHEN ?>0 THEN ? ELSE last_seen END, last_heartbeat=CASE WHEN ? THEN ? ELSE last_heartbeat END, "
                      "info_json=COALESCE(?,info_json) WHERE id=?",
                      (events, threats, rejected, events, now, 1 if heartbeat else 0, now, json.dumps(info) if info is not None else None, source_id))

    def known_eids(self, source_id, eids):
        """Which of these event ids were already stored for this source (idempotent ingestion)."""
        eids = [e for e in eids if e]
        found = set()
        with self.db.connect() as c:
            for i in range(0, len(eids), 500):
                chunk = eids[i:i + 500]
                q = ",".join("?" * len(chunk))
                found |= {r[0] for r in c.execute(f"SELECT eid FROM events WHERE source_id=? AND eid IN ({q})", (source_id, *chunk))}
        return found

    # ------------------------------------------------------------------ settings & retention
    def get_setting(self, key, default=None):
        with self.db.connect() as c:
            r = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
            return r[0] if r else default

    def set_setting(self, key, value):
        with self.db.connect() as c:
            c.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))

    def purge_older_than(self, days):
        cutoff = time.time() - days * 86400
        with self.db.connect() as c:
            e = c.execute("DELETE FROM events WHERE ts<? AND (alert_id IS NULL OR alert_id IN "
                          "(SELECT id FROM alerts WHERE status IN ('resolved','false_positive')))", (cutoff,)).rowcount
            a = c.execute("DELETE FROM alerts WHERE last_seen<? AND status IN ('resolved','false_positive')", (cutoff,)).rowcount
            c.execute("DELETE FROM audit_log WHERE ts<?", (time.time() - max(days, 90) * 86400,))
        return e, a
