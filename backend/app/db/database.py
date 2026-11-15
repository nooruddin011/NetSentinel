"""SQLite access (standard library). One short-lived connection per operation, WAL mode for
concurrent readers. The repository layer is the only code that writes SQL, so moving to
PostgreSQL later means re-implementing one module."""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS workspaces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at REAL NOT NULL,
    owner_user_id INTEGER
);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('viewer','analyst','admin')),
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL,
    full_name TEXT,
    avatar_data TEXT,
    last_login REAL,
    workspace_id INTEGER
);
CREATE TABLE IF NOT EXISTS auth_identities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT NOT NULL,
    subject TEXT NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    email_verified INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL,
    UNIQUE(provider, subject),
    UNIQUE(user_id, provider)
);
CREATE INDEX IF NOT EXISTS idx_auth_identities_user ON auth_identities(user_id);
CREATE TABLE IF NOT EXISTS role_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    requester_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    requested_role TEXT NOT NULL CHECK (requested_role IN ('analyst','admin')),
    message TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','declined')),
    created_at REAL NOT NULL,
    reviewed_at REAL,
    reviewer_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_role_requests_workspace_status ON role_requests(workspace_id,status,created_at);
CREATE TABLE IF NOT EXISTS workspace_notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    recipient_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at REAL NOT NULL,
    read_at REAL
);
CREATE INDEX IF NOT EXISTS idx_workspace_notifications_recipient ON workspace_notifications(recipient_user_id,created_at);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER,
    ts REAL NOT NULL,
    src_ip TEXT, dst_ip TEXT, dst_port INTEGER, protocol TEXT,
    bytes_total REAL,
    features_json TEXT,
    payload_sample TEXT,
    verdict TEXT NOT NULL,
    attack_type TEXT,
    confidence REAL, risk_score REAL, severity TEXT,
    sources_json TEXT,
    origin TEXT NOT NULL DEFAULT 'stream',
    job_id INTEGER,
    alert_id INTEGER,
    blocked INTEGER NOT NULL DEFAULT 0,
    source_id INTEGER,
    eid TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_verdict_ts ON events(verdict, ts);
CREATE INDEX IF NOT EXISTS idx_events_src ON events(src_ip);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER,
    event_id INTEGER,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    count INTEGER NOT NULL DEFAULT 1,
    attack_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    risk_score REAL NOT NULL,
    confidence REAL NOT NULL,
    src_ip TEXT, dst_ip TEXT,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','acknowledged','mitigated','resolved','false_positive')),
    explanation_json TEXT,
    sources_json TEXT,
    origin TEXT NOT NULL DEFAULT 'stream',
    job_id INTEGER,
    handled_by TEXT,
    updated_at REAL NOT NULL,
    source_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_first ON alerts(first_seen);
CREATE INDEX IF NOT EXISTS idx_alerts_dedupe ON alerts(src_ip, attack_type, last_seen);
CREATE TABLE IF NOT EXISTS mitigations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER,
    alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    solution_id TEXT NOT NULL,
    title TEXT NOT NULL,
    rule_text TEXT,
    status TEXT NOT NULL DEFAULT 'simulated',
    applied_by TEXT,
    applied_at REAL NOT NULL,
    details_json TEXT
);
CREATE TABLE IF NOT EXISTS blocklist (
    workspace_id INTEGER,
    ip TEXT NOT NULL,
    reason TEXT,
    alert_id INTEGER,
    created_by TEXT,
    created_at REAL NOT NULL,
    PRIMARY KEY(workspace_id, ip)
);
CREATE TABLE IF NOT EXISTS upload_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER,
    filename TEXT, created_by TEXT, created_at REAL NOT NULL,
    status TEXT NOT NULL, rows_total INTEGER DEFAULT 0, rows_flagged INTEGER DEFAULT 0,
    summary_json TEXT, error TEXT
);
CREATE TABLE IF NOT EXISTS model_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at REAL NOT NULL,
    dataset TEXT, is_active INTEGER NOT NULL DEFAULT 0,
    artifact_path TEXT,
    report_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER,
    ts REAL NOT NULL, username TEXT, action TEXT NOT NULL, target TEXT, detail TEXT, ip TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    policy_json TEXT NOT NULL,
    created_by TEXT,
    created_at REAL NOT NULL,
    revoked_at REAL,
    last_seen REAL,
    last_heartbeat REAL,
    events_total INTEGER NOT NULL DEFAULT 0,
    threats_total INTEGER NOT NULL DEFAULT 0,
    rejected_total INTEGER NOT NULL DEFAULT 0,
    info_json TEXT
);
"""


class Database:
    def __init__(self, path):
        self.path = Path(path)
        self._init_lock = threading.Lock()

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(str(self.path), timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init(self):
        with self._init_lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.connect() as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.executescript(SCHEMA)
                self._migrate(conn)

    @staticmethod
    def _migrate(conn):
        """Apply additive schema changes and isolate pre-workspace accounts and data."""
        workspace_cols = {r[1] for r in conn.execute("PRAGMA table_info(workspaces)")}
        if "owner_user_id" not in workspace_cols:
            conn.execute("ALTER TABLE workspaces ADD COLUMN owner_user_id INTEGER")
        have = {r[1] for r in conn.execute("PRAGMA table_info(users)")}
        for col, ddl in (("full_name", "TEXT"), ("avatar_data", "TEXT"), ("last_login", "REAL"), ("workspace_id", "INTEGER")):
            if col not in have:
                conn.execute(f"ALTER TABLE users ADD COLUMN {col} {ddl}")
        conn.execute("INSERT OR IGNORE INTO workspaces(id,name,created_by,created_at) VALUES(1,'Admin workspace','system',strftime('%s','now'))")
        # The old installation was a shared workspace. Preserve Admin-created teammates in it;
        # give legacy self-registered users an empty private workspace and Admin role.
        users = conn.execute("SELECT id,username,role FROM users WHERE workspace_id IS NULL ORDER BY id").fetchall()
        for user in users:
            was_invited = conn.execute("SELECT 1 FROM audit_log WHERE action='user.create' AND target=? LIMIT 1",
                                       (user["username"],)).fetchone()
            if user["role"] == "admin" or was_invited:
                wid = 1
            else:
                cur = conn.execute("INSERT INTO workspaces(name,created_by,created_at) VALUES(?,?,strftime('%s','now'))",
                                   (f"{user['username']}'s workspace", user["username"]))
                wid = cur.lastrowid
                conn.execute("UPDATE users SET role='admin' WHERE id=?", (user["id"],))
            conn.execute("UPDATE users SET workspace_id=? WHERE id=?", (wid, user["id"]))
        # Resolve owners for workspaces created before owner_user_id was introduced.
        conn.execute("UPDATE workspaces SET owner_user_id=(SELECT id FROM users WHERE users.workspace_id=workspaces.id AND users.username=workspaces.created_by COLLATE NOCASE ORDER BY id LIMIT 1) WHERE owner_user_id IS NULL AND created_by<>'system'")
        # The original shared workspace used a system creator; its earliest member is the original owner.
        conn.execute("UPDATE workspaces SET owner_user_id=(SELECT id FROM users WHERE users.workspace_id=workspaces.id ORDER BY id LIMIT 1) WHERE owner_user_id IS NULL AND id=1 AND created_by='system'")
        # The owner always keeps Admin capability, including installs where another Admin changed it before this migration.
        conn.execute("UPDATE users SET role='admin' WHERE id IN (SELECT owner_user_id FROM workspaces WHERE owner_user_id IS NOT NULL) AND role<>'admin'")
        # Existing workspace-owned records remain with the original Admin workspace.
        for table in ("events", "alerts", "sources", "mitigations", "blocklist", "upload_jobs", "audit_log"):
            cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
            if "workspace_id" not in cols:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN workspace_id INTEGER")
            conn.execute(f"UPDATE {table} SET workspace_id=1 WHERE workspace_id IS NULL")
        # Legacy events and alerts may have been merged across upload jobs, so keep all historical
        # records in the original Admin workspace rather than guessing ownership.
        conn.execute("UPDATE mitigations SET workspace_id=(SELECT workspace_id FROM alerts WHERE alerts.id=mitigations.alert_id) WHERE alert_id IN (SELECT id FROM alerts)")
        conn.execute("UPDATE blocklist SET workspace_id=(SELECT workspace_id FROM alerts WHERE alerts.id=blocklist.alert_id) WHERE alert_id IN (SELECT id FROM alerts)")
        # Older SQLite databases had a global IP primary key; allow each workspace its own blocklist.
        block_pk = [r[1] for r in sorted(conn.execute("PRAGMA table_info(blocklist)"), key=lambda x: x[5]) if r[5]]
        if block_pk == ["ip"]:
            conn.execute("ALTER TABLE blocklist RENAME TO blocklist_legacy")
            conn.execute("CREATE TABLE blocklist (workspace_id INTEGER NOT NULL, ip TEXT NOT NULL, reason TEXT, alert_id INTEGER, created_by TEXT, created_at REAL NOT NULL, PRIMARY KEY(workspace_id,ip))")
            conn.execute("INSERT OR REPLACE INTO blocklist(workspace_id,ip,reason,alert_id,created_by,created_at) SELECT COALESCE(workspace_id,1),ip,reason,alert_id,created_by,created_at FROM blocklist_legacy")
            conn.execute("DROP TABLE blocklist_legacy")
        for table in ("events", "alerts", "sources", "mitigations", "upload_jobs", "audit_log"):
            conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{table}_workspace ON {table}(workspace_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_owner ON upload_jobs(created_by)")
        ev = {r[1] for r in conn.execute("PRAGMA table_info(events)")}
        for col, ddl in (("source_id", "INTEGER"), ("eid", "TEXT")):
            if col not in ev:
                conn.execute(f"ALTER TABLE events ADD COLUMN {col} {ddl}")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_source_eid ON events(source_id, eid)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_origin_ts ON events(origin, ts)")
        al = {r[1] for r in conn.execute("PRAGMA table_info(alerts)")}
        if "source_id" not in al:
            conn.execute("ALTER TABLE alerts ADD COLUMN source_id INTEGER")
