"""SQLite access (standard library). One short-lived connection per operation, WAL mode for
concurrent readers. The repository layer is the only code that writes SQL, so moving to
PostgreSQL later means re-implementing one module."""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('viewer','analyst','admin')),
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL,
    full_name TEXT,
    last_login REAL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    ip TEXT PRIMARY KEY,
    reason TEXT,
    alert_id INTEGER,
    created_by TEXT,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS upload_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    ts REAL NOT NULL, username TEXT, action TEXT NOT NULL, target TEXT, detail TEXT, ip TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
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
        """Bring databases created by an older version up to date (additive changes only)."""
        have = {r[1] for r in conn.execute("PRAGMA table_info(users)")}
        for col, ddl in (("full_name", "TEXT"), ("last_login", "REAL")):
            if col not in have:
                conn.execute(f"ALTER TABLE users ADD COLUMN {col} {ddl}")
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
