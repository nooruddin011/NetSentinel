"""Central configuration. Everything is driven by environment variables (or a .env file)."""
from __future__ import annotations

import logging
import os
import secrets
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

log = logging.getLogger(__name__)

# backend/app/config.py -> parents[2] is the project root
ROOT_DIR = Path(__file__).resolve().parents[2]
PLACEHOLDER_SECRETS = {"", "change-me", "changeme", "change-me-to-a-long-random-string"}


def _load_dotenv(path: Path) -> None:
    """Tiny .env reader (no extra dependency). Real environment variables always win."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except ValueError:
        return default


def _split(name: str, default: list) -> list:
    raw = os.getenv(name)
    return [p.strip() for p in raw.split(",") if p.strip()] if raw else default


@dataclass
class Settings:
    app_env: str = "development"
    db_path: Path = ROOT_DIR / "data" / "cyberwatch.db"
    model_dir: Path = ROOT_DIR / "models" / "active"
    web_model_dir: Path = ROOT_DIR / "models" / "web"
    jwt_secret: str = ""
    jwt_ttl_minutes: int = 60
    cors_origins: list = field(default_factory=lambda: ["http://localhost:5173", "http://127.0.0.1:5173"])
    admin_username: str = "admin"
    admin_password: str = ""
    simulation_enabled: bool = True
    simulation_interval: float = 1.0
    simulation_attack_ratio: float = 0.12
    max_upload_mb: int = 20
    max_upload_rows: int = 200_000
    retention_days: int = 14
    dedupe_window_seconds: int = 300
    critical_assets: list = field(default_factory=lambda: ["10.0.0.10", "10.0.0.20"])
    # email alerts (disabled unless SMTP_HOST is set)
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = True
    alert_email_from: str = "argus@localhost"
    alert_email_to: list = field(default_factory=list)
    alert_email_min_severity: str = "High"
    allow_self_registration: bool = True
    # connectors (live log ingestion)
    ingest_max_batch: int = 500
    ingest_max_body_bytes: int = 1_000_000
    ingest_events_per_second: int = 1000
    source_silent_after_seconds: int = 150
    bootstrap_source_key: str = ""   # optional fixed key for the Docker lab (never use in production)
    bootstrap_source_name: str = "Lab web server"
    login_max_failures: int = 5
    login_lockout_seconds: int = 900

    @property
    def is_production(self) -> bool:
        return self.app_env.lower() == "production"


def load_settings() -> Settings:
    _load_dotenv(ROOT_DIR / ".env")
    s = Settings(
        app_env=os.getenv("APP_ENV", "development"),
        db_path=Path(os.getenv("DB_PATH", str(ROOT_DIR / "data" / "cyberwatch.db"))),
        model_dir=Path(os.getenv("MODEL_DIR", str(ROOT_DIR / "models" / "active"))),
        web_model_dir=Path(os.getenv("WEB_MODEL_DIR", str(ROOT_DIR / "models" / "web"))),
        jwt_secret=os.getenv("JWT_SECRET", ""),
        jwt_ttl_minutes=_int("JWT_TTL_MINUTES", 60),
        cors_origins=_split("CORS_ORIGINS", ["http://localhost:5173", "http://127.0.0.1:5173"]),
        admin_username=os.getenv("ADMIN_USERNAME", "admin"),
        admin_password=os.getenv("ADMIN_PASSWORD", ""),
        simulation_enabled=_bool("SIMULATION_ENABLED", True),
        simulation_interval=_float("SIMULATION_INTERVAL", 1.0),
        simulation_attack_ratio=_float("SIMULATION_ATTACK_RATIO", 0.12),
        max_upload_mb=_int("MAX_UPLOAD_MB", 20),
        max_upload_rows=_int("MAX_UPLOAD_ROWS", 200_000),
        retention_days=_int("RETENTION_DAYS", 14),
        dedupe_window_seconds=_int("DEDUPE_WINDOW_SECONDS", 300),
        critical_assets=_split("CRITICAL_ASSETS", ["10.0.0.10", "10.0.0.20"]),
        smtp_host=os.getenv("SMTP_HOST", ""),
        smtp_port=_int("SMTP_PORT", 587),
        smtp_user=os.getenv("SMTP_USER", ""),
        smtp_password=os.getenv("SMTP_PASSWORD", ""),
        smtp_use_tls=_bool("SMTP_USE_TLS", True),
        alert_email_from=os.getenv("ALERT_EMAIL_FROM", "argus@localhost"),
        alert_email_to=_split("ALERT_EMAIL_TO", []),
        alert_email_min_severity=os.getenv("ALERT_EMAIL_MIN_SEVERITY", "High"),
        allow_self_registration=_bool("ALLOW_SELF_REGISTRATION", True),
        ingest_max_batch=_int("INGEST_MAX_BATCH", 500),
        ingest_max_body_bytes=_int("INGEST_MAX_BODY_BYTES", 1_000_000),
        ingest_events_per_second=_int("INGEST_EVENTS_PER_SECOND", 1000),
        source_silent_after_seconds=_int("SOURCE_SILENT_AFTER_SECONDS", 150),
        bootstrap_source_key=os.getenv("ARGUS_BOOTSTRAP_SOURCE_KEY", ""),
        bootstrap_source_name=os.getenv("ARGUS_BOOTSTRAP_SOURCE_NAME", "Lab web server"),
        login_max_failures=_int("LOGIN_MAX_FAILURES", 5),
        login_lockout_seconds=_int("LOGIN_LOCKOUT_SECONDS", 900),
    )
    if s.jwt_secret.strip().lower() in PLACEHOLDER_SECRETS:
        if s.is_production:
            raise RuntimeError("JWT_SECRET must be set to a long random value when APP_ENV=production")
        s.jwt_secret = secrets.token_urlsafe(48)
        log.warning("JWT_SECRET not set: using an ephemeral secret (tokens are invalidated on restart).")
    if s.is_production and s.admin_password.strip().lower() in PLACEHOLDER_SECRETS | {"admin", "password"}:
        raise RuntimeError("ADMIN_PASSWORD must be set to a strong value when APP_ENV=production")
    if s.is_production and s.bootstrap_source_key:
        raise RuntimeError("ARGUS_BOOTSTRAP_SOURCE_KEY is for the local Docker lab only; create sources in the dashboard in production")
    if s.is_production and "*" in s.cors_origins:
        raise RuntimeError("CORS_ORIGINS must list explicit origins in production (no wildcard)")
    return s


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return load_settings()
