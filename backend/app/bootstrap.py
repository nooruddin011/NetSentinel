"""Builds the application object graph (no web-framework imports, so it is usable from scripts and tests)."""
from __future__ import annotations

import logging
import secrets
import time

from app.api.context import AppContext
from app.config import Settings
from app.db.database import Database
from app.db.repository import Repository
from app.ml.registry import load_or_train
from app.ml.webregistry import load_or_train_web
from app.security.passwords import hash_password
from app.security.apikeys import hash_key, looks_like_key
from app.security.ratelimit import TokenBucket
from app.security.throttle import LoginThrottle
from app.services.alerting import EmailNotifier
from app.services.chatbot.engine import ChatEngine
from app.services.detection.pipeline import DetectionPipeline
from app.services.connectors.ingest import IngestService
from app.services.connectors.webevent import normalize_policy
from app.services.detection.processor import EventProcessor
from app.services.detection.web_pipeline import WebDetectionPipeline
from app.services.simmode import refresh_sim
from app.services.ingestion.simulator import TrafficSimulator
from app.services.model_manager import ModelManager
from app.services.recommendation import Recommender
from app.services.stream import Hub

log = logging.getLogger("cyberwatch")


def build_context(settings: Settings, bundle=None, web_model=None) -> AppContext:
    db = Database(settings.db_path)
    db.init()
    repo = Repository(db)
    if repo.count_users() == 0:
        pw = settings.admin_password
        generated = not pw
        if generated:
            pw = secrets.token_urlsafe(12) + "aA1"
            log.warning("=" * 70)
            log.warning("No ADMIN_PASSWORD set. Created user '%s' with generated password: %s", settings.admin_username, pw)
            log.warning("Set ADMIN_PASSWORD in .env to choose your own. This message is shown once.")
            log.warning("=" * 70)
        repo.create_user(settings.admin_username, hash_password(pw), "admin")
    bundle = bundle or load_or_train(settings.model_dir, quick=True)
    pipeline = DetectionPipeline(bundle, settings.critical_assets)
    notifier = EmailNotifier(settings)
    processor = EventProcessor(repo, pipeline, settings, notifier)
    models = ModelManager(repo, pipeline, settings)
    models.register_active()
    mode = repo.get_setting("sim.mode")
    if mode not in ("auto", "on", "off"):
        mode = "auto" if settings.simulation_enabled else "off"
    sim = dict(mode=mode, enabled=False, live_connected=False,
               interval=float(repo.get_setting("sim.interval", settings.simulation_interval)),
               attack_ratio=float(repo.get_setting("sim.attack_ratio", settings.simulation_attack_ratio)))
    simulator = TrafficSimulator(attack_ratio=sim["attack_ratio"])
    web_report = {}
    if web_model is None:
        web_model, web_report = load_or_train_web(settings.web_model_dir)
    else:
        web_model, web_report = (web_model if isinstance(web_model, tuple) else (web_model, {}))
    web_pipeline = WebDetectionPipeline(web_model, settings.critical_assets, report=web_report)
    hub = Hub()
    ingest = IngestService(repo, web_pipeline, settings, hub, notifier)
    _register_bootstrap_source(repo, settings)
    recommender = Recommender(models.report, lambda: web_pipeline.report)
    ctx = AppContext(settings=settings, db=db, repo=repo, pipeline=pipeline, processor=processor, hub=hub,
                      throttle=LoginThrottle(settings.login_max_failures, settings.login_lockout_seconds),
                      recommender=recommender, chat=ChatEngine(repo, recommender, models.report, settings.source_silent_after_seconds), models=models,
                      notifier=notifier, simulator=simulator, sim=sim, started_at=time.time(),
                      reg_throttle=LoginThrottle(10, 3600),  # max 10 sign-ups per IP per hour
                      web_pipeline=web_pipeline, ingest=ingest, key_throttle=LoginThrottle(30, 900),  # 30 bad API keys per IP per 15 min
                      ingest_limiter=TokenBucket(capacity=settings.ingest_events_per_second * 5, refill_per_second=settings.ingest_events_per_second))
    refresh_sim(ctx)
    return ctx


def _register_bootstrap_source(repo, settings):
    """Docker-lab convenience: register a source with a fixed, pre-shared key so the collector works with zero clicks.
    Refused in production (see config)."""
    key = settings.bootstrap_source_key.strip()
    if not key:
        return
    if not looks_like_key(key):
        log.warning("ARGUS_BOOTSTRAP_SOURCE_KEY ignored: it must look like agk_ followed by 32-64 URL-safe characters")
        return
    h = hash_key(key)
    if repo.get_source_by_key_hash(h) is None:
        repo.create_source(settings.bootstrap_source_name, "web_access_log", key[:10], h,
                           normalize_policy({"exclude_paths": ["/healthz"]}), "bootstrap")
        log.warning("Registered lab source '%s' with the key from ARGUS_BOOTSTRAP_SOURCE_KEY (local lab only!)", settings.bootstrap_source_name)
