"""Application context: the object graph shared by all routes."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AppContext:
    settings: object
    db: object
    repo: object
    pipeline: object
    processor: object
    hub: object
    throttle: object
    recommender: object
    chat: object
    models: object
    notifier: object
    simulator: object
    sim: dict = field(default_factory=dict)  # runtime simulation settings
    started_at: float = 0.0
    reg_throttle: object = None
    web_pipeline: object = None
    ingest: object = None
    key_throttle: object = None
    ingest_limiter: object = None
