"""Owns the active model: registers it in the DB, and runs background retraining with hot-swap."""
from __future__ import annotations

import logging
import threading
import time

from app.ml.registry import save_bundle
from app.ml.trainer import TrainConfig, train

log = logging.getLogger(__name__)


class ModelManager:
    def __init__(self, repo, pipeline, settings):
        self.repo, self.pipeline, self.settings = repo, pipeline, settings
        self._lock = threading.Lock()
        self.status = dict(state="idle", stage="", progress=0.0, started_at=None, finished_at=None, error=None)

    def report(self) -> dict:
        return self.pipeline.bundle.report or {}

    def register_active(self):
        """Make sure the DB knows about the loaded bundle (metrics are stored in the database)."""
        rep = self.report()
        active = self.repo.get_active_run()
        if rep and (not active or (active["report"] or {}).get("created_at") != rep.get("created_at")):
            self.repo.add_model_run(rep, str(self.settings.model_dir), activate=True)

    def start_retrain(self, quick: bool, samples: int | None, username: str) -> bool:
        if not self._lock.acquire(blocking=False):
            return False
        self.status = dict(state="running", stage="Starting", progress=0.0, started_at=time.time(), finished_at=None, error=None)
        threading.Thread(target=self._run, args=(quick, samples, username), daemon=True).start()
        return True

    def _run(self, quick, samples, username):
        try:
            kw = {"n_samples": samples} if samples else {}
            cfg = TrainConfig.quick(**kw) if quick else TrainConfig(**kw)

            def prog(stage, frac):
                self.status.update(stage=stage, progress=round(frac, 3))

            bundle = train(cfg, progress=prog)
            save_bundle(bundle, self.settings.model_dir)
            self.pipeline.set_bundle(bundle)
            self.repo.add_model_run(bundle.report, str(self.settings.model_dir), activate=True)
            self.repo.audit(username, "model.retrain.done", None, f"f1={bundle.report['models']['ensemble']['f1']}")
            self.status.update(state="done", stage="Done", progress=1.0, finished_at=time.time())
        except Exception as exc:
            log.exception("Retraining failed")
            self.status.update(state="error", error=str(exc)[:300], finished_at=time.time())
        finally:
            self._lock.release()
