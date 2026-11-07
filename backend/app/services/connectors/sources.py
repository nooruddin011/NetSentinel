"""Source (connector) helpers: health status, descriptions and the 'is a live source connected?' question."""
from __future__ import annotations

import time

from app.models.coverage import source_kind


def source_status(src: dict, silent_after: float, now: float | None = None) -> str:
    """revoked | waiting (never contacted us) | connected | silent (was connected, has gone quiet)."""
    now = now or time.time()
    if src.get("revoked_at"):
        return "revoked"
    last = max(src.get("last_seen") or 0, src.get("last_heartbeat") or 0)
    if not last:
        return "waiting"
    return "connected" if now - last <= silent_after else "silent"


def describe(src: dict, silent_after: float) -> dict:
    out = dict(src)
    out["status"] = source_status(src, silent_after)
    out["last_contact"] = max(src.get("last_seen") or 0, src.get("last_heartbeat") or 0) or None
    meta = source_kind(src["kind"])
    out["kind_label"], out["live"] = meta.get("label", src["kind"]), bool(meta.get("live"))
    return out


def list_described(repo, silent_after: float) -> list:
    return [describe(s, silent_after) for s in repo.list_sources()]


def live_connected(repo, silent_after: float) -> bool:
    """True when at least one real, healthy live source exists (the simulator then switches itself off in Auto mode)."""
    return any(s["status"] == "connected" and s["live"] for s in list_described(repo, silent_after))
