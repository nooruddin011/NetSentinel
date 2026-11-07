"""Demo / Live mode.

The simulator produces *demo* traffic. In "auto" mode (the default) it switches itself off while a real, healthy
live source is connected, so real and simulated events never mix on the dashboard. An Admin can force it on or off.
"""
from __future__ import annotations

from app.services.connectors.sources import live_connected

MODES = ("auto", "on", "off")


def refresh_sim(ctx) -> dict:
    """Recompute `ctx.sim['live_connected']` and the effective `ctx.sim['enabled']` from the current mode."""
    live = live_connected(ctx.repo, ctx.settings.source_silent_after_seconds)
    mode = ctx.sim.get("mode", "auto")
    ctx.sim["live_connected"] = live
    ctx.sim["enabled"] = mode == "on" or (mode == "auto" and not live)
    return ctx.sim
