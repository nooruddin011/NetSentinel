from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.api.deps import get_ctx, require
from app.services.analytics import holt_forecast

router = APIRouter(prefix="/api", tags=["analytics"])


@router.get("/stats/overview")
def overview(hours: int = Query(default=24, ge=1, le=24 * 90), scope: str = Query(default="all", pattern="^(all|live|demo|upload)$"), user=Depends(require("viewer")), ctx=Depends(get_ctx)):
    return ctx.repo.overview(hours, scope)


@router.get("/stats/timeline")
def timeline(hours: int = Query(default=24, ge=1, le=24 * 14), scope: str = Query(default="all", pattern="^(all|live|demo|upload)$"), user=Depends(require("viewer")), ctx=Depends(get_ctx)):
    return dict(points=ctx.repo.timeline(hours, scope))


@router.get("/stats/heatmap")
def heatmap(hours: int = Query(default=24 * 7, ge=1, le=24 * 90), scope: str = Query(default="all", pattern="^(all|live|demo|upload)$"), user=Depends(require("viewer")), ctx=Depends(get_ctx)):
    return dict(cells=ctx.repo.heatmap(hours, scope), timezone="UTC")


@router.get("/stats/top-sources")
def top_sources(hours: int = Query(default=24, ge=1, le=24 * 90), limit: int = Query(default=10, ge=1, le=50), scope: str = Query(default="all", pattern="^(all|live|demo|upload)$"),
                user=Depends(require("viewer")), ctx=Depends(get_ctx)):
    return dict(sources=ctx.repo.top_sources(hours, limit, scope))


@router.get("/stats/forecast")
def forecast(horizon: int = Query(default=6, ge=1, le=24), scope: str = Query(default="all", pattern="^(all|live|demo|upload)$"), user=Depends(require("viewer")), ctx=Depends(get_ctx)):
    pts = ctx.repo.timeline(72, scope)
    return dict(history=pts[-24:], **holt_forecast([p["threats"] for p in pts], horizon))


@router.get("/events/recent")
def recent_events(limit: int = Query(default=50, ge=1, le=200), threats_only: bool = False, scope: str = Query(default="all", pattern="^(all|live|demo|upload)$"),
                  user=Depends(require("viewer")), ctx=Depends(get_ctx)):
    return dict(events=ctx.repo.recent_events(limit, threats_only, scope))
