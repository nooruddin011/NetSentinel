from __future__ import annotations

import os
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response

from app.api.deps import client_ip, get_ctx, require
from app.api.routes.auth import registration_enabled
from app.branding import APP_NAME
from app.schemas.api import ChatRequest, RegistrationSetting, RetrainRequest, SimulationSettings
from app.services import reports
from app.services.simmode import refresh_sim

router = APIRouter(prefix="/api", tags=["platform"])


@router.get("/health")
def health(ctx=Depends(get_ctx)):
    """Public liveness probe (used by Docker). Detailed status is Admin-only: see /api/admin/system."""
    return dict(status="ok", uptime_seconds=round(time.time() - ctx.started_at))


@router.get("/admin/system")
def system_info(user=Depends(require("admin")), ctx=Depends(get_ctx)):
    b = ctx.pipeline.bundle
    try:
        db_bytes = os.path.getsize(ctx.settings.db_path)
    except OSError:
        db_bytes = None
    return dict(app_name=APP_NAME, version="2.2.0", uptime_seconds=round(time.time() - ctx.started_at),
                model_members=b.member_names, model_trained_at=(b.report or {}).get("created_at"),
                dataset=((b.report or {}).get("dataset") or {}).get("name"), cache=ctx.pipeline.cache_stats(),
                stream_clients=ctx.hub.client_count, simulation=refresh_sim(ctx), web_model_trained_at=(ctx.web_pipeline.report or {}).get("created_at"), sources=len(ctx.repo.list_sources()), email_alerts=ctx.notifier.enabled,
                registration_enabled=registration_enabled(ctx), db_bytes=db_bytes, environment=ctx.settings.app_env,
                users=ctx.repo.count_users(), retention_days=ctx.settings.retention_days)


@router.post("/admin/registration")
def set_registration(body: RegistrationSetting, request: Request, user=Depends(require("admin")), ctx=Depends(get_ctx)):
    ctx.repo.set_setting("registration.enabled", "true" if body.enabled else "false")
    ctx.repo.audit(user["username"], "registration.update", None, f"enabled={body.enabled}", client_ip(request))
    return dict(registration_enabled=body.enabled)


# ---- models
@router.get("/models/active")
def active_model(user=Depends(require("viewer")), ctx=Depends(get_ctx)):
    return ctx.models.report()


@router.get("/models/runs")
def model_runs(user=Depends(require("viewer")), ctx=Depends(get_ctx)):
    return dict(runs=ctx.repo.list_runs())


@router.post("/models/retrain", status_code=202)
def retrain(body: RetrainRequest, request: Request, user=Depends(require("admin")), ctx=Depends(get_ctx)):
    if not ctx.models.start_retrain(body.quick, body.samples, user["username"]):
        raise HTTPException(409, "Training already in progress")
    ctx.repo.audit(user["username"], "model.retrain.start", None, f"quick={body.quick}", client_ip(request))
    return ctx.models.status


@router.get("/models/retrain/status")
def retrain_status(user=Depends(require("viewer")), ctx=Depends(get_ctx)):
    return ctx.models.status


# ---- chat
@router.post("/chat")
def chat(body: ChatRequest, user=Depends(require("viewer")), ctx=Depends(get_ctx)):
    return ctx.chat.reply(body.message)


# ---- reports
@router.get("/reports/summary.pdf")
def pdf_report(request: Request, hours: int = Query(default=24, ge=1, le=24 * 90), scope: str = Query(default="all", pattern="^(all|live|demo|upload)$"), user=Depends(require("viewer")),
               ctx=Depends(get_ctx)):
    since = time.time() - hours * 3600
    pdf = reports.build_pdf(ctx.repo.overview(hours, scope), ctx.repo.iter_alerts_for_export(since, 2000, scope), ctx.repo.top_sources(hours, 10, scope),
                            ctx.models.report(), hours)
    ctx.repo.audit(user["username"], "report.pdf", None, f"hours={hours}", client_ip(request))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    return Response(pdf, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="argus-report-{stamp}.pdf"'})


@router.get("/reports/alerts.csv")
def csv_report(request: Request, hours: int = Query(default=24 * 7, ge=1, le=24 * 90), scope: str = Query(default="all", pattern="^(all|live|demo|upload)$"), user=Depends(require("analyst")),
               ctx=Depends(get_ctx)):
    rows = ctx.repo.iter_alerts_for_export(time.time() - hours * 3600, scope=scope)
    ctx.repo.audit(user["username"], "report.csv", None, f"rows={len(rows)}", client_ip(request))
    return Response(reports.alerts_csv(rows), media_type="text/csv", headers={"Content-Disposition": 'attachment; filename="alerts.csv"'})


# ---- admin
@router.get("/admin/audit")
def audit(limit: int = Query(default=100, ge=1, le=500), offset: int = Query(default=0, ge=0),
          user=Depends(require("admin")), ctx=Depends(get_ctx)):
    return dict(entries=ctx.repo.list_audit(limit, offset))


@router.get("/admin/simulation")
def get_simulation(user=Depends(require("viewer")), ctx=Depends(get_ctx)):
    return refresh_sim(ctx)


@router.post("/admin/simulation")
def set_simulation(body: SimulationSettings, request: Request, user=Depends(require("admin")), ctx=Depends(get_ctx)):
    if body.mode is not None:
        ctx.sim["mode"] = body.mode
    elif body.enabled is not None:  # legacy field
        ctx.sim["mode"] = "on" if body.enabled else "off"
    if body.interval is not None:
        ctx.sim["interval"] = body.interval
    if body.attack_ratio is not None:
        ctx.sim["attack_ratio"] = body.attack_ratio
        ctx.simulator.attack_ratio = body.attack_ratio
    for k in ("mode", "interval", "attack_ratio"):
        ctx.repo.set_setting(f"sim.{k}", ctx.sim[k])
    refresh_sim(ctx)
    ctx.repo.audit(user["username"], "simulation.update", None, str(ctx.sim), client_ip(request))
    return ctx.sim
