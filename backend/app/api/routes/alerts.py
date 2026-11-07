from __future__ import annotations

import ipaddress
import time
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.api.deps import client_ip, get_ctx, require
from app.models.attacks import ATTACKS, SEVERITY_ORDER
from app.schemas.api import MitigateRequest, StatusUpdate
from app.services.recommendation import apply_mitigation

router = APIRouter(prefix="/api", tags=["alerts"])


@router.get("/alerts")
def list_alerts(status: Optional[str] = None, severity: Optional[str] = Query(default=None), attack_type: Optional[str] = None,
                q: Optional[str] = Query(default=None, max_length=64), hours: Optional[int] = Query(default=None, ge=1, le=24 * 90),
                sort: str = Query(default="time", pattern="^(time|risk|count)$"), scope: str = Query(default="all", pattern="^(all|live|demo|upload)$"),
                limit: int = Query(default=50, ge=1, le=200), offset: int = Query(default=0, ge=0),
                user=Depends(require("viewer")), ctx=Depends(get_ctx)):
    if severity and severity not in SEVERITY_ORDER:
        raise HTTPException(422, "invalid severity")
    if attack_type and attack_type not in ATTACKS:
        raise HTTPException(422, "invalid attack_type")
    since = time.time() - hours * 3600 if hours else None
    rows, total = ctx.repo.list_alerts(status, severity, attack_type, q, since, sort, limit, offset, scope)
    return dict(alerts=rows, total=total, limit=limit, offset=offset)


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: int, user=Depends(require("viewer")), ctx=Depends(get_ctx)):
    a = ctx.repo.get_alert(alert_id)
    if not a:
        raise HTTPException(404, "Alert not found")
    if a["explanation"] is None and a.get("origin") != "connector" and a.get("event") and a["event"].get("features"):
        a["explanation"] = ctx.pipeline.explain(a["event"]["features"], a["attack_type"])  # computed on demand
        ctx.repo.set_alert_explanation(alert_id, a["explanation"])
    return a


@router.patch("/alerts/{alert_id}")
def update_status(alert_id: int, body: StatusUpdate, request: Request, user=Depends(require("analyst")), ctx=Depends(get_ctx)):
    if not ctx.repo.update_alert_status(alert_id, body.status, user["username"]):
        raise HTTPException(404, "Alert not found")
    ctx.repo.audit(user["username"], "alert.status", str(alert_id), body.status, client_ip(request))
    return dict(status="ok", alert_status=body.status)


@router.get("/alerts/{alert_id}/recommendations")
def alert_recommendations(alert_id: int, user=Depends(require("viewer")), ctx=Depends(get_ctx)):
    a = ctx.repo.get_alert(alert_id)
    if not a:
        raise HTTPException(404, "Alert not found")
    return ctx.recommender.for_attack(a["attack_type"])


@router.get("/recommendations/{attack_type}")
def recommendations(attack_type: str, user=Depends(require("viewer")), ctx=Depends(get_ctx)):
    if attack_type not in ATTACKS:
        raise HTTPException(404, "Unknown attack type")
    return ctx.recommender.for_attack(attack_type)


@router.post("/alerts/{alert_id}/mitigate")
def mitigate(alert_id: int, body: MitigateRequest, request: Request, user=Depends(require("analyst")), ctx=Depends(get_ctx)):
    a = ctx.repo.get_alert(alert_id)
    if not a:
        raise HTTPException(404, "Alert not found")
    try:
        res = apply_mitigation(ctx.repo, a, body.solution_id, user["username"])
    except KeyError:
        raise HTTPException(422, "Unknown solution for this attack type")
    ctx.repo.audit(user["username"], "mitigation.simulate", str(alert_id), body.solution_id, client_ip(request))
    return res


@router.get("/mitigations")
def mitigations(user=Depends(require("viewer")), ctx=Depends(get_ctx)):
    return dict(mitigations=ctx.repo.list_mitigations(), blocklist=ctx.repo.list_blocklist())


@router.delete("/blocklist/{ip}")
def unblock(ip: str, request: Request, user=Depends(require("admin")), ctx=Depends(get_ctx)):
    try:
        ip = str(ipaddress.ip_address(ip))
    except ValueError:
        raise HTTPException(422, "Invalid IP")
    if not ctx.repo.unblock_ip(ip):
        raise HTTPException(404, "IP not on blocklist")
    ctx.repo.audit(user["username"], "blocklist.remove", ip, None, client_ip(request))
    return dict(status="ok")
