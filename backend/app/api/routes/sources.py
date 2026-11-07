"""Connectors: source management (Admin), the ingest 'door' (API-key authenticated) and the coverage panel."""
from __future__ import annotations

import time
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response

from app.api.deps import client_ip, get_ctx, require
from app.config import ROOT_DIR
from app.models.coverage import SOURCE_KINDS, compute_coverage
from app.schemas.api import HeartbeatInfo, IngestBatch, SourceCreate, SourceUpdate
from app.security.apikeys import generate_key, hash_key, looks_like_key
from app.services.connectors.sources import describe, list_described
from app.services.connectors.webevent import normalize_policy
from app.services.simmode import refresh_sim

router = APIRouter(prefix="/api", tags=["connectors"])
COLLECTOR_FILE = ROOT_DIR / "collector" / "argus_collector.py"


# ------------------------------------------------------------------ the door (API-key authenticated)
def authenticate_source(ctx, request: Request, x_argus_key: Optional[str], authorization: Optional[str]) -> dict:
    ip = client_ip(request)
    throttle_key = f"apikey|{ip}"
    wait = ctx.key_throttle.retry_after(throttle_key)
    if wait:
        raise HTTPException(429, "Too many invalid API keys from this address. Try again later.", headers={"Retry-After": str(wait)})
    key = (x_argus_key or "").strip()
    if not key and authorization and authorization[:7].lower() == "bearer ":
        key = authorization[7:].strip()
    src = ctx.repo.get_source_by_key_hash(hash_key(key)) if looks_like_key(key) else None
    if not src or src["revoked_at"]:
        ctx.key_throttle.failure(throttle_key)
        raise HTTPException(401, "Invalid, revoked or missing API key", headers={"WWW-Authenticate": "ApiKey"})
    return src


@router.post("/ingest/events")
def ingest_events(body: IngestBatch, request: Request, x_argus_key: Optional[str] = Header(default=None),
                  authorization: Optional[str] = Header(default=None), ctx=Depends(get_ctx)):
    """Receive a batch of web events from a collector. Authenticated by the source's API key (no user login)."""
    src = authenticate_source(ctx, request, x_argus_key, authorization)
    if SOURCE_KINDS.get(src["kind"], {}).get("live") is not True or src["kind"] != "web_access_log":
        raise HTTPException(400, "This source type does not accept web events")
    n = len(body.events)
    if n > ctx.settings.ingest_max_batch:
        raise HTTPException(413, f"Batch too large: send at most {ctx.settings.ingest_max_batch} events per request")
    if n and not ctx.ingest_limiter.allow(src["id"], n):
        raise HTTPException(429, "Rate limit exceeded for this source", headers={"Retry-After": str(ctx.ingest_limiter.retry_after(src["id"], n))})
    return ctx.ingest.ingest_web(src, body.events)


@router.post("/ingest/heartbeat")
def ingest_heartbeat(body: HeartbeatInfo, request: Request, x_argus_key: Optional[str] = Header(default=None),
                     authorization: Optional[str] = Header(default=None), ctx=Depends(get_ctx)):
    """The collector calls this every ~30 s: proves it is alive (even on a quiet site) and fetches the current privacy policy."""
    src = authenticate_source(ctx, request, x_argus_key, authorization)
    ctx.repo.touch_source(src["id"], heartbeat=True, info=dict(body.model_dump(), ip=client_ip(request)))
    return dict(status="ok", server_time=time.time(), policy=normalize_policy(src["policy"]))


@router.get("/ingest/policy")
def ingest_policy(request: Request, x_argus_key: Optional[str] = Header(default=None),
                  authorization: Optional[str] = Header(default=None), ctx=Depends(get_ctx)):
    src = authenticate_source(ctx, request, x_argus_key, authorization)
    return dict(policy=normalize_policy(src["policy"]), name=src["name"])


# ------------------------------------------------------------------ management (dashboard users)
@router.get("/sources")
def list_sources(user=Depends(require("viewer")), ctx=Depends(get_ctx)):
    return dict(sources=list_described(ctx.repo, ctx.settings.source_silent_after_seconds))


@router.post("/sources", status_code=201)
def create_source(body: SourceCreate, request: Request, user=Depends(require("admin")), ctx=Depends(get_ctx)):
    if any(s["name"].lower() == body.name.lower() for s in ctx.repo.list_sources()):
        raise HTTPException(409, "A source with this name already exists")
    policy = normalize_policy(body.policy.model_dump())
    if body.policy.protected_ip and not policy["protected_ip"]:
        raise HTTPException(422, "Protected server address is not a valid IP address")
    full, prefix, key_hash = generate_key()
    sid = ctx.repo.create_source(body.name, body.kind, prefix, key_hash, policy, user["username"])
    ctx.repo.audit(user["username"], "source.create", body.name, f"kind={body.kind}", client_ip(request))
    src = describe(ctx.repo.get_source(sid), ctx.settings.source_silent_after_seconds)
    return dict(source=src, api_key=full, notice="Copy this key now: it is shown only once and cannot be recovered (rotate it if lost).")


def _get_or_404(ctx, source_id):
    src = ctx.repo.get_source(source_id)
    if not src:
        raise HTTPException(404, "Source not found")
    return src


@router.patch("/sources/{source_id}")
def update_source(source_id: int, body: SourceUpdate, request: Request, user=Depends(require("admin")), ctx=Depends(get_ctx)):
    src = _get_or_404(ctx, source_id)
    policy = None
    if body.policy is not None:
        policy = normalize_policy(body.policy.model_dump())
        if body.policy.protected_ip and not policy["protected_ip"]:
            raise HTTPException(422, "Protected server address is not a valid IP address")
    if body.name and any(s["id"] != source_id and s["name"].lower() == body.name.lower() for s in ctx.repo.list_sources()):
        raise HTTPException(409, "A source with this name already exists")
    ctx.repo.update_source(source_id, name=" ".join(body.name.split()) if body.name else None, policy=policy)
    ctx.repo.audit(user["username"], "source.update", src["name"], "policy changed" if policy else "renamed", client_ip(request))
    return dict(source=describe(ctx.repo.get_source(source_id), ctx.settings.source_silent_after_seconds))


@router.post("/sources/{source_id}/rotate")
def rotate_source(source_id: int, request: Request, user=Depends(require("admin")), ctx=Depends(get_ctx)):
    src = _get_or_404(ctx, source_id)
    full, prefix, key_hash = generate_key()
    ctx.repo.set_source_key(source_id, prefix, key_hash)
    ctx.repo.audit(user["username"], "source.rotate", src["name"], None, client_ip(request))
    return dict(source=describe(ctx.repo.get_source(source_id), ctx.settings.source_silent_after_seconds), api_key=full,
                notice="The previous key no longer works. Update the collector with this new key.")


@router.post("/sources/{source_id}/revoke")
def revoke_source(source_id: int, request: Request, user=Depends(require("admin")), ctx=Depends(get_ctx)):
    src = _get_or_404(ctx, source_id)
    ctx.repo.revoke_source(source_id)
    ctx.repo.audit(user["username"], "source.revoke", src["name"], None, client_ip(request))
    refresh_sim(ctx)
    return dict(source=describe(ctx.repo.get_source(source_id), ctx.settings.source_silent_after_seconds))


@router.delete("/sources/{source_id}")
def delete_source(source_id: int, request: Request, user=Depends(require("admin")), ctx=Depends(get_ctx)):
    src = _get_or_404(ctx, source_id)
    ctx.repo.delete_source(source_id)
    ctx.repo.audit(user["username"], "source.delete", src["name"], "key destroyed; recorded events kept", client_ip(request))
    refresh_sim(ctx)
    return dict(status="ok")


# ------------------------------------------------------------------ coverage & downloads
@router.get("/coverage")
def coverage(user=Depends(require("viewer")), ctx=Depends(get_ctx)):
    """Which attack types the connected sources can see - and which they cannot, with what would be needed."""
    sim = refresh_sim(ctx)
    sources = list_described(ctx.repo, ctx.settings.source_silent_after_seconds)
    cov = compute_coverage([dict(kind=s["kind"], name=s["name"], status=s["status"]) for s in sources], demo_active=bool(sim["enabled"]))
    live = [s for s in sources if s["live"] and s["status"] in ("connected", "silent", "waiting")]
    kinds = [dict(kind=k, label=v["label"], available=v["available"], live=v["live"], description=v["description"], covers=v["covers"]) for k, v in SOURCE_KINDS.items()]
    return dict(mode="live" if sim["live_connected"] else "demo", simulator=sim, sources=[dict(id=s["id"], name=s["name"], kind=s["kind"], status=s["status"]) for s in live],
                kinds=kinds, **cov)


@router.get("/collector/download")
def download_collector(request: Request, user=Depends(require("admin")), ctx=Depends(get_ctx)):
    if not COLLECTOR_FILE.is_file():
        raise HTTPException(404, "Collector file is not installed on this server")
    ctx.repo.audit(user["username"], "collector.download", None, None, client_ip(request))
    return Response(COLLECTOR_FILE.read_bytes(), media_type="text/x-python",
                    headers={"Content-Disposition": 'attachment; filename="argus_collector.py"'})
