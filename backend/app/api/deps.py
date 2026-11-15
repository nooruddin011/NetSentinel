"""FastAPI dependencies: context, authentication, role checks."""
from __future__ import annotations

import copy

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.security.jwt import TokenError, decode_token
from app.security.passwords import password_version
from app.security.rbac import has_role

_bearer = HTTPBearer(auto_error=False)


def get_ctx(request: Request):
    base = request.app.state.ctx
    header = request.headers.get("authorization", "")
    if header[:7].lower() != "bearer ":
        return base
    try:
        user = authenticate_token(base, header[7:].strip())
    except HTTPException:
        return base  # current_user reports the authentication failure
    if not user.get("workspace_id"):
        return base
    return workspace_context(base, user["workspace_id"])


def workspace_context(base, workspace_id):
    """Return request-local services backed by one tenant-scoped repository."""
    if getattr(base.repo, "workspace_id", None) == workspace_id:
        return base
    from app.services.chatbot.engine import ChatEngine
    from app.services.connectors.ingest import IngestService
    from app.services.detection.processor import EventProcessor

    ctx = copy.copy(base)
    ctx.repo = base.repo.for_workspace(workspace_id)
    ctx.processor = EventProcessor(ctx.repo, ctx.pipeline, ctx.settings, ctx.notifier)
    ctx.ingest = IngestService(ctx.repo, ctx.web_pipeline, ctx.settings, ctx.hub, ctx.notifier)
    ctx.chat = ChatEngine(ctx.repo, ctx.recommender, ctx.models.report, ctx.settings.source_silent_after_seconds)
    mode = ctx.repo.get_setting("sim.mode", "auto" if ctx.settings.simulation_enabled else "off")
    ctx.sim = dict(mode=mode, enabled=False, live_connected=False,
                   interval=float(ctx.repo.get_setting("sim.interval", ctx.settings.simulation_interval)),
                   attack_ratio=float(ctx.repo.get_setting("sim.attack_ratio", ctx.settings.simulation_attack_ratio)))
    with base.workspace_simulators_lock:
        if workspace_id not in base.workspace_simulators:
            if workspace_id == 1:
                base.workspace_simulators[workspace_id] = base.simulator
            else:
                from app.services.ingestion.simulator import TrafficSimulator
                base.workspace_simulators[workspace_id] = TrafficSimulator(attack_ratio=ctx.sim["attack_ratio"])
        ctx.simulator = base.workspace_simulators[workspace_id]
        ctx.simulator.attack_ratio = ctx.sim["attack_ratio"]
    return ctx


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def authenticate_token(ctx, token: str) -> dict:
    deny = lambda msg: HTTPException(401, msg, headers={"WWW-Authenticate": "Bearer"})  # noqa: E731
    try:
        payload = decode_token(token, ctx.settings.jwt_secret)
        user = ctx.repo.get_user(int(payload["sub"]))
    except (TokenError, KeyError, ValueError):
        raise deny("Your session has expired. Please sign in again.")
    if not user:
        raise deny("This account no longer exists.")
    if not user["is_active"]:
        raise deny("This account has been disabled by an administrator.")
    if payload.get("pv") != password_version(user["password_hash"]):
        raise deny("Your password was changed. Please sign in again.")
    return user


def current_user(creds: HTTPAuthorizationCredentials = Depends(_bearer), ctx=Depends(get_ctx)) -> dict:
    if creds is None or creds.scheme.lower() != "bearer":
        raise HTTPException(401, "Authentication required", headers={"WWW-Authenticate": "Bearer"})
    return authenticate_token(ctx, creds.credentials)


def require(role: str):
    def dep(user: dict = Depends(current_user)) -> dict:
        if not has_role(user["role"], role):
            raise HTTPException(403, f"This action requires the {role.capitalize()} role")
        return user
    return dep
