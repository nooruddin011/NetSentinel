from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect

from app.api.deps import authenticate_token
from app.security.rbac import has_role

log = logging.getLogger(__name__)
router = APIRouter()


@router.websocket("/ws/stream")
async def stream(ws: WebSocket):
    """Live event feed. Authentication is the first message ({"type":"auth","token":...}) so the JWT never
    appears in a URL or access log. Unauthenticated sockets are closed after 5 seconds."""
    ctx = ws.app.state.ctx
    origin = ws.headers.get("origin")
    if origin and origin not in ctx.settings.cors_origins and "*" not in ctx.settings.cors_origins:
        await ws.close(code=1008)
        return
    await ws.accept()
    try:
        first = await asyncio.wait_for(ws.receive_json(), timeout=5)
        user = authenticate_token(ctx, str(first.get("token", ""))) if first.get("type") == "auth" else None
        if not user or not has_role(user["role"], "viewer"):
            raise ValueError("unauthorised")
    except Exception:
        await ws.close(code=1008)
        return
    q = ctx.hub.register()
    await ws.send_json(dict(type="hello", user=user["username"], simulation=ctx.sim))
    try:
        token = str(first["token"])
        while True:
            try:
                msg = await asyncio.wait_for(q.get(), timeout=30)
            except asyncio.TimeoutError:
                authenticate_token(ctx, token)  # expired / disabled sessions stop streaming (raises HTTPException)
                await ws.send_json(dict(type="ping"))
                continue
            await ws.send_json(msg)
    except (WebSocketDisconnect, RuntimeError, HTTPException):
        pass
    finally:
        ctx.hub.unregister(q)
