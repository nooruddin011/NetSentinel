"""Application factory: wires the object graph, background tasks and HTTP middleware."""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.services.simmode import refresh_sim

from app.api.context import AppContext
from app.bootstrap import build_context
from app.api.routes import alerts, analytics, auth, detect, misc, sources, stream
from app.api.deps import workspace_context
from app.branding import APP_NAME
from app.config import Settings, get_settings
from app.utils.logging import setup_logging

log = logging.getLogger("cyberwatch")


async def _simulation_loop(ctx: AppContext):
    while True:
        try:
            workspace_ids = ctx.repo.list_workspace_ids()
            interval = 5.0
            for workspace_id in workspace_ids:
                tenant = workspace_context(ctx, workspace_id)
                refresh_sim(tenant)
                interval = min(interval, tenant.sim["interval"])
                if tenant.sim["enabled"] and ctx.hub.client_count_for(workspace_id):
                    ev = tenant.simulator.next_event()
                    out = await asyncio.to_thread(tenant.processor.process, ev, "stream")
                    ctx.hub.publish(dict(type="event", workspace_id=workspace_id,
                                         **{k: v for k, v in out.items() if k not in ("explanation", "class_probs")}))
            await asyncio.sleep(max(0.2, interval / max(len(workspace_ids), 1)))
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("simulation tick failed")
            await asyncio.sleep(2)


async def _retention_loop(ctx: AppContext):
    while True:
        try:
            e, a = await asyncio.to_thread(ctx.repo.purge_older_than, ctx.settings.retention_days)
            if e or a:
                log.info("Retention: purged %d events, %d alerts", e, a)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("retention purge failed")
        await asyncio.sleep(3600)


def create_app(settings: Settings | None = None, bundle=None, background: bool = True, web_model=None) -> FastAPI:
    settings = settings or get_settings()
    setup_logging(settings.db_path.parent / "logs")

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        ctx = await asyncio.to_thread(build_context, settings, bundle, web_model)
        ctx.hub.bind(asyncio.get_running_loop())
        app.state.ctx = ctx
        tasks = [asyncio.create_task(_simulation_loop(ctx)), asyncio.create_task(_retention_loop(ctx))] if background else []
        log.info("%s ready", APP_NAME)
        log.info("Detection models loaded: %s", ", ".join(ctx.pipeline.bundle.member_names))
        yield
        for t in tasks:
            t.cancel()

    app = FastAPI(title=f"{APP_NAME} - Threat Detection API", version="2.2.0", lifespan=lifespan,
                  docs_url=None if settings.is_production else "/docs", redoc_url=None, openapi_url=None if settings.is_production else "/openapi.json")
    app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=False,
                       allow_methods=["GET", "POST", "PATCH", "DELETE"], allow_headers=["Authorization", "Content-Type"])

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        if request.url.path.startswith("/api/ingest"):  # refuse oversized collector payloads before parsing them
            try:
                too_big = int(request.headers.get("content-length", "0")) > settings.ingest_max_body_bytes
            except ValueError:
                too_big = True
            if too_big:
                return JSONResponse({"detail": f"Request body exceeds {settings.ingest_max_body_bytes} bytes"}, status_code=413)
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        if request.url.path.startswith("/api"):
            resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    for r in (auth.router, alerts.router, analytics.router, detect.router, misc.router, sources.router, stream.router):
        app.include_router(r)
    return app

