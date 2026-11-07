from __future__ import annotations

import os
import re

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile

from app.api.deps import client_ip, get_ctx, require
from app.schemas.api import DetectEvent, SimulateRequest
from app.services.ingestion import loader

router = APIRouter(prefix="/api", tags=["detection"])


@router.post("/detect/event")
def detect_event(body: DetectEvent, request: Request, user=Depends(require("analyst")), ctx=Depends(get_ctx)):
    """Analyse one request/flow. The text payload is inspected server-side; client-supplied payload features are ignored."""
    raw = dict(body.features)
    raw.update({k: v for k, v in dict(src_ip=body.src_ip, dst_ip=body.dst_ip, protocol=body.protocol,
                                     payload_sample=body.payload_sample).items() if v is not None})
    raw.setdefault("src_ip", client_ip(request))
    out = ctx.processor.process(raw, origin="api")
    ctx.hub.publish(dict(type="event", **{k: v for k, v in out.items() if k not in ("explanation", "class_probs")}))
    return out


@router.post("/lab/simulate")
def lab_simulate(body: SimulateRequest, request: Request, user=Depends(require("analyst")), ctx=Depends(get_ctx)):
    """Inject a scenario from the traffic simulator. The detector gets NO label: it must classify it."""
    ev, truth = ctx.simulator.next_event(body.scenario)
    out = ctx.processor.process(ev, origin="lab")
    out["injected_scenario"] = truth
    out["correct"] = (out["attack_type"] == truth)
    ctx.hub.publish(dict(type="event", **{k: v for k, v in out.items() if k not in ("explanation", "class_probs")}))
    ctx.repo.audit(user["username"], "lab.simulate", truth, f"detected={out['attack_type']}", client_ip(request))
    return out


@router.post("/detect/upload")
def upload(request: Request, file: UploadFile = File(...), user=Depends(require("analyst")), ctx=Depends(get_ctx)):
    s = ctx.settings
    name = re.sub(r"[^A-Za-z0-9_.-]", "_", os.path.basename(file.filename or "upload.csv"))[:100]
    if not name.lower().endswith(".csv"):
        raise HTTPException(415, "Only .csv files are accepted")
    limit = s.max_upload_mb * 1024 * 1024
    data = file.file.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(413, f"File exceeds {s.max_upload_mb} MB")
    job_id = ctx.repo.create_job(name, user["username"])
    try:
        df = loader.read_upload(data, s.max_upload_rows)
        summary = ctx.processor.process_dataframe(df, job_id)
    except loader.UploadError as exc:
        ctx.repo.finish_job(job_id, "failed", error=str(exc)[:300])
        raise HTTPException(422, str(exc))
    except Exception:
        ctx.repo.finish_job(job_id, "failed", error="internal error")
        raise
    ctx.repo.finish_job(job_id, "done", summary["rows"], summary["flagged"], summary)
    ctx.repo.audit(user["username"], "upload.analyse", name, f"rows={summary['rows']} flagged={summary['flagged']}", client_ip(request))
    return dict(job_id=job_id, **summary)


def _visible(user, job) -> bool:
    return user["role"] == "admin" or job["created_by"] == user["username"]


@router.get("/detect/jobs")
def jobs(user=Depends(require("viewer")), ctx=Depends(get_ctx)):
    """Admins see every upload; everyone else sees only their own."""
    return dict(jobs=ctx.repo.list_jobs(50, None if user["role"] == "admin" else user["username"]))


@router.get("/detect/jobs/{job_id}")
def job(job_id: int, user=Depends(require("viewer")), ctx=Depends(get_ctx)):
    j = ctx.repo.get_job(job_id)
    if not j or not _visible(user, j):  # 404 (not 403) so other users' job ids cannot be probed
        raise HTTPException(404, "Job not found")
    return j


@router.delete("/detect/jobs/{job_id}")
def delete_job(job_id: int, request: Request, delete_findings: bool = False, user=Depends(require("viewer")), ctx=Depends(get_ctx)):
    """Delete an upload log. Admins can delete any; Analysts/Viewers only their own.
    `delete_findings=true` also removes the alerts and events that upload produced."""
    j = ctx.repo.get_job(job_id)
    if not j or not _visible(user, j):
        raise HTTPException(404, "Job not found")
    res = ctx.repo.delete_job(job_id, delete_findings)
    ctx.repo.audit(user["username"], "upload.delete", f"{j['filename']} (#{job_id}, by {j['created_by']})",
                   f"findings_deleted={delete_findings}", client_ip(request))
    return dict(status="ok", **res)
