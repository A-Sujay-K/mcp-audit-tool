import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel

from mcp_audit.api.deps import get_repository
from mcp_audit.db.repository import AuditRepository

router = APIRouter()

class ScanRequest(BaseModel):
    config_path: str | None = None
    auto_detect: bool = True
    confirm_exploits: bool = False

async def run_scan_pipeline(scan_id: uuid.UUID, request: ScanRequest, repo: AuditRepository):
    # Dummy pipeline background task
    try:
        await repo.update_scan_status(scan_id, "completed")
        await repo.session.commit()
    except Exception:
        await repo.update_scan_status(scan_id, "failed")
        await repo.session.commit()

@router.post("/scans", status_code=202)
async def trigger_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    repo: AuditRepository = Depends(get_repository)
):
    scan = await repo.create_scan(config_path=request.config_path)
    await repo.session.commit()

    background_tasks.add_task(run_scan_pipeline, scan.id, request, repo)

    return {"scan_id": scan.id, "status": "running"}

@router.get("/scans")
async def list_scans(repo: AuditRepository = Depends(get_repository)):
    scans = await repo.get_scans()
    return scans

@router.get("/scans/{scan_id}")
async def get_scan(scan_id: uuid.UUID, repo: AuditRepository = Depends(get_repository)):
    scan = await repo.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@router.get("/scans/{scan_id}/tools")
async def get_scan_tools(scan_id: uuid.UUID, repo: AuditRepository = Depends(get_repository)):
    tools = await repo.get_tools_for_scan(scan_id)
    return tools
