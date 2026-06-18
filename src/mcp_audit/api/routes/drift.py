from fastapi import APIRouter, Depends

from mcp_audit.api.deps import get_repository
from mcp_audit.db.repository import AuditRepository

router = APIRouter()

@router.get("/drift")
async def list_drift_events(repo: AuditRepository = Depends(get_repository)):
    events = await repo.get_drift_events()
    return events

@router.post("/drift/check", status_code=202)
async def trigger_drift_check():
    return {"status": "drift check triggered"}
