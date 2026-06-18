import uuid

from fastapi import APIRouter, Depends

from mcp_audit.api.deps import get_repository
from mcp_audit.db.repository import AuditRepository

router = APIRouter()

@router.get("/scans/{scan_id}/graph")
async def get_scan_graph(scan_id: uuid.UUID, repo: AuditRepository = Depends(get_repository)):
    return {"nodes": [], "edges": []}
