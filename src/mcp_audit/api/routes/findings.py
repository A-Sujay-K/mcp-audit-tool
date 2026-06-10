import uuid

from fastapi import APIRouter, Depends, HTTPException

from mcp_audit.api.deps import get_repository
from mcp_audit.db.repository import AuditRepository

router = APIRouter()

@router.get("/scans/{scan_id}/findings")
async def get_scan_findings(scan_id: uuid.UUID, repo: AuditRepository = Depends(get_repository)):
    findings = await repo.get_findings_for_scan(scan_id)
    return findings

@router.get("/findings/{finding_id}")
async def get_finding(finding_id: uuid.UUID, repo: AuditRepository = Depends(get_repository)):
    finding = await repo.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding

@router.post("/findings/{finding_id}/approve")
async def approve_finding(finding_id: uuid.UUID, repo: AuditRepository = Depends(get_repository)):
    finding = await repo.update_finding_status(finding_id, "approved")
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    await repo.session.commit()
    return finding

@router.post("/findings/{finding_id}/dismiss")
async def dismiss_finding(finding_id: uuid.UUID, repo: AuditRepository = Depends(get_repository)):
    finding = await repo.update_finding_status(finding_id, "dismissed")
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    await repo.session.commit()
    return finding
