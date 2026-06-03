"""Async SQLAlchemy repository — scan, finding, and drift storage."""

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from mcp_audit.config import Settings
from mcp_audit.db.models import (
    Base,
    DriftEventRecord,
    ExploitResultRecord,
    FindingRecord,
    ScanRecord,
    ServerSnapshotRecord,
    ToolSnapshotRecord,
)


def get_engine(settings: Settings):
    return create_async_engine(settings.db_url, echo=settings.db_echo)

def get_async_session_factory(engine):
    return async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

async def init_db(engine):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

class AuditRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_scan(self, config_path: str | None = None) -> ScanRecord:
        scan = ScanRecord(config_path=config_path)
        self.session.add(scan)
        await self.session.flush()
        return scan

    async def get_scan(self, scan_id: uuid.UUID) -> ScanRecord | None:
        result = await self.session.execute(select(ScanRecord).where(ScanRecord.id == scan_id))
        return result.scalar_one_or_none()

    async def get_scans(self) -> list[ScanRecord]:
        result = await self.session.execute(select(ScanRecord).order_by(ScanRecord.start_time.desc()))
        return list(result.scalars().all())

    async def update_scan_status(self, scan_id: uuid.UUID, status: str, end_time=None) -> ScanRecord | None:
        values = {"status": status}
        if end_time:
            values["end_time"] = end_time
        await self.session.execute(update(ScanRecord).where(ScanRecord.id == scan_id).values(**values))
        await self.session.flush()
        return await self.get_scan(scan_id)

    async def create_server(self, server: ServerSnapshotRecord) -> ServerSnapshotRecord:
        self.session.add(server)
        await self.session.flush()
        return server

    async def create_tool(self, tool: ToolSnapshotRecord) -> ToolSnapshotRecord:
        self.session.add(tool)
        await self.session.flush()
        return tool

    async def get_tools_for_scan(self, scan_id: uuid.UUID) -> list[ToolSnapshotRecord]:
        stmt = select(ToolSnapshotRecord).join(ServerSnapshotRecord).where(ServerSnapshotRecord.scan_id == scan_id)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def create_finding(self, finding: FindingRecord) -> FindingRecord:
        self.session.add(finding)
        await self.session.flush()
        return finding

    async def get_findings_for_scan(self, scan_id: uuid.UUID) -> list[FindingRecord]:
        result = await self.session.execute(select(FindingRecord).where(FindingRecord.scan_id == scan_id))
        return list(result.scalars().all())

    async def get_finding(self, finding_id: uuid.UUID) -> FindingRecord | None:
        result = await self.session.execute(select(FindingRecord).where(FindingRecord.id == finding_id))
        return result.scalar_one_or_none()

    async def update_finding_status(self, finding_id: uuid.UUID, status: str) -> FindingRecord | None:
        await self.session.execute(update(FindingRecord).where(FindingRecord.id == finding_id).values(status=status))
        await self.session.flush()
        return await self.get_finding(finding_id)

    async def create_exploit_result(self, result: ExploitResultRecord) -> ExploitResultRecord:
        self.session.add(result)
        await self.session.flush()
        return result

    async def create_drift_event(self, event: DriftEventRecord) -> DriftEventRecord:
        self.session.add(event)
        await self.session.flush()
        return event

    async def get_drift_events(self) -> list[DriftEventRecord]:
        result = await self.session.execute(select(DriftEventRecord).order_by(DriftEventRecord.timestamp.desc()))
        return list(result.scalars().all())
