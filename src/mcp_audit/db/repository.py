import uuid

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
