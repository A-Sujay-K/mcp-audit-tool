import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass

class ScanRecord(Base):
    __tablename__ = "scans"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    start_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    end_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String, default="running")
    config_path: Mapped[str | None] = mapped_column(String, nullable=True)

    servers: Mapped[list["ServerSnapshotRecord"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    findings: Mapped[list["FindingRecord"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    drift_events: Mapped[list["DriftEventRecord"]] = relationship(back_populates="scan", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<ScanRecord(id={self.id}, status={self.status})>"

class ServerSnapshotRecord(Base):
    __tablename__ = "server_snapshots"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"))
    name: Mapped[str] = mapped_column(String)
    server_type: Mapped[str] = mapped_column(String)
    command: Mapped[str | None] = mapped_column(String, nullable=True)
    args: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    env: Mapped[dict[str, str] | None] = mapped_column(JSON, nullable=True)
    url: Mapped[str | None] = mapped_column(String, nullable=True)

    scan: Mapped["ScanRecord"] = relationship(back_populates="servers")
    tools: Mapped[list["ToolSnapshotRecord"]] = relationship(back_populates="server", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<ServerSnapshotRecord(name={self.name}, scan_id={self.scan_id})>"

class ToolSnapshotRecord(Base):
    __tablename__ = "tool_snapshots"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    server_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("server_snapshots.id"))
    name: Mapped[str] = mapped_column(String)
    description: Mapped[str | None] = mapped_column(String, nullable=True)
    input_schema: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    server: Mapped["ServerSnapshotRecord"] = relationship(back_populates="tools")
    findings: Mapped[list["FindingRecord"]] = relationship(back_populates="tool", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<ToolSnapshotRecord(name={self.name}, server_id={self.server_id})>"

class FindingRecord(Base):
