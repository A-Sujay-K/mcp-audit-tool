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
    __tablename__ = "findings"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"))
    tool_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tool_snapshots.id"))
    severity: Mapped[str] = mapped_column(String)
    category: Mapped[str] = mapped_column(String)
    description: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String, default="open")

    scan: Mapped["ScanRecord"] = relationship(back_populates="findings")
    tool: Mapped["ToolSnapshotRecord"] = relationship(back_populates="findings")
    exploit_results: Mapped[list["ExploitResultRecord"]] = relationship(back_populates="finding", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<FindingRecord(id={self.id}, severity={self.severity}, status={self.status})>"

class ExploitResultRecord(Base):
    __tablename__ = "exploit_results"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id"))
    success: Mapped[bool] = mapped_column(default=False)
    summary: Mapped[str] = mapped_column(String)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

    finding: Mapped["FindingRecord"] = relationship(back_populates="exploit_results")
    steps: Mapped[list["ExploitStepRecord"]] = relationship(back_populates="exploit_result", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<ExploitResultRecord(id={self.id}, success={self.success})>"

class ExploitStepRecord(Base):
    __tablename__ = "exploit_steps"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    exploit_result_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("exploit_results.id"))
    action: Mapped[str] = mapped_column(String)
    input_data: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    output_data: Mapped[Any | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(String, nullable=True)

    exploit_result: Mapped["ExploitResultRecord"] = relationship(back_populates="steps")

    def __repr__(self) -> str:
        return f"<ExploitStepRecord(id={self.id}, action={self.action})>"

class DriftEventRecord(Base):
    __tablename__ = "drift_events"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"))
    server_name: Mapped[str] = mapped_column(String)
    tool_name: Mapped[str | None] = mapped_column(String, nullable=True)
    event_type: Mapped[str] = mapped_column(String)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

    scan: Mapped["ScanRecord"] = relationship(back_populates="drift_events")

    def __repr__(self) -> str:
        return f"<DriftEventRecord(id={self.id}, event_type={self.event_type})>"
