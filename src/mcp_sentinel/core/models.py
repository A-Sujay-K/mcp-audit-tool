from __future__ import annotations

import hashlib
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class StandardMapping(BaseModel):
    cwe: list[str] = Field(default_factory=list)
    owasp_llm: list[str] = Field(default_factory=list)
    owasp_mcp: list[str] = Field(default_factory=list)


class RuleMetadata(BaseModel):
    id: str
    name: str
    severity: Severity
    description: str
    standards: StandardMapping
    remediation: str


class TransportType(str, Enum):
    STDIO = "stdio"
    SSE = "sse"
    STREAMABLE_HTTP = "streamable-http"


class ServerTarget(BaseModel):
    name: str
    transport: TransportType
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    url: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    source_file: str | None = None
    client_type: str | None = None


class ToolDefinition(BaseModel):
    name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    server_name: str = ""


class Finding(BaseModel):
    rule_id: str
    rule_name: str
    severity: Severity
    target: str
    message: str
    evidence: str
    remediation: str
    standards: StandardMapping
    fingerprint: str = ""
    location: str | None = None

    def model_post_init(self, __context: Any) -> None:
        if not self.fingerprint:
            raw = f"{self.rule_id}|{self.target}|{self.message}|{self.evidence}"
            self.fingerprint = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


class ScanReport(BaseModel):
    version: str = "0.1.0"
    timestamp: str
    targets_scanned: int = 0
    findings: list[Finding] = Field(default_factory=list)
    summary: dict[str, int] = Field(default_factory=dict)

    def recompute_summary(self) -> None:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        self.summary = counts


class BaselineEntry(BaseModel):
    tool_name: str
    schema_hash: str
    description_hash: str
    composite_hash: str


class ServerBaseline(BaseModel):
    server_name: str
    baseline_timestamp: str
    tools: dict[str, BaselineEntry] = Field(default_factory=dict)
