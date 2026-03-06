"""Shared Pydantic models used across every module in the MCP Audit Tool.

This is the single source of truth for data structures that flow between
the parser, graph analyser, sandbox, API, and CLI layers.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

# ════════════════════════════════════════════════════════════════════════
# Tool Capability Taxonomy
# ════════════════════════════════════════════════════════════════════════

class ToolCapability(str, Enum):
    """Security-relevant capability categories for MCP tools.

    The classifier assigns one or more of these to every discovered tool.
    """

    READS_SENSITIVE_DATA = "reads_sensitive_data"
    """Tool can read files, databases, secrets, PII, or private user data."""

    INGESTS_UNTRUSTED = "ingests_untrusted_content"
    """Tool fetches URLs, reads emails, processes user-uploaded files,
    or ingests any content not fully controlled by the tool owner."""

    SENDS_DATA_OUT = "sends_data_out"
    """Tool can make outbound HTTP requests, send emails, post to webhooks,
    or transmit data to external services."""

    EXECUTES_CODE = "executes_code"
    """Tool can run shell commands, evaluate code, or execute scripts."""

    MODIFIES_FILESYSTEM = "modifies_filesystem"
    """Tool can create, write, or delete files on the host."""

    MANAGES_CREDENTIALS = "manages_credentials"
    """Tool handles API keys, tokens, passwords, or secrets."""


# ════════════════════════════════════════════════════════════════════════
# MCP Transport & Server Configuration
# ════════════════════════════════════════════════════════════════════════

class TransportType(str, Enum):
    """MCP server transport mechanism."""

    STDIO = "stdio"
    SSE = "sse"
    STREAMABLE_HTTP = "streamable_http"


class ServerConfig(BaseModel):
    """Parsed configuration for a single MCP server from a client config file."""

    name: str = Field(..., description="Server identifier from the config key.")
    transport: TransportType = Field(default=TransportType.STDIO)
    command: str | None = Field(default=None, description="Executable command (stdio transport).")
    args: list[str] = Field(default_factory=list, description="Command arguments.")
    env: dict[str, str] = Field(default_factory=dict, description="Environment variables.")
    url: str | None = Field(default=None, description="Server URL (SSE / HTTP transport).")
    config_source: str = Field(
        default="unknown",
        description="Path to the config file this server was parsed from.",
    )
    has_auth: bool = Field(
        default=False,
        description="Whether authentication is configured for this server.",
    )


class ClientConfig(BaseModel):
    """Parsed MCP client configuration containing multiple servers."""

    client_type: str = Field(
        ..., description="Client type: claude_desktop, cursor, windsurf, generic, etc."
    )
    config_path: str = Field(..., description="Absolute path to the config file.")
    servers: list[ServerConfig] = Field(default_factory=list)


# ════════════════════════════════════════════════════════════════════════
# Tool Discovery & Classification
# ════════════════════════════════════════════════════════════════════════

class DiscoveredTool(BaseModel):
    """Raw tool definition as returned by an MCP server's tools/list response."""

    server_name: str
    tool_name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    annotations: dict[str, Any] | None = Field(
        default=None,
        description="MCP tool annotations (readOnlyHint, destructiveHint, etc.).",
    )


class ClassificationResult(BaseModel):
    """LLM classification output for a single tool."""

    capabilities: list[ToolCapability]
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str = ""


class ClassifiedTool(BaseModel):
    """A discovered tool enriched with its LLM-assigned capability classification."""

    id: UUID = Field(default_factory=uuid4)
    server_name: str
    tool_name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    capabilities: list[ToolCapability] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    reasoning: str = ""
    description_hash: str = Field(
        default="",
        description="SHA-256 hash for drift / rug-pull detection.",
    )
    annotations: dict[str, Any] | None = None
    classified_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def compute_hash(self) -> str:
        """Compute a deterministic SHA-256 hash of this tool's security-relevant fields."""
