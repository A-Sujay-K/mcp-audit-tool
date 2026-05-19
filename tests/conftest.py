"""Shared pytest fixtures for the mcp-audit test suite."""
from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from typing import AsyncGenerator

import pytest
import pytest_asyncio


# ── Async event loop ─────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def event_loop():
    """Create a single event loop for the entire test session."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# ── Config file fixtures ─────────────────────────────────────────────────────

@pytest.fixture
def claude_config_path(tmp_path: Path) -> Path:
    """Write a sample Claude Desktop config to a temp file."""
    config = {
        "mcpServers": {
            "filesystem": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
            },
            "slack": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-slack"],
                "env": {"SLACK_BOT_TOKEN": "xoxb-test-token"},
            },
        }
    }
    p = tmp_path / "claude_desktop_config.json"
    p.write_text(json.dumps(config))
    return p


@pytest.fixture
def cursor_config_path(tmp_path: Path) -> Path:
    """Write a sample Cursor MCP config to a temp file."""
    config = {
        "mcpServers": {
            "fetch": {
                "command": "uvx",
                "args": ["mcp-server-fetch"],
            }
        }
    }
    p = tmp_path / "mcp.json"
    p.write_text(json.dumps(config))
    return p


@pytest.fixture
def empty_config_path(tmp_path: Path) -> Path:
    """Write an empty MCP config."""
    p = tmp_path / "empty_config.json"
    p.write_text(json.dumps({"mcpServers": {}}))
    return p


@pytest.fixture
def malformed_config_path(tmp_path: Path) -> Path:
    """Write a malformed JSON file."""
    p = tmp_path / "bad_config.json"
    p.write_text("{ this is not valid json }")
    return p


# ── Tool fixture helpers ──────────────────────────────────────────────────────

@pytest.fixture
def mock_discovered_tools():
    """Return a list of mock discovered tools covering all capability types."""
    from mcp_audit.parser.schemas import DiscoveredTool, TransportType
    return [
        DiscoveredTool(
            server_name="filesystem",
            name="read_file",
            description="Read the contents of a file at the specified path",
            input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
            transport=TransportType.STDIO,
        ),
        DiscoveredTool(
            server_name="fetch",
            name="fetch_url",
            description="Fetch content from a URL and return the response body",
            input_schema={"type": "object", "properties": {"url": {"type": "string"}}},
            transport=TransportType.STDIO,
        ),
        DiscoveredTool(
            server_name="slack",
            name="send_message",
            description="Send a message to a Slack channel",
            input_schema={"type": "object", "properties": {
                "channel": {"type": "string"}, "text": {"type": "string"}
            }},
            transport=TransportType.STDIO,
        ),
    ]
