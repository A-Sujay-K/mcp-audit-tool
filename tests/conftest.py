"""Shared test fixtures for the MCP Audit Tool test suite."""

import pytest

from mcp_audit.config import Settings
from mcp_audit.parser.schemas import (
    ClassifiedTool,
    DiscoveredTool,
    ServerConfig,
    ToolCapability,
    TransportType,
)


@pytest.fixture
def sample_settings():
    """Return a Settings instance with test defaults."""
    return Settings(
        llm_provider="openai",
        llm_model="gpt-4o",
        llm_api_key="test-key",
        sandbox_enabled=False,
    )


@pytest.fixture
def sample_server_configs():
    """Return raw JSON config data matching Claude Desktop format."""
    return {
        "mcpServers": {
            "filesystem": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"],
            },
            "fetch": {
                "command": "uvx",
                "args": ["mcp-server-fetch"],
            },
            "slack": {
                "command": "npx",
                "args": ["-y", "@anthropic/mcp-server-slack"],
                "env": {
                    "SLACK_TOKEN": "xoxb-test-token",
                },
            },
        }
    }


@pytest.fixture
def sample_servers():
    """Return parsed ServerConfig objects."""
    return [
        ServerConfig(
            name="filesystem",
            transport=TransportType.STDIO,
            command="npx",
            args=["-y", "@modelcontextprotocol/server-filesystem", "/"],
            has_auth=False,
        ),
        ServerConfig(
            name="fetch",
            transport=TransportType.STDIO,
            command="uvx",
            args=["mcp-server-fetch"],
            has_auth=False,
        ),
        ServerConfig(
            name="slack",
            transport=TransportType.STDIO,
            command="npx",
            args=["-y", "@anthropic/mcp-server-slack"],
            env={"SLACK_TOKEN": "xoxb-test-token"},
            has_auth=True,
        ),
    ]


@pytest.fixture
def sample_discovered_tools():
    """Return DiscoveredTool objects from mock tool discovery."""
    return [
        DiscoveredTool(
            server_name="filesystem",
            tool_name="read_file",
            description="Read the complete contents of a file from the filesystem.",
            input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
        ),
        DiscoveredTool(
            server_name="fetch",
            tool_name="fetch_url",
            description="Fetch content from a URL and return the text.",
            input_schema={"type": "object", "properties": {"url": {"type": "string"}}},
        ),
        DiscoveredTool(
            server_name="slack",
            tool_name="send_message",
            description="Send a message to a Slack channel.",
            input_schema={
                "type": "object",
                "properties": {
                    "channel": {"type": "string"},
                    "text": {"type": "string"},
                },
            },
        ),
    ]


@pytest.fixture
def sample_classified_tools():
    """Return ClassifiedTool objects with capability assignments."""
    return [
        ClassifiedTool(
            server_name="filesystem",
            tool_name="read_file",
            description="Read the complete contents of a file from the filesystem.",
            input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
            capabilities=[ToolCapability.READS_SENSITIVE_DATA],
            confidence=0.95,
        ),
        ClassifiedTool(
            server_name="fetch",
            tool_name="fetch_url",
            description="Fetch content from a URL and return the text.",
            input_schema={"type": "object", "properties": {"url": {"type": "string"}}},
            capabilities=[ToolCapability.INGESTS_UNTRUSTED],
            confidence=0.92,
        ),
        ClassifiedTool(
            server_name="slack",
            tool_name="send_message",
            description="Send a message to a Slack channel.",
            input_schema={
                "type": "object",
                "properties": {
                    "channel": {"type": "string"},
                    "text": {"type": "string"},
                },
            },
            capabilities=[ToolCapability.SENDS_DATA_OUT],
            confidence=0.97,
        ),
    ]


@pytest.fixture
def lethal_trifecta_tools(sample_classified_tools):
    """Return the classic lethal trifecta: read + ingest + send across 3 servers."""
    return sample_classified_tools
