import sys
from pathlib import Path

import pytest

from mcp_sentinel.core.models import ServerTarget, TransportType
from mcp_sentinel.dynamic.client import McpTargetClient
from mcp_sentinel.rules.registry import RuleRegistry


@pytest.mark.asyncio
async def test_live_vulnerable_mcp_server() -> None:
    fixture_path = Path(__file__).parent / "fixtures" / "vulnerable_mcp_server.py"
    target = ServerTarget(
        name="vuln-server",
        transport=TransportType.STDIO,
        command=sys.executable,
        args=[str(fixture_path)],
    )

    client = McpTargetClient(target)
    tools = await client.list_tools()
    assert len(tools) == 2

    tool_names = {t.name for t in tools}
    assert "run_shell_cmd" in tool_names
    assert "read_unbounded_file" in tool_names

    # Run static rule audit against discovered tools
    registry = RuleRegistry()
    findings = registry.run_static_scan(targets=[target], tools=tools)

    rule_ids = {f.rule_id for f in findings}
    assert "MCP-SEC-006" in rule_ids  # Zero-width Unicode cloaking
    assert "MCP-SEC-008" in rule_ids  # Instruction poisoning (ignore directives)
    assert "MCP-SEC-010" in rule_ids  # Over-permissive unbounded schema sink


@pytest.mark.asyncio
async def test_live_secure_mcp_server() -> None:
    fixture_path = Path(__file__).parent / "fixtures" / "secure_mcp_server.py"
    target = ServerTarget(
        name="secure-server",
        transport=TransportType.STDIO,
        command=sys.executable,
        args=[str(fixture_path)],
    )

    client = McpTargetClient(target)
    tools = await client.list_tools()
    assert len(tools) == 1
    assert tools[0].name == "read_allowed_file"

    registry = RuleRegistry()
    findings = registry.run_static_scan(targets=[target], tools=tools)
    # Secure server tools should have zero findings
    tool_findings = [f for f in findings if f.target.endswith("read_allowed_file")]
    assert len(tool_findings) == 0
