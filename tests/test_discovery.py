import json
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from mcp_sentinel.core.exceptions import ConfigParseError
from mcp_sentinel.core.models import TransportType
from mcp_sentinel.discovery.detector import discover_targets
from mcp_sentinel.discovery.parsers.claude import ClaudeDesktopParser
from mcp_sentinel.discovery.parsers.cursor import CursorParser
from mcp_sentinel.discovery.parsers.mcp_json import McpJsonParser
from mcp_sentinel.discovery.parsers.vscode import VSCodeParser


def test_claude_parser_stdio_and_sse(tmp_path: Path) -> None:
    config = {
        "mcpServers": {
            "sqlite-server": {
                "command": "uvx",
                "args": ["mcp-server-sqlite", "--db-path", "test.db"],
                "env": {"DEBUG": "1"},
            },
            "remote-sse": {
                "url": "https://mcp.example.com/sse",
                "headers": {"Authorization": "Bearer token"},
            },
        }
    }
    cfg_file = tmp_path / "claude_desktop_config.json"
    cfg_file.write_text(json.dumps(config), encoding="utf-8")

    parser = ClaudeDesktopParser()
    targets = parser.parse_file(cfg_file)

    assert len(targets) == 2
    t1 = next(t for t in targets if t.name == "sqlite-server")
    assert t1.transport == TransportType.STDIO
    assert t1.command == "uvx"
    assert t1.args == ["mcp-server-sqlite", "--db-path", "test.db"]
    assert t1.env == {"DEBUG": "1"}
    assert t1.client_type == "claude-desktop"

    t2 = next(t for t in targets if t.name == "remote-sse")
    assert t2.transport == TransportType.SSE
    assert t2.url == "https://mcp.example.com/sse"
    assert t2.headers == {"Authorization": "Bearer token"}


def test_cursor_parser(tmp_path: Path) -> None:
    config = {
        "servers": [
            {
                "name": "filesystem",
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
            }
        ]
    }
    cfg_file = tmp_path / "cursor-mcp.json"
    cfg_file.write_text(json.dumps(config), encoding="utf-8")

    parser = CursorParser()
    targets = parser.parse_file(cfg_file)
    assert len(targets) == 1
    assert targets[0].name == "filesystem"
    assert targets[0].client_type == "cursor"


def test_vscode_and_windsurf_parser(tmp_path: Path) -> None:
    config = {"mcpServers": {"fetch": {"command": "python", "args": ["-m", "mcp_server_fetch"]}}}
    cfg_file = tmp_path / "mcp_config.json"
    cfg_file.write_text(json.dumps(config), encoding="utf-8")

    parser = VSCodeParser(client_type="windsurf")
    targets = parser.parse_file(cfg_file)
    assert len(targets) == 1
    assert targets[0].name == "fetch"
    assert targets[0].client_type == "windsurf"


def test_mcp_json_parser(tmp_path: Path) -> None:
    config = {
        "mcpServers": {
            "git-server": {"command": "docker", "args": ["run", "-i", "--rm", "mcp/git"]}
        }
    }
    cfg_file = tmp_path / "mcp.json"
    cfg_file.write_text(json.dumps(config), encoding="utf-8")

    parser = McpJsonParser()
    targets = parser.parse_file(cfg_file)
    assert len(targets) == 1
    assert targets[0].name == "git-server"


def test_malformed_json_raises_config_error(tmp_path: Path) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text("{ unquoted_key: 123, }", encoding="utf-8")
    with pytest.raises(ConfigParseError):
        ClaudeDesktopParser().parse_file(broken)


def test_discover_targets_directory(tmp_path: Path) -> None:
    config = {"mcpServers": {"test-srv": {"command": "node", "args": ["index.js"]}}}
    (tmp_path / "mcp.json").write_text(json.dumps(config), encoding="utf-8")
    targets = discover_targets([tmp_path])
    assert len(targets) == 1
    assert targets[0].name == "test-srv"


@given(st.text())
def test_hypothesis_fuzz_json_parsing(text: str) -> None:
    """Hypothesis fuzzing to ensure arbitrary strings never cause unhandled crashes."""
    parser = McpJsonParser()
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            # parse_dict should safely parse or handle valid dicts without crashing
            parser.parse_dict(data)
    except (json.JSONDecodeError, ConfigParseError, TypeError, ValueError):
        # Expected domain rejections
        pass
