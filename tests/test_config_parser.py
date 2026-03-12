"""Tests for the config parser module."""

import json

from mcp_audit.parser.config_parser import ConfigParser
from mcp_audit.parser.schemas import TransportType


class TestConfigParser:
    """Test MCP config file parsing."""

    def test_parse_claude_desktop_config(self, tmp_path):
        """Parse a standard Claude Desktop config."""
        config_data = {
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                },
                "fetch": {
                    "command": "uvx",
                    "args": ["mcp-server-fetch"],
                },
            }
        }
        config_file = tmp_path / "claude_desktop_config.json"
        config_file.write_text(json.dumps(config_data))

        parser = ConfigParser()
        client_config = parser.parse_file(str(config_file))

        assert client_config.client_type == "claude_desktop"
        assert len(client_config.servers) == 2

        fs_server = next(s for s in client_config.servers if s.name == "filesystem")
        assert fs_server.transport == TransportType.STDIO
        assert fs_server.command == "npx"
        assert fs_server.has_auth is False

    def test_parse_cursor_config(self, tmp_path):
        """Parse a Cursor MCP config."""
        config_data = {
            "mcpServers": {
                "slack": {
                    "command": "npx",
                    "args": ["-y", "@anthropic/mcp-server-slack"],
                    "env": {
                        "SLACK_TOKEN": "xoxb-test-token",
                    },
                }
            }
        }
        config_file = tmp_path / "mcp.json"
        config_file.write_text(json.dumps(config_data))

        parser = ConfigParser()
        client_config = parser.parse_file(str(config_file))

        assert len(client_config.servers) == 1
        slack = client_config.servers[0]
        assert slack.name == "slack"
        assert slack.has_auth is True  # SLACK_TOKEN matches TOKEN pattern

    def test_detect_http_transport(self, tmp_path):
        """Detect HTTP/SSE transport from URL keys."""
        config_data = {
            "mcpServers": {
                "remote": {
                    "url": "https://example.com/mcp",
                }
            }
        }
        config_file = tmp_path / "claude_desktop_config.json"
        config_file.write_text(json.dumps(config_data))

        parser = ConfigParser()
        client_config = parser.parse_file(str(config_file))

        assert client_config.servers[0].transport == TransportType.STREAMABLE_HTTP
        assert client_config.servers[0].url == "https://example.com/mcp"

    def test_empty_config(self, tmp_path):
        """Handle empty or missing mcpServers key."""
        config_file = tmp_path / "claude_desktop_config.json"
        config_file.write_text("{}")

        parser = ConfigParser()
        client_config = parser.parse_file(str(config_file))

        assert len(client_config.servers) == 0

    def test_malformed_json(self, tmp_path):
        """Handle malformed JSON gracefully."""
        config_file = tmp_path / "broken.json"
        config_file.write_text("not valid json {{{")

        parser = ConfigParser()
        client_config = parser.parse_file(str(config_file))

        assert len(client_config.servers) == 0
