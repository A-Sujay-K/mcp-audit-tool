"""Unit tests for ConfigParser — multiple client types and edge cases."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_audit.parser.config_parser import ConfigParser
from mcp_audit.parser.schemas import TransportType


class TestConfigParser:
    def setup_method(self):
        self.parser = ConfigParser()

    # ── Claude Desktop ────────────────────────────────────────────────────────

    def test_parse_claude_config_detects_stdio(self, claude_config_path):
        client = self.parser.parse_file(claude_config_path)
        servers = {s.name: s for s in client.servers}
        assert "filesystem" in servers
        assert servers["filesystem"].transport == TransportType.STDIO

    def test_parse_claude_config_detects_auth(self, claude_config_path):
        client = self.parser.parse_file(claude_config_path)
        servers = {s.name: s for s in client.servers}
        assert servers["slack"].has_auth is True

    def test_parse_claude_config_client_type(self, claude_config_path):
        client = self.parser.parse_file(claude_config_path)
        assert client.client_type == "claude_desktop"

    # ── Cursor ────────────────────────────────────────────────────────────────

    def test_parse_cursor_config(self, cursor_config_path):
        client = self.parser.parse_file(cursor_config_path)
        assert len(client.servers) == 1
        assert client.servers[0].name == "fetch"

    def test_parse_cursor_config_client_type(self, cursor_config_path):
        client = self.parser.parse_file(cursor_config_path)
        assert "cursor" in client.client_type.lower()

    # ── Edge cases ────────────────────────────────────────────────────────────

    def test_parse_empty_config(self, empty_config_path):
        client = self.parser.parse_file(empty_config_path)
        assert client.servers == []

    def test_parse_malformed_json_returns_empty(self, malformed_config_path):
        """Malformed JSON should not raise; it should return an empty client config."""
        client = self.parser.parse_file(malformed_config_path)
        assert client is not None
        assert client.servers == []

    def test_parse_missing_file_returns_empty(self, tmp_path):
        missing = tmp_path / "nonexistent_config.json"
        client = self.parser.parse_file(missing)
        assert client.servers == []

    def test_http_transport_detected(self, tmp_path):
        config = {
            "mcpServers": {
                "remote": {
                    "url": "https://example.com/mcp",
                    "type": "streamable_http",
                }
            }
        }
        p = tmp_path / "http_config.json"
        p.write_text(json.dumps(config))
        client = self.parser.parse_file(p)
        assert len(client.servers) == 1
        assert client.servers[0].transport in (
            TransportType.STREAMABLE_HTTP, TransportType.SSE
        )

    def test_auto_detect_returns_list(self):
        """auto_detect should return a list (possibly empty) without raising."""
        result = self.parser.auto_detect()
        assert isinstance(result, list)
