import json
import logging
import os
from pathlib import Path
from typing import Any

from mcp_audit.parser.schemas import ClientConfig, ServerConfig, TransportType

logger = logging.getLogger(__name__)

class ConfigParser:
    """Parses MCP client configuration files from various sources."""

    def __init__(self):
        self.auth_patterns = {"token", "key", "secret", "password", "auth", "credential"}

    def _detect_client_type(self, path: Path) -> str:
        """Infer the client type from the path."""
        path_str = str(path).lower()
        if "claude_desktop_config.json" in path_str:
            return "claude_desktop"
        elif "cursor" in path_str:
            return "cursor"
        elif "windsurf" in path_str:
            return "windsurf"
        elif "zed" in path_str:
            return "zed"
        elif ".mcp.json" in path_str:
            return "claude_code"
        return "generic"

    def _has_auth(self, env: dict[str, str]) -> bool:
        """Check if environment variables contain authentication tokens."""
        for key in env.keys():
            if any(pattern in key.lower() for pattern in self.auth_patterns):
                return True
        return False

    def _parse_standard_config(self, data: dict[str, Any], client_type: str, path: Path) -> ClientConfig:
        """Parse standard MCP config format `{"mcpServers": {...}}`."""
        servers = []
        mcp_servers = data.get("mcpServers", {})

        for name, config in mcp_servers.items():
            env = config.get("env", {})
            has_auth = self._has_auth(env)

            # Transport detection
            if "command" in config:
                transport = TransportType.STDIO
                servers.append(
                    ServerConfig(
                        name=name,
                        transport=transport,
                        command=config.get("command"),
                        args=config.get("args", []),
                        env=env,
                        config_source=str(path),
                        has_auth=has_auth,
                    )
                )
            elif "url" in config or "serverUrl" in config:
