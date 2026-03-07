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
        self.auth_patterns = {"token","key","secret","password","auth","credential","api_key"}

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
                transport = TransportType.STREAMABLE_HTTP  # Or SSE depending on details
                if "type" in config and config["type"] == "sse":
                    transport = TransportType.SSE
                url = config.get("url") or config.get("serverUrl")
                servers.append(
                    ServerConfig(
                        name=name,
                        transport=transport,
                        url=url,
                        env=env,
                        config_source=str(path),
                        has_auth=has_auth,
                    )
                )
            else:
                logger.warning(f"Unknown transport for server {name} in {path}")

        return ClientConfig(client_type=client_type, config_path=str(path), servers=servers)

    def _parse_zed_config(self, data: dict[str, Any], path: Path) -> ClientConfig:
        """Parse Zed context servers config format."""
        servers = []
        context_servers = data.get("context_servers", {})

        for name, config in context_servers.items():
            env = config.get("env", {})
            has_auth = self._has_auth(env)

            if "command" in config:
                servers.append(
                    ServerConfig(
                        name=name,
                        transport=TransportType.STDIO,
                        command=config.get("command"),
                        args=config.get("args", []),
                        env=env,
                        config_source=str(path),
                        has_auth=has_auth,
                    )
                )
            else:
                logger.warning(f"Unknown transport for Zed server {name} in {path}")

        return ClientConfig(client_type="zed", config_path=str(path), servers=servers)

    def parse_file(self, path: str | Path) -> ClientConfig:
        """Parse a single config file and auto-detect its format."""
        path = Path(path).resolve()
        client_type = self._detect_client_type(path)

        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)

            if "context_servers" in data:
                return self._parse_zed_config(data, path)
            else:
                return self._parse_standard_config(data, client_type, path)
        except FileNotFoundError:
            logger.error(f"Config file not found: {path}")
            return ClientConfig(client_type=client_type, config_path=str(path), servers=[])
        except json.JSONDecodeError:
            logger.error(f"Malformed JSON in config file: {path}")
            return ClientConfig(client_type=client_type, config_path=str(path), servers=[])
        except Exception as e:
            logger.error(f"Error parsing config file {path}: {e}")
            return ClientConfig(client_type=client_type, config_path=str(path), servers=[])

    def auto_detect(self) -> list[ClientConfig]:
        """Scan known OS locations for MCP configs."""
        configs = []
        home = Path.home()
        cwd = Path.cwd()

        # Define known paths
        appdata = os.environ.get("APPDATA")
        paths_to_check = []

        # Claude Desktop
        if appdata:
            paths_to_check.append(Path(appdata) / "Claude" / "claude_desktop_config.json")
        paths_to_check.append(home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json")

        # Cursor
        paths_to_check.append(cwd / ".cursor" / "mcp.json")
        paths_to_check.append(home / ".cursor" / "mcp.json")

        # Windsurf
        userprofile = os.environ.get("USERPROFILE")
        if userprofile:
            paths_to_check.append(Path(userprofile) / ".codeium" / "windsurf" / "mcp_config.json")
        paths_to_check.append(home / ".codeium" / "windsurf" / "mcp_config.json")

        # Claude Code
        paths_to_check.append(cwd / ".mcp.json")

        for path in paths_to_check:
            if path.exists() and path.is_file():
                logger.info(f"Detected config file at {path}")
                configs.append(self.parse_file(path))

        return configs
