import json
from pathlib import Path
from typing import Any

from mcp_sentinel.core.exceptions import ConfigParseError
from mcp_sentinel.core.models import ServerTarget
from mcp_sentinel.discovery.parsers.base import BaseConfigParser


class McpJsonParser(BaseConfigParser):
    """Parser for standard root mcp.json files."""

    def parse_file(self, path: Path) -> list[ServerTarget]:
        if not path.is_file():
            raise ConfigParseError(f"mcp.json file not found: {path}")
        try:
            content = path.read_text(encoding="utf-8")
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise ConfigParseError(f"Malformed JSON in mcp.json {path}: {e}") from e
        except OSError as e:
            raise ConfigParseError(f"Failed to read mcp.json {path}: {e}") from e

        return self.parse_dict(data, source=str(path))

    def parse_dict(self, data: dict[str, Any], source: str = "") -> list[ServerTarget]:
        targets: list[ServerTarget] = []
        servers_block = data.get("mcpServers") or data.get("servers") or {}

        if isinstance(servers_block, dict):
            for name, config in servers_block.items():
                if isinstance(config, dict):
                    targets.append(self._build_target(str(name), config, source))
        elif isinstance(servers_block, list):
            for item in servers_block:
                if isinstance(item, dict):
                    name = str(item.get("name") or item.get("id") or "unnamed-server")
                    targets.append(self._build_target(name, item, source))

        return targets

    def _build_target(self, name: str, config: dict[str, Any], source: str) -> ServerTarget:
        transport = self.infer_transport(config)
        command = config.get("command")
        args = (
            [str(a) for a in config.get("args", [])] if isinstance(config.get("args"), list) else []
        )
        env = (
            {str(k): str(v) for k, v in config.get("env", {}).items()}
            if isinstance(config.get("env"), dict)
            else {}
        )
        url = config.get("url")
        headers = (
            {str(k): str(v) for k, v in config.get("headers", {}).items()}
            if isinstance(config.get("headers"), dict)
            else {}
        )

        return ServerTarget(
            name=name,
            transport=transport,
            command=str(command) if command is not None else None,
            args=args,
            env=env,
            url=str(url) if url is not None else None,
            headers=headers,
            source_file=source or None,
            client_type="mcp-json",
        )
