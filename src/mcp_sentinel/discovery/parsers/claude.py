import json
from pathlib import Path
from typing import Any

from mcp_sentinel.core.exceptions import ConfigParseError
from mcp_sentinel.core.models import ServerTarget
from mcp_sentinel.discovery.parsers.base import BaseConfigParser


class ClaudeDesktopParser(BaseConfigParser):
    """Parser for Claude Desktop configuration format (claude_desktop_config.json)."""

    def parse_file(self, path: Path) -> list[ServerTarget]:
        if not path.is_file():
            raise ConfigParseError(f"Configuration file not found: {path}")
        try:
            content = path.read_text(encoding="utf-8")
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise ConfigParseError(f"Malformed JSON in {path}: {e}") from e
        except OSError as e:
            raise ConfigParseError(f"Failed to read {path}: {e}") from e

        return self.parse_dict(data, source=str(path))

    def parse_dict(self, data: dict[str, Any], source: str = "") -> list[ServerTarget]:
        servers_block = data.get("mcpServers", {})
        if not isinstance(servers_block, dict):
            raise ConfigParseError(f"'mcpServers' must be a dictionary in {source or 'input data'}")

        targets: list[ServerTarget] = []
        for name, config in servers_block.items():
            if not isinstance(config, dict):
                continue

            transport = self.infer_transport(config)
            command = config.get("command")
            args = (
                [str(a) for a in config.get("args", [])]
                if isinstance(config.get("args"), list)
                else []
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

            targets.append(
                ServerTarget(
                    name=str(name),
                    transport=transport,
                    command=str(command) if command is not None else None,
                    args=args,
                    env=env,
                    url=str(url) if url is not None else None,
                    headers=headers,
                    source_file=source or None,
                    client_type="claude-desktop",
                )
            )
        return targets
