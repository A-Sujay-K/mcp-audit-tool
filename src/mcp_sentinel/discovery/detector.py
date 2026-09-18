import os
import sys
from collections.abc import Sequence
from pathlib import Path

from mcp_sentinel.core.exceptions import ConfigParseError
from mcp_sentinel.core.models import ServerTarget
from mcp_sentinel.discovery.parsers.claude import ClaudeDesktopParser
from mcp_sentinel.discovery.parsers.cursor import CursorParser
from mcp_sentinel.discovery.parsers.mcp_json import McpJsonParser
from mcp_sentinel.discovery.parsers.vscode import VSCodeParser


def get_default_config_locations() -> list[tuple[str, Path]]:
    """Returns candidate paths for known MCP client configuration files on the current OS."""
    candidates: list[tuple[str, Path]] = []
    home = Path.home()

    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            candidates.append(("claude", Path(appdata) / "Claude" / "claude_desktop_config.json"))
        candidates.append(("cursor", home / ".cursor" / "mcp.json"))
        candidates.append(("windsurf", home / ".codeium" / "windsurf" / "mcp_config.json"))
    elif sys.platform == "darwin":
        candidates.append(
            (
                "claude",
                home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
            )
        )
        candidates.append(("cursor", home / ".cursor" / "mcp.json"))
        candidates.append(("windsurf", home / ".codeium" / "windsurf" / "mcp_config.json"))
    else:
        # Linux / Unix
        config_home = Path(os.environ.get("XDG_CONFIG_HOME", home / ".config"))
        candidates.append(("claude", config_home / "Claude" / "claude_desktop_config.json"))
        candidates.append(("cursor", home / ".cursor" / "mcp.json"))
        candidates.append(("windsurf", home / ".codeium" / "windsurf" / "mcp_config.json"))

    # Working directory candidates
    cwd = Path.cwd()
    candidates.append(("mcp-json", cwd / "mcp.json"))
    candidates.append(("mcp-json", cwd / ".mcp.json"))
    candidates.append(("vscode", cwd / ".vscode" / "mcp.json"))
    candidates.append(("cursor", cwd / ".cursor" / "mcp.json"))

    return candidates


def parse_target_file(file_path: Path) -> list[ServerTarget]:
    """Parses a specific configuration file using the appropriate parser."""
    if not file_path.exists() or not file_path.is_file():
        raise ConfigParseError(f"Target configuration file does not exist: {file_path}")

    filename = file_path.name.lower()
    if "claude" in filename or "claude_desktop" in filename:
        return ClaudeDesktopParser().parse_file(file_path)
    if "cursor" in filename:
        return CursorParser().parse_file(file_path)
    if "windsurf" in filename:
        return VSCodeParser(client_type="windsurf").parse_file(file_path)
    if "vscode" in str(file_path).lower():
        return VSCodeParser().parse_file(file_path)

    # Default to general mcp.json parser
    try:
        return McpJsonParser().parse_file(file_path)
    except ConfigParseError:
        # Fallback to Claude parser format
        return ClaudeDesktopParser().parse_file(file_path)


def discover_targets(explicit_paths: Sequence[str | Path] | None = None) -> list[ServerTarget]:
    """Discovers and parses MCP server targets from explicit paths or default system locations."""
    discovered: list[ServerTarget] = []
    seen_keys: set[str] = set()

    if explicit_paths:
        for p in explicit_paths:
            path = Path(p)
            if path.is_file():
                targets = parse_target_file(path)
                for t in targets:
                    key = f"{t.name}|{t.command}|{t.url}"
                    if key not in seen_keys:
                        seen_keys.add(key)
                        discovered.append(t)
            elif path.is_dir():
                for candidate_name in [
                    "mcp.json",
                    ".mcp.json",
                    "claude_desktop_config.json",
                    "cursor-mcp.json",
                ]:
                    sub_file = path / candidate_name
                    if sub_file.is_file():
                        for t in parse_target_file(sub_file):
                            key = f"{t.name}|{t.command}|{t.url}"
                            if key not in seen_keys:
                                seen_keys.add(key)
                                discovered.append(t)
        return discovered

    # Auto-discovery
    for client_name, path in get_default_config_locations():
        if path.is_file():
            try:
                targets = parse_target_file(path)
                for t in targets:
                    key = f"{t.name}|{t.command}|{t.url}"
                    if key not in seen_keys:
                        seen_keys.add(key)
                        discovered.append(t)
            except ConfigParseError:
                continue

    return discovered
