"""SHA-256 hashing for MCP tool definitions — rug-pull detection baseline.

Computes deterministic hashes of tool definitions so that any change
in name, description, or input schema between scans can be detected.
"""

from __future__ import annotations

import hashlib
import json

from mcp_audit.parser.schemas import ClassifiedTool, ToolCapability


class ToolHasher:
    """Computes and compares deterministic hashes of classified tools."""

    @staticmethod
    def hash_tool(tool: ClassifiedTool) -> str:
        """Compute a SHA-256 hash of a tool's security-relevant fields."""
        data = {
            "name": tool.tool_name,
            "description": tool.description,
            "input_schema": tool.input_schema,
            "capabilities": sorted(
                c.value if isinstance(c, ToolCapability) else c
                for c in (tool.capabilities or [])
            ),
        }
        data_str = json.dumps(data, sort_keys=True, ensure_ascii=True)
        return hashlib.sha256(data_str.encode("utf-8")).hexdigest()

    @staticmethod
    def hash_tool_set(tools: list[ClassifiedTool]) -> dict[str, str]:
        """Hash every tool in the set, keyed by 'server:tool_name'."""
        return {
            f"{t.server_name}:{t.tool_name}": ToolHasher.hash_tool(t) for t in tools
        }

    @staticmethod
    def compare_hashes(
        old: dict[str, str], new: dict[str, str]
    ) -> list[tuple[str, str, str]]:
        """Compare two hash sets, returning (key, change_type, detail) tuples."""
        events: list[tuple[str, str, str]] = []
        for key in new:
            if key not in old:
                events.append((key, "added", "Tool added in the new scan"))
            elif new[key] != old[key]:
                events.append((key, "changed", "Tool signature changed"))
        for key in old:
            if key not in new:
                events.append((key, "removed", "Tool removed in the new scan"))
        return events
