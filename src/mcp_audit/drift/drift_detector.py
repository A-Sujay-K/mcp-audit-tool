"""Drift / rug-pull detector — compares tool snapshots between scans.

Detects when MCP server operators silently change tool descriptions,
schemas, or capabilities after initial approval (the "rug-pull" attack).
"""

from __future__ import annotations

from mcp_audit.drift.hasher import ToolHasher
from mcp_audit.parser.schemas import (
    ClassifiedTool,
    DriftEvent,
    DriftType,
    ToolCapability,
)


class DriftDetector:
    """Compares two sets of classified tools to detect drift events."""

    @staticmethod
    def detect_drift(
        previous_tools: list[ClassifiedTool],
        current_tools: list[ClassifiedTool],
    ) -> list[DriftEvent]:
        """Detect all drift events between two tool snapshots.

        Returns a list of DriftEvent Pydantic models from the shared schema.
        """
        old_map = {f"{t.server_name}:{t.tool_name}": t for t in previous_tools}
        new_map = {f"{t.server_name}:{t.tool_name}": t for t in current_tools}

        old_hashes = ToolHasher.hash_tool_set(previous_tools)
        new_hashes = ToolHasher.hash_tool_set(current_tools)

        events: list[DriftEvent] = []

        # Check for additions and changes
        for key, new_tool in new_map.items():
            server_name, tool_name = key.split(":", 1)

            if key not in old_map:
                # Tool was added
                events.append(
                    DriftEvent(
                        server_name=server_name,
                        tool_name=tool_name,
                        drift_type=DriftType.TOOL_ADDED,
                        description=f"New tool '{tool_name}' appeared on server '{server_name}'",
                        new_hash=new_hashes.get(key),
                        new_capabilities=new_tool.capabilities,
                        severity="medium" if not _has_dangerous_caps(new_tool) else "high",
                    )
                )
            elif new_hashes.get(key) != old_hashes.get(key):
                old_tool = old_map[key]
                # Determine what changed
                drift_type, severity, description = _classify_change(old_tool, new_tool)
                events.append(
                    DriftEvent(
                        server_name=server_name,
                        tool_name=tool_name,
                        drift_type=drift_type,
                        description=description,
                        old_hash=old_hashes.get(key),
                        new_hash=new_hashes.get(key),
                        old_capabilities=old_tool.capabilities,
                        new_capabilities=new_tool.capabilities,
                        severity=severity,
                    )
                )

        # Check for removals
        for key in old_map:
            if key not in new_map:
                server_name, tool_name = key.split(":", 1)
                events.append(
                    DriftEvent(
                        server_name=server_name,
                        tool_name=tool_name,
