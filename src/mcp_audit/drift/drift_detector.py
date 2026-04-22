"""Drift detection — identifies tool-poisoning between scan baselines."""

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
                        drift_type=DriftType.TOOL_REMOVED,
                        description=f"Tool '{tool_name}' was removed from server '{server_name}'",
                        old_hash=old_hashes.get(key),
                        severity="low",
                    )
                )

        return events

    @staticmethod
    def format_drift_report(events: list[DriftEvent]) -> str:
        """Format drift events into a human-readable Rich-compatible report."""
        if not events:
            return "[bold green]✅ No drift detected.[/bold green]"

        lines = [f"[bold red]⚠️ {len(events)} drift event(s) detected:[/bold red]\n"]
        for event in events:
            severity_colors = {
                "critical": "bold red",
                "high": "red",
                "medium": "yellow",
                "low": "dim",
            }
            color = severity_colors.get(event.severity, "white")
            lines.append(
                f"  [{color}][{event.severity.upper()}][/{color}] "
                f"{event.drift_type.value}: "
                f"[cyan]{event.server_name}:{event.tool_name}[/cyan]"
            )
            lines.append(f"    {event.description}")
            if event.old_hash and event.new_hash:
                lines.append(
                    f"    [dim]Hash: {event.old_hash[:12]}… → {event.new_hash[:12]}…[/dim]"
                )
            lines.append("")

        return "\n".join(lines)


def _has_dangerous_caps(tool: ClassifiedTool) -> bool:
    """Check if a tool has any high-risk capabilities."""
    dangerous = {
        ToolCapability.EXECUTES_CODE,
        ToolCapability.MANAGES_CREDENTIALS,
        ToolCapability.SENDS_DATA_OUT,
    }
    return bool(set(tool.capabilities or []) & dangerous)


def _classify_change(
    old: ClassifiedTool, new: ClassifiedTool
) -> tuple[DriftType, str, str]:
    """Classify what kind of drift occurred between two versions of the same tool."""
    old_caps = set(old.capabilities or [])
    new_caps = set(new.capabilities or [])

    # Capability escalation — most dangerous
    gained = new_caps - old_caps
    if gained:
        gained_strs = ", ".join(c.value if hasattr(c, "value") else c for c in gained)
        return (
            DriftType.CAPABILITY_ESCALATION,
            "critical",
            f"Tool gained new capabilities: {gained_strs}",
        )

    # Capability de-escalation — less concerning
    lost = old_caps - new_caps
    if lost:
        lost_strs = ", ".join(c.value if hasattr(c, "value") else c for c in lost)
        return (
            DriftType.CAPABILITY_DEESCALATION,
            "low",
            f"Tool lost capabilities: {lost_strs}",
        )

    # Schema change
    if old.input_schema != new.input_schema:
        return (
            DriftType.SCHEMA_CHANGED,
            "high",
            "Tool input schema has changed — may accept new attack surfaces",
        )

    # Description change — possible tool poisoning
    if old.description != new.description:
        return (
            DriftType.DESCRIPTION_CHANGED,
            "high",
            "Tool description changed — check for hidden instructions or social engineering",
        )

    # Generic catch-all
    return (
        DriftType.DESCRIPTION_CHANGED,
        "medium",
        "Tool definition changed",
    )
