from abc import ABC, abstractmethod
from collections.abc import Sequence

from mcp_sentinel.core.models import Finding, RuleMetadata, ServerTarget, ToolDefinition


class BaseRule(ABC):
    """Abstract base class for all static and dynamic security rules."""

    @property
    @abstractmethod
    def metadata(self) -> RuleMetadata:
        """Returns rule identification, severity, standards mapping, and remediation guidance."""

    def evaluate_target(self, target: ServerTarget) -> list[Finding]:
        """Evaluates a single MCP server configuration target."""
        return []

    def evaluate_tool(self, tool: ToolDefinition) -> list[Finding]:
        """Evaluates a single discovered tool manifest or schema."""
        return []

    def evaluate_context(
        self,
        targets: Sequence[ServerTarget],
        tools: Sequence[ToolDefinition],
    ) -> list[Finding]:
        """Evaluates multi-target or cross-tool context (e.g. shadowing, collisions)."""
        return []
