from collections.abc import Sequence

from mcp_sentinel.core.models import Finding, ServerTarget, ToolDefinition
from mcp_sentinel.rules.base import BaseRule
from mcp_sentinel.rules.static.command_injection import (
    BroadFilesystemRootRule,
    DangerousCommandRule,
)
from mcp_sentinel.rules.static.poisoning import (
    BidiOverrideRule,
    InstructionPoisoningRule,
    ZeroWidthUnicodeRule,
)
from mcp_sentinel.rules.static.schema_risks import OverPermissiveSchemaRule
from mcp_sentinel.rules.static.secrets import HardcodedSecretsRule
from mcp_sentinel.rules.static.shadowing import ToolShadowingRule
from mcp_sentinel.rules.static.unpinned import UnpinnedPackageRule


class RuleRegistry:
    """Central registry and executor for static and dynamic security rules."""

    def __init__(self) -> None:
        self._rules: list[BaseRule] = []
        self._register_default_rules()

    def _register_default_rules(self) -> None:
        self.register(HardcodedSecretsRule())
        self.register(DangerousCommandRule())
        self.register(BroadFilesystemRootRule())
        self.register(UnpinnedPackageRule())
        self.register(ZeroWidthUnicodeRule())
        self.register(BidiOverrideRule())
        self.register(InstructionPoisoningRule())
        self.register(ToolShadowingRule())
        self.register(OverPermissiveSchemaRule())

    def register(self, rule: BaseRule) -> None:
        self._rules.append(rule)

    @property
    def rules(self) -> list[BaseRule]:
        return list(self._rules)

    def run_static_scan(
        self,
        targets: Sequence[ServerTarget],
        tools: Sequence[ToolDefinition] = (),
    ) -> list[Finding]:
        findings: list[Finding] = []

        # 1. Target evaluation
        for target in targets:
            for rule in self._rules:
                findings.extend(rule.evaluate_target(target))

        # 2. Individual tool evaluation
        for tool in tools:
            for rule in self._rules:
                findings.extend(rule.evaluate_tool(tool))

        # 3. Cross-target and cross-tool context evaluation
        for rule in self._rules:
            findings.extend(rule.evaluate_context(targets, tools))

        return findings
