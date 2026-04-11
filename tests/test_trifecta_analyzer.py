"""Tests for the trifecta analyzer module."""


from mcp_audit.graph.capability_graph import CapabilityGraphBuilder
from mcp_audit.graph.trifecta_analyzer import TrifectaAnalyzer
from mcp_audit.parser.schemas import TrifectaType


class TestTrifectaAnalyzer:
    """Test detection of dangerous cross-server capability combinations."""

    def test_find_lethal_trifecta(self, sample_classified_tools):
        """Should detect the classic lethal trifecta pattern."""
        builder = CapabilityGraphBuilder()
        graph = builder.build(sample_classified_tools)
        analyzer = TrifectaAnalyzer(graph)

        findings = analyzer.find_lethal_trifectas()

        assert len(findings) >= 1
        trifecta = findings[0]
        assert trifecta.finding_type == TrifectaType.LETHAL_TRIFECTA
        assert trifecta.injection_tool is not None
        assert trifecta.data_tool is not None
        assert trifecta.exfil_tool is not None
        assert trifecta.is_cross_server is True

    def test_find_all_returns_combined(self, sample_classified_tools):
        """find_all() should return findings from all chain types."""
        builder = CapabilityGraphBuilder()
        graph = builder.build(sample_classified_tools)
        analyzer = TrifectaAnalyzer(graph)

        all_findings = analyzer.find_all()

        assert len(all_findings) >= 1
        types = {f.finding_type for f in all_findings}
        assert TrifectaType.LETHAL_TRIFECTA in types

    def test_no_findings_for_safe_tools(self):
        """Tools with only read capability should not trigger findings."""
        from mcp_audit.parser.schemas import ClassifiedTool, ToolCapability

        safe_tools = [
            ClassifiedTool(
                server_name="safe",
                tool_name="list_items",
                description="List items in the database.",
                capabilities=[ToolCapability.READS_SENSITIVE_DATA],
                confidence=0.9,
            ),
        ]

        builder = CapabilityGraphBuilder()
        graph = builder.build(safe_tools)
        analyzer = TrifectaAnalyzer(graph)

        assert len(analyzer.find_lethal_trifectas()) == 0
        assert len(analyzer.find_code_execution_chains()) == 0

    def test_trifecta_has_description(self, sample_classified_tools):
        """Each finding should have a human-readable attack narrative."""
        builder = CapabilityGraphBuilder()
        graph = builder.build(sample_classified_tools)
        analyzer = TrifectaAnalyzer(graph)

        findings = analyzer.find_lethal_trifectas()
        if findings:
            assert len(findings[0].description) > 20
