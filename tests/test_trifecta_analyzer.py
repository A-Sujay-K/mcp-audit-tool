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
