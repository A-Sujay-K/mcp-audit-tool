"""Tests for the risk scorer module."""


from mcp_audit.graph.capability_graph import CapabilityGraphBuilder
from mcp_audit.graph.risk_scorer import RiskScorer
from mcp_audit.graph.trifecta_analyzer import TrifectaAnalyzer


class TestRiskScorer:
    """Test risk scoring of findings."""

    def test_score_trifecta_is_high(self, sample_classified_tools, sample_servers):
        """A full lethal trifecta should score high (>6)."""
        builder = CapabilityGraphBuilder()
        graph = builder.build(sample_classified_tools)
        analyzer = TrifectaAnalyzer(graph)
        findings = analyzer.find_lethal_trifectas()

        assert len(findings) > 0
        scorer = RiskScorer()
        scored = scorer.score_all(findings, sample_servers)

        assert scored[0].risk_score > 6.0

    def test_scores_are_sorted_descending(self, sample_classified_tools, sample_servers):
        """score_all should return findings sorted by risk score descending."""
        builder = CapabilityGraphBuilder()
        graph = builder.build(sample_classified_tools)
        analyzer = TrifectaAnalyzer(graph)
        findings = analyzer.find_all()

        scorer = RiskScorer()
        scored = scorer.score_all(findings, sample_servers)

        for i in range(len(scored) - 1):
            assert scored[i].risk_score >= scored[i + 1].risk_score

    def test_score_is_bounded(self, sample_classified_tools, sample_servers):
        """All scores should be in [0, 10]."""
        builder = CapabilityGraphBuilder()
        graph = builder.build(sample_classified_tools)
        analyzer = TrifectaAnalyzer(graph)
        findings = analyzer.find_all()

        scorer = RiskScorer()
        scored = scorer.score_all(findings, sample_servers)

        for f in scored:
            assert 0 <= f.risk_score <= 10.0

    def test_overall_risk(self, sample_classified_tools, sample_servers):
        """Overall risk should be at least as high as the max finding."""
        builder = CapabilityGraphBuilder()
        graph = builder.build(sample_classified_tools)
        analyzer = TrifectaAnalyzer(graph)
        findings = analyzer.find_all()

        scorer = RiskScorer()
        scored = scorer.score_all(findings, sample_servers)
        overall = scorer.compute_overall_risk(scored)

        if scored:
            assert overall >= scored[0].risk_score
        assert 0 <= overall <= 10.0
