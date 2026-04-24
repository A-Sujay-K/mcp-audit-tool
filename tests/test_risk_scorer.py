"""Unit tests for RiskScorer — score bands, edge cases, overall risk."""
from __future__ import annotations

import pytest

from mcp_audit.graph.risk_scorer import RiskScorer
from mcp_audit.parser.schemas import (
    ClassifiedTool,
    ClassificationResult,
    DiscoveredTool,
    TrifectaFinding,
    TrifectaType,
    ToolCapability,
    TransportType,
)


def make_finding(
    trifecta_type: TrifectaType = TrifectaType.DATA_EXFILTRATION,
    server_names: set[str] | None = None,
    capabilities: list[ToolCapability] | None = None,
) -> TrifectaFinding:
    """Build a minimal TrifectaFinding for testing."""
    return TrifectaFinding(
        trifecta_type=trifecta_type,
        server_names=server_names or {"server-a"},
        involved_tools=[],
        attack_narrative="Test finding",
        capabilities=capabilities or [
            ToolCapability.READS_SENSITIVE_DATA,
            ToolCapability.INGESTS_UNTRUSTED,
            ToolCapability.SENDS_DATA_OUT,
        ],
    )


class TestRiskScorer:
    def setup_method(self):
        self.scorer = RiskScorer()

    def test_score_returns_float_in_range(self):
        finding = make_finding()
        score = self.scorer.score_finding(finding)
        assert 0.0 <= score <= 100.0

    def test_cross_server_finding_scores_higher(self):
        single = make_finding(server_names={"server-a"})
        multi  = make_finding(server_names={"server-a", "server-b"})
        assert self.scorer.score_finding(multi) > self.scorer.score_finding(single)

    def test_more_capabilities_scores_higher(self):
        few  = make_finding(capabilities=[ToolCapability.READS_SENSITIVE_DATA])
        many = make_finding(capabilities=[
            ToolCapability.READS_SENSITIVE_DATA,
            ToolCapability.INGESTS_UNTRUSTED,
            ToolCapability.SENDS_DATA_OUT,
            ToolCapability.EXECUTES_CODE,
        ])
        assert self.scorer.score_finding(many) > self.scorer.score_finding(few)

    def test_overall_risk_empty_list(self):
        assert self.scorer.compute_overall_risk([]) == 0.0

    def test_overall_risk_single_finding(self):
        finding = make_finding()
        scored = self.scorer.score_all([finding])
        overall = self.scorer.compute_overall_risk(scored)
        assert 0.0 <= overall <= 100.0

    def test_score_all_preserves_order(self):
        findings = [
            make_finding(trifecta_type=TrifectaType.DATA_EXFILTRATION),
            make_finding(trifecta_type=TrifectaType.CODE_EXECUTION_CHAIN),
        ]
        scored = self.scorer.score_all(findings)
        assert len(scored) == 2
        # Higher-scoring finding should appear first after sort
        scores = [self.scorer.score_finding(f) for f in scored]
        assert scores == sorted(scores, reverse=True)

    def test_credential_theft_type_scores_high(self):
        finding = make_finding(trifecta_type=TrifectaType.CREDENTIAL_THEFT)
        score = self.scorer.score_finding(finding)
        assert score >= 30.0  # credential theft should never be trivial

    def test_score_all_returns_list(self):
        findings = [make_finding() for _ in range(5)]
        result = self.scorer.score_all(findings)
        assert isinstance(result, list)
        assert len(result) == 5
