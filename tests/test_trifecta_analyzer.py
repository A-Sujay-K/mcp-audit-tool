"""Unit tests for TrifectaAnalyzer — detection logic and edge cases."""
from __future__ import annotations

import pytest

from mcp_audit.graph.capability_graph import CapabilityGraphBuilder
from mcp_audit.graph.trifecta_analyzer import TrifectaAnalyzer
from mcp_audit.parser.schemas import (
    ClassificationResult,
    ClassifiedTool,
    DiscoveredTool,
    ToolCapability,
    TrifectaType,
    TransportType,
)


def make_classified(
    name: str,
    server: str,
    capabilities: list[ToolCapability],
) -> ClassifiedTool:
    discovered = DiscoveredTool(
        server_name=server,
        name=name,
        description=f"Tool {name} on {server}",
        input_schema={},
        transport=TransportType.STDIO,
    )
    result = ClassificationResult(
        capabilities=capabilities,
        confidence=0.95,
        reasoning=f"Test classification for {name}",
    )
    return ClassifiedTool(
        discovered=discovered,
        classification=result,
        description_hash="abc123",
    )


READER = [ToolCapability.READS_SENSITIVE_DATA]
FETCHER = [ToolCapability.INGESTS_UNTRUSTED]
SENDER  = [ToolCapability.SENDS_DATA_OUT]


class TestTrifectaAnalyzer:
    def setup_method(self):
        self.builder  = CapabilityGraphBuilder()
        self.analyzer = TrifectaAnalyzer()

    def test_detects_trifecta_single_server(self):
        tools = [
            make_classified("read_file",  "svr", READER),
            make_classified("fetch_url",  "svr", FETCHER),
            make_classified("send_slack", "svr", SENDER),
        ]
        graph = self.builder.build(tools)
        findings = self.analyzer.analyze(graph, tools)
        assert len(findings) > 0

    def test_detects_cross_server_trifecta(self):
        tools = [
            make_classified("read_file",  "svr-a", READER),
            make_classified("fetch_url",  "svr-b", FETCHER),
            make_classified("send_email", "svr-c", SENDER),
        ]
        graph = self.builder.build(tools)
        findings = self.analyzer.analyze(graph, tools)
        cross = [f for f in findings if len(f.server_names) > 1]
        assert len(cross) > 0

    def test_no_finding_when_trifecta_incomplete(self):
        # Only reader and sender — no ingest tool
        tools = [
            make_classified("read_file",  "svr", READER),
            make_classified("send_slack", "svr", SENDER),
        ]
        graph = self.builder.build(tools)
        findings = self.analyzer.analyze(graph, tools)
        # Without ingestion, no full trifecta should be reported
        full = [f for f in findings
                if f.trifecta_type == TrifectaType.DATA_EXFILTRATION]
        assert len(full) == 0

    def test_findings_have_attack_narrative(self):
        tools = [
            make_classified("read_file",  "svr", READER),
            make_classified("fetch_url",  "svr", FETCHER),
            make_classified("send_email", "svr", SENDER),
        ]
        graph = self.builder.build(tools)
        findings = self.analyzer.analyze(graph, tools)
        for f in findings:
            assert f.attack_narrative
            assert len(f.attack_narrative) > 10

    def test_empty_tools_returns_no_findings(self):
        graph = self.builder.build([])
        findings = self.analyzer.analyze(graph, [])
        assert findings == []
