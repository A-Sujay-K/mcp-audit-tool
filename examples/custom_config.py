#!/usr/bin/env python3
"""
Custom config example: override settings and use a specific config file.

Demonstrates loading settings from environment variables, parsing a specific
MCP client config file, and exporting findings to SARIF format.

Usage:
    MCP_AUDIT_LLM_PROVIDER=openai python examples/custom_config.py
"""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
from pathlib import Path


SAMPLE_CONFIG = {
    "mcpServers": {
        "filesystem": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/user/docs"],
        },
        "slack": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-slack"],
            "env": {
                "SLACK_BOT_TOKEN": "xoxb-demo-token-placeholder",
                "SLACK_TEAM_ID": "T0123456789",
            },
        },
        "fetch": {
            "command": "uvx",
            "args": ["mcp-server-fetch"],
        },
    }
}


def build_sarif(findings: list, tool_version: str = "0.1.0") -> dict:
    """Build a minimal SARIF 2.1.0 document from findings."""
    rules = []
    results = []

    for i, f in enumerate(findings):
        rule_id = f"MCP{i:04d}"
        rules.append({
            "id": rule_id,
            "name": f.trifecta_type.value.replace("_", " ").title(),
            "shortDescription": {"text": f.trifecta_type.value},
            "helpUri": (
                "https://github.com/A-Sujay-K/mcp-audit-tool"
                "/blob/main/docs/security_model.md"
            ),
        })
        results.append({
            "ruleId": rule_id,
            "level": "error",
            "message": {"text": getattr(f, "attack_narrative", str(f.trifecta_type.value))},
            "locations": [],
        })

    return {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec"
            "/master/Schemata/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "mcp-audit",
                    "version": tool_version,
                    "rules": rules,
                }
            },
            "results": results,
        }],
    }


async def main():
    from mcp_audit.parser.config_parser import ConfigParser
    from mcp_audit.parser.tool_discovery import MockToolDiscoverer
    from mcp_audit.parser.capability_classifier import RuleBasedFallbackClassifier
    from mcp_audit.graph.capability_graph import CapabilityGraphBuilder
    from mcp_audit.graph.trifecta_analyzer import TrifectaAnalyzer
    from mcp_audit.graph.risk_scorer import RiskScorer

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(SAMPLE_CONFIG, f)
        tmp_path = f.name

    try:
        parser = ConfigParser()
        client = parser.parse_file(tmp_path)
        servers = client.servers

        discoverer = MockToolDiscoverer()
        discovered = await discoverer.discover_all(servers)

        classifier = RuleBasedFallbackClassifier()
        classified = await classifier.classify_batch(discovered)

        builder = CapabilityGraphBuilder()
        graph = builder.build(classified)

        analyzer = TrifectaAnalyzer()
        findings = analyzer.analyze(graph, classified)

        scorer = RiskScorer()
        scored = scorer.score_all(findings)

        sarif = build_sarif(scored)
        output = Path("mcp-audit-results.sarif.json")
        output.write_text(json.dumps(sarif, indent=2))
        print(f"SARIF report written to {output.resolve()}")
        print(f"Found {len(scored)} findings.")
        print(f"Overall risk: {scorer.compute_overall_risk(scored):.0f}%")
    finally:
        os.unlink(tmp_path)


if __name__ == "__main__":
    asyncio.run(main())
