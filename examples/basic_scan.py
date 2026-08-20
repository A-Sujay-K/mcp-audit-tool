#!/usr/bin/env python3
"""
Basic example: run mcp-audit programmatically.

Shows how to call the scanner from Python without going through the CLI.
Useful for embedding in CI pipelines or custom tooling.

Usage:
    python examples/basic_scan.py
    python examples/basic_scan.py --config /path/to/claude_desktop_config.json
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path


async def run_scan(config_path: str | None = None) -> dict:
    """Run a complete audit scan and return the results dict."""
    from mcp_audit.parser.config_parser import ConfigParser
    from mcp_audit.parser.tool_discovery import MockToolDiscoverer
    from mcp_audit.parser.capability_classifier import RuleBasedFallbackClassifier
    from mcp_audit.graph.capability_graph import CapabilityGraphBuilder
    from mcp_audit.graph.trifecta_analyzer import TrifectaAnalyzer
    from mcp_audit.graph.risk_scorer import RiskScorer

    # 1. Parse config
    parser = ConfigParser()
    if config_path:
        clients = [parser.parse_file(config_path)]
    else:
        clients = parser.auto_detect()

    servers = [s for c in clients for s in c.servers] if clients else []

    if not servers:
        print("No MCP servers found. Using mock data for demonstration.")

    # 2. Discover tools (use mock for this example)
    discoverer = MockToolDiscoverer()
    discovered = await discoverer.discover_all(servers)

    # 3. Classify capabilities
    classifier = RuleBasedFallbackClassifier()
    classified = await classifier.classify_batch(discovered)

    # 4. Build graph and analyse
    builder = CapabilityGraphBuilder()
    graph = builder.build(classified)

    analyzer = TrifectaAnalyzer()
    findings = analyzer.analyze(graph, classified)

    scorer = RiskScorer()
    scored = scorer.score_all(findings)
    overall = scorer.compute_overall_risk(scored)

    return {
        "servers_scanned": len(servers),
        "tools_discovered": len(discovered),
        "findings": len(scored),
        "overall_risk_pct": round(overall, 1),
        "top_findings": [
            {
                "type": f.trifecta_type.value,
                "risk_score": round(scorer.score_finding(f), 1),
                "servers": list(f.server_names),
            }
            for f in scored[:3]
        ],
    }


def main():
    parser = argparse.ArgumentParser(description="Basic mcp-audit example")
    parser.add_argument("--config", help="Path to MCP client config file")
    parser.add_argument("--json", action="store_true", help="Output raw JSON")
    args = parser.parse_args()

    results = asyncio.run(run_scan(args.config))

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print("\n=== MCP Audit Results ===")
        print(f"Servers scanned : {results['servers_scanned']}")
        print(f"Tools discovered: {results['tools_discovered']}")
        print(f"Findings        : {results['findings']}")
        print(f"Overall risk    : {results['overall_risk_pct']}%")
        if results["top_findings"]:
            print("\nTop findings:")
            for i, f in enumerate(results["top_findings"], 1):
                print(f"  {i}. [{f['type']}] risk={f['risk_score']}  servers={f['servers']}")


if __name__ == "__main__":
    main()
