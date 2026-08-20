#!/usr/bin/env python3
"""
CI integration example: fail the build if overall risk exceeds a threshold.

Designed to run as a step in GitHub Actions, GitLab CI, or any CI system.
Exits with code 1 (fail) if the scan finds critical trifecta risks.

Usage in GitHub Actions:
    - name: MCP Security Audit
      run: python examples/ci_integration.py --threshold 70
      env:
        MCP_AUDIT_LLM_API_KEY: ${{ secrets.OPENAI_API_KEY }}

Exit codes:
    0 -- scan passed (risk below threshold)
    1 -- scan failed (risk at or above threshold)
    2 -- scan error (could not complete)
"""
from __future__ import annotations

import argparse
import asyncio
import sys


async def scan_and_score(config_path: str | None) -> tuple[float, int]:
    """Run a full scan and return (overall_risk_pct, finding_count)."""
    try:
        from mcp_audit.parser.config_parser import ConfigParser
        from mcp_audit.parser.tool_discovery import MockToolDiscoverer
        from mcp_audit.parser.capability_classifier import RuleBasedFallbackClassifier
        from mcp_audit.graph.capability_graph import CapabilityGraphBuilder
        from mcp_audit.graph.trifecta_analyzer import TrifectaAnalyzer
        from mcp_audit.graph.risk_scorer import RiskScorer

        parser = ConfigParser()
        clients = [parser.parse_file(config_path)] if config_path else parser.auto_detect()
        servers = [s for c in clients for s in c.servers] if clients else []

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
        overall = scorer.compute_overall_risk(scored)

        return overall, len(scored)

    except Exception as e:
        print(f"::error::mcp-audit scan failed: {e}", file=sys.stderr)
        return -1.0, -1


def main() -> int:
    parser = argparse.ArgumentParser(description="mcp-audit CI gate")
    parser.add_argument("--config", help="Path to MCP client config file")
    parser.add_argument("--threshold", type=float, default=80.0,
                        help="Risk threshold to fail the build (default: 80)")
    parser.add_argument("--no-fail", action="store_true",
                        help="Report only; never fail the build")
    args = parser.parse_args()

    overall, count = asyncio.run(scan_and_score(args.config))

    if overall < 0:
        return 2  # scan error

    print(f"::notice::mcp-audit: {count} finding(s), overall risk {overall:.1f}%")

    if args.no_fail:
        return 0

    if overall >= args.threshold:
        print(
            f"::error::mcp-audit risk score {overall:.1f}% exceeds threshold "
            f"{args.threshold}%. Review the {count} finding(s).",
            file=sys.stderr,
        )
        return 1

    print(f"::notice::mcp-audit passed: risk {overall:.1f}% < threshold {args.threshold}%")
    return 0


if __name__ == "__main__":
    sys.exit(main())
