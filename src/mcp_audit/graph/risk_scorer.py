"""Risk scoring for trifecta findings — cross-server weighting."""


class RiskScorer:
    def score_finding(self, finding: TrifectaFinding, server_configs: list[ServerConfig] | None = None) -> float:
        score = 0.0
        server_configs = server_configs or []

        tools = []
        if finding.injection_tool: tools.append(finding.injection_tool)
        if finding.data_tool: tools.append(finding.data_tool)
        if finding.exfil_tool: tools.append(finding.exfil_tool)

        legs = len(tools)
        if legs >= 3:
            score += 3.0
        elif legs == 2:
            score += 1.5
        elif legs == 1:
            score += 0.5

        if finding.is_cross_server:
            score += 2.0
        else:
            score += 0.5

        servers = {t.server_name for t in tools if t and t.server_name}
        for server in servers:
            config = next((c for c in server_configs if c.name == server), None)
            if config and not config.has_auth:
                score += 2.0
                break

        has_hints = False
        has_short_desc = False
        has_rce = False

        for tool in tools:
            if tool.description:
                desc_lower = tool.description.lower()
                if "destructive" in desc_lower or "open world" in desc_lower:
                    has_hints = True
                if len(tool.description) < 20:
                    has_short_desc = True

            if any(cap == ToolCapability.EXECUTES_CODE for cap in tool.capabilities):
                has_rce = True

        if has_hints: score += 1.0
        if has_short_desc: score += 1.0
        if has_rce: score += 1.0

        return min(score, 10.0)

    def score_all(self, findings: list[TrifectaFinding], server_configs: list[ServerConfig] | None = None) -> list[TrifectaFinding]:
        for f in findings:
            f.risk_score = self.score_finding(f, server_configs)
        findings.sort(key=lambda x: x.risk_score, reverse=True)
        return findings

    def compute_overall_risk(self, findings: list[TrifectaFinding], server_configs: list[ServerConfig] | None = None) -> float:
        if not findings:
            return 0.0

        scored = self.score_all(findings, server_configs)
        max_score = scored[0].risk_score

        high_severity_count = sum(1 for f in scored[1:] if f.risk_score > 7.0)
        overall = max_score + (0.5 * high_severity_count)

        return min(overall, 10.0)
