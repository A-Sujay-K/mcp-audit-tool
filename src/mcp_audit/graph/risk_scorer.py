from mcp_audit.parser.schemas import ServerConfig, ToolCapability, TrifectaFinding


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
