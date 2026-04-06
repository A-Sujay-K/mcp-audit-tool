import networkx as nx

from mcp_audit.parser.schemas import ClassifiedTool, ToolCapability, TrifectaFinding, TrifectaType


class TrifectaAnalyzer:
    def __init__(self, graph: nx.DiGraph):
        self.graph = graph

    def _get_tools_with_capability(self, capability: ToolCapability) -> list[dict]:
        tools = []
        for n, data in self.graph.nodes(data=True):
            caps = data.get("capabilities", [])
            cap_val = capability.value if hasattr(capability, 'value') else capability
            if cap_val in caps or capability in caps:
                tools.append({"id": n, **data})
        return tools

    def _create_dummy_tool(self, node_data: dict) -> ClassifiedTool:
        return ClassifiedTool(
            server_name=node_data.get("server_name", ""),
            tool_name=node_data.get("tool_name", ""),
            description=node_data.get("description", ""),
            capabilities=[],
            confidence=node_data.get("confidence", 0.0)
        )

    def find_lethal_trifectas(self) -> list[TrifectaFinding]:
        findings = []
        ingest_tools = self._get_tools_with_capability(ToolCapability.INGESTS_UNTRUSTED)
        read_tools = self._get_tools_with_capability(ToolCapability.READS_SENSITIVE_DATA)
        exfil_tools = self._get_tools_with_capability(ToolCapability.SENDS_DATA_OUT)

        for inj in ingest_tools:
            for read in read_tools:
                for exfil in exfil_tools:
                    is_cross_server = len({inj.get('server_name'), read.get('server_name'), exfil.get('server_name')}) > 1

                    finding = TrifectaFinding(
                        finding_type=TrifectaType.LETHAL_TRIFECTA,
                        injection_tool=self._create_dummy_tool(inj),
                        data_tool=self._create_dummy_tool(read),
                        exfil_tool=self._create_dummy_tool(exfil),
                        is_cross_server=is_cross_server,
                        description=f"An attacker could embed a prompt injection in content fetched by '{inj['tool_name']}' on server '{inj['server_name']}', instruct the agent to read sensitive data via '{read['tool_name']}' on server '{read['server_name']}', and exfiltrate it through '{exfil['tool_name']}' on server '{exfil['server_name']}'.",
                        mitigation="Isolate these tools on different agent contexts or implement strict authorization and human-in-the-loop approvals for data exfiltration."
                    )
                    findings.append(finding)
        return findings

    def find_code_execution_chains(self) -> list[TrifectaFinding]:
        findings = []
        ingest_tools = self._get_tools_with_capability(ToolCapability.INGESTS_UNTRUSTED)
        exec_tools = self._get_tools_with_capability(ToolCapability.EXECUTES_CODE)

        for inj in ingest_tools:
            for exc in exec_tools:
                is_cross_server = inj.get('server_name') != exc.get('server_name')

                finding = TrifectaFinding(
                    finding_type=TrifectaType.CODE_EXECUTION_CHAIN,
                    injection_tool=self._create_dummy_tool(inj),
                    exfil_tool=self._create_dummy_tool(exc),
                    is_cross_server=is_cross_server,
                    description=f"An attacker could provide malicious instructions via '{inj['tool_name']}' to execute arbitrary code via '{exc['tool_name']}'.",
                    mitigation="Implement a sandbox for code execution or remove arbitrary code execution capabilities."
                )
                findings.append(finding)
        return findings

    def find_credential_theft_chains(self) -> list[TrifectaFinding]:
        findings = []
        cred_tools = self._get_tools_with_capability(ToolCapability.MANAGES_CREDENTIALS)
        exfil_tools = self._get_tools_with_capability(ToolCapability.SENDS_DATA_OUT)

        for cred in cred_tools:
            for exfil in exfil_tools:
                is_cross_server = cred.get('server_name') != exfil.get('server_name')

                finding = TrifectaFinding(
                    finding_type=TrifectaType.CREDENTIAL_THEFT,
                    data_tool=self._create_dummy_tool(cred),
                    exfil_tool=self._create_dummy_tool(exfil),
                    is_cross_server=is_cross_server,
