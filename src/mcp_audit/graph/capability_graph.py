import networkx as nx

from mcp_audit.parser.schemas import ClassifiedTool, ToolCapability


class CapabilityGraphBuilder:
    def __init__(self):
        self.graph = nx.DiGraph()

    def build(self, tools: list[ClassifiedTool]) -> nx.DiGraph:
        for tool in tools:
            node_id = f"{tool.server_name}:{tool.tool_name}"
            self.graph.add_node(
                node_id,
                server_name=tool.server_name,
                tool_name=tool.tool_name,
                capabilities=[cap.value if hasattr(cap, 'value') else cap for cap in tool.capabilities] if tool.capabilities else [],
                confidence=tool.confidence,
                description_hash=tool.description_hash,
                description=tool.description
            )

        for source in tools:
            for target in tools:
                if source.server_name == target.server_name and source.tool_name == target.tool_name:
                    continue

                source_id = f"{source.server_name}:{source.tool_name}"
                target_id = f"{target.server_name}:{target.tool_name}"
                is_cross_server = source.server_name != target.server_name

                source_caps = source.capabilities or []
                target_caps = target.capabilities or []

                if ToolCapability.READS_SENSITIVE_DATA in source_caps and ToolCapability.SENDS_DATA_OUT in target_caps:
                    self.graph.add_edge(source_id, target_id, edge_type='data_exfiltration', is_cross_server=is_cross_server)

                if ToolCapability.INGESTS_UNTRUSTED in source_caps:
                    self.graph.add_edge(source_id, target_id, edge_type='injection_surface', is_cross_server=is_cross_server)

                if ToolCapability.INGESTS_UNTRUSTED in source_caps and ToolCapability.EXECUTES_CODE in target_caps:
                    self.graph.add_edge(source_id, target_id, edge_type='rce_path', is_cross_server=is_cross_server)

                if ToolCapability.MANAGES_CREDENTIALS in source_caps and ToolCapability.SENDS_DATA_OUT in target_caps:
                    self.graph.add_edge(source_id, target_id, edge_type='credential_theft', is_cross_server=is_cross_server)

        return self.graph

    def get_graph(self) -> nx.DiGraph:
        return self.graph

    def to_dict(self) -> dict:
        nodes = []
        for n, data in self.graph.nodes(data=True):
            nodes.append({
                "id": n,
                "server_name": data.get("server_name"),
                "tool_name": data.get("tool_name"),
                "capabilities": data.get("capabilities", []),
                "confidence": data.get("confidence"),
