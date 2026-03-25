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

