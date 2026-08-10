"""MCP tool discovery — async with concurrent server support."""
import logging

import httpx

# If using official MCP SDK (example imports, assumes mcp package is available)
try:
    from mcp.client.session import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
except ImportError:
    # Fallback to mocking or standard lib if MCP SDK isn't fully installed
    pass

from mcp_audit.parser.schemas import DiscoveredTool, ServerConfig, TransportType

logger = logging.getLogger(__name__)

class ToolDiscoverer:
    """Discovers tools exposed by an MCP server."""

    async def _discover_stdio(self, server: ServerConfig) -> list[DiscoveredTool]:
        if not server.command:
            return []

        params = StdioServerParameters(
            command=server.command,
            args=server.args,
            env=server.env
        )

        try:
            async with stdio_client(params) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    response = await session.list_tools()

                    tools = []
                    # Assuming response.tools has a similar structure
                    for tool in response.tools:
                        tools.append(
                            DiscoveredTool(
                                server_name=server.name,
                                tool_name=tool.name,
                                description=tool.description or "",
                                input_schema=tool.inputSchema or {},
                                annotations=getattr(tool, "annotations", None)
                            )
                        )
                    return tools
        except Exception as e:
            logger.error(f"Error discovering stdio tools for {server.name}: {e}")
            return []

    async def _discover_http(self, server: ServerConfig) -> list[DiscoveredTool]:
        if not server.url:
            return []

        # Simplified JSON-RPC call for tools/list
        payload = {
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 1,
            "params": {}
        }

        headers = {}
        # Simple heuristic to extract auth header if needed (can be extended)
        for k, v in server.env.items():
            if "TOKEN" in k.upper() or "KEY" in k.upper() or "AUTH" in k.upper():
                headers["Authorization"] = f"Bearer {v}"
                break

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(server.url, json=payload, headers=headers)
                resp.raise_for_status()
                data = resp.json()

                tools = []
                # Assume standard JSON-RPC response format for MCP
                for tool in data.get("result", {}).get("tools", []):
                    tools.append(
                        DiscoveredTool(
                            server_name=server.name,
                            tool_name=tool.get("name"),
                            description=tool.get("description", ""),
                            input_schema=tool.get("inputSchema", {}),
                            annotations=tool.get("annotations")
                        )
                    )
                return tools
        except Exception as e:
            logger.error(f"Error discovering http tools for {server.name}: {e}")
            return []

    async def discover_tools(self, server: ServerConfig) -> list[DiscoveredTool]:
        """Connect to MCP server and call tools/list."""
        logger.info(f"Discovering tools for {server.name} via {server.transport.value}")
        if server.transport == TransportType.STDIO:
            return await self._discover_stdio(server)
        elif server.transport in (TransportType.STREAMABLE_HTTP, TransportType.SSE):
            return await self._discover_http(server)
        else:
            logger.warning(f"Unsupported transport type: {server.transport}")
            return []

    async def discover_all(self, servers: list[ServerConfig]) -> list[DiscoveredTool]:
        """Discover tools across all servers concurrently."""
        tasks = [self.discover_tools(server) for server in servers]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_tools = []
        for i, res in enumerate(results):
            if isinstance(res, Exception):
                logger.error(f"Failed to discover tools for server {servers[i].name}: {res}")
            else:
                all_tools.extend(res)
        return all_tools


class MockToolDiscoverer(ToolDiscoverer):
    """Returns realistic fixture data for testing purposes."""

    async def discover_tools(self, server: ServerConfig) -> list[DiscoveredTool]:
        await asyncio.sleep(0.1) # Simulate network delay
        return [
            DiscoveredTool(
                server_name=server.name,
                tool_name="read_file",
                description="Read contents of a file on the local filesystem.",
                input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
                annotations={"readOnlyHint": True}
            ),
            DiscoveredTool(
                server_name=server.name,
                tool_name="send_email",
                description="Send an email to a recipient.",
                input_schema={"type": "object", "properties": {"to": {"type": "string"}, "body": {"type": "string"}}},
            ),
            DiscoveredTool(
                server_name=server.name,
                tool_name="query_database",
                description="Execute a SQL query against the internal database.",
                input_schema={"type": "object", "properties": {"query": {"type": "string"}}},
                annotations={"destructiveHint": False}
            ),
            DiscoveredTool(
                server_name=server.name,
                tool_name="post_to_slack",
                description="Post a message to a Slack channel.",
                input_schema={"type": "object", "properties": {"channel": {"type": "string"}, "message": {"type": "string"}}},
            )
        ]
