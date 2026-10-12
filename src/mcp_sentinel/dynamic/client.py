import asyncio
import json
import logging

import httpx

from mcp_sentinel.core.exceptions import TransportError
from mcp_sentinel.core.models import ServerTarget, ToolDefinition, TransportType

logger = logging.getLogger(__name__)

CONNECT_TIMEOUT = 5.0
REQUEST_TIMEOUT = 10.0
MAX_RESPONSE_BYTES = 5 * 1024 * 1024  # 5 MB safety limit


class McpTargetClient:
    """Safely connects to and inspects target MCP servers over stdio or SSE/HTTP."""

    def __init__(self, target: ServerTarget) -> None:
        self.target = target

    async def list_tools(self) -> list[ToolDefinition]:
        """Queries the target MCP server for its declared tool definitions."""
        if self.target.transport == TransportType.STDIO:
            return await self._list_tools_stdio()
        return await self._list_tools_http()

    async def _list_tools_stdio(self) -> list[ToolDefinition]:
        if not self.target.command:
            raise TransportError(f"Server '{self.target.name}' missing executable command.")

        cmd = [self.target.command] + self.target.args
        try:
            # Spawn isolated subprocess without shell
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self.target.env or None,
            )
        except OSError as e:
            raise TransportError(f"Failed to start stdio server '{self.target.name}': {e}") from e

        # Standard MCP JSON-RPC initialize handshake request
        init_req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcp-sentinel", "version": "0.1.0"},
            },
        }
        tools_req = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        }

        try:
            payload = f"{json.dumps(init_req)}\n{json.dumps(tools_req)}\n".encode()
            stdout_data, _ = await asyncio.wait_for(
                proc.communicate(input=payload),
                timeout=REQUEST_TIMEOUT,
            )
        except TimeoutError as e:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            raise TransportError(f"Stdio communication timed out for '{self.target.name}'") from e
        except Exception as e:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            raise TransportError(f"Error communicating with '{self.target.name}': {e}") from e

        return self._parse_jsonrpc_tools(stdout_data.decode("utf-8", errors="replace"))

    async def _list_tools_http(self) -> list[ToolDefinition]:
        if not self.target.url:
            raise TransportError(f"Server '{self.target.name}' missing target URL.")

        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            try:
                # Test basic endpoint responsiveness
                resp = await client.get(self.target.url, headers=self.target.headers)
                if resp.status_code == 401 or resp.status_code == 403:
                    # Endpoint requires authentication
                    logger.info(
                        "Server '%s' requires authentication (status %d)",
                        self.target.name,
                        resp.status_code,
                    )
                    return []
                # Attempt standard tools/list POST
                tools_req = {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/list",
                    "params": {},
                }
                tools_resp = await client.post(
                    self.target.url,
                    json=tools_req,
                    headers=self.target.headers,
                )
                if tools_resp.status_code == 200:
                    return self._parse_jsonrpc_tools(tools_resp.text)
            except httpx.RequestError as e:
                raise TransportError(f"HTTP connection failed for '{self.target.name}': {e}") from e

        return []

    def _parse_jsonrpc_tools(self, output: str) -> list[ToolDefinition]:
        tools: list[ToolDefinition] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue

            result = msg.get("result", {})
            if isinstance(result, dict) and "tools" in result:
                for t in result["tools"]:
                    if isinstance(t, dict) and "name" in t:
                        tools.append(
                            ToolDefinition(
                                name=str(t["name"]),
                                description=str(t.get("description", "")),
                                input_schema=t.get("inputSchema", {})
                                if isinstance(t.get("inputSchema"), dict)
                                else {},
                                server_name=self.target.name,
                            )
                        )
        return tools
