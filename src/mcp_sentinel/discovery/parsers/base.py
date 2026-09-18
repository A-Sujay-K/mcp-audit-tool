from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from mcp_sentinel.core.models import ServerTarget, TransportType


class BaseConfigParser(ABC):
    """Abstract base class for all client configuration parsers."""

    @abstractmethod
    def parse_file(self, path: Path) -> list[ServerTarget]:
        """Parses an MCP client configuration file into normalized ServerTarget objects."""

    @abstractmethod
    def parse_dict(self, data: dict[str, Any], source: str = "") -> list[ServerTarget]:
        """Parses a dictionary representation of an MCP client config."""

    @staticmethod
    def infer_transport(server_config: dict[str, Any]) -> TransportType:
        """Determines the MCP transport type based on configured fields."""
        explicit_type = str(
            server_config.get("transport", "") or server_config.get("type", "")
        ).lower()
        if explicit_type == "sse":
            return TransportType.SSE
        if explicit_type in ("http", "streamable-http"):
            return TransportType.STREAMABLE_HTTP
        if explicit_type == "stdio":
            return TransportType.STDIO

        url = server_config.get("url")
        if url:
            if "sse" in str(url).lower():
                return TransportType.SSE
            return TransportType.STREAMABLE_HTTP

        return TransportType.STDIO
