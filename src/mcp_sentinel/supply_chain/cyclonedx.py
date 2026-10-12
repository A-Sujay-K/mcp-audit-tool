from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from mcp_sentinel.core.models import ServerTarget


def generate_cyclonedx_sbom(
    targets: Sequence[ServerTarget], version: str = "0.1.0"
) -> dict[str, Any]:
    """Generates a CycloneDX v1.6 JSON Software Bill of Materials (SBOM) for discovered MCP servers."""
    components: list[dict[str, Any]] = []

    for target in targets:
        # Determine package spec from args or command
        pkg_name = target.command or target.name
        pkg_ver = "unknown"

        for arg in target.args:
            if not arg.startswith("-") and ("@" in arg or "==" in arg):
                if "==" in arg:
                    parts = arg.split("==")
                    pkg_name, pkg_ver = parts[0], parts[1]
                elif "@" in arg and not arg.startswith("@"):
                    parts = arg.split("@")
                    pkg_name, pkg_ver = parts[0], parts[1]
                elif arg.startswith("@") and "@" in arg[1:]:
                    idx = arg[1:].index("@") + 1
                    pkg_name, pkg_ver = arg[:idx], arg[idx + 1 :]
                break

        purl = (
            f"pkg:generic/{pkg_name}@{pkg_ver}"
            if pkg_ver != "unknown"
            else f"pkg:generic/{pkg_name}"
        )

        components.append(
            {
                "type": "application",
                "name": pkg_name,
                "version": pkg_ver,
                "purl": purl,
                "description": f"MCP server '{target.name}' via {target.transport.value}",
                "properties": [
                    {"name": "mcp:server_name", "value": target.name},
                    {"name": "mcp:transport", "value": target.transport.value},
                    {"name": "mcp:client_type", "value": target.client_type or "custom"},
                ],
            }
        )

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:mcp-sentinel-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "mcp-sentinel",
                        "version": version,
                    }
                ]
            },
        },
        "components": components,
    }
    return sbom
