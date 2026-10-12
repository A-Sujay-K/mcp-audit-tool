#!/usr/bin/env python3
"""Secure hardened reference MCP server for test fixtures."""
import json
import sys


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue

        method = req.get("method")
        msg_id = req.get("id")

        if method == "initialize":
            resp = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "secure-test-server", "version": "1.0.0"},
                },
            }
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()

        elif method == "tools/list":
            resp = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "tools": [
                        {
                            "name": "read_allowed_file",
                            "description": "Reads vetted files within the restricted sandbox directory.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "filename": {
                                        "type": "string",
                                        "maxLength": 64,
                                        "pattern": r"^[a-zA-Z0-9_\-\.]+\.txt$",
                                    }
                                },
                                "required": ["filename"],
                            },
                        }
                    ]
                },
            }
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
