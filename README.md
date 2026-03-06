# 🛡️ MCP Audit Tool

> Cross-server MCP security auditor with sandboxed exploit confirmation

**MCP Audit** scans your entire Model Context Protocol toolset — across Claude Desktop, Cursor, Windsurf, and any MCP-compatible client — maps what those tools can do *in combination*, and then uses a red-team agent to actually *attempt* the exploit chain in an isolated Docker sandbox.

---

## The Problem

MCP gives AI agents powerful tools: file access, web browsing, email sending, code execution, and more. Each tool seems safe in isolation, but **combine them** and you get attack chains:

```
fetch_url (attacker-controlled) → read_file (secrets) → send_message (exfiltrate via Slack)
```

This is the **"lethal trifecta"**: ingest untrusted content + read sensitive data + send data out. Research shows ~38% of live MCP servers have no auth at all, and tool descriptions can be crafted to steer agent behavior.

## What MCP Audit Does

| Phase | What happens |
|-------|-------------|
| **1. Parse** | Auto-detects MCP configs (Claude Desktop, Cursor, Windsurf, etc.) and discovers all tools via `tools/list` |
| **2. Classify** | LLM + rule-based fallback assigns security capabilities (reads_data, sends_out, executes_code, etc.) |
| **3. Graph** | Builds a cross-server capability graph, finds lethal trifectas, code execution chains, credential theft paths |
| **4. Score** | Risk-scores each finding (0–10) based on trifecta completeness, auth gaps, cross-server span |
| **5. Exploit** | Spins up a Docker sandbox with mock MCP servers and has a red-team agent *actually try* the attack |
| **6. Drift** | SHA-256 hashes every tool definition to catch silent rug-pull changes between scans |

## Quick Start

```bash
# Install
pip install -e .

# Auto-detect your MCP configs and scan
mcp-audit scan

# Scan with exploit confirmation (requires Docker)
mcp-audit scan --confirm-exploits

# Check for tool definition drift
mcp-audit drift-check

# Start the API server + dashboard
mcp-audit serve

# Show detected configs and system info
mcp-audit info
```

## Project Structure

```
mcp-audit/
├── src/mcp_audit/
│   ├── parser/            # Config parsing, tool discovery, LLM classification
│   │   ├── config_parser.py       # Auto-detect Claude, Cursor, Windsurf configs
│   │   ├── tool_discovery.py      # JSON-RPC tools/list via stdio/HTTP
│   │   ├── capability_classifier.py # LLM + rule-based capability tagging
│   │   └── schemas.py             # Pydantic models (single source of truth)
│   ├── graph/             # Cross-server capability analysis
│   │   ├── capability_graph.py    # NetworkX directed graph builder
