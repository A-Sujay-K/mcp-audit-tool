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
│   │   ├── trifecta_analyzer.py   # Lethal trifecta + attack chain detection
│   │   └── risk_scorer.py         # 0–10 risk scoring algorithm
│   ├── sandbox/           # Docker-isolated exploit confirmation
│   │   ├── mock_mcp_server.py     # Generates fake MCP servers with synthetic data
│   │   ├── sandbox_manager.py     # Docker lifecycle (network=none, read-only)
│   │   ├── exploit_agent.py       # CrewAI red-team agent builder
│   │   ├── exploit_tasks.py       # Recon → injection → exfiltration tasks
│   │   └── exploit_logger.py      # Structured exploit attempt logging
│   ├── drift/             # Rug-pull / tool poisoning detection
│   │   ├── hasher.py              # SHA-256 tool definition hashing
│   │   └── drift_detector.py      # Baseline comparison + severity classification
│   ├── api/               # FastAPI REST API
│   │   ├── main.py                # App factory with CORS, lifecycle
│   │   └── routes/                # Scans, findings, drift, graph endpoints
│   ├── db/                # SQLAlchemy 2.0 async ORM
│   │   ├── models.py              # Scan, Server, Tool, Finding, Exploit records
│   │   └── repository.py          # Async CRUD data access layer
│   ├── cli.py             # Typer CLI with Rich output
│   └── config.py          # Pydantic Settings (.env configuration)
├── dashboard/             # React + Vite dashboard
│   └── src/
│       ├── App.jsx                # Tabbed layout with demo data
│       ├── components/            # RiskGauge, CapabilityGraph, FindingsTable, etc.
│       └── index.css              # Dark mode glassmorphism design system
├── tests/                 # pytest test suite
├── Dockerfile.sandbox     # Minimal sandbox container image
├── docker-compose.yml     # Full stack orchestration
└── pyproject.toml         # Python project metadata + dependencies
```

## Configuration

Set environment variables (prefix: `MCP_AUDIT_`) or create a `.env` file:

```env
# LLM for capability classification
MCP_AUDIT_LLM_PROVIDER=openai          # openai, anthropic, google, ollama
MCP_AUDIT_LLM_MODEL=gpt-4o
MCP_AUDIT_LLM_API_KEY=sk-...

# Database
MCP_AUDIT_DB_BACKEND=sqlite            # sqlite or postgresql
MCP_AUDIT_DB_URL=sqlite+aiosqlite:///./mcp_audit.db

# Sandbox (requires Docker)
MCP_AUDIT_SANDBOX_ENABLED=true
MCP_AUDIT_SANDBOX_TIMEOUT_SECONDS=120
MCP_AUDIT_SANDBOX_MEMORY_LIMIT=512m
MCP_AUDIT_SANDBOX_NETWORK_DISABLED=true  # Non-negotiable for safety
```

## Dashboard

The dashboard provides a real-time view of scan results:

- **📊 Overview** — Risk gauge, server/tool/finding counts
- **🕸️ Capability Graph** — Interactive force-directed visualization of tool relationships
- **⚠️ Findings** — Sortable table with attack chain visualization
- **💥 Exploit Timeline** — Step-by-step replay of what the red-team agent tried
- **🔔 Drift Alerts** — Rug-pull detection with hash diffs

```bash
cd dashboard
npm install
npm run dev    # http://localhost:5173
```

## Safety Design

- Sandbox containers run with `network_mode: none` — no internet access
- Read-only root filesystem with tmpfs for `/tmp`
- Memory capped (default 512MB), hard timeout (default 120s)
- Mock MCP servers use synthetic data (no real secrets)
- All exploit logs require human review before findings are confirmed
- `cap_drop: ALL` + `no-new-privileges` on all containers

## Development

```bash
# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest -v

# Type checking
mypy src/

# Start API server with auto-reload
mcp-audit serve
```

## License

MIT
