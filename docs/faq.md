# Frequently Asked Questions

## General

### What is the "lethal trifecta"?

The lethal trifecta is a pattern where a combination of three tool capabilities
creates a high-risk data exfiltration path:

1. **Read** - A tool that reads private data (files, emails, credentials)
2. **Ingest** - A tool that fetches external, attacker-controlled content (URLs)
3. **Exfiltrate** - A tool that sends data out (Slack, email, webhooks)

When an LLM agent has access to all three, an attacker can embed instructions in
the content fetched by the ingest tool, steering the agent to exfiltrate private
data without the user knowing.

### Is this tool safe to run?

Yes. By default, `mcp-audit scan` only reads your MCP config files and calls
`tools/list` on running servers. It does NOT invoke any tools or send any data.

The exploit engine (enabled with `--confirm-exploits`) runs inside Docker with
`--network none`, so it cannot reach the internet or your real services.

### Does this tool store my MCP tokens?

No. Auth-bearing env var values are detected and masked before storage. Only the
key names (e.g., `SLACK_BOT_TOKEN`) are recorded, never the values.

## Installation

### `pip install mcp-audit` says "No matching distribution found"

The package is currently only installable from source:

```bash
git clone https://github.com/A-Sujay-K/mcp-audit-tool.git
cd mcp-audit-tool
pip install -e ".[dev]"
```

### Docker not found when running exploits

Install Docker Desktop: https://docs.docker.com/get-docker/

Then ensure it is running before invoking `mcp-audit scan --confirm-exploits`.

## Dashboard

### The dashboard shows demo data, not my real scans

The dashboard falls back to built-in demo data when the API is unreachable.
Start the API first:

```bash
make run-api
```

Then open http://localhost:5173 in a separate terminal:

```bash
cd dashboard && npm run dev
```

### How do I deploy the dashboard publicly?

See the [Deployment Guide](deployment.md). Short version:

1. Deploy the FastAPI backend to Render (free tier).
2. Deploy the React dashboard to Vercel (free tier).
3. Set `VITE_API_URL` to your Render URL in Vercel env vars.

## Contributing

### How do I add a new exploit type?

1. Add a new `TrifectaType` variant in `src/mcp_audit/parser/schemas.py`.
2. Add detection logic in `src/mcp_audit/graph/trifecta_analyzer.py`.
3. Add a test in `tests/test_trifecta_analyzer.py`.
4. Open a PR with the `enhancement` label.
