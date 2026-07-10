# Configuration Reference

All mcp-audit settings are controlled via environment variables with the
`MCP_AUDIT_` prefix.

## Core Settings

| Variable                  | Default                                    | Description                                  |
|---------------------------|--------------------------------------------|----------------------------------------------|
| `MCP_AUDIT_DB_URL`        | `sqlite+aiosqlite:///./mcp_audit.db`       | SQLAlchemy database URL                      |
| `MCP_AUDIT_DB_ECHO`       | `false`                                    | Log all SQL statements (debug mode)          |
| `MCP_AUDIT_CORS_ORIGINS`  | `["http://localhost:5173"]`                | List of allowed CORS origins (JSON array)    |
| `DATABASE_URL`            | (none)                                     | Render.com standard var; maps to DB_URL      |

## LLM Settings

| Variable                    | Default      | Description                                    |
|-----------------------------|--------------|------------------------------------------------|
| `MCP_AUDIT_LLM_PROVIDER`    | `openai`     | LLM provider: `openai`, `anthropic`, `gemini`  |
| `MCP_AUDIT_LLM_API_KEY`     | (none)       | API key for the LLM provider                   |
| `MCP_AUDIT_LLM_MODEL`       | `gpt-4o-mini`| Model name to use for classification           |
| `MCP_AUDIT_LLM_TEMPERATURE` | `0.1`        | LLM temperature (low = more deterministic)     |
| `MCP_AUDIT_MIN_CONFIDENCE`  | `0.7`        | Minimum LLM confidence; below falls back to rules |
| `MCP_AUDIT_MAX_BATCH_SIZE`  | `10`         | Max tools per LLM classify_batch() call        |

## Discovery Settings

| Variable                       | Default | Description                                       |
|--------------------------------|---------|---------------------------------------------------|
| `MCP_AUDIT_DISCOVERY_TIMEOUT`  | `10`    | Seconds to wait per MCP server connection         |
| `MCP_AUDIT_MAX_CONCURRENCY`    | `5`     | Max concurrent server connections during discovery|

## Sandbox Settings

| Variable                        | Default | Description                                      |
|---------------------------------|---------|--------------------------------------------------|
| `MCP_AUDIT_SANDBOX_MEMORY_MB`   | `512`   | Docker container memory limit in MB              |
| `MCP_AUDIT_SANDBOX_CPU`         | `0.5`   | Docker container CPU limit (fractional cores)    |
| `MCP_AUDIT_SANDBOX_TIMEOUT_SEC` | `120`   | Max seconds per exploit attempt                  |

## Example .env file

```bash
# Database
MCP_AUDIT_DB_URL=sqlite+aiosqlite:///./mcp_audit.db

# LLM (optional; falls back to rule-based if not set)
MCP_AUDIT_LLM_PROVIDER=openai
MCP_AUDIT_LLM_API_KEY=sk-...
MCP_AUDIT_LLM_MODEL=gpt-4o-mini

# CORS (set to your Vercel URL for production)
MCP_AUDIT_CORS_ORIGINS=["https://your-app.vercel.app"]
```
