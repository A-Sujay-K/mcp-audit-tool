---
name: "Bug Report"
about: Report a reproducible bug in mcp-audit-tool
labels: ["bug", "needs-triage"]
assignees: []
---

## Description

<!-- A clear description of what the bug is. -->

## Steps to Reproduce

1. Run `mcp-audit ...`
2. See error

## Expected Behaviour

<!-- What you expected to happen. -->

## Actual Behaviour

<!-- What actually happened. Include the full error message/traceback. -->

```
paste error here
```

## Environment

| Field             | Value                  |
|-------------------|------------------------|
| OS                |                        |
| Python version    | `python --version`     |
| mcp-audit version | `mcp-audit --version`  |
| Docker version    | `docker --version`     |
| LLM provider      | OpenAI / Anthropic / none |

## MCP Client Config (redacted)

<!-- Remove all tokens and passwords before pasting. -->

```json
{
  "mcpServers": {
    "your-server": {}
  }
}
```

## Additional Context

<!-- Logs, screenshots, or other useful information. -->
