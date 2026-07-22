# Supported MCP Clients

mcp-audit auto-detects configuration files from the following MCP clients.

## Claude Desktop

**Config file locations:**

| OS      | Path                                                             |
|---------|------------------------------------------------------------------|
| Windows | `%APPDATA%\Claude\claude_desktop_config.json`                 |
| macOS   | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Linux   | `~/.config/Claude/claude_desktop_config.json`                   |

**Config format:**
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/path/to/dir"]
    }
  }
}
```

## Cursor IDE

**Config file locations:**

| Scope   | Path                                  |
|---------|---------------------------------------|
| Project | `.cursor/mcp.json` (in project root)  |
| Global  | `~/.cursor/mcp.json`                  |

**Config format:** Same as Claude Desktop (`mcpServers` key).

## Windsurf

**Config file locations:**

| OS      | Path                                                              |
|---------|-------------------------------------------------------------------|
| Windows | `%USERPROFILE%\.codeium\windsurf\mcp_config.json`             |
| macOS   | `~/.codeium/windsurf/mcp_config.json`                             |

**Config format:** Same as Claude Desktop (`mcpServers` key).

## Claude Code (CLI)

**Config file:** `.mcp.json` in the current working directory.

**Config format:** Same as Claude Desktop (`mcpServers` key).

## Zed Editor

**Config file:** `~/.config/zed/settings.json`

**Config format:**
```json
{
  "context_servers": {
    "my-server": {
      "command": {
        "path": "npx",
        "args": ["-y", "my-mcp-server"]
      }
    }
  }
}
```

## Adding Your Own Config

You can always pass a specific config file path directly:

```bash
mcp-audit scan --config /path/to/your/mcp_config.json
```
