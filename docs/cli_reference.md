# CLI Reference

## Overview

```
mcp-audit [--verbose] [--config PATH] COMMAND [OPTIONS]
```

## Global Options

| Flag             | Description                                          |
|------------------|------------------------------------------------------|
| `--verbose`, `-v`| Enable debug logging                                 |
| `--config PATH`  | Path to a specific MCP client config file            |
| `--version`      | Show version and exit                                |
| `--help`         | Show help message and exit                           |

---

## Commands

### `scan`

Run a security audit scan against all detected (or specified) MCP servers.

```
mcp-audit scan [--config PATH] [--output FORMAT] [--confirm-exploits] [--verbose]
```

| Option              | Default    | Description                                      |
|---------------------|------------|--------------------------------------------------|
| `--config PATH`     | auto-detect| Path to MCP client config file                   |
| `--output FORMAT`   | table      | Output format: `table` or `json`                 |
| `--confirm-exploits`| off        | Run sandbox exploit engine to confirm findings   |

**Examples:**

```bash
# Auto-detect configs and scan
mcp-audit scan

# Scan a specific config, output JSON
mcp-audit scan --config ~/.config/claude/claude_desktop_config.json --output json

# Scan with exploit confirmation
mcp-audit scan --confirm-exploits
```

---

### `drift-check`

Compare current tool definitions against the last scan baseline. Detects rug-pull attacks.

```
mcp-audit drift-check [--baseline-scan-id UUID] [--output FORMAT]
```

| Option                    | Default       | Description                             |
|---------------------------|---------------|-----------------------------------------|
| `--baseline-scan-id UUID` | latest scan   | UUID of the scan to use as baseline     |
| `--output FORMAT`         | table         | Output format: `table` or `json`        |

**Example:**

```bash
mcp-audit drift-check --output json
```

---

### `serve`

Start the FastAPI REST API server.

```
mcp-audit serve [--host HOST] [--port PORT] [--reload]
```

| Option        | Default       | Description                              |
|---------------|---------------|------------------------------------------|
| `--host HOST` | `0.0.0.0`     | Host to bind to                          |
| `--port PORT` | `8000`        | Port to listen on                        |
| `--reload`    | off           | Enable hot-reload for development        |

---

### `export`

Export scan results to SARIF or JSON format.

```
mcp-audit export --scan-id UUID --format FORMAT [--output-dir PATH]
```

| Option             | Default     | Description                              |
|--------------------|-------------|------------------------------------------|
| `--scan-id UUID`   | required    | ID of the scan to export                 |
| `--format FORMAT`  | sarif       | Export format: `sarif` or `json`         |
| `--output-dir PATH`| current dir | Directory to write the output file       |

---

### `info`

Show system information: Python version, Docker status, detected MCP configs.

```
mcp-audit info
```
