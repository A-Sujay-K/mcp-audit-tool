# Drift Detection

Drift detection is the process of comparing MCP tool snapshots taken at different
points in time to identify unauthorized changes — a technique for detecting the
"rug-pull" attack.

## What is a Rug-Pull?

A rug-pull occurs when an MCP server operator silently modifies a tool's:
- **Description** — injecting new instructions that the LLM will follow
- **Input schema** — adding or removing parameters to change tool behaviour
- **Capabilities** — escalating what the tool can access or do

The term comes from DeFi, where a project appears legitimate until the creators
suddenly remove liquidity. In MCP, the "rug" is the tool definition changing
after the user has already trusted and approved it.

## How mcp-audit Detects Drift

### Step 1: Baseline Snapshot

On the first scan, `DriftDetector` hashes every tool's name, description, and
input schema using SHA-256. This hash is stored in the database alongside the
scan timestamp.

### Step 2: Comparison Scan

On subsequent scans, the same hashing is performed. The new hashes are compared
against the stored baseline.

### Step 3: Classification

Changes are classified by severity:

| Event Type              | Severity | Description                                           |
|-------------------------|----------|-------------------------------------------------------|
| `TOOL_ADDED`            | Medium   | A new tool appeared on a previously scanned server    |
| `TOOL_REMOVED`          | Low      | A tool disappeared from a previously scanned server   |
| `DESCRIPTION_CHANGED`   | High     | Tool description was modified since last scan         |
| `SCHEMA_CHANGED`        | High     | Tool input schema was modified since last scan        |
| `CAPABILITY_ESCALATION` | Critical | New dangerous capabilities detected in updated tool   |

### Step 4: Alerting

Drift events are:
- Stored in the `drift_events` database table
- Returned by the `/api/drift` API endpoint
- Displayed in the dashboard DriftAlert component
- Printed in the CLI `mcp-audit drift-check` command output

## Configuration

```bash
# Check for drift since last scan
mcp-audit drift-check

# Check drift against a specific scan ID
mcp-audit drift-check --baseline-scan-id <uuid>

# Output as JSON
mcp-audit drift-check --output json
```

## Limitations

- Drift detection requires at least two scans to compare against
- The first scan always sets the baseline; no drift is reported
- Servers that are offline during a scan are excluded from comparison
