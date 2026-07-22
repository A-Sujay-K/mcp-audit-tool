# Capability Graph Analysis

The capability graph is the core analytical structure in mcp-audit.
It models how data can flow between MCP tools across one or more servers.

## Graph Structure

### Nodes

Each node represents a single MCP tool instance, identified by `server_name::tool_name`.

Node properties:
- `server` — MCP server name
- `tool` — tool name
- `capabilities` — list of detected capabilities
- `confidence` — classification confidence score

### Edges

Edges represent potential data-flow connections between tools:

| Edge Type              | Meaning                                              |
|------------------------|------------------------------------------------------|
| `data_exfiltration`    | Reader tool can feed data to exfil tool              |
| `injection`            | Ingest tool can deliver attacker payload to reader   |
| `rce_path`             | Code execution tool reachable from ingest tool       |
| `credential_theft`     | Credential tool reachable from exfil tool            |

### Example Graph

```
filesystem::read_file  ──data_exfil──>  slack::send_message
       ^
       |  injection
       |
  fetch::fetch_url
```

This graph contains the lethal trifecta:
1. `fetch_url` ingests an attacker-controlled URL
2. The attacker's content contains injection instructions
3. The LLM reads a file via `read_file`
4. The LLM sends the file contents via `send_message`

## Analyzing the Graph

The graph is built by `CapabilityGraphBuilder` and analyzed by `TrifectaAnalyzer`.

`TrifectaAnalyzer` searches for subgraph patterns that match:
- Any path from an ingest node through a read node to an exfil node
- Any path from an ingest node to a code-execution node
- Any path from a read node to a credential node to an exfil node

## Visualizing the Graph

The React dashboard's **Capability Graph** view renders the networkx graph
using a force-directed layout (react-flow). Nodes are colored by server,
and edges are colored by edge type:

- Red: `data_exfiltration`
- Orange: `injection`
- Purple: `rce_path`
- Yellow: `credential_theft`

## Exporting the Graph

```bash
# Get graph JSON for a specific scan via API
curl http://localhost:8000/api/graph/<scan_id>
```

The response is a D3.js-compatible node-link format.
