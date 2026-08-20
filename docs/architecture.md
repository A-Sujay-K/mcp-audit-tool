# Architecture Overview

## Component Diagram

```
+-----------------------------------------------------------------+
|                        mcp-audit-tool                           |
|                                                                 |
|  +----------+   +--------------+   +-----------------------+   |
|  | CLI / API |-->| Scan Engine  |-->|   FastAPI REST Routes |   |
|  +----------+   +------+-------+   +----------+------------+   |
|                        |                      |                 |
|         +--------------v--------------+       |                 |
|         |           Parser            |       |                 |
|         |  ConfigParser               |       |                 |
|         |  ToolDiscoverer             |       |                 |
|         |  CapabilityClassifier       |       |                 |
|         +--------------+--------------+       |                 |
|                        |                      |                 |
|         +--------------v--------------+       |                 |
|         |       Graph Analysis        |       |                 |
|         |  CapabilityGraphBuilder     |       |                 |
|         |  TrifectaAnalyzer           |       |                 |
|         |  RiskScorer                 |       |                 |
|         +--------------+--------------+       |                 |
|                        |                      |                 |
|         +--------------v--------------+       |                 |
|         |       Exploit Engine        |       |                 |
|         |  SandboxManager (Docker)    |       |                 |
|         |  ExploitAgent (CrewAI)      |       |                 |
|         |  ExploitLogger              |       |                 |
|         +--------------+--------------+       |                 |
|                        |                      |                 |
|         +--------------v--------------+       |                 |
|         |         Persistence         +-------+                 |
|         |  SQLAlchemy Async + SQLite  |                         |
|         +-----------------------------+                         |
+-----------------------------------------------------------------+
```

## Data Flow

1. **Discovery**: `ConfigParser` locates MCP client config files on disk.
2. **Connection**: `ToolDiscoverer` connects to each declared MCP server and calls `tools/list`.
3. **Classification**: `CapabilityClassifier` tags each tool with capability flags.
4. **Graph build**: `CapabilityGraphBuilder` creates a directed networkx graph.
5. **Trifecta scan**: `TrifectaAnalyzer` finds lethal trifecta combinations.
6. **Risk score**: `RiskScorer` computes a 0-100 risk percentage per finding.
7. **Optional exploit**: `SandboxManager` runs a CrewAI agent inside Docker to confirm findings.
8. **Storage**: Results are persisted to SQLite via `AuditRepository`.
9. **Output**: CLI renders Rich tables; API exposes REST; dashboard shows React UI.

## Key Design Decisions

| Decision              | Rationale                                                    |
|-----------------------|--------------------------------------------------------------|
| Async-first           | MCP servers can be slow; concurrent discovery is critical    |
| SQLite default        | Zero ops cost for single-user installs                       |
| LLM + rule-based      | LLM handles ambiguous tools; rules handle obvious ones       |
| Docker for exploits   | Prevents any real damage during red-team testing             |
| `src/` layout         | Prevents accidental imports of source instead of installed   |
