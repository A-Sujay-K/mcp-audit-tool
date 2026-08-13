# Changelog

All notable changes to **mcp-audit-tool** are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### Planned
- Live dashboard WebSocket streaming for real-time scan progress
- Homebrew formula for macOS one-line install
- Integration with Semgrep for static taint-flow analysis

---

## [0.1.0] - 2026-08-10

### Added
- **ConfigParser** - auto-detects Claude Desktop, Cursor, Windsurf, Claude Code configs
- **ToolDiscoverer** - async MCP `tools/list` with concurrent server support
- **CapabilityClassifier** - LLM + rule-based tool classification with caching
- **CapabilityGraphBuilder** - networkx cross-server data-flow graph
- **TrifectaAnalyzer** - lethal trifecta (read + ingest + exfiltrate) detection
- **RiskScorer** - 6-component weighted scoring with overall risk percentage
- **DriftDetector** - rug-pull detection comparing tool snapshots between scans
- **SandboxManager** - Docker isolation for red-team exploit confirmation
- **ExploitAgent** - CrewAI-based agent with mock tool wrappers
- **FastAPI backend** - REST API with `/api/scans`, `/api/findings`, `/api/drift`, `/api/graph`
- **React dashboard** - Vite + Tailwind with CapabilityGraph, RiskGauge, FindingsTable
- **CLI** - `mcp-audit scan`, `drift-check`, `serve`, `export`, `info` commands
- **SARIF export** - for integration with GitHub Code Scanning
- **Render + Vercel deployment** - free-tier production deploy config

### Security
- Sandboxed exploits run with `--network none`, `--read-only`, dropped Linux capabilities
- Auth-bearing env vars detected and masked in scan output

---

## [0.0.1] - 2026-03-04

### Added
- Initial project scaffold with `src/` layout and `pyproject.toml`
- Core Pydantic schemas: `ServerConfig`, `ClientConfig`, `DiscoveredTool`
