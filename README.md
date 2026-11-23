# MCP-Sentinel

[![CI](https://github.com/A-Sujay-K/mcp-audit-tool/actions/workflows/ci.yml/badge.svg)](https://github.com/A-Sujay-K/mcp-audit-tool/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python: 3.11+](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Checked with mypy](https://img.shields.io/badge/mypy-strict-blue)](https://mypy-lang.org/)

Autonomous, production-grade security auditor for **Model Context Protocol (MCP)** server configurations and client manifests.

---

## What It Does & What It Does NOT Do

### What MCP-Sentinel Does:
- **Client Configuration Auditing**: Auto-discovers and parses configurations across Claude Desktop, Cursor, VS Code, Windsurf, and repository `mcp.json` files.
- **Static Manifest Analysis**: Identifies hardcoded secrets (Shannon entropy + regex patterns), dangerous interactive shell wrappers (`sh -c`, `powershell`, pipe chains), broad filesystem roots, unpinned package installations, and typosquatting attempts.
- **Prompt Injection & Cloaking Detection**: Detects hidden zero-width Unicode characters, bidirectional override formatting (RLO), instruction smuggling aimed at model override, and cross-server tool shadowing.
- **Dynamic Protocol Auditing**: Evaluates live MCP endpoints for plaintext HTTP, DNS rebinding vulnerability (missing Host validation), OAuth 2.1 compliance, cryptographic manifest drift ("rug pulls"), and benign canary reflection.
- **Supply Chain Security**: Queries the real OSV.dev REST API for active CVEs/GHSAs in declared dependencies and generates CycloneDX v1.6 SBOM documents.
- **Multi-Format Standards Reporting**: Emits validated OASIS SARIF 2.1.0 (for GitHub Code Scanning), Markdown, and self-contained zero-CDN HTML.
- **Autonomous Monitoring**: Runs as a daemon (`mcp-sentinel watch`) with automated GitHub Issue synchronization and auto-closure on remediation.

### What MCP-Sentinel Does NOT Do:
- **No Aggressive Exploitation**: Does not execute destructive exploit payloads. Active probing uses benign sentinel strings (`mcp-canary-<uuid>`) and strictly requires the `--i-have-authorization` flag.
- **No Mock or Fabricated Findings**: Every finding is backed by real static parser or live protocol analysis.
- **No Automatic Code Modification**: Audits and reports vulnerabilities; does not silently rewrite user configuration files without consent.

---

## Installation

### Using `uv` (Recommended)
```bash
uv tool install mcp-sentinel
```

### Using `pip`
```bash
pip install mcp-sentinel
```

### From Source
```bash
git clone https://github.com/A-Sujay-K/mcp-audit-tool.git
cd mcp-audit-tool
uv venv --python 3.11
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
uv pip install -e ".[dev]"
```

---

## CLI Usage

### 1. Static Configuration Scan
Scan all auto-discovered client configurations on the current machine:
```bash
mcp-sentinel scan
```

Scan an explicit configuration file or workspace directory:
```bash
mcp-sentinel scan ./mcp.json
```

Generate an OASIS SARIF report for GitHub Code Scanning:
```bash
mcp-sentinel scan ./mcp.json --format sarif --output audit-results.sarif
```

Generate a self-contained HTML report:
```bash
mcp-sentinel scan ./mcp.json --format html --output audit-report.html
```

Enforce CI quality gate (exit code 1 if findings meet or exceed severity):
```bash
mcp-sentinel scan ./mcp.json --fail-on HIGH
```

### 2. CycloneDX SBOM Export
Generate a CycloneDX v1.6 SBOM JSON for all configured servers:
```bash
mcp-sentinel sbom --output cyclonedx-sbom.json
```

### 3. Autonomous Watch Mode
Continuously monitor configuration files and sync new findings to GitHub Issues:
```bash
export GITHUB_TOKEN="ghp_..."
mcp-sentinel watch --interval 300 --repo "A-Sujay-K/mcp-audit-tool"
```

---

## Rule Catalog

| Rule ID | Name | Severity | Standards |
| :--- | :--- | :--- | :--- |
| **MCP-SEC-001** | Hardcoded Secret in Environment or Arguments | CRITICAL | CWE-798, OWASP LLM06 |
| **MCP-SEC-002** | Dangerous Shell Wrapper Execution | HIGH | CWE-78, OWASP LLM02 |
| **MCP-SEC-003** | Broad Filesystem Root Access | HIGH | CWE-22, CWE-552, OWASP LLM02 |
| **MCP-SEC-004** | Unpinned Package Execution | MEDIUM | CWE-829, OWASP LLM05 |
| **MCP-SEC-005** | Potential Package Typosquatting | HIGH | CWE-829, OWASP LLM05 |
| **MCP-SEC-006** | Zero-Width & Invisible Unicode Characters | HIGH | CWE-116, OWASP LLM01 |
| **MCP-SEC-007** | Bidirectional Text Override | HIGH | CWE-116, OWASP LLM01 |
| **MCP-SEC-008** | Prompt Injection / Instruction Smuggling | HIGH | CWE-74, OWASP LLM01 |
| **MCP-SEC-009** | Tool Shadowing & Namespace Hijacking | MEDIUM | CWE-699, OWASP LLM02 |
| **MCP-SEC-010** | Over-Permissive String Parameter Schema | MEDIUM | CWE-20, OWASP LLM02 |
| **MCP-SEC-011** | Insecure Transport Protocol | HIGH | CWE-319, OWASP LLM06 |
| **MCP-SEC-012** | DNS Rebinding / Host Header Permissiveness | HIGH | CWE-942, CWE-346 |
| **MCP-SEC-013** | Missing Authentication / Insecure Auth Flow | HIGH | CWE-306, OWASP LLM06 |
| **MCP-SEC-014** | Manifest Drift ("Rug Pull") | CRITICAL | CWE-353, OWASP LLM05 |
| **MCP-SEC-015** | Canary Input Reflection / Execution Sink | HIGH | CWE-20, CWE-22, CWE-78 |
| **MCP-SEC-016** | Known Vulnerability in Declared Dependency | HIGH | CWE-1395, OWASP LLM05 |

---

## Security & Threat Model

See [docs/threat_model.md](docs/threat_model.md) for the STRIDE threat model covering the auditor itself. To report vulnerabilities, refer to [SECURITY.md](SECURITY.md).

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
