# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-23

### Added
- **Config Discovery & Parsing**: Auto-detection and parsing for Claude Desktop, Cursor, VS Code, Windsurf, and root `mcp.json` configs with support for `stdio`, `sse`, and `streamable-http` transports.
- **Static Security Analysis Rules**:
  - `MCP-SEC-001`: Shannon entropy and regex-based hardcoded credential detection.
  - `MCP-SEC-002`: Dangerous interactive shell wrapper and shell pipe detection.
  - `MCP-SEC-003`: Broad host filesystem root path and traversal detection.
  - `MCP-SEC-004`: Unpinned package execution via dynamic runtime runners.
  - `MCP-SEC-005`: Damerau-Levenshtein typosquatting distance analyzer.
  - `MCP-SEC-006`: Zero-width and invisible Unicode character cloaking detection.
  - `MCP-SEC-007`: Bidirectional Unicode override detection.
  - `MCP-SEC-008`: Prompt injection and system instruction smuggling detection.
  - `MCP-SEC-009`: Cross-server tool shadowing and namespace collision detection.
  - `MCP-SEC-010`: Over-permissive unbounded string parameter schema detection.
- **Dynamic Protocol Auditing**:
  - `MCP-SEC-011`: Plaintext transport detection for non-loopback endpoints.
  - `MCP-SEC-012`: Host and Origin header validation against DNS rebinding.
  - `MCP-SEC-013`: Missing authentication and OAuth 2.1 compliance checks.
  - `MCP-SEC-014`: Cryptographic tool manifest drift ("rug pull") detection with baseline engine.
  - `MCP-SEC-015`: Non-destructive canary input reflection probing guarded by `--i-have-authorization`.
- **Supply Chain Security**:
  - `MCP-SEC-016`: Real OSV.dev REST API client querying active CVEs/GHSAs.
  - CycloneDX v1.6 SBOM export.
- **Reporting**:
  - OASIS SARIF v2.1.0 report generation validated against the official schema.
  - GitHub-flavored Markdown generator for CI PR comments.
  - Self-contained zero-CDN HTML reporting.
- **Autonomous Watch Daemon**:
  - Continuous audit loop with state differential and GitHub Issues REST lifecycle automation.
- **Auditor Hardening**:
  - STRIDE threat model document in `docs/threat_model.md`.
  - Terminal and HTML output sanitization.
  - Multi-stage non-root hardened Dockerfile pinned to base image SHA-256 digest.
