# Threat Model (STRIDE) — MCP-Sentinel

## Overview

MCP-Sentinel is an autonomous security auditor for Model Context Protocol (MCP) servers and client configurations. Because the auditor processes untrusted manifests, connects to local or remote endpoints, and outputs security telemetry, the auditor itself presents an attack surface that must be rigorously modeled and defended.

This document analyzes MCP-Sentinel according to the STRIDE threat classification model.

---

## 1. Spoofing (Identity & Authenticity)

| Threat | Risk | Mitigation in MCP-Sentinel |
| :--- | :--- | :--- |
| **Rogue MCP Server Impersonation** | High | Dynamic probing validates target TLS certificates (`https://`) on remote connections. Loopback exceptions (`127.0.0.1`, `localhost`) are strictly confined and cannot be overridden by external host headers. |
| **Spoofed Client Configuration** | Medium | Config parsers inspect canonical filesystem paths (`mcp.json`, Claude Desktop, Cursor) with path normalization, rejecting symlink escapes or unauthorized directory traversals. |

---

## 2. Tampering (Data Integrity)

| Threat | Risk | Mitigation in MCP-Sentinel |
| :--- | :--- | :--- |
| **Tool Manifest Rug-Pull** | Critical | MCP-SEC-014 computes canonical SHA-256 baseline hashes (`.mcp-sentinel.baseline.json`) of both schemas and descriptions. Any divergence in schema or description triggers immediate critical alerts. |
| **Terminal / Log Injection via Payloads** | High | Server-supplied strings are sanitized through `sanitize_terminal` and `sanitize_for_log`, which strip ANSI escape sequences, control characters, zero-width characters, and bidirectional overrides. |
| **HTML Report Script Injection (XSS)** | High | The HTML reporter (`generate_html_report`) strictly HTML-escapes all finding messages, evidence, targets, and remediation strings with `sanitize_html`. |

---

## 3. Repudiation (Audit Integrity)

| Threat | Risk | Mitigation in MCP-Sentinel |
| :--- | :--- | :--- |
| **Finding Manipulation / Duplication** | Medium | Each finding receives an immutable SHA-256 fingerprint derived from `rule_id`, `target`, `message`, and canonical evidence. |
| **Unsigned Reports** | Medium | Reports support OASIS SARIF 2.1.0 and CycloneDX v1.6 standards, enabling verifiable hashing in CI/CD pipelines. |

---

## 4. Information Disclosure

| Threat | Risk | Mitigation in MCP-Sentinel |
| :--- | :--- | :--- |
| **Credential Leakage in Reports** | Critical | MCP-SEC-001 uses a dedicated `mask_secret` function that redacts all detected tokens (displaying only the first 4 and last 3 characters). Secrets are never logged in plaintext. |
| **Host System Path Leaks** | Low | Path locations are canonicalized relative to repository root (`%SRCROOT%`) in SARIF output. |

---

## 5. Denial of Service (Availability)

| Threat | Risk | Mitigation in MCP-Sentinel |
| :--- | :--- | :--- |
| **Hanging Stdio Process** | High | Subprocess execution uses `asyncio.wait_for` with an enforced timeout (`REQUEST_TIMEOUT = 10.0s`). Non-responsive processes are terminated via `proc.kill()`. |
| **ReDoS in Parser Regexes** | Medium | All static rule regexes are bounded and tested using Hypothesis property-based fuzzing with arbitrary input strings. |
| **Excessive Response Memory Bomb** | Medium | Network responses and stdio streams are capped at a maximum of 5 MB (`MAX_RESPONSE_BYTES`). |

---

## 6. Elevation of Privilege

| Threat | Risk | Mitigation in MCP-Sentinel |
| :--- | :--- | :--- |
| **Command Injection via Server Args** | Critical | Stdio target invocation strictly uses `asyncio.create_subprocess_exec` with discrete argument vectors, never invoking an interactive shell (`shell=False`). |
| **Container Breakout** | High | The hardened Dockerfile runs as an unprivileged non-root user (`sentinel:sentinel`, UID 10001) on an immutable pinned digest (`python:3.11-slim@sha256:...`). |
| **Unauthorized Active Probing** | High | Active canary probes require the explicit `--i-have-authorization` flag and target allowlist verification; otherwise an `AuthorizationRequiredError` is raised immediately. |
