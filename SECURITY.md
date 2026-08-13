# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x     | Yes       |

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Send a private report via
[GitHub Security Advisories](https://github.com/A-Sujay-K/mcp-audit-tool/security/advisories/new).

Include:
- A clear description of the vulnerability
- Steps to reproduce
- Potential impact (data exposure, RCE, DoS, etc.)
- Any proof-of-concept code

## Response Timeline

| Stage              | Target SLA                        |
|--------------------|-----------------------------------|
| Acknowledgement    | 48 hours                          |
| Initial assessment | 5 business days                   |
| Patch release      | 14 business days for critical     |

## Scope

This project scans MCP server configurations and executes sandboxed exploits.
Areas of highest security sensitivity:

- **Sandbox escapes** - Docker isolation bypass in `sandbox_manager.py`
- **Credential exposure** - env-var scanning in `config_parser.py`
- **LLM prompt injection** - via tool description payloads in `capability_classifier.py`
- **Path traversal** - in SARIF export output paths in `cli.py`

## Out of Scope

- Vulnerabilities in third-party dependencies (report to upstream)
- Social engineering attacks
- Denial-of-service via intentionally malformed config files

## Disclosure Policy

We follow coordinated disclosure. We ask reporters to allow 90 days before
public disclosure. We will credit reporters in release notes unless anonymity is
requested.
