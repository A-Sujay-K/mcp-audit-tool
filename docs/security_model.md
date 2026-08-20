# Security Model

This document describes the threat model, trust boundaries, and security
controls built into `mcp-audit-tool`.

## Threat Model

### Actors

| Actor                | Trust Level    | Description                                              |
|----------------------|----------------|----------------------------------------------------------|
| Tool user            | High           | Developer running the CLI on their own machine           |
| MCP server operator  | Untrusted      | May have changed tool behaviour since approval           |
| LLM provider         | Semi-trusted   | Receives tool descriptions; could be injected            |
| Exploit target       | Untrusted      | Mock server running inside Docker sandbox                |

### Attack Vectors Detected

#### 1. Lethal Trifecta

A combination of tools where:
- **Tool A** reads private/sensitive data (files, emails, credentials)
- **Tool B** ingests untrusted external content (URLs, uploaded files, emails)
- **Tool C** can exfiltrate data (HTTP POST, email send, Slack message)

When an LLM agent uses all three, an adversary can craft content ingested by
Tool B to steer the agent into exfiltrating private data via Tool C.

#### 2. Rug-Pull / Drift Attack

An MCP server operator silently changes a tool description after it has been
approved. The new description may contain injected instructions the LLM follows
without the user's knowledge.

#### 3. Credential Extraction

MCP server configs often contain API tokens in `env` blocks. A malicious tool
could exfiltrate these tokens.

## Security Controls

### Sandbox Isolation

Exploit agents run inside Docker containers with:

```
--network none              # no outbound network
--read-only                 # immutable root filesystem
--cap-drop ALL              # all Linux capabilities dropped
--security-opt no-new-privileges
--user sandboxuser          # non-root user
--memory 512m               # memory cap
--cpus 0.5                  # CPU cap
```

### No Credential Logging

The scanner detects auth-bearing env var keys and masks their values in all
output. Raw values are never stored.

### LLM Prompt Hardening

Classification prompts use structured JSON output mode and explicit role
separation to reduce susceptibility to tool-description injection.

## Known Limitations

- Sandbox escape via kernel exploits is out of scope (OS-level risk)
- Rule-based classifier can miss novel capability patterns
- Drift detection requires at least two scans to compare
