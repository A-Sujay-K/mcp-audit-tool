# Project Roadmap

## Current: v0.1.0 (Released Aug 2026)

Core scanner, graph analysis, sandbox exploit engine, React dashboard,
REST API, CLI, and deployment configs are complete.

---

## Upcoming: v0.2.0

### LLM-Assisted Analysis

- [ ] Stream LLM classification results to dashboard in real-time via WebSocket
- [ ] Add confidence scores to LLM classifications visible in the dashboard UI
- [ ] Support Gemini, Mistral, and local Ollama models in addition to OpenAI/Anthropic
- [ ] Cache LLM responses in SQLite to avoid repeated API calls for identical tool descriptions

### Extended Detection Patterns

- [ ] **Credential Harvesting Chain**: tools that write to env files + tools that read env files
- [ ] **Persistence Backdoor**: tools that modify shell profiles or crontabs
- [ ] **Supply Chain**: detection of tools that install packages or modify lock files
- [ ] **Cross-session Memory**: tools that write to shared memory or temp files accessible across sessions

### Multi-Client Correlation

- [ ] Detect when the same MCP server is configured in multiple clients (Claude, Cursor, Windsurf)
- [ ] Show unified risk view across all clients on a single scan

---

## Upcoming: v0.3.0

### Developer Experience

- [ ] VS Code extension: inline warnings when editing MCP config files
- [ ] `mcp-audit watch` - continuous background monitoring with system tray notifications
- [ ] Homebrew formula for macOS: `brew install mcp-audit`
- [ ] Windows Installer (.msi) for users without Python

### Integrations

- [ ] Slack bot: post scan results to a channel after each CI run
- [ ] GitHub App: automatic PR comments when MCP config files are modified
- [ ] Jira integration: create tickets for critical findings automatically
- [ ] SIEM export: CEF format for Splunk/QRadar integration

---

## Future Considerations

- **Formal verification**: model-check the capability graph for information-flow violations
- **Plugin system**: third-party detection rules without modifying core
- **SaaS mode**: multi-tenant API for teams to share scan results

---

## How to Influence the Roadmap

Open a [Feature Request issue](.github/ISSUE_TEMPLATE/feature_request.md) and
describe your use case. Items with the most upvotes (thumbs-up reactions) get
prioritised in the next release cycle.
