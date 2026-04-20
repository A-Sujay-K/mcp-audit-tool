# Capability Classification

Capability classification is the process of determining what a tool can do from
its name, description, and input schema — without executing it.

## Classification Modes

### 1. LLM Mode (Default when API key is set)

When `MCP_AUDIT_LLM_API_KEY` is configured, each tool's name and description
are sent to the configured LLM with a structured prompt asking it to identify
which capabilities the tool possesses.

**Advantages:**
- Handles ambiguous, metaphorical, or obfuscated tool descriptions
- Can detect indirect capabilities (e.g., "generates a summary" that happens to call an HTTP endpoint)
- Provides reasoning in the classification output

**Disadvantages:**
- Requires a paid API key
- Adds latency to scans (mitigated by batch processing and caching)
- Subject to LLM hallucination (mitigated by confidence thresholds)

### 2. Rule-Based Mode (Default when no API key)

When no LLM API key is present, `RuleBasedFallbackClassifier` uses keyword
matching against the tool name and description.

**Keyword sets by capability:**

| Capability               | Keywords                                                            |
|--------------------------|---------------------------------------------------------------------|
| `reads_sensitive_data`   | read, file, database, query, get, fetch, secret, list_files, search |
| `ingests_untrusted`      | url, http, fetch, browse, email, upload, download, web, scrape      |
| `sends_data_out`         | send, post, webhook, notify, email, push, slack, message, chat      |
| `executes_code`          | exec, run, shell, command, eval, script, terminal, bash, python     |
| `modifies_filesystem`    | write, create, delete, remove, save, update_file, mkdir             |
| `manages_credentials`    | key, token, password, secret, credential, auth, login, api_key     |

## Caching

Classifications are cached in memory by tool `description_hash`. If the same
tool description is seen twice (e.g., across multiple clients sharing a server),
the LLM is only called once.

## Confidence Thresholds

LLM responses below `MCP_AUDIT_MIN_CONFIDENCE` (default: 0.7) fall back to
rule-based classification automatically.

## Configuring the LLM Provider

```bash
# OpenAI
export MCP_AUDIT_LLM_PROVIDER=openai
export MCP_AUDIT_LLM_API_KEY=sk-...
export MCP_AUDIT_LLM_MODEL=gpt-4o-mini

# Anthropic
export MCP_AUDIT_LLM_PROVIDER=anthropic
export MCP_AUDIT_LLM_API_KEY=sk-ant-...
export MCP_AUDIT_LLM_MODEL=claude-3-haiku-20240307

# Google Gemini
export MCP_AUDIT_LLM_PROVIDER=gemini
export MCP_AUDIT_LLM_API_KEY=AIza...
export MCP_AUDIT_LLM_MODEL=gemini-1.5-flash
```
