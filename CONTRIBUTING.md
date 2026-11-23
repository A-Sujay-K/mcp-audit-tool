# Contributing to MCP-Sentinel

Thank you for your interest in contributing to MCP-Sentinel.

## Development Workflow

1. **Environment Setup**:
   ```bash
   uv venv --python 3.11
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   uv pip install -e ".[dev]"
   ```

2. **Code Standards**:
   - Formatting and linting: `ruff check src/mcp_sentinel tests` and `ruff format src/mcp_sentinel tests`
   - Strict static type checking: `mypy --strict src/mcp_sentinel`
   - Tests and coverage gate: `pytest --cov=src/mcp_sentinel --cov-report=term-missing` (Minimum coverage: ≥ 85%)

3. **Pull Request Guidelines**:
   - Create a feature branch from `main`.
   - Ensure all unit and property tests pass.
   - Use Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`).
