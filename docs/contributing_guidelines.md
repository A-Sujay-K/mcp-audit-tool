# Contribution Guidelines

Thank you for considering contributing to **mcp-audit-tool**!
This document describes the standards and processes for contributions.

## Code Standards

### Python

- All Python code must pass `ruff check` and `ruff format` with zero warnings.
- Type hints are required on all public functions and class methods.
- Every public function must have a docstring (Google style).
- Async functions should be used wherever I/O is involved.

### JavaScript (Dashboard)

- Use functional React components with hooks only (no class components).
- Prefer named exports over default exports.
- Use `const` everywhere; avoid `let` unless reassignment is necessary.
- CSS modules or Tailwind utility classes only; no inline styles.

## Testing Requirements

| Category              | Requirement                                            |
|-----------------------|--------------------------------------------------------|
| New features          | Must include unit tests with >80% line coverage        |
| Bug fixes             | Must include a regression test that fails without fix  |
| API changes           | Must include updated API smoke tests                   |
| Dashboard components  | Manual visual verification required                    |

### Running Tests

```bash
# Run all tests
make test

# Run a specific test file
pytest tests/test_trifecta_analyzer.py -v

# Run with coverage report
make test-cov
```

## Documentation Requirements

- New CLI commands must be documented in the README quickstart section.
- New config options must be added to `src/mcp_audit/config.py` docstring.
- New security detection patterns must be described in `docs/security_model.md`.
- New public API endpoints must have OpenAPI descriptions (FastAPI auto-generates these).

## Review Process

1. Open a PR against `main` with a descriptive title following Conventional Commits.
2. Ensure all CI checks pass: ruff lint, pytest, CodeQL.
3. Request review from a maintainer.
4. Address review comments; push additional commits (do not force-push during review).
5. After approval, the maintainer squash-merges the PR.

## Code of Conduct

Be respectful and constructive in all interactions. This project follows the
[Contributor Covenant](https://www.contributor-covenant.org/) v2.1.
