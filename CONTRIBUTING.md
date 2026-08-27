

---

## Development Workflow

We use `uv` for fast dependency management and `ruff` for linting.

```bash
# Clone and set up
git clone https://github.com/A-Sujay-K/mcp-audit-tool.git
cd mcp-audit-tool
make dev-install

# Install pre-commit hooks (optional but recommended)
pip install pre-commit
pre-commit install

# Run tests before pushing
make test
make lint
```

### Branch Naming

| Type        | Pattern               | Example                         |
|-------------|-----------------------|---------------------------------|
| Feature     | `feat/<short-desc>`   | `feat/streaming-scan-progress`  |
| Bug fix     | `fix/<short-desc>`    | `fix/sandbox-timeout-cleanup`   |
| Docs        | `docs/<short-desc>`   | `docs/architecture-diagram`     |
| Refactor    | `refactor/<topic>`    | `refactor/classifier-caching`   |

### Commit Style

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(parser): support Zed context_servers config format
fix(sandbox): cleanup container on SIGTERM in addition to timeout
docs(faq): add troubleshooting steps for Docker not found error
```

### Release Process

1. Update `CHANGELOG.md` - move items from `[Unreleased]` to a new version section.
2. Bump version in `pyproject.toml`.
3. Open a PR titled `chore: release v0.x.0`.
4. After merge, tag: `git tag v0.x.0 && git push origin v0.x.0`.
5. GitHub Actions publishes to PyPI automatically via Trusted Publishing.
