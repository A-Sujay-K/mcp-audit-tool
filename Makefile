.PHONY: help install dev-install lint test test-cov run-api run-dashboard clean

PYTHON := python
UV     := uv
PORT   := 8000

help:  ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | 	 awk 'BEGIN {FS=":.*##"}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

install:  ## Install runtime dependencies
	$(UV) pip install -e .

dev-install:  ## Install all dev + test dependencies
	$(UV) pip install -e ".[dev]"

lint:  ## Run ruff linter and formatter check
	ruff check src/ tests/
	ruff format --check src/ tests/

lint-fix:  ## Auto-fix lint issues
	ruff check --fix src/ tests/
	ruff format src/ tests/

test:  ## Run pytest test suite
	pytest tests/ -v

test-cov:  ## Run pytest with coverage report
	pytest tests/ --cov=src/mcp_audit --cov-report=term-missing --cov-report=html

run-api:  ## Start the FastAPI backend (dev mode)
	uvicorn mcp_audit.api.main:app --host 0.0.0.0 --port $(PORT) --reload

run-dashboard:  ## Install npm deps and start Vite dev server
	cd dashboard && npm install && npm run dev

build-dashboard:  ## Build React dashboard for production
	cd dashboard && npm install && npm run build

scan:  ## Run a quick scan with auto-detect
	mcp-audit scan --auto-detect

clean:  ## Remove build artifacts, caches, and coverage reports
	rm -rf dist/ build/ *.egg-info .pytest_cache .ruff_cache htmlcov .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
