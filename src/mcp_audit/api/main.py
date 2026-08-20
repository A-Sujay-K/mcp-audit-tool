"""FastAPI application factory for the MCP Audit Tool API."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse

from mcp_audit.config import get_settings


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Initialize database on startup, cleanup on shutdown."""
        try:
            from mcp_audit.api.deps import engine
            from mcp_audit.db.repository import init_db

            await init_db(engine)
            yield
            await engine.dispose()
        except Exception:
            # Allow app to start even without DB (e.g., in test mode)
            yield

    app = FastAPI(
        title="MCP Audit Tool",
        description="Cross-server MCP security auditor with sandboxed exploit confirmation.",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register route modules
    from mcp_audit.api.routes import drift, findings, graph, scans

    app.include_router(scans.router, prefix="/api", tags=["scans"])
    app.include_router(findings.router, prefix="/api", tags=["findings"])
    app.include_router(drift.router, prefix="/api", tags=["drift"])
    app.include_router(graph.router, prefix="/api", tags=["graph"])

    @app.get("/api/health")
    async def health_check():
        return {"status": "ok", "version": "0.1.0"}

    @app.get("/", include_in_schema=False)
    async def root():
        return RedirectResponse(url="/docs")

    return app


# Module-level instance for uvicorn / Render
app = create_app()
