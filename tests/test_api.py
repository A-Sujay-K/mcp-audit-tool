"""Tests for the API routes (smoke tests)."""



class TestAPISmoke:
    """Basic smoke tests for API route registration."""

    def test_fastapi_app_creates(self):
        """The FastAPI app factory should create without errors."""
        from mcp_audit.api.main import create_app
        app = create_app()
        assert app is not None
        assert app.title == "MCP Audit Tool"

    def test_routes_registered(self):
        """All expected routes should be registered."""
        from mcp_audit.api.main import create_app
        app = create_app()
        
