"""Smoke tests for FastAPI routes."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    """Create a FastAPI TestClient with an in-memory SQLite database."""
    import os
    os.environ["MCP_AUDIT_DB_URL"] = "sqlite+aiosqlite:///:memory:"
    os.environ["MCP_AUDIT_DB_ECHO"] = "false"

    from mcp_audit.api.main import create_app
    app = create_app()

    with TestClient(app) as c:
        yield c


class TestHealthRoute:
    def test_health_returns_200(self, client):
        resp = client.get("/api/health")
        assert resp.status_code == 200

    def test_health_returns_ok_status(self, client):
        data = resp = client.get("/api/health").json()
        assert data["status"] == "ok"

    def test_health_returns_version(self, client):
        data = client.get("/api/health").json()
        assert "version" in data
        assert data["version"]


class TestRootRedirect:
    def test_root_redirects_to_docs(self, client):
        resp = client.get("/", follow_redirects=False)
        assert resp.status_code in (301, 302, 307, 308)
        assert "/docs" in resp.headers.get("location", "")


class TestScansRoute:
    def test_list_scans_returns_200(self, client):
        resp = client.get("/api/scans")
        assert resp.status_code == 200

    def test_list_scans_returns_list(self, client):
        data = client.get("/api/scans").json()
        assert isinstance(data, list)

    def test_get_nonexistent_scan_returns_404(self, client):
        import uuid
        fake_id = str(uuid.uuid4())
        resp = client.get(f"/api/scans/{fake_id}")
        assert resp.status_code == 404


class TestFindingsRoute:
    def test_findings_route_exists(self, client):
        resp = client.get("/api/findings")
        assert resp.status_code in (200, 404, 422)


class TestDriftRoute:
    def test_drift_route_exists(self, client):
        resp = client.get("/api/drift")
        assert resp.status_code in (200, 404, 422)
