"""Basic tests for OVNode."""
import pytest
from fastapi.testclient import TestClient


def test_app_imports():
    """Verify the app can be imported without errors."""
    from core.app import api
    assert api is not None


def test_health_endpoint():
    """Test the health check endpoint."""
    from core.app import api
    client = TestClient(api)
    response = client.get("/sync/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"


def test_version_endpoint():
    """Test version is available."""
    from core.version import __version__
    assert __version__ is not None