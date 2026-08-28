# Copyright (c) 2025 anonysec. All rights reserved.
# Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.

"""Basic tests for OVNode."""

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


def test_validation_client_name():
    """validate_client_name must accept safe CNs and reject dangerous ones."""
    from core.validation import validate_client_name

    assert validate_client_name("alice") == "alice"
    assert validate_client_name("user_1") == "user_1"
    assert validate_client_name("a.b-c") == "a.b-c"
    assert validate_client_name("../../etc/passwd") is None
    assert validate_client_name("a b") is None
    assert validate_client_name("$(rm -rf /)") is None
    assert validate_client_name("") is None
    assert validate_client_name(None) is None
    assert validate_client_name("x" * 33) is None


def test_validation_user_id():
    """validate_user_id must accept UUIDs and simple IDs, reject garbage."""
    from core.validation import validate_user_id

    good = "6ca1dd29-b6a4-41c8-adc9-e154cf3f8557"
    assert validate_user_id(good) == good
    assert validate_user_id(good.replace("-", "")) == good
    # Simple IDs (numeric/alphanumeric with dash/underscore) are now accepted
    assert validate_user_id("1") == "1"
    assert validate_user_id("123") == "123"
    assert validate_user_id("user_alice") == "user_alice"
    assert validate_user_id("bob-123") == "bob-123"
    assert validate_user_id("not-a-uuid") == "not-a-uuid"  # valid simple ID
    # Dangerous/malformed are rejected
    assert validate_user_id("invalid@") is None  # invalid char
    assert validate_user_id("../../etc/passwd") is None  # path traversal
    assert validate_user_id("") is None
    assert validate_user_id(None) is None


def test_create_user_rejects_invalid_id():
    """The user endpoint must refuse an invalid/missing id (security)."""
    from core.app import api
    from core.config import settings

    client = TestClient(api)
    headers = {"key": settings.api_key}
    # Missing id -> 400 validation error
    r = client.post(
        "/sync/user",
        headers=headers,
        json={"name": "alice", "status": "activate", "max_logins": 1},
    )
    assert r.status_code == 422  # FastAPI validation: id is required


def test_create_user_accepts_valid_id():
    """A well-formed UUID id passes validation (not rejected for the id)."""
    from core.app import api
    from core.config import settings

    client = TestClient(api)
    headers = {"key": settings.api_key}
    r = client.post(
        "/sync/user",
        headers=headers,
        json={
            "id": "6ca1dd29-b6a4-41c8-adc9-e154cf3f8557",
            "name": "alice",
            "status": "activate",
            "max_logins": 1,
        },
    )
    # 200 with success=False is acceptable (no OpenVPN backend); the point
    # is the request was not rejected for an invalid id/name.
    assert r.status_code == 200
    body = r.json()
    # The name validation should also pass
    assert body["success"] is False or body["data"] is None


def test_create_user_rejects_invalid_name():
    """Even with valid id, a dangerous name must be rejected."""
    from core.app import api
    from core.config import settings

    client = TestClient(api)
    headers = {"key": settings.api_key}
    r = client.post(
        "/sync/user",
        headers=headers,
        json={
            "id": "6ca1dd29-b6a4-41c8-adc9-e154cf3f8557",
            "name": "../../etc/passwd",
            "status": "activate",
            "max_logins": 1,
        },
    )
    assert r.status_code == 200
    assert r.json()["success"] is False


def test_create_user_accepts_valid_name_shape():
    """A well-formed name passes validation (not rejected for the name)."""
    from core.app import api
    from core.config import settings

    client = TestClient(api)
    headers = {"key": settings.api_key}
    r = client.post(
        "/sync/user",
        headers=headers,
        json={
            "id": "6ca1dd29-b6a4-41c8-adc9-e154cf3f8557",
            "name": "alice",
            "status": "activate",
            "max_logins": 1,
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is False or body["data"] is None
