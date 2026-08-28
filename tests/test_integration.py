# Copyright (c) 2025 anonysec. All rights reserved.
# Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.

"""Integration tests for the OVNode sync API (simulating panel requests).

These tests verify the API contract between OVManager and OVNode:
- UUID-based identity
- Input validation
- Response format
- Error handling
"""

from fastapi.testclient import TestClient


def _client():
    from core.app import api
    from core.config import settings

    return TestClient(api), {"key": settings.api_key}


def test_health_no_auth():
    """Health check requires no auth."""
    from core.app import api

    c = TestClient(api)
    r = c.get("/sync/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_status_requires_auth():
    """Status endpoint requires API key."""
    from core.app import api

    c = TestClient(api)
    r = c.get("/sync/status")
    assert r.status_code == 422  # missing required header


def test_status_with_auth():
    """Status returns version and system info."""
    c, headers = _client()
    r = c.get("/sync/status", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is True
    data = body["data"]
    from core.version import __version__

    assert data["version"] == __version__
    assert "cpu_usage" in data
    assert "memory_usage" in data


def test_create_user_with_uuid_id():
    """Panel sends UUID as id, gets expected response."""
    c, headers = _client()
    r = c.post(
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
    # Creation fails without OpenVPN backend, but validation passes
    assert body["success"] is False
    assert body["msg"] in ("Failed to create user", "Invalid client name")


def test_create_user_with_simple_id():
    """Panel sends simple numeric ID."""
    c, headers = _client()
    r = c.post(
        "/sync/user",
        headers=headers,
        json={
            "id": "42",
            "name": "bob",
            "status": "activate",
            "max_logins": 1,
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is False
    assert body["msg"] in ("Failed to create user", "Invalid client name")


def test_create_user_rejects_invalid_id():
    """Panel sends truly invalid id format."""
    c, headers = _client()
    r = c.post(
        "/sync/user",
        headers=headers,
        json={
            "id": "../../etc/passwd",
            "name": "alice",
            "status": "activate",
            "max_logins": 1,
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is False
    assert body["msg"] == "Invalid user id (must be UUID)"


def test_create_user_missing_id():
    """Panel omits id entirely."""
    c, headers = _client()
    r = c.post(
        "/sync/user",
        headers=headers,
        json={"name": "alice", "status": "activate", "max_logins": 1},
    )
    assert r.status_code == 422  # FastAPI validation: id is required


def test_change_user_status():
    """PUT /user with UUID id."""
    c, headers = _client()
    r = c.put(
        "/sync/user",
        headers=headers,
        json={
            "id": "6ca1dd29-b6a4-41c8-adc9-e154cf3f8557",
            "name": "alice",
            "status": "deactivate",
            "max_logins": 1,
        },
    )
    assert r.status_code == 200
    body = r.json()
    # Status change succeeds even without OpenVPN (CCD file creation)
    assert body["success"] is True
    assert body["data"]["id"] == "6ca1dd29-b6a4-41c8-adc9-e154cf3f8557"
    assert body["data"]["name"] == "alice"


def test_set_user_limit():
    """PUT /user/limit with UUID id."""
    c, headers = _client()
    r = c.put(
        "/sync/user/limit",
        headers=headers,
        json={"id": "6ca1dd29-b6a4-41c8-adc9-e154cf3f8557", "max_logins": 0},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is True
    assert body["data"]["id"] == "6ca1dd29-b6a4-41c8-adc9-e154cf3f8557"
    assert body["data"]["max_logins"] == 0


def test_set_user_limit_with_simple_id():
    """PUT /user/limit with simple numeric ID."""
    c, headers = _client()
    r = c.put(
        "/sync/user/limit",
        headers=headers,
        json={"id": "42", "max_logins": 1},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is True
    assert body["data"]["id"] == "42"
    assert body["data"]["max_logins"] == 1


def test_delete_user():
    """DELETE /user/{uid} with UUID."""
    c, headers = _client()
    r = c.delete("/sync/user/6ca1dd29-b6a4-41c8-adc9-e154cf3f8557", headers=headers)
    assert r.status_code == 200
    body = r.json()
    # NOT_FOUND returns success=True so the panel's delete_user_on_all_nodes()
    # can proceed even when the cert was already manually removed from the node.
    assert body["success"] is True
    assert body["msg"] == "User not found on node (already deleted)"


def test_delete_user_simple_id():
    """DELETE /user/{uid} with simple numeric ID."""
    c, headers = _client()
    r = c.delete("/sync/user/42", headers=headers)
    assert r.status_code == 200
    body = r.json()
    # NOT_FOUND returns success=True so panel cleanup can proceed.
    assert body["success"] is True
    assert body["msg"] == "User not found on node (already deleted)"


def test_delete_user_invalid_id():
    """DELETE /user/{uid} rejects invalid UUID-like path."""
    c, headers = _client()
    r = c.delete("/sync/user/invalid@", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is False
    assert body["msg"] == "Invalid user id (must be UUID)"


def test_delete_user_not_found():
    """DELETE /user/{uid} with non-existent UUID."""
    c, headers = _client()
    r = c.delete("/sync/user/d3c9a618-6311-4f8a-9b6c-7e2d2a1b3c44", headers=headers)
    assert r.status_code == 200
    body = r.json()
    # NOT_FOUND returns success=True so panel cleanup can proceed.
    assert body["success"] is True
    assert body["msg"] == "User not found on node (already deleted)"


def test_download_ovpn_missing():
    """Download fails gracefully for non-existent user."""
    c, headers = _client()
    r = c.get("/sync/download/ovpn/6ca1dd29-b6a4-41c8-adc9-e154cf3f8557", headers=headers)
    assert r.status_code == 404


def test_sessions_no_auth():
    """Sessions endpoint requires auth."""
    from core.app import api

    c = TestClient(api)
    r = c.get("/sync/sessions")
    assert r.status_code == 422


def test_sessions_with_auth():
    """Sessions returns empty diagnostics gracefully."""
    c, headers = _client()
    r = c.get("/sync/sessions", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is True


def test_usage_no_auth():
    """Usage endpoint requires auth."""
    from core.app import api

    c = TestClient(api)
    r = c.get("/sync/usage")
    assert r.status_code == 422


def test_usage_with_auth():
    """Usage returns empty gracefully."""
    c, headers = _client()
    r = c.get("/sync/usage", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is True


def test_disconnect_user():
    """Disconnect accepts UUID."""
    c, headers = _client()
    r = c.post("/sync/user/6ca1dd29-b6a4-41c8-adc9-e154cf3f8557/disconnect", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is True
