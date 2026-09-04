# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Tests for error handling, log diagnostics and persistent user usage."""

import os

from fastapi.testclient import TestClient


def _client(**kwargs):
    from core.app import api
    from core.config import settings

    return TestClient(api, **kwargs), {"key": settings.api_key}


# ── error handling ───────────────────────────────────────────────────


def test_unhandled_error_returns_contract_shape_with_ref(monkeypatch):
    """Unhandled exceptions → HTTP 500 in the {success,msg,data} envelope
    with a searchable ref, never a leaked traceback."""
    import core.api.routes as routes

    def boom():
        raise RuntimeError("kaboom secret-internal-detail")

    monkeypatch.setattr(routes, "get_users_usage", boom)
    c, headers = _client(raise_server_exceptions=False)
    r = c.get("/sync/usage", headers=headers)
    assert r.status_code == 500
    body = r.json()
    assert body["success"] is False
    assert "ref=" in body["msg"]
    assert "secret-internal-detail" not in body["msg"]
    assert "Traceback" not in r.text


def test_http_errors_use_contract_shape():
    c, headers = _client()
    r = c.get("/sync/status", headers={"key": "wrong-key-000000000000"})
    assert r.status_code == 401
    body = r.json()
    assert body["success"] is False and body["msg"]

    r = c.get("/sync/status")  # missing header → validation error
    assert r.status_code == 422
    body = r.json()
    assert body["success"] is False
    assert "Invalid request" in body["msg"]


# ── logs ─────────────────────────────────────────────────────────────


def test_ring_buffer_and_stats():
    from core.logger import log_stats, logger, recent_logs

    logger.warning("unit-test warning %s", "w1")
    logger.error("unit-test error %s", "e1")

    records = recent_logs(min_level="WARNING", limit=50)
    messages = [r["message"] for r in records]
    assert any("unit-test warning w1" in m for m in messages)
    assert any("unit-test error e1" in m for m in messages)
    # INFO is filtered out at WARNING threshold
    assert all(r["levelno"] >= 30 for r in records)

    stats = log_stats()
    assert stats["errors_1h"] >= 1
    assert "unit-test error e1" in (stats["last_error"] or "")


def test_logs_endpoint_requires_auth_and_returns_records():
    from core.logger import logger

    logger.error("endpoint-visible error")
    c, headers = _client()

    assert c.get("/sync/logs").status_code == 422  # no key header
    r = c.get("/sync/logs", params={"level": "ERROR", "limit": 10}, headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is True
    records = body["data"]["records"]
    assert len(records) <= 10
    assert any("endpoint-visible error" in rec["message"] for rec in records)
    assert "errors_1h" in body["data"]


def test_status_includes_diagnostics():
    c, headers = _client()
    r = c.get("/sync/status", headers=headers)
    data = r.json()["data"]
    # Contract keys stay intact...
    assert "cpu_usage" in data and "memory_usage" in data and "cert_expiry" in data
    # ...plus the additive diagnostics.
    assert "openvpn_running" in data
    assert "uptime_seconds" in data
    assert "errors_1h" in data


# ── persistent user usage ────────────────────────────────────────────


def test_usage_totals_combine_banked_and_live():
    """totals = disconnect-hook accumulated bytes + live session bytes,
    while the panel-contract keys (users/sessions) stay live-only."""
    from core.openvpn import store
    from core.openvpn import users as um

    status_file = os.environ["OVNODE_STATUS_FILE"]
    os.makedirs(os.path.dirname(status_file), exist_ok=True)
    os.makedirs(store.USAGE_DIR, exist_ok=True)
    try:
        store.set_name("42", "alice")
        # Simulate the disconnect hook having banked two finished sessions.
        with open(os.path.join(store.USAGE_DIR, "42"), "w") as f:
            f.write("5000\n")
        with open(status_file, "w") as f:
            f.write(
                "HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,"
                "Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,"
                "Connected Since (time_t),Username,Client ID,Peer ID,Data Channel Cipher\n"
            )
            f.write("CLIENT_LIST,42,1.2.3.4:5555,10.8.0.2,,1000,2000,now,0,42,0,0,AES\n")

        usage = um.get_users_usage()
        assert usage["users"]["alice"] == 3000  # live only (panel contract)
        assert usage["totals"]["alice"] == 8000  # banked 5000 + live 3000
    finally:
        os.remove(status_file)
        store.delete_user("42")


def test_usage_totals_for_offline_user():
    """A user with banked usage but no live session still appears in totals."""
    from core.openvpn import store
    from core.openvpn import users as um

    os.makedirs(store.USAGE_DIR, exist_ok=True)
    try:
        with open(os.path.join(store.USAGE_DIR, "77"), "w") as f:
            f.write("1234\n")
        usage = um.get_users_usage()
        assert usage["totals"]["77"] == 1234
        assert "77" not in usage["users"]  # not live → not in the live map
    finally:
        store.reset_usage("77")


def test_delete_user_resets_usage():
    from core.openvpn import store

    os.makedirs(store.USAGE_DIR, exist_ok=True)
    with open(os.path.join(store.USAGE_DIR, "88"), "w") as f:
        f.write("999\n")
    store.set_limit("88", 1)
    store.delete_user("88")
    assert store.accumulated_usage("88") == 0
    assert not store.user_exists("88")


def test_disconnect_hook_banks_usage():
    """The disconnect hook must accumulate bytes_received+bytes_sent."""
    script = os.path.join(
        os.path.dirname(__file__), "..", "core", "scripts", "ovnode-client-disconnect.sh"
    )
    with open(script) as f:
        content = f.read()
    assert 'USAGE_DIR="/etc/openvpn/ovnode/usage"' in content
    assert "bytes_received" in content and "bytes_sent" in content
    assert "old + session_total" in content
