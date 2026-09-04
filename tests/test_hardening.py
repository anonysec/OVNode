# Copyright (c) 2025 anonysec. All rights reserved.
# Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.

"""Hardening regression tests: management kill gate, journal absence,
env handling, schema validation ranges, and envelope-shaped failures."""

import importlib

from fastapi.testclient import TestClient


def _client():
    from core.app import api
    from core.config import settings

    return TestClient(api), {"key": settings.api_key}


def test_kill_gate_accepts_uuid_and_rejects_injection():
    from core.openvpn.sessions import _kill_target_ok

    assert _kill_target_ok("6ca1dd29-b6a4-41c8-adc9-e154cf3f8557") is True
    assert _kill_target_ok("42") is True
    assert _kill_target_ok("alice_1") is True
    assert _kill_target_ok("alice; reboot") is False
    assert _kill_target_ok("a b") is False
    assert _kill_target_ok("$(id)") is False
    assert _kill_target_ok("") is False
    assert _kill_target_ok("../x") is False


def test_journal_missing_returns_empty_quietly(monkeypatch, caplog):
    import core.openvpn.sessions as sessions

    monkeypatch.setattr(sessions.shutil, "which", lambda *_a, **_k: None)
    monkeypatch.setattr(sessions, "_journal_available", None)
    monkeypatch.setattr(sessions, "_journal_cache", {})
    with caplog.at_level("WARNING", logger="ovnode"):
        assert sessions._journal_lines(8) == []
    assert sessions._journal_available is False
    # Second call must not fork or warn again (cached unavailability).
    with caplog.at_level("WARNING", logger="ovnode"):
        assert sessions._journal_lines(8) == []
    assert not [r for r in caplog.records if "journal" in r.message.lower()]


def test_mgmt_port_garbage_falls_back():
    from core.openvpn.sessions import _parse_mgmt_port

    assert _parse_mgmt_port("7505") == 7505
    assert _parse_mgmt_port("bogus") == 7505
    assert _parse_mgmt_port("") == 7505
    assert _parse_mgmt_port(None) == 7505
    assert _parse_mgmt_port("99999") == 7505
    assert _parse_mgmt_port("1194") == 1194


def test_mgmt_host_env_alias(monkeypatch):
    monkeypatch.delenv("OVNODE_MANAGEMENT_HOST", raising=False)
    monkeypatch.setenv("OVNODE_MGMT_HOST", "10.0.0.9")
    import core.openvpn.sessions as sessions

    importlib.reload(sessions)
    try:
        assert sessions.MANAGEMENT_HOST == "10.0.0.9"
    finally:
        monkeypatch.delenv("OVNODE_MGMT_HOST", raising=False)
        importlib.reload(sessions)


def test_schema_rejects_bad_protocol_and_ranges():
    c, headers = _client()
    # Unknown protocol -> 422, not a silent map to udp.
    r = c.post(
        "/sync/config",
        json={
            "tunnel_address": "10.8.0.1",
            "protocol": "bogus",
            "ovpn_port": 1194,
            "set_new_setting": True,
        },
        headers=headers,
    )
    assert r.status_code == 422
    # Negative logins -> 422, not a silent coerce to unlimited.
    r = c.post("/sync/user", json={"name": "alice", "max_logins": -3}, headers=headers)
    assert r.status_code == 422
    r = c.put("/sync/user/limit", json={"id": "alice", "max_logins": -1}, headers=headers)
    assert r.status_code == 422
    # Absurd ovpn port -> 422.
    r = c.post(
        "/sync/config",
        json={
            "tunnel_address": "10.8.0.1",
            "protocol": "tcp",
            "ovpn_port": 99999,
            "set_new_setting": True,
        },
        headers=headers,
    )
    assert r.status_code == 422


def test_disconnect_invalid_id_is_envelope():
    c, headers = _client()
    r = c.post("/sync/user/not!!valid/disconnect", headers=headers)
    assert r.status_code == 200
    assert r.json()["success"] is False


def test_download_invalid_id_is_envelope():
    c, headers = _client()
    r = c.get("/sync/download/ovpn/not!!valid", headers=headers)
    assert r.status_code == 200
    assert r.json()["success"] is False


def test_disconnect_uuid_shape_accepted():
    """A UUID disconnect must pass the kill gate (mgmt may be down in CI,
    but the response must not report 'invalid cn format')."""
    c, headers = _client()
    uid = "6ca1dd29-b6a4-41c8-adc9-e154cf3f8557"
    r = c.post(f"/sync/user/{uid}/disconnect", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is True
    assert body["data"]["management"].get("error") != "invalid cn format"
