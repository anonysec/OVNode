# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Blocking easyrsa work must run in the threadpool, and a failed rebind
restart must roll server.conf/template back to the previous config.

1. POST /sync/user, DELETE /sync/user/{uid} and GET /sync/download/ovpn/{uid}
   all reach their blocking worker through ``run_in_threadpool``.
2. A port/proto change whose restart fails restores the ``.bak`` files, retries
   the restart and reports the change as failed; an identical push stays a
   total no-op.
"""

import pytest
from fastapi.testclient import TestClient

CONF = """port 1194
proto udp
dev tun
explicit-exit-notify 1
server 10.8.0.0 255.255.255.0
"""

TEMPLATE = """client
proto udp
remote vpn.example.com 1194
"""


def _client():
    from core.app import api
    from core.config import settings

    return TestClient(api), {"key": settings.api_key}


# ── offload proof ────────────────────────────────────────────────────


def test_cert_endpoints_offload_to_threadpool(monkeypatch):
    """Every blocking PKI worker must be invoked via run_in_threadpool."""
    from fastapi.concurrency import run_in_threadpool as real_run_in_threadpool

    from core.api import auth, routes
    from core.validation import DeleteResult

    threaded: list[str] = []

    async def recording_run_in_threadpool(fn, *args, **kwargs):
        threaded.append(fn.__name__)
        return await real_run_in_threadpool(fn, *args, **kwargs)

    monkeypatch.setattr(routes, "run_in_threadpool", recording_run_in_threadpool)

    # Stubs keep the real easyrsa/openssl forks out of the test and keep the
    # original names so the recorded __name__ values match the workers.
    def create_user_on_server(uid, name, max_logins=1):
        return True

    def delete_user_on_server(uid):
        return DeleteResult.OK

    def download_ovpn_file(uid):
        return None

    monkeypatch.setattr(routes, "create_user_on_server", create_user_on_server)
    monkeypatch.setattr(routes, "delete_user_on_server", delete_user_on_server)
    monkeypatch.setattr(routes, "download_ovpn_file", download_ovpn_file)

    auth._ratelimit_buckets.clear()
    auth._heavy_buckets.clear()
    try:
        c, headers = _client()

        created = c.post(
            "/sync/user",
            headers=headers,
            json={"id": "424242", "name": "alice", "max_logins": 2},
        )
        assert created.status_code == 200, created.text
        assert created.json()["success"] is True

        deleted = c.delete("/sync/user/424242", headers=headers)
        assert deleted.status_code == 200, deleted.text
        assert deleted.json()["success"] is True

        downloaded = c.get("/sync/download/ovpn/424242", headers=headers)
        assert downloaded.status_code == 200, downloaded.text
        assert downloaded.json()["success"] is False  # stub returns no path
    finally:
        auth._ratelimit_buckets.clear()
        auth._heavy_buckets.clear()

    for worker in ("create_user_on_server", "delete_user_on_server", "download_ovpn_file"):
        assert worker in threaded, f"{worker} must be offloaded to the threadpool"


# ── rollback proof ───────────────────────────────────────────────────


@pytest.fixture()
def isolated_root(tmp_path, monkeypatch):
    server = tmp_path / "server"
    server.mkdir()
    (server / "server.conf").write_text(CONF)
    (server / "client-common.txt").write_text(TEMPLATE)
    # change_config() reads the root env at call time (module constants used by
    # restart_openvpn are not exercised here — that call is monkeypatched).
    monkeypatch.setenv("OVNODE_OPENVPN_ROOT", str(tmp_path))
    monkeypatch.delenv("OVNODE_EXTRA_PORTS", raising=False)

    from core.openvpn import control, ports, store

    users = tmp_path / "users"
    users.mkdir()
    monkeypatch.setattr(store, "USERS_DIR", str(users))
    monkeypatch.setattr(control, "_sighup_fallback", lambda: True)
    # Never touch the host's installer NAT files.
    monkeypatch.setattr(ports, "NAT_CONF", str(tmp_path / "no-ovnode-nat"))
    monkeypatch.setattr(ports, "NAT_SCRIPT", str(tmp_path / "no-ovnode-nat.sh"))
    monkeypatch.setattr(ports, "is_docker", lambda: True)

    import core.openvpn.multilogin as ml

    monkeypatch.setattr(ml, "ensure_multilogin_setup", lambda: None)
    return tmp_path


def _settings(**overrides):
    from core.api.schemas import SetSettingsModel

    payload = {
        "tunnel_address": "",
        "protocol": "udp",
        "ovpn_port": 1194,
        "set_new_setting": True,
    }
    payload.update(overrides)
    return SetSettingsModel(**payload)


def test_failed_restart_rolls_back_and_reports_failure(isolated_root, monkeypatch):
    from core.openvpn import control

    attempts: list[int] = []

    def restart_openvpn():
        attempts.append(1)
        return len(attempts) > 1  # first call fails, the rollback retry succeeds

    monkeypatch.setattr(control, "restart_openvpn", restart_openvpn)

    conf = isolated_root / "server" / "server.conf"
    template = isolated_root / "server" / "client-common.txt"

    assert control.change_config(_settings(ovpn_port=1195)) is False
    assert len(attempts) == 2, "the rollback restart must be attempted after a failure"
    assert "port 1194" in conf.read_text()
    assert "port 1195" not in conf.read_text()
    assert "remote vpn.example.com 1194" in template.read_text()

    # Identical push after the rollback: total no-op, zero further restarts.
    assert control.change_config(_settings(ovpn_port=1194)) is True
    assert len(attempts) == 2
