# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Per-node DNS management + panel-triggered software update.

Isolated like the other core tests: OVNODE_OPENVPN_ROOT points at a tmp
tree, so server.conf / state files never touch the real node.
"""

import time
import types

import pytest
from fastapi.testclient import TestClient

CONF = """port 1194
proto tcp
dev tun
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.8.8"
push "block-outside-dns"
status-version 3
"""

TEMPLATE = """client
proto tcp
remote vpn.example.com 1194
"""


@pytest.fixture()
def root(tmp_path, monkeypatch):
    server = tmp_path / "server"
    server.mkdir()
    (server / "server.conf").write_text(CONF)
    (server / "client-common.txt").write_text(TEMPLATE)
    monkeypatch.setenv("OVNODE_OPENVPN_ROOT", str(tmp_path))
    monkeypatch.delenv("OVNODE_EXTRA_PORTS", raising=False)
    users = tmp_path / "users"
    users.mkdir()
    calls = {"restart": 0, "sighup": 0}

    from core.openvpn import control, store

    def _restart():
        calls["restart"] += 1
        return True

    def _sighup():
        calls["sighup"] += 1
        return True

    monkeypatch.setattr(control, "restart_openvpn", _restart)
    monkeypatch.setattr(control, "_sighup_fallback", _sighup)
    monkeypatch.setattr(store, "USERS_DIR", str(users))
    import core.openvpn.multilogin as ml

    monkeypatch.setattr(ml, "ensure_multilogin_setup", lambda: None)
    return tmp_path, calls


def _client():
    from core.app import api
    from core.config import settings

    return TestClient(api), {"key": settings.api_key}


def _req(dns1=None, dns2=None):
    return types.SimpleNamespace(
        protocol="tcp",
        ovpn_port=1194,
        tunnel_address="vpn.example.com",
        dns1=dns1,
        dns2=dns2,
    )


def _config_payload(**extra):
    payload = {
        "tunnel_address": "vpn.example.com",
        "protocol": "tcp",
        "ovpn_port": 1194,
        "set_new_setting": True,
    }
    payload.update(extra)
    return payload


# ── DNS ──────────────────────────────────────────────────────────────


def test_applied_dns_appears_exactly_once(root):
    tmp_path, calls = root
    from core.openvpn.control import change_config

    assert change_config(_req(dns1="9.9.9.9", dns2="149.112.112.112")) is True
    conf = (tmp_path / "server" / "server.conf").read_text()
    assert conf.count('push "dhcp-option DNS 9.9.9.9"') == 1
    assert conf.count('push "dhcp-option DNS 149.112.112.112"') == 1
    assert conf.count("dhcp-option DNS ") == 2
    assert "1.1.1.1" not in conf
    assert "8.8.8.8" not in conf
    # DNS-only change is a reload, never a teardown.
    assert calls == {"restart": 0, "sighup": 1}
    state = (tmp_path / "ovnode" / "dns").read_text()
    assert "dns1=9.9.9.9" in state
    assert "dns2=149.112.112.112" in state


def test_duplicate_push_lines_collapse(root):
    tmp_path, _ = root
    from core.openvpn.control import change_config

    conf_path = tmp_path / "server" / "server.conf"
    conf_path.write_text(
        CONF.replace(
            'push "dhcp-option DNS 8.8.8.8"',
            'push "dhcp-option DNS 8.8.8.8"\n'
            'push "dhcp-option DNS 1.1.1.1"\n'
            'push "dhcp-option DNS 8.8.8.8"',
        )
    )
    assert change_config(_req(dns1="9.9.9.9", dns2="8.8.8.8")) is True
    conf = conf_path.read_text()
    assert conf.count("dhcp-option DNS ") == 2
    assert conf.count('push "dhcp-option DNS 9.9.9.9"') == 1
    assert conf.count('push "dhcp-option DNS 8.8.8.8"') == 1


def test_omitted_field_keeps_existing_value(root):
    tmp_path, _ = root
    from core.openvpn.control import change_config

    assert change_config(_req(dns1="9.9.9.9")) is True
    conf = (tmp_path / "server" / "server.conf").read_text()
    assert conf.count('push "dhcp-option DNS 9.9.9.9"') == 1
    # dns2 was omitted → the previous 8.8.8.8 stays.
    assert conf.count('push "dhcp-option DNS 8.8.8.8"') == 1
    assert "1.1.1.1" not in conf
    state = (tmp_path / "ovnode" / "dns").read_text()
    assert "dns1=9.9.9.9" in state and "dns2=8.8.8.8" in state


def test_invalid_dns_rejected_before_any_write(root):
    tmp_path, calls = root
    from core.openvpn.control import change_config

    conf_path = tmp_path / "server" / "server.conf"
    before = conf_path.read_bytes()
    assert change_config(_req(dns1="not-an-ip")) is False
    assert change_config(_req(dns2="999.1.1.1")) is False
    assert conf_path.read_bytes() == before
    assert calls == {"restart": 0, "sighup": 0}
    assert not (tmp_path / "ovnode" / "dns").exists()


def test_missing_push_lines_are_inserted(root):
    tmp_path, calls = root
    from core.openvpn.control import change_config

    conf_path = tmp_path / "server" / "server.conf"
    conf_path.write_text(
        "port 1194\nproto tcp\ndev tun\nserver 10.8.0.0 255.255.255.0\n"
        'push "redirect-gateway def1 bypass-dhcp"\nstatus-version 3\n'
    )
    assert change_config(_req(dns1="9.9.9.9", dns2="149.112.112.112")) is True
    conf = conf_path.read_text()
    assert conf.count('push "dhcp-option DNS 9.9.9.9"') == 1
    assert conf.count('push "dhcp-option DNS 149.112.112.112"') == 1
    # Inserted next to the other pushes, not appended after daemon settings.
    assert conf.index("dhcp-option DNS") < conf.index("status-version")
    assert calls == {"restart": 0, "sighup": 1}


def test_fresh_conf_generation_honours_dns_state(root):
    tmp_path, _ = root
    from core.openvpn import dns as dns_policy
    from core.openvpn import pki

    dns_policy.write_state(["9.9.9.9", "149.112.112.112"])
    conf = pki._fresh_server_conf()
    assert conf.count('push "dhcp-option DNS 9.9.9.9"') == 1
    assert conf.count('push "dhcp-option DNS 149.112.112.112"') == 1
    assert "1.1.1.1" not in conf
    assert "8.8.8.8" not in conf


def test_sync_config_endpoint_applies_dns(root):
    tmp_path, calls = root

    c, headers = _client()
    r = c.post(
        "/sync/config",
        headers=headers,
        json=_config_payload(dns1="9.9.9.9", dns2="149.112.112.112"),
    )
    assert r.status_code == 200
    assert r.json()["success"] is True
    conf = (tmp_path / "server" / "server.conf").read_text()
    assert conf.count('push "dhcp-option DNS 9.9.9.9"') == 1
    assert conf.count('push "dhcp-option DNS 149.112.112.112"') == 1
    assert calls == {"restart": 0, "sighup": 1}


def test_sync_config_endpoint_rejects_invalid_dns(root):
    tmp_path, calls = root

    c, headers = _client()
    r = c.post("/sync/config", headers=headers, json=_config_payload(dns1="999.1.1.1"))
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is False
    assert calls == {"restart": 0, "sighup": 0}
    assert "1.1.1.1" in (tmp_path / "server" / "server.conf").read_text()


# ── software update ──────────────────────────────────────────────────


def test_update_endpoint_refuses_in_docker(monkeypatch):
    from core import updater

    launched = []
    monkeypatch.setattr(updater, "is_docker", lambda: True)
    monkeypatch.setattr(updater.subprocess, "Popen", lambda *a, **k: launched.append(a))
    c, headers = _client()
    r = c.post("/sync/update", headers=headers)
    body = r.json()
    assert r.status_code == 200
    assert body["success"] is False
    assert "container" in body["msg"]
    assert "host" in body["msg"]
    assert launched == []


def test_update_endpoint_requires_install_script(monkeypatch, tmp_path):
    from core import updater

    monkeypatch.setenv("OVNODE_APP_DIR", str(tmp_path))
    monkeypatch.setattr(updater, "is_docker", lambda: False)
    launched = []
    monkeypatch.setattr(updater.subprocess, "Popen", lambda *a, **k: launched.append(a))
    c, headers = _client()
    body = c.post("/sync/update", headers=headers).json()
    assert body["success"] is False
    assert "install.sh" in body["msg"]
    assert launched == []


def test_update_endpoint_launches_detached(monkeypatch, tmp_path):
    from core import updater
    from core.version import __version__

    app_dir = tmp_path / "app"
    app_dir.mkdir()
    script = app_dir / "install.sh"
    script.write_text("#!/usr/bin/env bash\nexit 0\n")
    monkeypatch.setenv("OVNODE_APP_DIR", str(app_dir))
    monkeypatch.setattr(updater, "is_docker", lambda: False)
    seen = {}

    class FakePopen:
        def __init__(self, argv, **kwargs):
            seen["argv"] = argv
            seen["kwargs"] = kwargs

    monkeypatch.setattr(updater.subprocess, "Popen", FakePopen)
    c, headers = _client()
    started = time.monotonic()
    r = c.post("/sync/update", headers=headers)
    elapsed = time.monotonic() - started
    body = r.json()
    assert r.status_code == 200
    assert body["success"] is True
    assert body["data"]["version"] == __version__
    assert seen["argv"] == ["bash", str(script), "update", "--json"]
    assert seen["kwargs"]["start_new_session"] is True
    assert elapsed < 5, "the endpoint must not wait for the updater"


def test_update_endpoint_requires_auth():
    from core.app import api

    assert TestClient(api).post("/sync/update").status_code == 422
