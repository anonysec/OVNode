# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Panel-triggered OpenVPN restart + panel-managed IPv6 on server.conf.

Isolated like the other core tests: OVNODE_OPENVPN_ROOT points at a tmp
tree, so server.conf / state files never touch the real node.
"""

import types

import pytest
from fastapi.testclient import TestClient

CONF = """port 1194
proto tcp
dev tun
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "block-outside-dns"
status-version 3
"""

CONF_IPV6 = CONF.replace(
    'push "block-outside-dns"',
    'push "block-outside-dns"\n'
    "tun-ipv6\n"
    "server-ipv6 fd42:42:42:42::/64\n"
    'push "route-ipv6 2000::/3"',
)

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
    monkeypatch.delenv("OVNODE_ENABLE_IPV6", raising=False)
    monkeypatch.delenv("OVNODE_IPV6_PREFIX", raising=False)
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


def _req(enable_ipv6=None, ipv6_prefix=None, dns1=None, dns2=None):
    return types.SimpleNamespace(
        protocol="tcp",
        ovpn_port=1194,
        tunnel_address="vpn.example.com",
        dns1=dns1,
        dns2=dns2,
        enable_ipv6=enable_ipv6,
        ipv6_prefix=ipv6_prefix,
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


# ── restart endpoint ─────────────────────────────────────────────────


def test_restart_endpoint_reports_success_and_liveness(monkeypatch):
    from core.openvpn import control

    monkeypatch.setattr(control, "restart_openvpn", lambda: True)
    monkeypatch.setattr(control, "openvpn_is_running", lambda: True)
    c, headers = _client()
    r = c.post("/sync/restart", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["success"] is True
    assert body["data"]["openvpn_running"] is True


def test_restart_endpoint_maps_restart_failure(monkeypatch):
    from core.openvpn import control

    monkeypatch.setattr(control, "restart_openvpn", lambda: False)
    monkeypatch.setattr(control, "openvpn_is_running", lambda: False)
    c, headers = _client()
    r = c.post("/sync/restart", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["success"] is False
    assert "failed" in body["msg"].lower()
    assert body["data"]["openvpn_running"] is False


def test_restart_endpoint_survives_restart_exception(monkeypatch):
    """A raising service manager must still produce a contract envelope."""
    from core.openvpn import control

    def boom():
        raise RuntimeError("systemctl exploded")

    monkeypatch.setattr(control, "restart_openvpn", boom)
    monkeypatch.setattr(control, "openvpn_is_running", lambda: False)
    c, headers = _client()
    r = c.post("/sync/restart", headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["success"] is False
    assert "systemctl exploded" in body["msg"]
    assert body["data"]["openvpn_running"] is False


def test_restart_endpoint_requires_auth():
    from core.app import api

    assert TestClient(api).post("/sync/restart").status_code == 422


# ── IPv6 via change_config() ─────────────────────────────────────────


def test_enable_ipv6_adds_exactly_one_block(root):
    tmp_path, calls = root
    from core.openvpn.control import change_config

    assert change_config(_req(enable_ipv6=True, ipv6_prefix="fd42:1:2:3::/64")) is True
    conf = (tmp_path / "server" / "server.conf").read_text()
    assert conf.count("tun-ipv6") == 1
    assert conf.count("server-ipv6 fd42:1:2:3::/64") == 1
    assert conf.count('push "route-ipv6 2000::/3"') == 1
    # IPv6 is a reload (SIGHUP), never a rebind restart.
    assert calls == {"restart": 0, "sighup": 1}
    state = (tmp_path / "ovnode" / "ipv6").read_text()
    assert "enabled=1" in state
    assert "prefix=fd42:1:2:3::/64" in state


def test_enable_ipv6_replaces_old_prefix_without_duplicates(root):
    tmp_path, calls = root
    conf_path = tmp_path / "server" / "server.conf"
    conf_path.write_text(
        CONF_IPV6.replace(
            'push "route-ipv6 2000::/3"',
            'push "route-ipv6 2000::/3"\ntun-ipv6\nserver-ipv6 fd42:42:42:42::/64',
        )
    )
    from core.openvpn.control import change_config

    assert change_config(_req(enable_ipv6=True, ipv6_prefix="fd42:9:9:9::/64")) is True
    conf = conf_path.read_text()
    assert conf.count("tun-ipv6") == 1
    assert conf.count("server-ipv6 ") == 1
    assert conf.count("server-ipv6 fd42:9:9:9::/64") == 1
    assert "fd42:42:42:42::/64" not in conf
    assert conf.count('push "route-ipv6 2000::/3"') == 1
    assert calls == {"restart": 0, "sighup": 1}


def test_disable_ipv6_removes_generated_lines(root):
    tmp_path, calls = root
    conf_path = tmp_path / "server" / "server.conf"
    conf_path.write_text(CONF_IPV6)
    from core.openvpn.control import change_config

    assert change_config(_req(enable_ipv6=False)) is True
    conf = conf_path.read_text()
    assert "tun-ipv6" not in conf
    assert "server-ipv6" not in conf
    assert "route-ipv6" not in conf
    assert calls == {"restart": 0, "sighup": 1}
    assert "enabled=0" in (tmp_path / "ovnode" / "ipv6").read_text()


def test_invalid_ipv6_prefix_rejected_before_any_write(root):
    tmp_path, calls = root
    conf_path = tmp_path / "server" / "server.conf"
    before = conf_path.read_bytes()
    from core.openvpn.control import change_config

    assert change_config(_req(enable_ipv6=True, ipv6_prefix="not-a-prefix")) is False
    assert change_config(_req(enable_ipv6=True, ipv6_prefix="10.0.0.0/24")) is False
    assert change_config(_req(enable_ipv6=True, ipv6_prefix="fd42:42:42:42::")) is False
    assert conf_path.read_bytes() == before
    assert calls == {"restart": 0, "sighup": 0}
    assert not (tmp_path / "ovnode" / "ipv6").exists()


def test_omitted_ipv6_fields_leave_conf_unchanged(root):
    tmp_path, calls = root
    conf_path = tmp_path / "server" / "server.conf"
    before = conf_path.read_bytes()
    from core.openvpn.control import change_config

    assert change_config(_req()) is True
    assert conf_path.read_bytes() == before
    assert "tun-ipv6" not in conf_path.read_text()
    assert calls == {"restart": 0, "sighup": 0}


def test_prefix_only_keeps_current_enabled_state(root):
    tmp_path, _ = root
    from core.openvpn import ipv6 as ipv6_policy
    from core.openvpn.control import change_config

    ipv6_policy.write_state(True, "fd42:1:2:3::/64")
    assert change_config(_req(ipv6_prefix="fd42:7:7:7::/64")) is True
    conf = (tmp_path / "server" / "server.conf").read_text()
    assert conf.count("tun-ipv6") == 1
    assert "server-ipv6 fd42:7:7:7::/64" in conf
    assert "fd42:1:2:3::/64" not in conf


def test_prefix_only_keeps_enabled_state_from_conf(root):
    """A node that predates the state file still keeps its live IPv6 block."""
    tmp_path, calls = root
    conf_path = tmp_path / "server" / "server.conf"
    conf_path.write_text(CONF_IPV6)
    from core.openvpn.control import change_config

    assert change_config(_req(ipv6_prefix="fd42:4:4:4::/64")) is True
    conf = conf_path.read_text()
    assert "tun-ipv6" in conf
    assert conf.count("server-ipv6 fd42:4:4:4::/64") == 1
    assert "fd42:42:42:42::/64" not in conf
    assert calls == {"restart": 0, "sighup": 1}


def test_sync_config_endpoint_applies_ipv6(root):
    tmp_path, calls = root
    c, headers = _client()
    r = c.post(
        "/sync/config",
        headers=headers,
        json=_config_payload(enable_ipv6=True, ipv6_prefix="fd42:5:5:5::/64"),
    )
    assert r.status_code == 200, r.text
    assert r.json()["success"] is True
    conf = (tmp_path / "server" / "server.conf").read_text()
    assert conf.count("tun-ipv6") == 1
    assert conf.count("server-ipv6 fd42:5:5:5::/64") == 1
    assert calls == {"restart": 0, "sighup": 1}


def test_sync_config_endpoint_rejects_invalid_ipv6_prefix(root):
    tmp_path, calls = root
    c, headers = _client()
    r = c.post(
        "/sync/config",
        headers=headers,
        json=_config_payload(enable_ipv6=True, ipv6_prefix="nope"),
    )
    assert r.status_code == 200, r.text
    assert r.json()["success"] is False
    assert calls == {"restart": 0, "sighup": 0}
    assert "tun-ipv6" not in (tmp_path / "server" / "server.conf").read_text()


def test_fresh_conf_honours_ipv6_state(root):
    from core.openvpn import ipv6 as ipv6_policy
    from core.openvpn import pki

    ipv6_policy.write_state(True, "fd42:5:5:5::/64")
    conf = pki._fresh_server_conf()
    assert conf.count("tun-ipv6") == 1
    assert conf.count("server-ipv6 fd42:5:5:5::/64") == 1
    assert conf.count('push "route-ipv6 2000::/3"') == 1
    ipv6_policy.write_state(False, "fd42:5:5:5::/64")
    conf = pki._fresh_server_conf()
    assert "tun-ipv6" not in conf
    assert "server-ipv6" not in conf
