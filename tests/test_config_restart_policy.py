# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""change_config() restart policy: tunnels are user traffic, never bounce idly.

- Identical push → no write, no signal, no multilogin re-apply.
- Tunnel-address-only push → template rewrite, zero daemon signals.
- Port/proto change → exactly one full restart.
- Conf normalization without value change (tcp-server → tcp) → SIGHUP only.
"""

import types

import pytest

from core.openvpn import control, store

CONF = """port 1194
proto udp
dev tun
explicit-exit-notify 1
status /tmp/x/status.log 5
"""

TEMPLATE = """client
proto udp
remote vpn.example.com 1194
"""


@pytest.fixture()
def root(tmp_path, monkeypatch):
    server = tmp_path / "server"
    server.mkdir()
    (server / "server.conf").write_text(CONF)
    (server / "client-common.txt").write_text(TEMPLATE)
    monkeypatch.setenv("OVNODE_OPENVPN_ROOT", str(tmp_path))
    users = tmp_path / "users"
    users.mkdir()
    monkeypatch.setattr(store, "USERS_DIR", str(users))
    calls = {"restart": 0, "sighup": 0}

    def _restart():
        calls["restart"] += 1
        return True

    def _sighup():
        calls["sighup"] += 1
        return True

    monkeypatch.setattr(control, "restart_openvpn", _restart)
    monkeypatch.setattr(control, "_sighup_fallback", _sighup)
    import core.openvpn.multilogin as ml

    monkeypatch.setattr(ml, "ensure_multilogin_setup", lambda: None)
    return tmp_path, calls


def _req(proto="udp", port=1194, tunnel="vpn.example.com"):
    return types.SimpleNamespace(protocol=proto, ovpn_port=port, tunnel_address=tunnel)


def test_identical_push_is_total_noop(root):
    tmp_path, calls = root
    conf_path = tmp_path / "server" / "server.conf"
    before = conf_path.read_bytes()
    assert control.change_config(_req()) is True
    assert conf_path.read_bytes() == before
    assert (tmp_path / "server" / "client-common.txt").read_text() == TEMPLATE
    assert calls == {"restart": 0, "sighup": 0}


def test_tunnel_only_change_signals_nothing(root):
    tmp_path, calls = root
    (tmp_path / "users" / "alice").mkdir()
    cached = tmp_path / "users" / "alice" / "client.ovpn"
    cached.write_text("old")
    assert control.change_config(_req(tunnel="vpn2.example.com")) is True
    assert "remote vpn2.example.com 1194" in (tmp_path / "server" / "client-common.txt").read_text()
    assert calls == {"restart": 0, "sighup": 0}
    assert not cached.exists(), "stale cached profile must be invalidated"


def test_port_change_restarts_exactly_once(root):
    tmp_path, calls = root
    assert control.change_config(_req(port=1195)) is True
    assert "port 1195" in (tmp_path / "server" / "server.conf").read_text()
    assert calls == {"restart": 1, "sighup": 0}


def test_proto_normalization_sighups_without_restart(root):
    tmp_path, calls = root
    (tmp_path / "server" / "server.conf").write_text(CONF.replace("proto udp", "proto udp6"))
    assert control.change_config(_req(proto="udp")) is True
    assert "\nproto udp\n" in (tmp_path / "server" / "server.conf").read_text()
    assert calls == {"restart": 0, "sighup": 1}


def test_bad_port_rejected_before_any_write(root):
    tmp_path, calls = root
    conf_path = tmp_path / "server" / "server.conf"
    before = conf_path.read_bytes()
    assert control.change_config(_req(port=99999)) is False
    assert conf_path.read_bytes() == before
    assert calls == {"restart": 0, "sighup": 0}
