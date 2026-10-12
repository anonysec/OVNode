# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""change_config() classification: structural vs hot, restart behavior untouched.

The panel cursor needs to know the KIND of an applied push without re-deriving
it from files. Gate vocabulary:

- structural (restart_required) = tunnel_address / protocol / ovpn_port changed
- hot (hot_reload)              = dns / ipv6 / extra_ports changed

The booleans label the change for the panel; what the daemon actually does is
asserted separately per case and must be byte-identical to the old policy
(port/proto → one full restart, dns/ipv6/extras → SIGHUP, tunnel-only →
zero signals).
"""

import types

import pytest

from backend.openvpn import control, store

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
    # setenv, not delenv: ports.write_state -> _sync_env mutates the process
    # env; setenv always registers the teardown restore, delenv on an absent
    # var does not — and the leak reaches every later test in the session.
    monkeypatch.setenv("OVNODE_EXTRA_PORTS", "")
    users = tmp_path / "users"
    users.mkdir()
    calls = {"restart": 0, "sighup": 0}

    def _restart():
        calls["restart"] += 1
        return True

    def _sighup():
        calls["sighup"] += 1
        return True

    monkeypatch.setattr(control, "restart_openvpn", _restart)
    monkeypatch.setattr(control, "_sighup_fallback", _sighup)
    monkeypatch.setattr(store, "USERS_DIR", str(users))
    # The host may carry the installer's real NAT files: never touch them.
    from backend.openvpn import ports

    monkeypatch.setattr(ports, "NAT_CONF", str(tmp_path / "no-ovnode-nat"))
    monkeypatch.setattr(ports, "NAT_SCRIPT", str(tmp_path / "no-ovnode-nat.sh"))
    monkeypatch.setattr(ports, "is_docker", lambda: False)
    import backend.openvpn.multilogin as ml

    monkeypatch.setattr(ml, "ensure_multilogin_setup", lambda: None)
    return tmp_path, calls


def _req(**kw):
    base = {"protocol": "udp", "ovpn_port": 1194, "tunnel_address": "vpn.example.com"}
    base.update(kw)
    return types.SimpleNamespace(**base)


def _apply(req):
    classification: dict = {}
    ok = control.change_config(req, classification)
    return ok, classification


def test_identical_push_is_unclassified_noop(root):
    tmp_path, calls = root
    before = (tmp_path / "server" / "server.conf").read_bytes()
    ok, cls = _apply(_req())
    assert ok is True
    assert cls == {"restart_required": False, "hot_reload": False}
    assert (tmp_path / "server" / "server.conf").read_bytes() == before
    assert calls == {"restart": 0, "sighup": 0}


def test_tunnel_address_is_structural_with_zero_signals(root):
    """Structural per the Gate vocabulary, yet the daemon is not touched:
    the template is only read when generating .ovpn profiles."""
    tmp_path, calls = root
    ok, cls = _apply(_req(tunnel_address="vpn2.example.com"))
    assert ok is True
    assert cls == {"restart_required": True, "hot_reload": False}
    assert "remote vpn2.example.com 1194" in (tmp_path / "server" / "client-common.txt").read_text()
    assert calls == {"restart": 0, "sighup": 0}


def test_protocol_change_is_structural_and_restarts_once(root):
    _, calls = root
    ok, cls = _apply(_req(protocol="tcp"))
    assert ok is True
    assert cls == {"restart_required": True, "hot_reload": False}
    assert calls == {"restart": 1, "sighup": 0}


def test_port_change_is_structural_and_restarts_once(root):
    tmp_path, calls = root
    ok, cls = _apply(_req(ovpn_port=1195))
    assert ok is True
    assert cls == {"restart_required": True, "hot_reload": False}
    assert "port 1195" in (tmp_path / "server" / "server.conf").read_text()
    assert calls == {"restart": 1, "sighup": 0}


def test_dns_change_is_hot_and_sighups(root):
    _, calls = root
    ok, cls = _apply(_req(dns1="9.9.9.9", dns2="149.112.112.112"))
    assert ok is True
    assert cls == {"restart_required": False, "hot_reload": True}
    assert calls == {"restart": 0, "sighup": 1}


def test_ipv6_change_is_hot_and_sighups(root):
    _, calls = root
    ok, cls = _apply(_req(enable_ipv6=True, ipv6_prefix="fd42:1:2:3::/64"))
    assert ok is True
    assert cls == {"restart_required": False, "hot_reload": True}
    assert calls == {"restart": 0, "sighup": 1}


def test_extra_ports_change_is_hot_and_sighups(root):
    _, calls = root
    ok, cls = _apply(_req(extra_ports="443,8443"))
    assert ok is True
    assert cls == {"restart_required": False, "hot_reload": True}
    assert calls == {"restart": 0, "sighup": 1}


def test_mixed_push_labels_both_and_restarts_once(root):
    """Port + DNS in one push: both kinds changed, restart wins the signal
    path exactly as before (one restart, no SIGHUP)."""
    _, calls = root
    ok, cls = _apply(_req(ovpn_port=1195, dns1="9.9.9.9"))
    assert ok is True
    assert cls == {"restart_required": True, "hot_reload": True}
    assert calls == {"restart": 1, "sighup": 0}


def test_proto_normalization_is_neither_kind(root):
    """tcp-server → tcp style normalization rewrites conf bytes but changes
    no value: not structural, not hot — yet still SIGHUPs as before."""
    tmp_path, calls = root
    (tmp_path / "server" / "server.conf").write_text(CONF.replace("proto udp", "proto udp6"))
    ok, cls = _apply(_req(proto="udp"))
    assert ok is True
    assert cls == {"restart_required": False, "hot_reload": False}
    assert calls == {"restart": 0, "sighup": 1}


def test_invalid_port_fails_without_classification(root):
    tmp_path, calls = root
    before = (tmp_path / "server" / "server.conf").read_bytes()
    classification: dict = {}
    assert control.change_config(_req(ovpn_port=99999), classification) is False
    # Rejected before any diff: nothing classified, nothing written.
    assert classification == {}
    assert (tmp_path / "server" / "server.conf").read_bytes() == before
    assert calls == {"restart": 0, "sighup": 0}
