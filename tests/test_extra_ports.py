# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Panel-managed extra VPN ports (core.openvpn.ports + POST /sync/config).

Isolated like the other core tests: OVNODE_OPENVPN_ROOT points at a tmp tree
and the installer NAT paths at (non-)tmp files, so no real config, state file
or iptables rule is ever touched.
"""

import types

import pytest
from fastapi.testclient import TestClient

CONF = """port 1194
proto tcp
dev tun
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
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

    from core.openvpn import control, ports, store

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
    monkeypatch.setattr(ports, "NAT_CONF", str(tmp_path / "no-ovnode-nat"))
    monkeypatch.setattr(ports, "NAT_SCRIPT", str(tmp_path / "no-ovnode-nat.sh"))
    monkeypatch.setattr(ports, "is_docker", lambda: False)
    import core.openvpn.multilogin as ml

    monkeypatch.setattr(ml, "ensure_multilogin_setup", lambda: None)
    return tmp_path, calls


def _client():
    from core.app import api
    from core.config import settings

    return TestClient(api), {"key": settings.api_key}


def _req(extra_ports=None):
    return types.SimpleNamespace(
        protocol="tcp",
        ovpn_port=1194,
        tunnel_address="vpn.example.com",
        extra_ports=extra_ports,
    )


def _req_old_panel():
    """A pre-extra-ports panel payload: the attribute is absent entirely."""
    return types.SimpleNamespace(protocol="tcp", ovpn_port=1194, tunnel_address="vpn.example.com")


def _config_payload(**extra):
    payload = {
        "tunnel_address": "vpn.example.com",
        "protocol": "tcp",
        "ovpn_port": 1194,
        "set_new_setting": True,
    }
    payload.update(extra)
    return payload


def _remotes(tmp_path):
    template = (tmp_path / "server" / "client-common.txt").read_text()
    return [line for line in template.splitlines() if line.startswith("remote ")]


# ── validation ───────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("443,8443", [443, 8443]),
        (" 443 , 8443 ", [443, 8443]),
        ("443;8443", [443, 8443]),
        ("443,443,8443", [443, 8443]),
        ("1194,443", [443]),  # primary port is dropped, not duplicated
        ("443,,8443", [443, 8443]),
        ("", []),  # clear
        ("   ", []),
        (",,", []),
        (None, None),  # omitted = unchanged
        ("0", None),
        ("65536", None),
        ("-1", None),
        ("443.0", None),
        ("nope", None),
        ("443,nope", None),
    ],
)
def test_validate_table(raw, expected):
    from core.openvpn.ports import validate

    assert validate(raw, 1194) == expected


def test_extra_ports_state_roundtrip(root):
    tmp_path, _ = root
    from core.openvpn import ports

    assert ports.read_state() is None
    assert ports.write_state([443, 8443]) is True
    assert ports.read_state() == [443, 8443]
    state = (tmp_path / "ovnode" / "ports").read_text()
    assert "ports=443,8443" in state
    # Unchanged content → no rewrite.
    assert ports.write_state([443, 8443]) is False
    # Empty means "explicitly cleared", not "no state".
    assert ports.write_state([]) is True
    assert ports.read_state() == []
    assert "ports=" in (tmp_path / "ovnode" / "ports").read_text()


def test_state_overrides_env_and_empty_stays_cleared(root, monkeypatch):
    tmp_path, _ = root
    from core.openvpn import ports

    monkeypatch.setenv("OVNODE_EXTRA_PORTS", "53")
    assert ports.effective(1194) == [53]
    assert ports.set_extra_ports(1194, "443,8443")[0] is True
    assert ports.effective(1194) == [443, 8443]
    # Clearing pins "none" — the installer env must not resurrect extras.
    assert ports.set_extra_ports(1194, "")[0] is True
    assert ports.read_state() == []
    assert ports.effective(1194) == []
    assert _remotes(tmp_path) == ["remote vpn.example.com 1194"]


# ── template rebuild ─────────────────────────────────────────────────


def test_template_has_one_remote_per_port_without_duplicates(root):
    tmp_path, _ = root
    from core.openvpn import ports

    ok, msg = ports.set_extra_ports(1194, "443, 443, 8443")
    assert ok is True
    assert "443,8443" in msg
    assert _remotes(tmp_path) == [
        "remote vpn.example.com 1194",
        "remote vpn.example.com 443",
        "remote vpn.example.com 8443",
    ]
    assert (tmp_path / "server" / "client-common.txt").read_text().count("remote ") == 3


def test_duplicate_and_stale_remote_lines_collapse(root):
    tmp_path, _ = root
    from core.openvpn import ports

    template = tmp_path / "server" / "client-common.txt"
    template.write_text(
        "client\nproto tcp\n"
        "remote old.example.com 1194\n"
        "remote old.example.com 443\n"
        "remote old.example.com 443\n"
        "remote-cert-tls server\n"
    )
    assert ports.set_extra_ports(1194, "8443")[0] is True
    assert _remotes(tmp_path) == [
        "remote old.example.com 1194",
        "remote old.example.com 8443",
    ]
    assert "remote-cert-tls server" in template.read_text()


def test_missing_remote_block_is_inserted_after_client(root):
    tmp_path, _ = root
    from core.openvpn import ports

    (tmp_path / "server" / "client-common.txt").write_text("client\ndev tun\n")
    assert ports.set_extra_ports(1194, "443")[0] is True
    lines = (tmp_path / "server" / "client-common.txt").read_text().splitlines()
    assert lines[0] == "client"
    # Never the "UPDATE_VIA_PANEL" placeholder: fall back to this node's
    # own public address so the profile is usable immediately.
    assert all("UPDATE_VIA_PANEL" not in ln for ln in lines)
    assert lines[1].startswith("remote ") and lines[1].endswith(" 1194")
    assert lines[2].startswith("remote ") and lines[2].endswith(" 443")


def test_cached_profiles_invalidated(root):
    tmp_path, _ = root
    from core.openvpn import ports

    profile = tmp_path / "users" / "alice" / "client.ovpn"
    profile.parent.mkdir()
    profile.write_text("old")
    assert ports.set_extra_ports(1194, "443")[0] is True
    assert not profile.exists()


def test_template_generation_honours_state(root, monkeypatch):
    """A regenerated client-common.txt must list the panel's ports."""
    tmp_path, _ = root
    from core.openvpn import pki, ports

    template = tmp_path / "server" / "client-common.txt"
    monkeypatch.setattr(pki, "CLIENT_TEMPLATE", str(template))
    assert ports.set_extra_ports(1194, "443,8443")[0] is True
    template.unlink()
    pki._ensure_client_template()
    remotes = _remotes(tmp_path)
    assert len(remotes) == 3
    assert all("UPDATE_VIA_PANEL" not in r for r in remotes)
    assert remotes[0].endswith(" 1194") and remotes[1].endswith(" 443") and remotes[2].endswith(" 8443")
    # _fresh_server_conf() has no remote lines (ports live in the template);
    # it must keep generating cleanly while ports state exists.
    assert "remote " not in pki._fresh_server_conf()


# ── change_config integration ────────────────────────────────────────


def test_change_config_applies_extra_ports_with_reload(root):
    tmp_path, calls = root
    from core.openvpn.control import change_config

    assert change_config(_req(extra_ports="443,8443")) is True
    assert _remotes(tmp_path) == [
        "remote vpn.example.com 1194",
        "remote vpn.example.com 443",
        "remote vpn.example.com 8443",
    ]
    assert (tmp_path / "ovnode" / "ports").read_text().strip() == "ports=443,8443"
    # Normalization only: reload, never a rebind restart.
    assert calls == {"restart": 0, "sighup": 1}


def test_change_config_unchanged_extra_ports_is_a_total_noop(root):
    tmp_path, calls = root
    from core.openvpn.control import change_config

    assert change_config(_req(extra_ports="443,8443")) is True
    assert calls == {"restart": 0, "sighup": 1}
    template = tmp_path / "server" / "client-common.txt"
    conf = tmp_path / "server" / "server.conf"
    template_mtime = template.stat().st_mtime_ns
    conf_mtime = conf.stat().st_mtime_ns
    assert change_config(_req(extra_ports="443,8443")) is True
    assert template.stat().st_mtime_ns == template_mtime
    assert conf.stat().st_mtime_ns == conf_mtime
    assert calls == {"restart": 0, "sighup": 1}, "unchanged push must not signal"


def test_change_config_empty_string_clears(root):
    tmp_path, calls = root
    from core.openvpn.control import change_config

    assert change_config(_req(extra_ports="443,8443")) is True
    assert change_config(_req(extra_ports="")) is True
    assert _remotes(tmp_path) == ["remote vpn.example.com 1194"]
    assert (tmp_path / "ovnode" / "ports").read_text().strip() == "ports="
    assert calls == {"restart": 0, "sighup": 2}


def test_change_config_rejects_invalid_ports_before_any_write(root):
    tmp_path, calls = root
    from core.openvpn.control import change_config

    conf = tmp_path / "server" / "server.conf"
    template = tmp_path / "server" / "client-common.txt"
    conf_before = conf.read_bytes()
    template_before = template.read_bytes()
    assert change_config(_req(extra_ports="443,nope")) is False
    assert change_config(_req(extra_ports="0,443")) is False
    assert change_config(_req(extra_ports="70000")) is False
    assert conf.read_bytes() == conf_before
    assert template.read_bytes() == template_before
    assert not (tmp_path / "ovnode" / "ports").exists()
    assert calls == {"restart": 0, "sighup": 0}


def test_change_config_keeps_state_when_field_omitted(root, monkeypatch):
    tmp_path, calls = root
    from core.openvpn import ports
    from core.openvpn.control import change_config

    assert ports.set_extra_ports(1194, "8443")[0] is True
    monkeypatch.setenv("OVNODE_EXTRA_PORTS", "53")
    assert change_config(_req_old_panel()) is True
    assert _remotes(tmp_path) == [
        "remote vpn.example.com 1194",
        "remote vpn.example.com 8443",
    ]
    assert calls == {"restart": 0, "sighup": 0}, "omitted field is untouched"


def test_change_config_falls_back_to_env_without_state(root, monkeypatch):
    tmp_path, calls = root
    from core.openvpn.control import change_config

    monkeypatch.setenv("OVNODE_EXTRA_PORTS", "443")
    assert change_config(_req_old_panel()) is True
    assert _remotes(tmp_path) == [
        "remote vpn.example.com 1194",
        "remote vpn.example.com 443",
    ]
    assert not (tmp_path / "ovnode" / "ports").exists()
    assert calls == {"restart": 0, "sighup": 0}


# ── NAT ──────────────────────────────────────────────────────────────


def _tmp_nat(tmp_path):
    marker = tmp_path / "nat-called"
    script = tmp_path / "ovnode-nat.sh"
    script.write_text(f'#!/bin/sh\ntouch "{marker}"\n')
    script.chmod(0o755)
    conf = tmp_path / "ovnode-nat"
    conf.write_text("VPN_PRIMARY_PORT=1194\nVPN_EXTRA_PORTS=\n")
    return conf, script, marker


def test_nat_conf_rewritten_and_script_invoked_when_present(root, monkeypatch):
    tmp_path, _ = root
    from core.openvpn import ports

    conf, script, marker = _tmp_nat(tmp_path)
    monkeypatch.setattr(ports, "NAT_CONF", str(conf))
    monkeypatch.setattr(ports, "NAT_SCRIPT", str(script))

    ok, msg = ports.set_extra_ports(1194, "443,8443")
    assert ok is True
    assert marker.exists(), "ovnode-nat.sh apply must run on native installs"
    assert "NAT redirects applied" in msg
    content = conf.read_text()
    assert "VPN_PRIMARY_PORT=1194" in content
    assert "VPN_EXTRA_PORTS=443,8443" in content

    # Clearing also reaches the NAT conf.
    assert ports.set_extra_ports(1194, "")[0] is True
    assert "VPN_EXTRA_PORTS=\n" in conf.read_text()


def test_nat_skipped_when_files_absent(root):
    tmp_path, _ = root
    from core.openvpn import ports

    ok, msg = ports.set_extra_ports(1194, "443")
    assert ok is True
    assert "skipped" in msg.lower()
    assert _remotes(tmp_path) == [
        "remote vpn.example.com 1194",
        "remote vpn.example.com 443",
    ]


def test_nat_skipped_in_docker_even_with_files(root, monkeypatch):
    tmp_path, _ = root
    from core.openvpn import ports

    conf, script, marker = _tmp_nat(tmp_path)
    monkeypatch.setattr(ports, "NAT_CONF", str(conf))
    monkeypatch.setattr(ports, "NAT_SCRIPT", str(script))
    monkeypatch.setattr(ports, "is_docker", lambda: True)

    ok, msg = ports.set_extra_ports(1194, "443")
    assert ok is True
    assert "docker" in msg.lower()
    assert not marker.exists()
    assert conf.read_text() == "VPN_PRIMARY_PORT=1194\nVPN_EXTRA_PORTS=\n"


def test_nat_failure_is_reported_not_fatal(root, monkeypatch):
    tmp_path, _ = root
    from core.openvpn import ports

    conf, script, _ = _tmp_nat(tmp_path)
    script.write_text("#!/bin/sh\nexit 1\n")
    monkeypatch.setattr(ports, "NAT_CONF", str(conf))
    monkeypatch.setattr(ports, "NAT_SCRIPT", str(script))

    ok, msg = ports.set_extra_ports(1194, "443")
    assert ok is True, "the template/state already changed — not a failure"
    assert "not applied" in msg
    assert _remotes(tmp_path)[-1] == "remote vpn.example.com 443"


# ── sync endpoint ────────────────────────────────────────────────────


def test_sync_config_endpoint_applies_extra_ports(root):
    tmp_path, calls = root

    c, headers = _client()
    r = c.post("/sync/config", headers=headers, json=_config_payload(extra_ports="443,8443"))
    assert r.status_code == 200, r.text
    assert r.json()["success"] is True
    assert _remotes(tmp_path) == [
        "remote vpn.example.com 1194",
        "remote vpn.example.com 443",
        "remote vpn.example.com 8443",
    ]
    assert calls == {"restart": 0, "sighup": 1}


def test_sync_config_endpoint_rejects_invalid_extra_ports(root):
    tmp_path, calls = root

    c, headers = _client()
    r = c.post("/sync/config", headers=headers, json=_config_payload(extra_ports="not-a-port"))
    assert r.status_code == 200, r.text
    assert r.json()["success"] is False
    assert calls == {"restart": 0, "sighup": 0}
    assert not (tmp_path / "ovnode" / "ports").exists()
    assert _remotes(tmp_path) == ["remote vpn.example.com 1194"]


def test_sync_config_endpoint_accepts_old_payload_without_extra_ports(root):
    tmp_path, calls = root

    c, headers = _client()
    r = c.post("/sync/config", headers=headers, json=_config_payload())
    assert r.status_code == 200, r.text
    assert r.json()["success"] is True
    assert calls == {"restart": 0, "sighup": 0}
