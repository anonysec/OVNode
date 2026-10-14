# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""redirect-gateway def1 gives clients a full tunnel; server.conf also pushes
``route <endpoint> 255.255.255.255 net_gateway`` so one host — the same address
the client ``remote`` lines dial — stays outside it, reaching the panel."""

import pytest

OLD, NEW = "panel.example.org", "vpn.example.org"
LEGACY_CONF = 'port 1194\nproto tcp\ndev tun\npush "redirect-gateway def1 bypass-dhcp"\n'


@pytest.fixture()
def sandbox(tmp_path, monkeypatch):
    from backend.openvpn import pki

    server = tmp_path / "ovpn" / "server"
    server.mkdir(parents=True)
    for attr, path in (
        ("_OPENVPN_ROOT", tmp_path / "ovpn"),
        ("SERVER_CONF", server / "server.conf"),
        ("CLIENT_TEMPLATE", server / "client-common.txt"),
        ("MGMT_PASS_FILE", server / "mgmt.pass"),
        ("SCRIPTS_DIR", tmp_path / "scripts"),
    ):
        monkeypatch.setattr(pki, attr, str(path))
    monkeypatch.delenv("TUNNEL_ADDRESS", raising=False)
    (server / "client-common.txt").write_text(f"client\nproto tcp\nremote {OLD} 1194\n")
    (server / "server.conf").write_text(LEGACY_CONF)
    return server


def _bypasses(conf):
    return [ln.strip() for ln in conf.splitlines() if " net_gateway" in ln]


def _line(addr):
    return f'push "route {addr} 255.255.255.255 net_gateway"'


def test_fresh_conf_pushes_bypass(sandbox):
    from backend.openvpn.pki import _fresh_server_conf

    conf = _fresh_server_conf()
    assert _bypasses(conf) == [_line(OLD)]
    assert conf.index('push "redirect-gateway def1 bypass-dhcp"') < conf.index(_line(OLD))


def test_placeholder_remote_falls_back_to_tunnel_address(sandbox, monkeypatch):
    """A placeholder remote must never become the pushed route."""
    from backend.openvpn.pki import _fresh_server_conf

    (sandbox / "client-common.txt").write_text("client\nproto tcp\nremote UPDATE_VIA_PANEL 1194\n")
    monkeypatch.setenv("TUNNEL_ADDRESS", "env.example.org")
    conf = _fresh_server_conf()
    assert _bypasses(conf) == [_line("env.example.org")]


def test_harden_adds_refreshes_and_stays_idempotent(sandbox):
    from backend.openvpn.pki import _ensure_server_conf

    conf = sandbox / "server.conf"
    assert _ensure_server_conf() is True  # missing bypass added
    assert _bypasses(conf.read_text()) == [_line(OLD)]
    assert _ensure_server_conf() is False  # nothing left to do
    # The panel moves the endpoint; the next harden pass follows it.
    (sandbox / "client-common.txt").write_text(f"client\nproto tcp\nremote {NEW} 1194\n")
    assert _ensure_server_conf() is True
    assert _bypasses(conf.read_text()) == [_line(NEW)]  # one line, new address
    assert OLD not in conf.read_text()


def test_client_template_never_gains_net_gateway(sandbox):
    from backend.openvpn import pki

    pki._fresh_server_conf()
    pki._ensure_client_template()
    template = open(pki.CLIENT_TEMPLATE, encoding="utf-8").read()
    assert "net_gateway" not in template and "route " not in template
