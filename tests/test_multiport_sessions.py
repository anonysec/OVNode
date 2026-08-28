# Copyright (c) 2025 anonysec. All rights reserved.
# Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.

"""Unit tests for multi-port support and dynamic-IP-safe session matching."""

import os

import pytest

# ── multi-port ───────────────────────────────────────────────────────


def test_parse_extra_ports():
    from core.config import parse_extra_ports

    assert parse_extra_ports("443,8443", 1194) == [443, 8443]
    # primary port and duplicates are excluded, junk is skipped
    assert parse_extra_ports("1194, 443, 443, nope, 0, 70000; 53", 1194) == [443, 53]
    assert parse_extra_ports("", 1194) == []
    assert parse_extra_ports(None, 1194) == []


def test_client_template_lists_all_ports(tmp_path, monkeypatch):
    """A fresh client template must carry one remote line per reachable port."""
    from core.openvpn import pki

    monkeypatch.setenv("OPENVPN_PORT", "1194")
    monkeypatch.setenv("OVNODE_EXTRA_PORTS", "443,8443")
    monkeypatch.setenv("TUNNEL_ADDRESS", "vpn.example.com")
    monkeypatch.setattr(pki, "CLIENT_TEMPLATE", str(tmp_path / "client-common.txt"))

    pki._ensure_client_template()
    content = (tmp_path / "client-common.txt").read_text()
    remotes = [ln for ln in content.splitlines() if ln.startswith("remote ")]
    assert remotes == [
        "remote vpn.example.com 1194",
        "remote vpn.example.com 443",
        "remote vpn.example.com 8443",
    ]


def test_change_config_rebuilds_remote_block(tmp_path, monkeypatch):
    """POST /sync/config must rewrite ALL remote lines (primary + extras)."""
    from core.api.schemas import SetSettingsModel
    from core.openvpn import control

    server_dir = tmp_path / "server"
    server_dir.mkdir()
    (server_dir / "server.conf").write_text(
        "port 1194\nproto tcp\nexplicit-exit-notify 0\nstatus-version 3\n"
    )
    (server_dir / "client-common.txt").write_text(
        "client\ndev tun\nproto tcp\n"
        "remote old.example.com 1194\nremote old.example.com 443\n"
        "resolv-retry infinite\nremote-cert-tls server\n"
    )
    monkeypatch.setenv("OVNODE_OPENVPN_ROOT", str(tmp_path))
    monkeypatch.setenv("OVNODE_EXTRA_PORTS", "443,8443")
    monkeypatch.setattr(control, "restart_openvpn", lambda: True)
    monkeypatch.setattr(control, "_invalidate_cached_ovpn", lambda: None)
    import core.openvpn.multilogin as ml

    monkeypatch.setattr(ml, "ensure_multilogin_setup", lambda: None)

    req = SetSettingsModel(
        tunnel_address="new.example.com", protocol="udp", ovpn_port=1194, set_new_setting=True
    )
    assert control.change_config(req) is True

    template = (server_dir / "client-common.txt").read_text()
    remotes = [ln for ln in template.splitlines() if ln.startswith("remote ")]
    assert remotes == [
        "remote new.example.com 1194",
        "remote new.example.com 443",
        "remote new.example.com 8443",
    ]
    # remote-cert-tls must never be clobbered by the remote-line rewrite
    assert "remote-cert-tls server" in template
    assert "proto udp" in template
    assert "proto udp" in (server_dir / "server.conf").read_text()


def test_change_config_keeps_address_without_tunnel(tmp_path, monkeypatch):
    """Without tunnel_address, the existing remote address must be kept."""
    from core.api.schemas import SetSettingsModel
    from core.openvpn import control

    server_dir = tmp_path / "server"
    server_dir.mkdir()
    (server_dir / "server.conf").write_text("port 1194\nproto tcp\n")
    (server_dir / "client-common.txt").write_text(
        "client\nproto tcp\nremote keep.example.com 1194\n"
    )
    monkeypatch.setenv("OVNODE_OPENVPN_ROOT", str(tmp_path))
    monkeypatch.delenv("OVNODE_EXTRA_PORTS", raising=False)
    monkeypatch.setattr(control, "restart_openvpn", lambda: True)
    monkeypatch.setattr(control, "_invalidate_cached_ovpn", lambda: None)
    import core.openvpn.multilogin as ml

    monkeypatch.setattr(ml, "ensure_multilogin_setup", lambda: None)

    req = SetSettingsModel(tunnel_address="", protocol="tcp", ovpn_port=8443, set_new_setting=True)
    assert control.change_config(req) is True
    template = (server_dir / "client-common.txt").read_text()
    assert "remote keep.example.com 8443" in template


# ── status parser (header-aware) ─────────────────────────────────────

_V2_STATUS = (
    "TITLE,OpenVPN 2.6.12\n"
    "TIME,now,0\n"
    "HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,"
    "Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t),Username,"
    "Client ID,Peer ID,Data Channel Cipher\n"
    "CLIENT_LIST,alice,1.2.3.4:5555,10.8.0.2,,1000,2000,now,0,alice,3,0,AES-256-GCM\n"
)

_V3_STATUS = _V2_STATUS.replace(",", "\t")


@pytest.mark.parametrize("payload", [_V2_STATUS, _V3_STATUS], ids=["v2-commas", "v3-tabs"])
def test_status_parser_counts_both_directions(tmp_path, payload):
    """Bytes Received AND Bytes Sent must both be parsed (regression:
    the old fixed-column parser dropped Bytes Sent on OpenVPN >= 2.4)."""
    from core.openvpn.status import parse_sessions, parse_usage

    status = tmp_path / "status.log"
    status.write_text(payload)

    usage = parse_usage(str(status))
    assert usage["users"]["alice"] == 3000

    (session,) = parse_sessions(str(status))
    assert session["virtual_address"] == "10.8.0.2"
    assert session["client_id"] == "3"
    assert session["trusted_ip"] == "1.2.3.4"
    assert session["trusted_port"] == "5555"


def test_status_parser_old_openvpn_layout(tmp_path):
    """OpenVPN 2.3 had no Virtual IPv6 column — the header must drive parsing."""
    from core.openvpn.status import parse_usage

    status = tmp_path / "status.log"
    status.write_text(
        "HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,"
        "Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t),Username\n"
        "CLIENT_LIST,bob,9.9.9.9:1234,10.8.0.5,10,20,now,0,bob\n"
    )
    assert parse_usage(str(status))["users"]["bob"] == 30


# ── dynamic-IP session matching ──────────────────────────────────────


def _marker(cn, pool_ip, trusted_ip="1.2.3.4", trusted_port="1111"):
    return {
        "common_name": cn,
        "ifconfig_pool_remote_ip": pool_ip,
        "trusted_ip": trusted_ip,
        "trusted_port": trusted_port,
    }


def _live(cn, virtual, trusted_ip="9.9.9.9", trusted_port="2222"):
    return {
        "common_name": cn,
        "virtual_address": virtual,
        "trusted_ip": trusted_ip,
        "trusted_port": trusted_port,
    }


def test_marker_live_despite_ip_change():
    """A marker stays live when the client's real IP changed mid-session —
    matching is on (CN, pool IP), never on the real address."""
    from core.openvpn.sessions import _marker_is_live

    marker = _marker("42", "10.8.0.2", trusted_ip="1.2.3.4")
    live = [_live("42", "10.8.0.2", trusted_ip="5.6.7.8")]  # real IP changed
    assert _marker_is_live(marker, live) is True


def test_marker_stale_when_pool_ip_gone():
    from core.openvpn.sessions import _marker_is_live

    marker = _marker("42", "10.8.0.2")
    assert _marker_is_live(marker, [_live("42", "10.8.0.9")]) is False
    assert _marker_is_live(marker, []) is False


def test_marker_legacy_fallback_uses_real_address():
    """Markers without a pool IP (legacy) fall back to real-address matching."""
    from core.openvpn.sessions import _marker_is_live

    marker = _marker("42", "", trusted_ip="1.2.3.4", trusted_port="1111")
    assert _marker_is_live(marker, [_live("42", "10.8.0.2", "1.2.3.4", "1111")]) is True
    assert _marker_is_live(marker, [_live("42", "10.8.0.2", "5.6.7.8", "1111")]) is False


def test_connect_script_uses_pool_ip_session_key():
    """The connect hook must key sessions by CN + pool IP, not real IP."""
    script = os.path.join(
        os.path.dirname(__file__), "..", "core", "scripts", "ovnode-client-connect.sh"
    )
    with open(script) as f:
        content = f.read()
    assert 'session_key="${safe_cn}.${pool_ip_s}"' in content
    # takeover kills must target the management client id, not "kill ip:port"
    assert "client-kill $cid" in content


# ── CRL auto-renewal ─────────────────────────────────────────────────


def test_crl_date_parsing():
    """openssl `nextUpdate=` output must parse into days-remaining."""
    from core.openvpn.pki import _days_until_openssl_date

    assert _days_until_openssl_date("nextUpdate=Jan  1 00:00:00 2020 GMT") < 0
    assert _days_until_openssl_date("nextUpdate=Dec 31 23:59:59 2099 GMT") > 300
    assert _days_until_openssl_date("garbage") is None
    assert _days_until_openssl_date("nextUpdate=not a date") is None


def test_crl_renewed_when_near_expiry(tmp_path, monkeypatch):
    """An existing CRL close to (or past) nextUpdate must be regenerated —
    with crl-verify, an expired CRL locks every client out."""
    from core.openvpn import pki

    crl = tmp_path / "crl.pem"
    crl.write_text("dummy")
    monkeypatch.setattr(pki, "CRL_FILE", str(crl))

    calls = []
    monkeypatch.setattr(pki, "_easyrsa", lambda *a, **k: calls.append(a) or True)

    # Fresh CRL → no regeneration.
    monkeypatch.setattr(pki, "_crl_days_remaining", lambda: 200)
    assert pki._ensure_crl() is True
    assert calls == []

    # Near expiry → gen-crl.
    monkeypatch.setattr(pki, "_crl_days_remaining", lambda: 10)
    assert pki._ensure_crl() is True
    assert calls == [("gen-crl",)]

    # Renewal fails but CRL still currently valid → keep serving it.
    monkeypatch.setattr(pki, "_easyrsa", lambda *a, **k: False)
    assert pki._ensure_crl() is True

    # Renewal fails and CRL already expired → report failure.
    monkeypatch.setattr(pki, "_crl_days_remaining", lambda: -1)
    assert pki._ensure_crl() is False
