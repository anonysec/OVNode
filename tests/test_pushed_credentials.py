# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Panel-pushed PKI: PUT /sync/users/{cn} and PUT /sync/pki.

The panel owns the CA; the node stores pushed cert/key/state passively and
writes the pushed CA + server cert to the paths server.conf reads.
"""

import os

from fastapi.testclient import TestClient

CERT = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
KEY = "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n"
CA = "-----BEGIN CERTIFICATE-----\nMICA\n-----END CERTIFICATE-----\n"


def _client():
    from backend.app import api
    from backend.config import settings

    return TestClient(api), {"key": settings.api_key}


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def _install_template(tmp_path, monkeypatch):
    from backend.openvpn import users

    tmpl = tmp_path / "client-common.txt"
    tmpl.write_text("client\ndev tun\nremote vpn.example.com 1194\n")
    monkeypatch.setattr(users, "CLIENT_TEMPLATE", str(tmpl))


def test_push_user_writes_credentials_and_state(tmp_path, monkeypatch):
    from backend.openvpn import store, users

    monkeypatch.setattr(store, "USERS_DIR", str(tmp_path / "users"))
    _install_template(tmp_path, monkeypatch)
    c, headers = _client()

    r = c.put(
        "/sync/users/424242",
        headers=headers,
        json={"max_logins": 3, "disabled": True, "cert_pem": CERT, "key_pem": KEY},
    )
    assert r.status_code == 200, r.text
    assert r.json()["ok"] is True and r.json()["success"] is True

    user_dir = store.user_dir("424242")
    assert _read(os.path.join(user_dir, "cert.pem")) == CERT
    assert _read(os.path.join(user_dir, "key.pem")) == KEY
    state = _read(os.path.join(user_dir, "state"))
    assert "limit=3" in state and "disabled=1" in state
    assert users._profile_head_is_valid(store.ovpn_path("424242"))


def test_push_user_without_cert_is_400(tmp_path, monkeypatch):
    from backend.openvpn import store

    monkeypatch.setattr(store, "USERS_DIR", str(tmp_path / "users"))
    c, headers = _client()
    r = c.put("/sync/users/424242", headers=headers, json={"max_logins": 1})
    assert r.status_code == 400


def test_push_pki_writes_ca_and_server_material(tmp_path, monkeypatch):
    from backend.openvpn import control, pki

    monkeypatch.setattr(pki, "PKI_DIR", str(tmp_path / "pki"))
    monkeypatch.setattr(pki, "CA_CERT", str(tmp_path / "pki" / "ca.crt"))
    monkeypatch.setattr(pki, "SERVER_CERT", str(tmp_path / "pki" / "issued" / "server.crt"))
    monkeypatch.setattr(control, "openvpn_is_running", lambda: False)
    c, headers = _client()

    r = c.put(
        "/sync/pki",
        headers=headers,
        json={"ca_pem": CA, "server_cert_pem": CERT, "server_key_pem": KEY},
    )
    assert r.status_code == 200, r.text
    assert r.json()["ok"] is True
    assert _read(os.path.join(pki.CA_CERT)) == CA
    assert _read(os.path.join(pki.SERVER_CERT)) == CERT
    assert _read(os.path.join(pki.PKI_DIR, "private", "server.key")) == KEY


def test_push_pki_rejects_non_pem(tmp_path, monkeypatch):
    from backend.openvpn import pki

    monkeypatch.setattr(pki, "PKI_DIR", str(tmp_path / "pki"))
    c, headers = _client()
    r = c.put(
        "/sync/pki",
        headers=headers,
        json={"ca_pem": "nope", "server_cert_pem": CERT, "server_key_pem": KEY},
    )
    assert r.status_code == 400


def test_legacy_create_without_cert_keeps_state_only(tmp_path, monkeypatch):
    """No pushed cert and no local PKI: dir + state exist, no cert/key."""
    from backend.openvpn import store, users

    monkeypatch.setattr(store, "USERS_DIR", str(tmp_path / "users"))
    # Force the "no PKI" branch regardless of the sandbox PKI state.
    monkeypatch.setattr(users, "PKI_DIR", str(tmp_path / "empty-pki"))

    assert users.create_user_on_server("9001", "carol", max_logins=4) is False
    user_dir = store.user_dir("9001")
    assert os.path.isdir(user_dir)
    assert _read(os.path.join(user_dir, "state")) == "limit=4\ndisabled=0\n"
    assert not os.path.exists(os.path.join(user_dir, "cert.pem"))
    assert not os.path.exists(os.path.join(user_dir, "key.pem"))

