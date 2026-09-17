# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""POST /sync/renew-cert: renewable OpenVPN server certificate.

The easyrsa / OpenVPN calls are monkeypatched, so nothing touches the PKI.
"""

from fastapi.testclient import TestClient


def _client():
    from core.api.auth import _heavy_buckets, _ratelimit_buckets
    from core.app import api
    from core.config import settings

    # Fresh buckets: several calls in one test file would otherwise brush the
    # cert-issuing limiter.
    _heavy_buckets.clear()
    _ratelimit_buckets.clear()
    return TestClient(api), {"key": settings.api_key}


def test_renew_cert_success(monkeypatch):
    from core.api import routes

    calls: list[str] = []

    def fake_renew() -> bool:
        calls.append("renew")
        return True

    def fake_restart() -> bool:
        calls.append("restart")
        return True

    monkeypatch.setattr("core.openvpn.pki.renew_server_certificate", fake_renew)
    monkeypatch.setattr("core.openvpn.control.restart_openvpn", fake_restart)
    monkeypatch.setattr(routes, "_openssl_enddate", lambda path: "2028-01-01")

    c, headers = _client()
    body = c.post("/sync/renew-cert", headers=headers).json()
    assert body["success"] is True
    assert body["data"]["server_expiry"] == "2028-01-01"
    assert calls == ["renew", "restart"]


def test_renew_cert_requires_auth():
    from core.app import api

    assert TestClient(api).post("/sync/renew-cert").status_code == 422


def test_renew_cert_renewal_failure(monkeypatch):
    monkeypatch.setattr("core.openvpn.pki.renew_server_certificate", lambda: False)
    c, headers = _client()
    body = c.post("/sync/renew-cert", headers=headers).json()
    assert body["success"] is False
    assert "failed" in body["msg"]


def test_renew_cert_restart_failure(monkeypatch):
    monkeypatch.setattr("core.openvpn.pki.renew_server_certificate", lambda: True)
    monkeypatch.setattr("core.openvpn.control.restart_openvpn", lambda: False)
    c, headers = _client()
    body = c.post("/sync/renew-cert", headers=headers).json()
    assert body["success"] is False
    assert "did not restart" in body["msg"]
