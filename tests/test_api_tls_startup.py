# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""The node API answers TLS or not at all.

The installer already refuses plain HTTP and the panel pins the node CA, so a
plaintext listener here is a hole rather than a fallback. These tests pin the
startup contract: without a readable cert/key pair the process dies before it
opens a socket, and a listener that does come up never speaks plain HTTP.

Paths come from ``backend.openvpn.pki.paths`` — OVNODE_OPENVPN_ROOT-aware, so
the suite points them at a tmp PKI tree and never at the host's /etc/openvpn.
"""

import http.client
import os
import socket
import ssl
import subprocess
import threading
import time

import pytest

import main
from backend.config import settings
from backend.openvpn.pki import paths


def _pair(directory):
    """A throwaway self-signed pair, built the way test_tls_reuse builds one."""
    os.makedirs(directory, exist_ok=True)
    key = directory / "server.key"
    cert = directory / "server.crt"
    done = subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-nodes",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-subj",
            "/CN=ovnode-test",
            "-days",
            "3650",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert done.returncode == 0, done.stderr.strip()[:200]
    return key, cert


def _point_pki_at(monkeypatch, key, cert):
    """Make the startup resolution see this pair as the node PKI's own."""
    monkeypatch.setattr(paths, "SERVER_CERT", str(cert))
    monkeypatch.setattr(paths, "SERVER_KEY", str(key))
    # No operator-declared pair: the PKI default must carry the server.
    monkeypatch.setattr(settings, "ssl_certfile", None)
    monkeypatch.setattr(settings, "ssl_keyfile", None)


def _trap_uvicorn(monkeypatch):
    """Record the Config main() builds; never open a socket."""
    import uvicorn

    seen: dict = {}

    class FakeConfig:
        def __init__(self, **kwargs):
            seen.update(kwargs)

    class FakeServer:
        def __init__(self, config=None, **kwargs):
            seen["config"] = config

        def run(self):
            seen["ran"] = True

    monkeypatch.setattr(uvicorn, "Config", FakeConfig)
    monkeypatch.setattr(uvicorn, "Server", FakeServer)
    return seen


@pytest.mark.parametrize("absent", ["cert", "key", "both"])
def test_startup_dies_without_cert_files(tmp_path, monkeypatch, absent):
    """No pair, no process: a plaintext fallback is the bug being removed."""
    key, cert = _pair(tmp_path)
    if absent in ("cert", "both"):
        cert.unlink()
    if absent in ("key", "both"):
        key.unlink()
    _point_pki_at(monkeypatch, key, cert)
    seen = _trap_uvicorn(monkeypatch)

    with pytest.raises(SystemExit) as exc:
        main.main()

    assert "TLS" in str(exc.value), f"the death must name TLS, got: {exc.value}"
    assert "ran" not in seen, "a server came up without TLS material"


def test_startup_always_configures_tls(tmp_path, monkeypatch):
    """With the PKI pair present, uvicorn gets ssl_certfile + ssl_keyfile."""
    key, cert = _pair(tmp_path)
    _point_pki_at(monkeypatch, key, cert)
    seen = _trap_uvicorn(monkeypatch)

    main.main()

    assert seen["ssl_certfile"] == str(cert)
    assert seen["ssl_keyfile"] == str(key)
    assert seen["port"] == settings.service_port


def test_plain_http_gets_no_http_response(tmp_path, monkeypatch):
    """Socket level: the port is TLS-only, so a plain GET never gets a reply."""
    key, cert = _pair(tmp_path)
    _point_pki_at(monkeypatch, key, cert)

    from uvicorn import Config, Server

    from backend.app import api

    certfile, keyfile = main._tls_material()
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    config = Config(
        app=api,
        host="127.0.0.1",
        port=port,
        log_config=None,
        # The lifespan would fork easy-rsa into a PKI of its own; the listener
        # and its TLS are what this test is about.
        lifespan="off",
        ssl_certfile=certfile,
        ssl_keyfile=keyfile,
    )
    server = Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.time() + 15
        while not server.started and thread.is_alive() and time.time() < deadline:
            time.sleep(0.05)
        assert server.started, "the TLS listener did not come up"

        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            sock.sendall(b"GET /sync/health HTTP/1.1\r\nHost: test\r\n\r\n")
            try:
                payload = sock.recv(4096)
            except OSError:
                # TLS alert / reset: exactly the rejection being asserted.
                payload = b""
        assert b"HTTP/" not in payload, f"plain HTTP was answered: {payload[:80]!r}"

        conn = http.client.HTTPSConnection(
            "127.0.0.1", port, context=ssl._create_unverified_context(), timeout=10
        )
        try:
            conn.request("GET", "/sync/health")
            response = conn.getresponse()
            assert response.status == 200
        finally:
            conn.close()
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        assert not thread.is_alive(), "the server refused to stop"


def test_defaults_come_from_the_node_pki():
    """Cert paths resolve from OVNODE_OPENVPN_ROOT, never the host /etc."""
    root = os.environ["OVNODE_OPENVPN_ROOT"]  # sandbox, set in conftest
    assert paths.PKI_DIR == os.path.join(root, "server", "pki")
    assert paths.SERVER_CERT == os.path.join(paths.PKI_DIR, "issued", "server.crt")
    assert paths.SERVER_KEY == os.path.join(paths.PKI_DIR, "private", "server.key")
