# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""P1 safety batch: single-writer conf, easyrsa lock, usage reset, PKI expiry.

- Legacy server.conf gets hooks + duplicate-cn from the merged pki tune-up
  (isolated subprocess so module path constants freeze correctly).
- Parallel easyrsa runs serialize on the lock file (fake binary log proves
  no interleave) instead of corrupting index.txt.
- POST /sync/user/{uid}/reset-usage zeroes counters; bad ids rejected.
- GET /sync/status carries ca_expiry/server_expiry keys for panel warnings.
"""

import os
import subprocess
import sys
import tempfile

from fastapi.testclient import TestClient

TUNE_SCRIPT = (
    r"""
import os
import sys

from core.openvpn.pki import SERVER_CONF, _ensure_server_conf

legacy = (
    "port 1194\n"
    "proto udp\n"
    "dev tun\n"
    "management 127.0.0.1 7505\n"
    "management-client-user nobody\n"
    "status-version 2\n"
    "client-connect /etc/openvpn/old-scripts/ovnode-client-connect.sh\n"
    "# admin custom line\n"
)
with open(SERVER_CONF, "w", encoding="utf-8") as f:
    f.write(legacy)

assert _ensure_server_conf() is True, "first tune must report changed"
assert _ensure_server_conf() is False, "second tune must be a no-op"

with open(SERVER_CONF, encoding="utf-8") as f:
    conf = f.read()
checks = [
    ("client-connect" in conf, "hook connect"),
    ("client-disconnect" in conf, "hook disconnect"),
    ("duplicate-cn" in conf, "duplicate-cn"),
    ("mgmt-pass" in conf, "mgmt pass"),
    (conf.count("management 127.0.0.1") == 1, "single mgmt"),
    ("management-client-user" not in conf, "mgmt-client dropped"),
    ("status-version 3" in conf, "status v3"),
    ("old-scripts" not in conf, "old hook repointed"),
    ("# admin custom line" in conf, "admin kept"),
]
bad = [name for cond, name in checks if not cond]
print("TUNE", "OK" if not bad else "MISSING " + ",".join(bad))
sys.exit(1 if bad else 0)
"""
)


def _run_check_script(script: str, root: str):
    env = {
        **os.environ,
        "OVNODE_OPENVPN_ROOT": root,
        "OVNODE_STATUS_FILE": os.path.join(root, "server", "status.log"),
        "API_KEY": "test-api-key-1234567890",
    }
    os.makedirs(os.path.join(root, "server"), exist_ok=True)
    return subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
        cwd=os.path.join(os.path.dirname(__file__), ".."),
    )


def test_tuneup_adds_hooks_and_is_idempotent():
    with tempfile.TemporaryDirectory(prefix="ovnode-tune-") as root:
        r = _run_check_script(TUNE_SCRIPT, root)
        assert r.returncode == 0, f"stdout={r.stdout}\nstderr={r.stderr[-2000:]}"
        assert "TUNE OK" in r.stdout


def _client():
    from core.app import api
    from core.config import settings

    return TestClient(api), {"key": settings.api_key}


def test_reset_usage_endpoint():
    c, headers = _client()
    uid = "6ca1dd29-b6a4-41c8-adc9-e154cf3f8557"
    r = c.post(f"/sync/user/{uid}/reset-usage", headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is True
    assert body["data"]["id"] == uid
    r = c.post("/sync/user/invalid@", headers=headers)
    assert r.json()["success"] is False


def test_status_carries_pki_expiry_keys():
    c, headers = _client()
    r = c.get("/sync/status", headers=headers)
    assert r.status_code == 200
    data = r.json()["data"]
    assert "ca_expiry" in data and "server_expiry" in data


def test_easyrsa_runs_serialize_on_lock(tmp_path, monkeypatch):
    import threading

    import core.openvpn.pki as pki

    log = tmp_path / "calls.log"
    fake = tmp_path / "easyrsa"
    # NOTE: run_easyrsa spawns with a minimal env (no test vars leak to the
    # child), so bake the log path into the stub itself.
    fake.write_text(f'#!/bin/sh\necho "start-$1" >> "{log}"\nsleep 0.3\necho "end-$1" >> "{log}"\n')
    fake.chmod(0o755)
    pki_dir = tmp_path / "pki"
    pki_dir.mkdir()
    monkeypatch.setattr(pki, "EASYRSA_DIR", str(tmp_path))
    results = []
    ts = []

    def run():
        import time

        ts.append(time.monotonic())
        results.append(pki.run_easyrsa("show", timeout=30, pki_dir=str(pki_dir)))

    threads = [threading.Thread(target=run) for _ in range(2)]
    [t.start() for t in threads]
    [t.join(timeout=60) for t in threads]
    assert results == [True, True]
    lines = log.read_text().split()
    # start/end pairs never interleave when serialized.
    assert lines[0].startswith("start-") and lines[1].startswith("end-")
    assert lines[1][4:] == lines[0][6:]
    assert os.path.exists(pki_dir / ".easyrsa.lock")
