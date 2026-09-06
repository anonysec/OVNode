# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Fresh-install transport selection: OVNODE_PROTO honors udp, defaults tcp.

Existing server.conf files are never rewritten by this value (only fresh
generation reads it); proto flips on live nodes go through change_config().
"""

import os
import subprocess
import sys
import tempfile

CHECK = r"""
import os
from core.openvpn.pki import _fresh_server_conf

conf = _fresh_server_conf()
proto = os.environ.get("EXPECT_PROTO", "tcp")
assert f"\nproto {proto}\n" in conf, conf
if proto == "udp":
    assert "explicit-exit-notify 1" in conf
    assert "\nfast-io\n" in conf
else:
    assert "explicit-exit-notify 0" in conf
    assert "\nfast-io\n" not in conf
print("PROTO-OK", proto)
"""


def _fresh_conf(proto=None, expect=None):
    with tempfile.TemporaryDirectory(prefix="ovn-proto-") as root:
        env = {**os.environ, "OVNODE_OPENVPN_ROOT": root}
        if proto is not None:
            env["OVNODE_PROTO"] = proto
        else:
            env.pop("OVNODE_PROTO", None)
        env["EXPECT_PROTO"] = expect or proto or "tcp"
        r = subprocess.run(
            [sys.executable, "-c", CHECK],
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
        )
        print(r.stdout)
        if r.stderr:
            print(r.stderr[-1000:])
        assert r.returncode == 0
        assert f"PROTO-OK {expect or proto or 'tcp'}" in r.stdout


def test_fresh_conf_defaults_tcp():
    _fresh_conf(None)


def test_fresh_conf_honors_udp():
    _fresh_conf("udp")


def test_fresh_conf_rejects_garbage_safely():
    _fresh_conf("bogus-proto", expect="tcp")
