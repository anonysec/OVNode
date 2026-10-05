# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Every directive the agent writes must be a real OpenVPN option.

`log-timestamp` looked plausible and was added so the security view could date
TLS failures, but OpenVPN 2.7 has no such directive. The node then refused to
start:

    Options error: Unrecognized option or missing or extra parameter(s) in
    server.conf:53: log-timestamp (2.7.0)

The log is written through `log-append`, so OpenVPN's output never reaches the
journal, and the distribution unit starts it with --suppress-timestamps, so the
log file cannot be stamped either. That is why the agent times TLS failures
itself (first/last seen) instead of parsing a timestamp that is not there.

`--help` is the option list, with one wrinkle: a few options this project uses
are accepted but no longer documented (`persist-key` is reported as ignored,
`data-ciphers-fallback` is a cipher-list synonym). They are listed explicitly
below so a future OpenVPN dropping one fails the test instead of the node.
"""

import re
import shutil
import subprocess

import pytest

OPENVPN = shutil.which("openvpn")

# Accepted by OpenVPN 2.7 but absent from --help. Do not add to this list
# without checking the daemon actually starts with it.
UNDOCUMENTED_BUT_VALID = {"persist-key", "data-ciphers-fallback"}


def _known_options() -> set[str]:
    out = subprocess.run([OPENVPN, "--help"], capture_output=True, text=True, timeout=30).stdout
    return set(re.findall(r"^--([a-z0-9][a-z0-9-]*)", out, re.MULTILINE)) | UNDOCUMENTED_BUT_VALID


def _directive_names(conf: str) -> set[str]:
    names = set()
    for raw in conf.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        names.add(line.split()[0].lstrip("-"))
    return names


@pytest.fixture
def generated_conf(monkeypatch, tmp_path):
    from core.openvpn import pki

    monkeypatch.setattr(pki, "_OPENVPN_ROOT", str(tmp_path))
    monkeypatch.setattr(pki, "SERVER_CONF", str(tmp_path / "server" / "server.conf"))
    monkeypatch.setattr(pki, "SCRIPTS_DIR", str(tmp_path / "scripts"))
    return pki._fresh_server_conf()


@pytest.mark.skipif(not OPENVPN, reason="openvpn not installed")
def test_fresh_server_conf_uses_only_real_openvpn_options(generated_conf):
    known = _known_options()
    assert known, "could not read the OpenVPN option list"
    unknown = sorted(d for d in _directive_names(generated_conf) if d not in known)
    assert not unknown, f"generated server.conf has unknown directives: {unknown}"


@pytest.mark.skipif(not OPENVPN, reason="openvpn not installed")
def test_log_timestamp_is_never_written(generated_conf):
    """The regression that stopped the node: a directive OpenVPN rejects."""
    assert "log-timestamp" not in _directive_names(generated_conf)
    assert "log-timestamp" not in _known_options()


@pytest.mark.skipif(not OPENVPN, reason="openvpn not installed")
def test_tls_event_times_come_from_the_agent(generated_conf):
    """No directive may be added hoping the log will carry timestamps."""
    assert "log-append" in generated_conf
    help_text = subprocess.run(
        [OPENVPN, "--help"], capture_output=True, text=True, timeout=30
    ).stdout
    assert "suppress-timestamps" in help_text, "assumption changed: the daemon may stamp logs now"
