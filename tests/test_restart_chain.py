# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""restart_openvpn() tries the dedicated unit first, legacy unit second.

The panel's POST /sync/restart used to hardcode the distro unit
openvpn-server@server, which crash-loops on hosts where the installer wrote
ovnode-openvpn.service — so every panel restart fell through to SIGHUP.
"""

import subprocess

import pytest

FAKE_SYSTEMCTL = "/usr/bin/systemctl"


@pytest.fixture()
def control(monkeypatch):
    from backend.openvpn import control

    # Only the systemd chain is under test; the store chmod/chown is not.
    monkeypatch.setattr(control.store, "fix_runtime_permissions", lambda: None)
    return control


def _record_systemctl(monkeypatch, control, fail_units=()):
    """systemctl stand-in recording the units restarted, in order."""
    calls = []
    real_run, real_which = control.subprocess.run, control.shutil.which

    def _which(name):
        return FAKE_SYSTEMCTL if name == "systemctl" else real_which(name)

    def _run(cmd, **kwargs):
        if not (isinstance(cmd, (list, tuple)) and cmd and cmd[0] == FAKE_SYSTEMCTL):
            return real_run(cmd, **kwargs)
        calls.append(cmd[-1])
        if cmd[-1] in fail_units:
            raise subprocess.CalledProcessError(1, cmd)
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(control.shutil, "which", _which)
    monkeypatch.setattr(control.subprocess, "run", _run)
    return calls


def test_restart_tries_dedicated_unit_first(monkeypatch, control):
    calls = _record_systemctl(monkeypatch, control)
    assert control.restart_openvpn() is True
    assert calls == ["ovnode-openvpn.service"]


def test_restart_falls_back_to_legacy_distro_unit(monkeypatch, control):
    calls = _record_systemctl(monkeypatch, control, fail_units={"ovnode-openvpn.service"})
    assert control.restart_openvpn() is True
    assert calls == ["ovnode-openvpn.service", "openvpn-server@server"]


def test_restart_reaches_sighup_when_no_unit_restarts(monkeypatch, control):
    calls = _record_systemctl(
        monkeypatch, control, fail_units={"ovnode-openvpn.service", "openvpn-server@server"}
    )
    real_exists = control.os.path.exists
    monkeypatch.setattr(
        control.os.path,
        "exists",
        lambda p: False if p == "/sbin/rc-service" else real_exists(p),
    )
    sighup = {"n": 0}

    def _sighup():
        sighup["n"] += 1
        return True

    monkeypatch.setattr(control, "_sighup_fallback", _sighup)
    assert control.restart_openvpn() is True
    assert calls == ["ovnode-openvpn.service", "openvpn-server@server"]
    assert sighup["n"] == 1
