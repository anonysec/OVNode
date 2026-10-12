# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""The two verbs that reach the host must not reach it from the suite.

`ovn backup` and `ovn restart` are the dispatch test's footguns: backup_dir()
hard-coded /var/backups (so every dispatch run wrote tarballs there and
prune_backups() deleted the node's real ones), and restart_vpn() called
manager.sh:229's `systemctl restart` for real — restarting this machine's
OpenVPN on every full run.

Both are redirected in the harness instead of in the frozen mains: backup_dir()
honours OVN_BACKUP_ROOT (production default unchanged when it is unset), and
every manager run gets a stub systemctl first on PATH. These tests pin each
half.
"""

import subprocess
from pathlib import Path

import pytest
from conftest import HARNESS
from test_manager_sh import sandbox

REPO = Path(__file__).resolve().parent.parent
COMMON = REPO / "scripts" / "lib" / "common.sh"


def test_the_backup_root_default_is_still_the_host_path():
    """An override that moves the production default is a migration, not a knob."""
    assert '"${OVN_BACKUP_ROOT:-/var/backups}"' in COMMON.read_text(encoding="utf-8")


def test_ovn_backup_root_moves_the_tarball_out_of_var_backups(tmp_path):
    """backup_dir() writes under OVN_BACKUP_ROOT when the variable is set."""
    src = tmp_path / "fixture"
    src.mkdir()
    (src / "state.json").write_text("{}", encoding="utf-8")
    dest = tmp_path / "elsewhere"
    dest.mkdir()

    out = HARNESS.run(f'backup_dir "{src}" node', tty=False, OVN_BACKUP_ROOT=str(dest))

    assert list(dest.glob("node-fixture-*.tar.gz")), out
    assert "Backup saved" in out, out
    assert "/var/backups" not in out, out


def test_manager_env_puts_the_stub_tools_first_on_path():
    """PATH is what decides which systemctl a manager run finds — pin the env
    the harness actually runs manager.sh with, not a copy of it."""
    which = subprocess.run(
        ["bash", "-c", "command -v systemctl; command -v curl"],
        env=HARNESS.manager_env,
        capture_output=True,
        text=True,
        check=False,
    )
    found = which.stdout.split()
    assert found == [str(HARNESS.stub_bin / "systemctl"), str(HARNESS.stub_bin / "curl")], found


@pytest.mark.skipif(
    not Path("/run/systemd/system").is_dir(),
    reason="`ovn status` only asks systemctl on a systemd host",
)
def test_a_manager_command_asks_the_stub_systemctl(tmp_path):
    """`ovn status` reports the agent state by asking systemctl — the answer
    must come from the stub, and the host must never be asked."""
    env, app = sandbox(tmp_path)
    (app / ".env").write_text(
        "NODE_NAME=eu-1\nSERVICE_PORT=2083\nTLS_METHOD=none\nAPI_KEY=x\n",
        encoding="utf-8",
    )
    log = HARNESS.systemctl_log
    log.unlink(missing_ok=True)

    HARNESS.manager("status", env={"OVN_APP_DIR": str(app)}, check=False)

    assert log.exists(), "manager.sh ran the host's systemctl"
    assert "is-active" in log.read_text(encoding="utf-8")
