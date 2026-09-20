# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Behavioral tests for manager.sh (ovnode/ovn): day-to-day operations.

The manager runs against an installed tree ($APP_DIR, overridable via
OVN_APP_DIR for hermetic tests) and sources $APP_DIR/lib/common.sh.
Update/uninstall delegate to install.sh. Tests never touch the live system:
sandbox trees plus stub tools stand in for systemd/OpenVPN.
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MANAGER = os.path.join(os.path.dirname(__file__), "..", "manager.sh")
MANAGER_PATH = Path(MANAGER)
LIB = REPO / "lib" / "common.sh"


def mgr(*args: str, env: dict | None = None):
    full_env = {**os.environ, **(env or {})}
    return subprocess.run(
        ["bash", MANAGER, *args],
        capture_output=True,
        text=True,
        timeout=30,
        env=full_env,
        stdin=subprocess.DEVNULL,
    )


def sandbox(tmp_path):
    """A fake installed tree: manager.sh runs with OVN_APP_DIR pointed here."""
    app = tmp_path / "opt"
    (app / "lib").mkdir(parents=True)
    shutil.copy(MANAGER_PATH, app / "manager.sh")
    shutil.copy(LIB, app / "lib" / "common.sh")
    (app / "install.sh").write_text("#!/bin/sh\necho \"STUB-INSTALLER $@\"\n", encoding="utf-8")
    (app / "install.sh").chmod(0o755)
    env = {**os.environ, "OVN_APP_DIR": str(app)}
    return env, app


def mgr_sb(env, app, *args: str):
    return subprocess.run(
        ["bash", str(app / "manager.sh"), *args],
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
        stdin=subprocess.DEVNULL,
    )


def test_manager_syntax():
    subprocess.run(["bash", "-n", MANAGER], check=True)


def test_help_documents_manager_surface():
    r = mgr("help")
    assert r.returncode == 0
    output = r.stdout + r.stderr
    for token in (
        "status", "update", "restart", "restart-vpn", "logs",
        "backup", "tls", "uninstall", "ovn",
    ):
        assert token in output, f"help missing {token}"


def test_bare_run_without_terminal_is_usage_error():
    """Bare `ovn` with no tty must not start doing things."""
    r = mgr()
    assert r.returncode != 0
    assert "No terminal" in r.stderr


def test_unknown_option_fails():
    r = mgr("--nonsense-flag")
    assert r.returncode == 2


def test_numbered_menu_lists_core_ops():
    """x-ui style: numbered entries for every core op, 0 exits."""
    with open(MANAGER, encoding="utf-8") as f:
        content = f.read()
    assert "manager_menu()" in content
    for label in (
        "Status", "Update node", "Restart agent", "Restart VPN",
        "Logs", "Backup now", "TLS certificate", "Uninstall node",
    ):
        assert label in content, f"menu missing {label}"


def test_update_delegates_to_installer(tmp_path):
    """`ovn update` execs install.sh update (machine flags pass through)."""
    env, app = sandbox(tmp_path)
    r = mgr_sb(env, app, "update", "-y")
    assert r.returncode == 0, r.stderr
    assert "STUB-INSTALLER update -y" in r.stdout


def test_uninstall_delegates_with_purge(tmp_path):
    env, app = sandbox(tmp_path)
    r = mgr_sb(env, app, "uninstall", "-y", "--purge")
    assert r.returncode == 0, r.stderr
    assert "STUB-INSTALLER uninstall -y --purge" in r.stdout


def test_update_requires_install_dir(tmp_path):
    """`ovn update` with no installed tree fails cleanly instead of execing."""
    env = {**os.environ, "OVN_APP_DIR": str(tmp_path / "missing")}
    r = mgr("update", env=env)
    assert r.returncode != 0
    assert "Not installed" in r.stderr


def test_status_not_installed_json(tmp_path):
    # OVN_APP_DIR points at an empty dir so this holds on machines that
    # already host a node (dev boxes, this repo's own CI sandbox, prod).
    r = mgr("status", "--json", env={**os.environ, "OVN_APP_DIR": str(tmp_path / "empty")})
    assert r.returncode == 4  # EX_NOTINSTALLED
    data = json.loads(r.stdout)  # stdout is exactly one JSON object
    assert data["ok"] is True
    assert data["installed"] is False


def test_logs_command_never_crashes(tmp_path):
    env, app = sandbox(tmp_path)
    r = mgr_sb(env, app, "logs", "5")
    assert r.returncode == 0, r.stderr


def test_auto_backup_host_timer_wiring():
    with open(MANAGER, encoding="utf-8") as f:
        content = f.read()
    assert "ovnode-backup.timer" in content
    assert "ovnode-backup.service" in content
    assert "backup --keep ${keep}" in content
    assert "auto-backup on" in content
    assert "prune_backups" in content


def test_manager_version_matches_agent():
    """manager.sh VERSION tracks the agent version (release checklist)."""
    import re

    manager_src = MANAGER_PATH.read_text(encoding="utf-8")
    mver = re.search(r'^VERSION="([^"]+)"', manager_src, re.M).group(1)
    agent_ver = re.search(
        r'__version__ = "([^"]+)"', (REPO / "core" / "version.py").read_text(encoding="utf-8")
    ).group(1)
    assert mver == agent_ver, f"manager {mver} != agent {agent_ver}"


def test_no_function_ends_with_a_failing_test():
    """Same `set -e` guard as the installer, applied to manager + lib."""
    import re

    def tails(path):
        lines = Path(path).read_text(encoding="utf-8").splitlines()
        out, func, body = [], None, []
        for i, line in enumerate(lines, 1):
            m = re.match(r"^([a-zA-Z_][a-zA-Z0-9_]*)\(\)\s*\{$", line)
            if m and func is None:
                func, body = m.group(1), []
                continue
            if func is None:
                continue
            if line == "}":
                tail = next(
                    (
                        ln.strip()
                        for ln in reversed(body)
                        if ln.strip() and not ln.strip().startswith("#")
                    ),
                    "",
                )
                out.append((func, tail, i))
                func = None
            else:
                body.append(line)
        return out

    offenders = [
        (str(path), name, tail, line)
        for path in (MANAGER_PATH, LIB)
        for name, tail, line in tails(path)
        if re.match(r"^\[\[.*\]\]\s*&&", tail)
    ]
    assert not offenders, offenders
