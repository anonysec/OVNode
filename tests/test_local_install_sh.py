# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Behavioral tests for install-local.sh — the from-checkout dev installer.

install.sh and manager.sh are frozen; this file carries the fast dev loop, so
it must stand alone: syntax-clean, --help usable as non-root, unknown flags
rejected, and a box without OpenVPN told which packages to install instead of
dying halfway through a write. Nothing in it may fetch — the checkout is the
whole payload.
"""

import os
import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "install-local.sh"


def _run(argv, env=None):
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, **(env or {})},
        stdin=subprocess.DEVNULL,
    )


def sh(*args, env=None):
    return _run(["bash", str(SCRIPT), *args], env=env)


def as_nobody(*args, env=None):
    """Run with uid/gid 65534: --help must work, install must not."""
    if os.geteuid() != 0:
        return sh(*args, env=env)
    return _run(
        ["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups",
         "bash", str(SCRIPT), *args],
        env=env,
    )


def test_install_local_syntax():
    subprocess.run(["bash", "-n", str(SCRIPT)], check=True)


def test_help_works_as_non_root():
    r = as_nobody("--help")
    assert r.returncode == 0, r.stderr
    out = r.stdout + r.stderr
    for token in ("--src", "--dest", "--uninstall", "--help"):
        assert token in out, f"help missing {token}"


def test_unknown_flag_exits_non_zero():
    r = sh("--frobnicate")
    assert r.returncode != 0
    assert "--frobnicate" in r.stderr, r.stderr


def test_install_without_root_refuses_before_writing():
    r = as_nobody()
    assert r.returncode != 0
    assert "root" in (r.stderr + r.stdout).lower(), r.stderr


def test_missing_openvpn_dies_with_the_packages_to_install():
    # PATH without /usr/sbin: Debian and Ubuntu keep openvpn there, so this
    # hides it without touching the real box.
    r = sh(env={"PATH": "/usr/bin:/bin"})
    assert r.returncode != 0, r.stdout
    assert "openvpn" in r.stderr and "easy-rsa" in r.stderr, r.stderr


def test_script_fetches_nothing():
    """No curl|sh, no URLs — the tree at --src already has everything."""
    text = SCRIPT.read_text(encoding="utf-8")
    assert "github" not in text.lower()
    assert not re.search(r"\|\s*(?:ba)?sh\b", text), "pipe-to-shell found"


def test_rsync_scope_and_env_safety():
    """Junk stays out of dest; the dest .env is created, never overwritten."""
    text = SCRIPT.read_text(encoding="utf-8")
    for pat in (
        "--exclude '.git'",
        "--exclude '.venv'",
        "--exclude '__pycache__'",
        "--exclude '.pytest_cache'",
        "--exclude '.slim'",
        "--exclude '.env'",
    ):
        assert pat in text, f"missing {pat}"
    assert '-f "$DEST/.env"' in text, "no create-only .env guard"
