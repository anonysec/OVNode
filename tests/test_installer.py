# Copyright (c) 2025 anonysec. All rights reserved.
# Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.

"""Behavioral tests for install.sh's machine interface (no root needed).

These exercise the paths automation/AI relies on: argument/env parsing,
validation, exit codes, and the one-JSON-object-on-stdout contract. They
never get past validation/root checks, so they cannot touch the system.
"""

import json
import os
import subprocess

INSTALLER = os.path.join(os.path.dirname(__file__), "..", "install.sh")


def sh(*args: str, env: dict | None = None):
    full_env = {**os.environ, **(env or {})}
    return subprocess.run(
        ["bash", INSTALLER, *args],
        capture_output=True,
        text=True,
        timeout=30,
        env=full_env,
        stdin=subprocess.DEVNULL,
    )


def test_installer_syntax():
    subprocess.run(["bash", "-n", INSTALLER], check=True)


def test_help_documents_the_machine_interface():
    r = sh("help")
    assert r.returncode == 0
    for token in ("--json", "OVN_API_KEY", "Exit codes", "status", "--docker", "--vpn-ports"):
        assert token in r.stderr, f"help missing {token}"


def test_status_not_installed_json():
    r = sh("status", "--json")
    assert r.returncode == 4  # EX_NOTINSTALLED
    data = json.loads(r.stdout)  # stdout is exactly one JSON object
    assert data["ok"] is True
    assert data["installed"] is False


def test_usage_errors_exit_2_with_json():
    cases = [
        ["install", "--json", "--port", "abc", "--api-key", "0123456789abcdef"],
        ["install", "--json", "--api-key", "short"],
        [
            "install",
            "--json",
            "--port",
            "1194",
            "--vpn-ports",
            "1194",
            "--api-key",
            "0123456789abcdef",
        ],
        ["install", "--json", "--tls", "bogus", "--api-key", "0123456789abcdef"],
        ["--nonsense-flag"],
    ]
    for args in cases:
        r = sh(*args)
        assert r.returncode == 2, f"{args}: rc={r.returncode}"
        if "--json" in args:
            data = json.loads(r.stdout)
            assert data["ok"] is False and data["exit_code"] == 2


def test_stdout_carries_only_json():
    """In --json mode stdout must be parseable as a single object even when
    the run fails — all human output goes to stderr."""
    r = sh("install", "--json", "--api-key", "0123456789abcdef")
    data = json.loads(r.stdout)
    assert data["ok"] is False  # dies at root check in the sandbox
    assert "error" in data
    # Progress/log lines never leak to stdout.
    assert "\n" not in r.stdout.strip()


def test_env_overrides_mirror_flags():
    r = sh("install", env={"OVN_JSON": "1", "OVN_API_KEY": "short"})
    assert r.returncode == 2
    data = json.loads(r.stdout)
    assert "16 characters" in data["error"]


def test_json_implies_noninteractive():
    """--json must never hang waiting for a prompt (AI/automation safety)."""
    import os

    if os.path.isdir("/opt/ovnode"):
        import pytest

        pytest.skip(
            "/opt/ovnode is already installed here; already-installed exit (3) is also correct"
        )
    r = sh("install", "--json", "--api-key", "0123456789abcdef")  # stdin closed
    assert r.returncode in (1, 2)  # fails fast, never blocks


def test_nat_script_is_idempotent_and_docker_skips_host_nat():
    with open(INSTALLER, encoding="utf-8") as f:
        content = f.read()
    # -C check before -A append: reapplying rules never duplicates them.
    assert 'iptables -t "$table" -C "$chain" "$@" 2>/dev/null || iptables' in content
    # Docker mode: container entrypoint owns iptables; host only sets sysctl.
    assert "NAT/redirect rules are applied inside the container" in content
    # Docker hosts don't need python/openvpn installed.
    assert 'if [[ "$DOCKER" -eq 0 ]] && ! command -v openvpn' in content
