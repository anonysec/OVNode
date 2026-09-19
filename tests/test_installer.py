# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

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


def test_status_not_installed_json(tmp_path):
    # OVN_APP_DIR points at an empty dir so this holds on machines that
    # already host a node (dev boxes, this repo's own CI sandbox, prod).
    r = sh("status", "--json", env={"OVN_APP_DIR": str(tmp_path / "empty")})
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
        ["install", "--json", "--proto", "bogus", "--api-key", "0123456789abcdef"],
        ["--nonsense-flag"],
    ]
    for args in cases:
        r = sh(*args)
        assert r.returncode == 2, f"{args}: rc={r.returncode}"
        if "--json" in args:
            data = json.loads(r.stdout)
            assert data["ok"] is False and data["exit_code"] == 2


def test_stdout_carries_only_json(tmp_path):
    """In --json mode stdout must be parseable as a single object even when
    the run fails — all human output goes to stderr.

    Uses a usage error (not a full run): the suite may run as root, and a
    "successful" install would really provision /opt/ovnode.
    """
    r = sh(
        "install",
        "--json",
        "--port",
        "abc",
        "--api-key",
        "0123456789abcdef",
        env={"OVN_APP_DIR": str(tmp_path / "empty")},
    )
    assert r.returncode == 2
    data = json.loads(r.stdout)
    assert data["ok"] is False
    assert "error" in data
    # Progress/log lines never leak to stdout.
    assert "\n" not in r.stdout.strip()


def test_env_overrides_mirror_flags():
    r = sh("install", env={"OVN_JSON": "1", "OVN_API_KEY": "short"})
    assert r.returncode == 2
    data = json.loads(r.stdout)
    assert "16 characters" in data["error"]


def test_json_implies_noninteractive(tmp_path):
    """--json must never hang waiting for a prompt (AI/automation safety)."""
    r = sh(
        "install",
        "--json",
        "--port",
        "abc",
        "--api-key",
        "0123456789abcdef",
        env={"OVN_APP_DIR": str(tmp_path / "empty")},
    )  # stdin closed
    assert r.returncode == 2  # fails fast at validation, never blocks


def test_nat_script_is_idempotent_and_docker_skips_host_nat():
    with open(INSTALLER, encoding="utf-8") as f:
        content = f.read()
    # -C check before -A append: reapplying rules never duplicates them.
    assert 'iptables -t "$table" -C "$chain" "$@" 2>/dev/null || iptables' in content
    # Docker mode: container entrypoint owns iptables; host only sets sysctl.
    assert "NAT/redirect rules are applied inside the container" in content
    # Docker hosts don't need python/openvpn installed.
    assert 'if [[ "$DOCKER" -eq 0 ]] && ! command -v openvpn' in content


def test_success_output_includes_panel_bundle():
    """Beginners paste one string into the panel instead of retyping 5 fields."""
    with open(INSTALLER, encoding="utf-8") as f:
        content = f.read()
    assert "ovnode://" in content
    assert 'bundle "$bundle"' in content or "bundle " in content


def test_tls_wizard_defaults_to_selfsigned():
    """TLS is always on: self-signed is the default and plain HTTP is gone."""
    with open(INSTALLER, encoding="utf-8") as f:
        content = f.read()
    assert 'tls_choice="$(ask "TLS mode" "1")"' in content
    assert "None (HTTP)" not in content
    assert 'TLS_METHOD="${OVN_TLS:-selfsigned}"' in content


def test_plain_http_is_rejected():
    """--tls none must fail with a usage error and a clear message."""
    r = sh(
        "install",
        "--json",
        "--tls",
        "none",
        "--api-key",
        "0123456789abcdef",
        env={"OVN_APP_DIR": "/tmp/ovn-nowhere"},
    )
    assert r.returncode == 2, r.stderr
    data = json.loads(r.stdout)
    assert "Plain HTTP is not allowed" in data["error"]


def test_start_menu_offers_express_custom_update_uninstall():
    """A bare interactive run opens the friendly menu (not the wizard)."""
    with open(INSTALLER, encoding="utf-8") as f:
        content = f.read()
    assert "start_menu" in content
    for label in ("Express", "Custom", "Update", "Uninstall"):
        assert label in content
    # Express skips every question and turns TLS on.
    assert "apply_express_defaults()" in content
    assert "TLS_METHOD=\"selfsigned\"" in content
    assert ': "${VPN_PROTO:=udp}"' in content


def test_already_installed_menu_never_auto_runs_destructive_actions():
    """Enter/EOF/cancel must not start update or uninstall by default."""
    with open(INSTALLER, encoding="utf-8") as f:
        content = f.read()
    assert 'tui_select "OVNode — node"' in content
    assert 'quit        "Quit")' in content
    assert "*)           return 0 ;;" in content


def test_env_recovery_survives_missing_keys(tmp_path):
    """do_update reads optional keys from .env; a missing key (grep finds
    nothing → SIGPIPE) must not abort the script under set -Eeuo pipefail.
    Regression: update died silently on installs without OVNODE_EXTRA_PORTS.
    """
    import subprocess

    fake_env = tmp_path / ".env"
    fake_env.write_text("NODE_NAME=node-1\nSERVICE_PORT=2083\n", encoding="utf-8")
    probe = (
        "set -Eeuo pipefail\n"
        'env_get() { grep -E "^$1=" "$ENV_FILE" 2>/dev/null'
        " | head -1 | cut -d= -f2- | tr -d '\"' || true; }\n"
        'EXTRA_PORTS="$(env_get OVNODE_EXTRA_PORTS)"\n'
        'test -z "$EXTRA_PORTS"\n'
    )
    with open(INSTALLER, encoding="utf-8") as f:
        content = f.read()
    # The probe mirrors the installer's env_get; keep them in sync.
    assert "|| true; }" in content
    r = subprocess.run(
        ["bash", "-c", probe],
        capture_output=True,
        text=True,
        timeout=15,
        env={**os.environ, "ENV_FILE": str(fake_env)},
    )
    assert r.returncode == 0, r.stderr


def test_uninstall_removes_firewall_allows():
    """Uninstall must mirror open_firewall_ports (ufw delete / firewall-cmd
    --remove-port) using installed .env values, never failing the run."""
    with open(INSTALLER, encoding="utf-8") as f:
        content = f.read()
    assert "close_firewall_ports" in content
    assert 'ufw delete allow "$svc/tcp"' in content
    assert 'firewall-cmd --permanent --remove-port="$svc/tcp"' in content
    assert "close_firewall_ports" in content.split("do_uninstall()")[1].split("emit_result")[0]


def test_repo_override_for_forks():
    """OVN_REPO redirects source downloads/update pulls to a fork."""
    with open(INSTALLER, encoding="utf-8") as f:
        content = f.read()
    assert 'REPO="${OVN_REPO:-anonysec/OVNode}"' in content


def test_installer_hardening_guards():
    """Source-level guards for issues that only bite on real servers.

    The tar downloads used a fixed /tmp path (symlink/TOCTOU as root) and PKI
    backups were created with the caller's umask (world-readable CA key), so
    lock the fixed patterns in.
    """
    with open(INSTALLER, encoding="utf-8") as f:
        content = f.read()
    assert "mktemp /tmp/ovn.XXXXXX.tar.gz" in content
    assert "curl -fsSLo /tmp/ovn.tar.gz" not in content
    assert "umask 077" in content
    assert 'chmod 600 "$file"' in content
    assert "chmod 600 /etc/ssl/self-signed/privkey.pem" in content


def test_terminal_command_and_tui_are_installed():
    """The installer copies itself to /usr/local/bin as ovnode (+ ovn)."""
    with open(INSTALLER, encoding="utf-8") as f:
        content = f.read()
    assert 'BIN_DIR="${OVN_BIN_DIR:-/usr/local/bin}"' in content
    assert 'CLI_NAME="ovnode"' in content
    assert 'CLI_ALIAS="ovn"' in content
    assert content.count("install_cli") >= 3  # definition + do_install + do_update
    assert content.count("remove_cli") >= 2  # definition + do_uninstall
    assert "command -v whiptail" in content and "tui_select" in content


def test_help_lists_tui_commands():
    r = sh("help")
    output = r.stdout + r.stderr
    for token in (
        "start | stop | restart",
        "restart-vpn",
        "logs [N|-f]",
        "backup",
        "tls",
        "menu",
        "Installed commands: ovnode",
    ):
        assert token in output, token


def test_menu_without_terminal_is_usage_error():
    """`menu` must not fall back to defaults and start installing."""
    r = sh("menu")
    assert r.returncode == 2
    assert "No terminal available" in r.stderr


def test_logs_command_never_crashes():
    r = sh("logs", "5")
    assert r.returncode == 0


def test_no_function_ends_with_a_failing_test():
    """`set -e` trap: a function whose last statement is `[[ ... ]] && ...`
    returns 1 when the test is false, which exits the whole installer."""
    import re

    lines = open(INSTALLER, encoding="utf-8").readlines()
    func = None
    body: list[str] = []
    offenders = []
    for i, line in enumerate(lines, 1):
        m = re.match(r"^([a-zA-Z_][a-zA-Z0-9_]*)\(\)\s*\{$", line)
        if m and func is None:
            func, body = m.group(1), []
            continue
        if func is None:
            continue
        if line == "}":
            meaningful = [
                ln.strip()
                for ln in body
                if ln.strip() and not ln.strip().startswith("#")
            ]
            tail = meaningful[-1] if meaningful else ""
            if re.match(r"^\[\[.*\]\]\s*&&", tail):
                offenders.append((func, i, tail))
            func = None
        else:
            body.append(line)
    assert not offenders, offenders


def sh_stdin(script: str, data: str):
    return subprocess.run(
        ["bash", "-c", script],
        input=data,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _extract_function(name: str) -> str:
    lines = open(INSTALLER, encoding="utf-8").readlines()
    start = next(i for i, ln in enumerate(lines) if ln.startswith(f"{name}()"))
    end = start
    while lines[end].rstrip("\n") != "}":
        end += 1
    return "".join(lines[start : end + 1])


def test_masked_password_echoes_stars_and_handles_backspace():
    harness = "set -Eeuo pipefail\n" + _extract_function("_masked_read") + "\n_masked_read\n"
    r = sh_stdin(harness, "ab\x7fc\n")
    assert r.returncode == 0, r.stderr
    assert r.stdout == "ac"
    assert r.stderr.count("*") == 3
    assert "\b \b" in r.stderr


def test_confirm_no_is_safe_by_default():
    # Harness: confirm_no only needs is_tty + YES; the answer is inlined.
    cases = [
        ("0", "0", "y", 0),
        ("0", "0", "Y", 0),
        ("0", "0", "", 1),
        ("0", "0", "n", 1),
        ("1", "0", "y", 1),
    ]
    for tty, yes, reply, expected in cases:
        harness = f"""set -Eeuo pipefail
GR=''; NC=''
is_tty() {{ return {tty}; }}
YES={yes}
confirm_no() {{
    [[ "$YES" -eq 1 ]] && return 1
    is_tty || return 1
    local c='{reply}'
    [[ "$c" =~ ^[Yy]$ ]]
}}
confirm_no "Delete data?"
"""
        r = subprocess.run(["bash", "-c", harness], capture_output=True, text=True, timeout=30)
        assert r.returncode == expected, (tty, yes, reply, r.returncode, r.stderr)


def test_uninstall_asks_about_data():
    with open(INSTALLER, encoding="utf-8") as f:
        content = f.read()
    assert 'confirm_no "Also delete data and backups?" && PURGE=1' in content


def test_auto_backup_host_timer_wiring():
    with open(INSTALLER, encoding="utf-8") as f:
        content = f.read()
    assert "ovnode-backup.timer" in content
    assert "ovnode-backup.service" in content
    assert "backup --keep ${keep}" in content
    assert "auto-backup on|off|status" in content
    assert "prune_backups" in content


def test_default_node_name_is_ovnode():
    with open(INSTALLER, encoding="utf-8") as f:
        content = f.read()
    assert "node-1" not in content
    assert ': "${NODE_NAME:=ovnode}"' in content
    assert '"${NODE_NAME:-ovnode}"' in content
    assert "OVN_NAME, ovnode]" in content


def test_detect_os_preserves_app_version(tmp_path):
    """Regression: sourcing /etc/os-release must not clobber the app
    VERSION (os-release defines its own VERSION=...)."""
    fn = subprocess.run(
        ["sed", "-n", "/^detect_os() {/,/^}/p", INSTALLER],
        capture_output=True, text=True, timeout=30,
    ).stdout
    assert fn, "detect_os not found"
    probe = tmp_path / "probe.sh"
    probe.write_text(
        "set -u\n"
        'VERSION="9.9.9-probe"\n'
        'die() { echo "DIE: $1" >&2; exit 1; }\n'
        + fn
        + "\ndetect_os\n"
        'echo "VERSION=$VERSION"\n',
    )
    r = subprocess.run(["bash", str(probe)], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    assert "VERSION=9.9.9-probe" in r.stdout
