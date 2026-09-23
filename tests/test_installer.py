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
    for token in ("--json", "OVN_KEY", "Exit codes", "update", "--docker", "--vpn-ports"):
        assert token in r.stderr, f"help missing {token}"


def test_manager_ops_redirect_to_ovn():
    """status/logs/etc. are no longer installer commands — point at ovn."""
    for cmd in ("status", "logs", "backup", "tls", "menu"):
        r = sh(cmd)
        assert r.returncode == 2, cmd
        assert "moved to the manager" in r.stderr, cmd
        assert "ovn" in r.stderr, cmd
    r = sh("install")
    assert r.returncode == 2
    assert "is the default" in r.stderr


def test_usage_errors_exit_2_with_json():
    cases = [
        ["--json", "--port", "abc", "-p", "0123456789abcdef"],
        ["--json", "-p", "short"],
        [
            "--json",
            "--port",
            "1194",
            "--vpn-ports",
            "1194",
            "-p",
            "0123456789abcdef",
        ],
        ["--json", "--tls", "bogus", "-p", "0123456789abcdef"],
        ["--json", "--proto", "bogus", "-p", "0123456789abcdef"],
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
        "--json",
        "--port",
        "abc",
        "-p",
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
    r = sh("--json", env={"OVN_JSON": "1", "OVN_KEY": "short"})
    assert r.returncode == 2
    data = json.loads(r.stdout)
    assert "16 characters" in data["error"]


def test_json_implies_noninteractive(tmp_path):
    """--json must never hang waiting for a prompt (AI/automation safety)."""
    r = sh(
        "--json",
        "--port",
        "abc",
        "-p",
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
        "--json",
        "--tls",
        "none",
        "-p",
        "0123456789abcdef",
        env={"OVN_APP_DIR": "/tmp/ovn-nowhere"},
    )
    assert r.returncode == 2, r.stderr
    data = json.loads(r.stdout)
    assert "Invalid --tls" in data["error"]


def test_start_menu_offers_install_or_docker():
    """A bare interactive run opens the friendly menu (not the wizard):
    Install (host, default) or Install with Docker — same shape as the
    panel installer."""
    with open(INSTALLER, encoding="utf-8") as f:
        content = f.read()
    assert "start_menu" in content
    assert "OVNode Setup" in content
    assert "1.${NC} Install" in content
    assert "2.${NC} Install with Docker" in content
    assert "0.${NC} Exit" in content
    assert "Cancelled. No changes were made." in content
    assert "How do you want to install?" not in content
    # Host install is the default; Docker is explicit.
    assert "DOCKER=1; apply_express_defaults" in content
    # Install still uses safe generated defaults with TLS on.
    assert "apply_express_defaults()" in content
    assert "TLS_METHOD=\"selfsigned\"" in content
    assert ': "${VPN_PROTO:=udp}"' in content


def test_already_installed_menu_is_installer_only():
    """The installer's already-installed menu offers update/uninstall/quit —
    day-to-day ops moved to ovn."""
    with open(INSTALLER, encoding="utf-8") as f:
        content = f.read()
    assert 'tui_select "OVNode — installer"' in content
    assert 'quit        "Quit")' in content
    assert "*)           return 0 ;;" in content
    assert "Manage the node with: ovn" in content


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
    assert "mktemp -d /tmp/ovn.XXXXXX" in content
    assert "curl -fsSLo /tmp/ovn.tar.gz" not in content
    assert "umask 077" in content
    assert 'chmod 600 "$file"' in content
    assert "chmod 600 /etc/ssl/self-signed/privkey.pem" in content


def test_installer_deploys_the_manager():
    """install.sh puts manager.sh on PATH as ovnode (+ ovn) — never itself."""
    with open(INSTALLER, encoding="utf-8") as f:
        content = f.read()
    assert 'BIN_DIR="${OVN_BIN_DIR:-/usr/local/bin}"' in content
    assert 'CLI_NAME="ovnode"' in content
    assert 'CLI_ALIAS="ovn"' in content
    assert 'local src="${APP_DIR}/manager.sh"' in content
    assert content.count("install_cli") >= 3  # definition + do_install + do_update
    assert content.count("remove_cli") >= 2  # definition + do_uninstall
    assert "command -v whiptail" in content and "tui_select" in content


def test_no_function_ends_with_a_failing_test():
    """`set -e` trap: a function whose last statement is `[[ ... ]] && ...`
    returns 1 when the test is false, which exits the whole installer."""
    import re

    lines = open(INSTALLER, encoding="utf-8").read().splitlines()
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


def test_tls_numbers_map_to_methods():
    """--tls takes 1-4 (names still accepted for old scripts)."""
    with open(INSTALLER, encoding="utf-8") as f:
        content = f.read()
    assert "1|selfsigned" in content
    assert "2|letsencrypt" in content
    assert "3|letsencrypt-ip" in content
    assert "4|custom" in content
    r = sh("--tls", "9")
    assert r.returncode == 2
    assert "Invalid --tls" in r.stderr


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


def test_bad_version_pin_fails_fast():
    r = sh("update", "-v", "notaversion")
    assert r.returncode == 2
    assert "Bad --version" in r.stderr


def test_update_rolls_back_on_health_failure():
    """do_update snapshots state + code first and fails over when the
    candidate never becomes healthy (transactional update failover)."""
    with open(INSTALLER, encoding="utf-8") as f:
        content = f.read()
    assert "snapshot_code" in content
    assert "state_safety_bundle" in content
    assert "Candidate verification failed — failing over" in content
    assert "failed over safely" in content


def test_snapshot_rotation_keeps_two(tmp_path):
    """snapshot_code keeps the newest 2 code snapshots, pruning older ones."""
    lines = open(INSTALLER, encoding="utf-8").readlines()
    start = next(i for i, ln in enumerate(lines) if ln.startswith("snapshot_code()"))
    end = start
    while lines[end].rstrip("\n") != "}":
        end += 1
    src = "".join(lines[start : end + 1]).replace("/var/backups", str(tmp_path))
    harness = (
        "set -Eeuo pipefail\n"
        'die() { echo "DIE: $1" >&2; exit 1; }\n'
        "step() { :; }\ninfo() { :; }\nwarn() { :; }\n"
        + src
        + f"\nmkdir -p {tmp_path}/app\n"
        + f"\nsnapshot_code {tmp_path}/app node 2 >/dev/null\nsleep 1.1\n"
        + f"snapshot_code {tmp_path}/app node 2 >/dev/null\nsleep 1.1\n"
        + f"snapshot_code {tmp_path}/app node 2 >/dev/null\n"
        + f"ls {tmp_path}/node-code-*.tar.gz | wc -l\n"
    )
    r = subprocess.run(["bash", "-c", harness], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "2", r.stdout


def test_interactive_verb_runs_wizard():
    """`interactive` forces the numbered wizard (Enter = default)."""
    with open(INSTALLER, encoding="utf-8") as f:
        content = f.read()
    assert 'interactive)  ACTION="interactive"; CMD_GIVEN=1; shift ;;' in content
    assert "INTERACTIVE=1" in content


def test_release_downloads_follow_redirects():
    """github.com/download answers 302 to release-assets — curl needs -L,
    or every release install/update breaks."""
    with open(INSTALLER, encoding="utf-8") as f:
        content = f.read()
    assert "curl -fsSL -o" in content
    assert "curl -fsSLo" not in content


def test_entry_points_are_executable():
    """install.sh/manager.sh must carry +x in git — tarballs preserve it,
    and the manager execs $APP_DIR/install.sh for update/uninstall."""
    import pathlib

    for name in ("install.sh", "manager.sh"):
        path = pathlib.Path(INSTALLER).parent / name
        assert os.access(path, os.X_OK), f"{name} lost its executable bit"


def test_no_pages_url():
    """The installer is bootstrapped from raw.githubusercontent.com — the
    anonysec.github.io Pages URL is retired (it served stale scripts)."""
    import pathlib

    repo = pathlib.Path(INSTALLER).parent
    for rel in ("README.md", "install.sh", "manager.sh"):
        assert "github.io" not in (repo / rel).read_text(encoding="utf-8"), rel
    for doc in (repo / "docs").glob("*.md"):
        assert "github.io" not in doc.read_text(encoding="utf-8"), doc.name


def test_release_stub_is_rejected_before_checksum(tmp_path):
    """A redirect stub saved as the tarball must fail as 'not a release
    archive' — never as a checksum mismatch (the v1.2.3 failure mode)."""
    stub = tmp_path / "stub.tar.gz"
    stub.write_text("<html>302 Found</html>", encoding="utf-8")
    real = tmp_path / "real.tar.gz"
    subprocess.run(["tar", "-czf", str(real), "-C", str(tmp_path), "stub.tar.gz"], check=True)
    harness = (
        _extract_function("is_release_archive") + "\n"
        f'is_release_archive "{stub}" && echo STUB-OK || echo STUB-BAD\n'
        f'is_release_archive "{real}" && echo REAL-OK || echo REAL-BAD\n'
    )
    r = subprocess.run(["bash", "-c", harness], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    assert "STUB-BAD" in r.stdout and "REAL-OK" in r.stdout


def test_installer_menu_copy_is_stepped():
    """One menu dialect: step counters in setup, a single front-door
    question."""
    with open(INSTALLER, encoding="utf-8") as f:
        content = f.read()
    assert "How do you want to install?" not in content
    assert "Ready — save this login" in content
    assert "verified release" in content
    for token in ("Step 1/4", "Step 4/4"):
        assert token in content, token


def test_no_source_build_paths():
    """The production installer consumes verified releases only —
    no source flags, no clone/pull logic."""
    with open(INSTALLER, encoding="utf-8") as f:
        content = f.read()
    for token in ("--from-source", "--branch)", "git clone", "git pull", "refs/heads/"):
        assert token not in content, f"source-build remnant: {token}"
    assert 'BRANCH="${OVN_BRANCH' not in content
    # OVN_BRANCH survives only as a migration guard pointing at clones.
    assert "OVN_BRANCH was removed" in content
    assert "clone the repo and follow CONTRIBUTING.md" in content


def test_release_checksum_is_mandatory():
    """An unverified download must never be installed (was warn-and-follow)."""
    with open(INSTALLER, encoding="utf-8") as f:
        content = f.read()
    assert "No checksum file" not in content
    assert "Release checksum file is missing" in content


def test_native_wording_is_gone_from_installer_text():
    """Host installs must not be called 'native' in user-facing text."""
    with open(INSTALLER, encoding="utf-8") as f:
        content = f.read()
    for token in ("Install with safe defaults", "Choose every option yourself",
                  "instead of v1.1.2", "Native —", "|| echo Native"):
        assert token not in content, f"stale wording: {token}"
    assert "|| echo Host" in content


def test_version_constants_are_synchronized():
    """install.sh, manager.sh and core/version.py must agree; --help must
    show the real version (was hardcoding v1.1.2)."""
    import pathlib
    import re

    repo = pathlib.Path(INSTALLER).parent
    shell_versions = set()
    for name in ("install.sh", "manager.sh"):
        m = re.search(r'^VERSION="([^"]+)"', (repo / name).read_text(encoding="utf-8"), re.M)
        assert m, name
        shell_versions.add(m.group(1))
    core_ns: dict = {}
    exec((repo / "core" / "version.py").read_text(encoding="utf-8"), core_ns)
    shell_versions.add(core_ns["__version__"])
    assert len(shell_versions) == 1, shell_versions
    r = subprocess.run(["bash", INSTALLER, "help"], capture_output=True, text=True, timeout=30)
    assert f"instead of v{core_ns['__version__']}" in r.stderr


def test_transactional_update_core_present():
    """Nine-phase journal, safety bundle, staging, op lock, recovery."""
    with open(INSTALLER, encoding="utf-8") as f:
        content = f.read()
    for token in ("update_state", "state_safety_bundle", "state_restore",
                  "UPDATE_STAGE", "UPDATE_PREVIOUS", "update_marker()",
                  "operation_begin", "do_recover_update", "node_failover",
                  "node_api_status", "identity_sha", "recover-update"):
        assert token in content, f"missing: {token}"
    assert "Step 1/6" in content and "Step 6/6" in content


def test_docker_uses_published_image_only():
    """Docker installs pull the versioned published image — never build."""
    with open(INSTALLER, encoding="utf-8") as f:
        content = f.read()
    assert "up -d --build" not in content
    assert 'image: ${IMAGE_REPO}:${tag}' in content
    assert "docker pull" in content


def test_update_recovers_full_config_for_compose():
    """do_update must recover TLS key/cert/IPv6 from .env: the compose
    rewrite dropped SSL mounts and broke every Docker update (defect)."""
    src = open(INSTALLER, encoding="utf-8").read()
    source = src.split("do_update()")[1].split("do_recover_update()")[0]
    for token in ('TLS_KEY="$(env_get SSL_KEYFILE)"', 'TLS_CERT="$(env_get SSL_CERTFILE)"',
                  'OVNODE_ENABLE_IPV6', 'EXTRA_PORTS="$(env_get OVNODE_EXTRA_PORTS)"'):
        assert token in source, f"update must recover: {token}"


def test_no_undefined_fail_helper():
    """install.sh has warn/step/info — a stray fail call dies with 127."""
    import re

    content = open(INSTALLER, encoding="utf-8").read()
    assert not re.search(r"(^|\s)fail \"", content)


def test_installer_design_language_matches_panel():
    """Anti-divergence: the node installer shares the panel's menu/card
    language (shared tokens mirror the panel suite) plus node-only rows.
    Update both suites together."""
    content = open(INSTALLER, encoding="utf-8").read()
    for token in (
        "Setup${NC}",
        "1.${NC} Install",
        "2.${NC} Install with Docker",
        "0.${NC} Exit",
        "Cancelled. No changes were made.",
        "installer${NC}",
        "up and running in a few minutes",
        "Step 1/4",
        "verified release",
        "Ready — save this login",
        "Proceed with installation?",
        "Options (every option has an OVN_* env equivalent; CLI wins):",
    ):
        assert token in content, f"design drift: {token}"
    for retired in (
        "How do you want to install?",
        "Installation complete!",
        "Choose every option yourself",
        "v$VERSION ($SRC)",
    ):
        assert retired not in content, f"retired wording back: {retired}"
