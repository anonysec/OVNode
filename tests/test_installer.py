# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Behavioral tests for install.sh's unattended interface (no root needed).

These exercise the paths scripts rely on: argument/env parsing, validation
and the documented exit codes. They never get past validation/root checks,
so they cannot touch the system.
"""

import os
import subprocess
from pathlib import Path

INSTALLER = os.path.join(os.path.dirname(__file__), "..", "install.sh")


def installer_lines() -> list[str]:
    """install.sh plus the libs it sources.

    The shared helpers live in scripts/lib now and install.sh only calls
    them, so every source-level assertion reads the two together — reading
    install.sh alone would silently stop finding what it checks.
    """
    paths = [Path(INSTALLER), *sorted(Path(INSTALLER).parent.glob("scripts/lib/*.sh"))]
    return [
        line
        for path in paths
        for line in path.read_text(encoding="utf-8").splitlines(keepends=True)
    ]


def installer_source() -> str:
    return "".join(installer_lines())


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


def test_help_documents_the_automation_surface():
    r = sh("help")
    assert r.returncode == 0
    for token in ("OVN_KEY", "Exit codes", "update", "--docker", "--vpn-ports"):
        assert token in r.stderr, f"help missing {token}"


def test_manager_ops_redirect_to_ovn():
    """status/logs/etc. are no longer installer commands — point at ovn."""
    for cmd in ("status", "logs", "backup", "tls"):
        r = sh(cmd)
        assert r.returncode == 2, cmd
        assert "moved to the manager" in r.stderr, cmd
        assert f"ovn {cmd}" in r.stderr, cmd

    # `menu` is not a manager subcommand either — the menu is what a bare
    # `ovn` opens. The generic redirect told people to run `ovn menu`, which
    # exits 2 with "Unknown option".
    r = sh("menu")
    assert r.returncode == 2
    assert "run: ovn" in r.stderr
    assert "ovn menu" not in r.stderr

    r = sh("install")
    assert r.returncode == 2
    assert "is the default" in r.stderr


def test_usage_errors_exit_2_with_a_message():
    cases = [
        ["--port", "abc", "-p", "0123456789abcdef"],
        ["-p", "short"],
        [
            "--port",
            "1194",
            "--vpn-ports",
            "1194",
            "-p",
            "0123456789abcdef",
        ],
        ["--tls", "bogus", "-p", "0123456789abcdef"],
        ["--proto", "bogus", "-p", "0123456789abcdef"],
        ["--nonsense-flag"],
    ]
    for args in cases:
        r = sh(*args)
        assert r.returncode == 2, f"{args}: rc={r.returncode}"
        assert "Error:" in r.stderr, f"{args}: no error message"
        assert r.stdout == "", f"{args}: stdout must stay empty"


# Every flag that left the three-flag surface, with the exact sentence its
# one-line deprecation warning must carry. The flags still work — removal is
# the next release, so this list is the contract for that release.
DEPRECATED_FLAGS = [
    (["-p", "0123456789abcdef"], "set OVN_KEY instead"),
    (["--key", "0123456789abcdef"], "set OVN_KEY instead"),
    (["--name", "eu-1"], "set OVN_NAME instead"),
    (["--port", "2083"], "set OVN_PORT instead"),
    (["--vpn-ports", "1194"], "set OVN_VPN_PORTS instead"),
    (["--vpn-port", "1194"], "set OVN_VPN_PORTS instead"),
    (["--proto", "tcp"], "set OVN_PROTO instead"),
    (["--tls", "1"], "set OVN_TLS instead"),
    (["--tls-domain", "node.example.com"], "set OVN_TLS_DOMAIN instead"),
    (["--tls-key", "/tmp/absent.key"], "set OVN_TLS_KEY instead"),
    (["--tls-cert", "/tmp/absent.crt"], "set OVN_TLS_CERT instead"),
    (["--ipv6"], "set OVN_IPV6=1 instead"),
    (["--no-nat"], "set OVN_NO_NAT=1 instead"),
    (["--purge"], "set OVN_PURGE=1 instead"),
    (["--quiet"], "set OVN_QUIET=1 instead"),
    (["-q"], "set OVN_QUIET=1 instead"),
    (["-v", "1.0.0"], "set OVN_VERSION instead"),
    (["--version", "1.0.0"], "set OVN_VERSION instead"),
    (["--from-release"], "verified releases are the only source now, so just drop it"),
]

KEPT_FLAGS = [["-y"], ["--yes"], ["--docker"], ["-h"], ["--help"]]


def test_deprecated_flags_still_work_and_name_their_replacement(tmp_path):
    """A deprecation that silently changes behaviour is a removal. Each cut
    flag must still do its job (exit 3 is the already-installed guard, so
    parsing, validation and the flag's own effect all ran) and say on stderr
    what to use instead."""
    landed = tmp_path / "installed"
    landed.mkdir()
    for args, replacement in DEPRECATED_FLAGS:
        r = sh(*args, env={"OVN_APP_DIR": str(landed)})
        assert r.returncode == 3, f"{args}: rc={r.returncode} {r.stderr}"
        assert f"{args[0]} is deprecated; {replacement}" in r.stderr, f"{args}: {r.stderr}"
        assert r.stdout == "", f"{args}: stdout must stay empty"


def test_kept_flags_do_not_warn(tmp_path):
    """The three that survive must be silent, or the warning stops meaning
    "this is going away"."""
    landed = tmp_path / "installed"
    landed.mkdir()
    for args in KEPT_FLAGS:
        r = sh(*args, env={"OVN_APP_DIR": str(landed)})
        assert "is deprecated;" not in r.stderr, f"{args}: {r.stderr}"


def test_help_leads_with_the_three_flags_and_separates_the_rest():
    r = sh("help")
    assert r.returncode == 0
    head, _, deprecated_block = r.stderr.partition("Deprecated (still works)")
    assert deprecated_block, "help has no 'Deprecated (still works)' heading"
    for flag in ("-y, --yes", "--docker", "-h, --help"):
        assert flag in head, f"help does not lead with {flag}"
    for flag in ("-p, --key", "--port", "--vpn-ports", "--tls", "--purge", "--quiet"):
        assert flag in deprecated_block, f"{flag} is not listed as deprecated"


def test_version_script_reports_the_installers_own_version():
    """Support asks "which installer did you run?" after a stale CDN copy is
    suspected. The version must come from this file, and the commit must be
    reported only when something actually stamped one."""
    import re

    from core.version import __version__

    declared = re.search(
        r'^VERSION="([^"]+)"', Path(INSTALLER).read_text(encoding="utf-8"), re.M
    ).group(1)
    assert declared == __version__

    r = sh("version-script")
    assert r.returncode == 0, r.stderr
    assert r.stdout == ""
    assert f"install.sh v{declared}" in r.stderr
    assert "not recorded" in r.stderr

    r = sh("script-version", env={"OVN_SCRIPT_COMMIT": "deadbee"})
    assert r.returncode == 0, r.stderr
    assert "deadbee" in r.stderr
    assert "not recorded" not in r.stderr


def test_failures_report_on_stderr_and_leave_stdout_clean(tmp_path):
    """Automation reads the exit code and shows stderr: a failure never
    writes to stdout, so `$(installer ...)` captures no log noise.

    Uses a usage error (not a full run): the suite may run as root, and a
    "successful" install would really provision /opt/ovnode.
    """
    r = sh(
        "--port",
        "abc",
        "-p",
        "0123456789abcdef",
        env={"OVN_APP_DIR": str(tmp_path / "empty")},
    )
    assert r.returncode == 2
    assert "Error:" in r.stderr
    assert r.stdout == ""


def test_env_overrides_mirror_flags():
    r = sh(env={"OVN_KEY": "short"})
    assert r.returncode == 2
    assert "16 characters" in r.stderr


def test_closed_stdin_never_blocks(tmp_path):
    """A run with no TTY must fail fast instead of waiting for a prompt."""
    r = sh(
        "--port",
        "abc",
        "-p",
        "0123456789abcdef",
        env={"OVN_APP_DIR": str(tmp_path / "empty")},
    )  # stdin closed
    assert r.returncode == 2  # fails fast at validation, never blocks


def test_nat_script_is_idempotent_and_docker_skips_host_nat():
    content = installer_source()
    # -C check before -A append: reapplying rules never duplicates them.
    assert 'iptables -t "$table" -C "$chain" "$@" 2>/dev/null || iptables' in content
    # Docker mode: container entrypoint owns iptables; host only sets sysctl.
    assert "NAT/redirect rules are applied inside the container" in content
    # Docker hosts don't need python/openvpn installed.
    assert 'if [[ "$DOCKER" -eq 0 ]] && ! command -v openvpn' in content


def test_success_output_includes_panel_bundle():
    """Beginners paste one string into the panel instead of retyping 5 fields."""
    content = installer_source()
    assert "ovnode://" in content
    assert 'bundle "$bundle"' in content or "bundle " in content


def test_tls_wizard_defaults_to_selfsigned():
    """TLS is always on: self-signed is the default and plain HTTP is gone.

    Three options, and the Let's Encrypt one is a single free-text field — the
    old wizard asked "domain or this IP?" as its own question, which made the
    operator decide a distinction the installer can make for itself.
    """
    content = installer_source()
    assert 'tls_choice="$(ask "1 self-signed · 2 lets encrypt · 3 custom" "1")"' in content
    assert "None (HTTP)" not in content
    assert 'TLS_METHOD="${OVN_TLS:-selfsigned}"' in content
    # The branch happens after the answer, from what was typed.
    assert "is_ip_literal" in content
    assert 'TLS_METHOD="letsencrypt-ip"' in content
    assert 'TLS_METHOD="letsencrypt"' in content


def test_plain_http_is_rejected():
    """--tls none must fail with a usage error and a clear message."""
    r = sh(
        "--tls",
        "none",
        "-p",
        "0123456789abcdef",
        env={"OVN_APP_DIR": "/tmp/ovn-nowhere"},
    )
    assert r.returncode == 2, r.stderr
    assert "Invalid --tls" in r.stderr

    r = sh("-p", "0123456789abcdef", env={"OVN_APP_DIR": "/tmp/ovn-nowhere", "OVN_TLS": "none"})
    assert r.returncode == 2, r.stderr
    assert "Plain HTTP is not allowed" in r.stderr


def test_start_menu_offers_install_or_docker():
    """A bare interactive run opens the friendly menu (not the wizard):
    Install (host, default) or Install with Docker — same shape as the
    panel installer."""
    content = installer_source()
    assert "start_menu" in content
    assert 'host   "install  ·  systemd on this box"' in content
    assert 'docker "install  ·  agent + openvpn in a container"' in content
    assert 'quit   "exit"' in content
    assert "nothing was changed" in content
    assert "How do you want to install?" not in content
    # Host install is the default; Docker is explicit.
    assert "DOCKER=1; apply_express_defaults" in content
    # And the wizard does not ask the mode again — the answer could be given
    # twice and the two did not always agree.
    wizard = _extract_function("interactive_setup")
    assert "Deployment" not in wizard
    # Install still uses safe generated defaults with TLS on.
    assert "apply_express_defaults()" in content
    assert 'TLS_METHOD="selfsigned"' in content
    assert ': "${VPN_PROTO:=udp}"' in content


def test_already_installed_menu_is_installer_only():
    """The installer's already-installed menu offers update/uninstall/quit —
    day-to-day ops moved to ovn."""
    content = installer_source()
    assert "installed_menu" in content
    assert 'update    "update to v${VERSION}"' in content
    assert 'uninstall "uninstall"' in content
    assert 'quit      "quit"' in content
    assert "render_menu" in content
    # tui_select survives only as a one-line alias into render_menu; a caller
    # reaching for it is fine, a second implementation of it is not.
    lib = installer_source().split("tui_select() {")[-1].lstrip()
    assert lib.startswith('render_menu "$@"'), lib


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
    content = installer_source()
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
    content = installer_source()
    assert "close_firewall_ports" in content
    assert 'ufw delete allow "$svc/tcp"' in content
    assert 'firewall-cmd --permanent --remove-port="$svc/tcp"' in content
    assert "close_firewall_ports" in content.split("do_uninstall()")[1].split("# ──")[0]


def test_repo_override_for_forks():
    """OVN_REPO redirects source downloads/update pulls to a fork."""
    content = installer_source()
    assert 'REPO="${OVN_REPO:-anonysec/OVNode}"' in content


def test_installer_hardening_guards():
    """Source-level guards for issues that only bite on real servers.

    The tar downloads used a fixed /tmp path (symlink/TOCTOU as root) and PKI
    backups were created with the caller's umask (world-readable CA key), so
    lock the fixed patterns in.
    """
    content = installer_source()
    assert "mktemp -d /tmp/ovn.XXXXXX" in content
    assert "curl -fsSLo /tmp/ovn.tar.gz" not in content
    assert "umask 077" in content
    assert 'chmod 600 "$file"' in content
    # The key is tightened on the generation path only. Naming the literal
    # path here was how this guard rotted: the paths became locals, and the
    # assertion would have to be deleted rather than kept meaningful.
    assert 'chmod 600 "$key"' in content


def test_installer_deploys_the_manager():
    """install.sh puts manager.sh on PATH as ovnode (+ ovn) — never itself."""
    content = installer_source()
    assert 'BIN_DIR="${OVN_BIN_DIR:-/usr/local/bin}"' in content
    assert 'CLI_NAME="ovnode"' in content
    assert 'CLI_ALIAS="ovn"' in content
    assert 'local src="${APP_DIR}/manager.sh"' in content
    assert content.count("install_cli") >= 3  # definition + do_install + do_update
    assert content.count("remove_cli") >= 2  # definition + do_uninstall
    assert "render_menu" in content


def test_no_function_ends_with_a_failing_test():
    """`set -e` trap: a function whose last statement is `[[ ... ]] && ...`
    returns 1 when the test is false, which exits the whole installer."""
    import re

    lines = installer_lines()
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
                ln.strip() for ln in body if ln.strip() and not ln.strip().startswith("#")
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
    lines = installer_lines()
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
    """The list of what goes comes first, and the destructive answer is a word.

    A y/N prompt put "yes, delete the CA and every issued client cert" one
    keystroke from the default. The PKI is not regenerable without reissuing
    every client, so Enter must keep it and --purge must be the only other way.
    """
    uninstall = _extract_function("do_uninstall")
    typed = 'confirm_word "delete the data and the PKI as well? type purge" "purge"'
    assert f"{typed} && PURGE=1" in uninstall
    assert 'confirm "remove the app and stop all services?"' in uninstall
    # Sizes before the question: "210 MB" and "84 MB" make the decision.
    assert "dir_size" in uninstall
    assert uninstall.index("dir_size") < uninstall.index("confirm_word")


def test_tls_numbers_map_to_methods():
    """--tls takes 1-4 (names still accepted for old scripts)."""
    content = installer_source()
    assert "1|selfsigned" in content
    assert "2|letsencrypt" in content
    assert "3|letsencrypt-ip" in content
    assert "4|custom" in content
    r = sh("--tls", "9")
    assert r.returncode == 2
    assert "Invalid --tls" in r.stderr


def test_default_node_name_is_ovnode():
    """One node per host, so the name is generated and never asked for.

    The wizard used to prompt for it and default it to ovnode. One question
    removed: a name is a decision nobody has an opinion about, and the value
    only ever names the data directory on a box that runs exactly one node.
    """
    content = installer_source()
    assert "node-1" not in content
    assert ': "${NODE_NAME:=ovnode}"' in content
    assert "OVN_NAME, ovnode]" in content
    assert 'ask "Node name"' not in content
    # The fallback still has to hold where the name is read back off disk.
    # The fallback used to be inlined wherever the name was read back off disk.
    # It is now node_name_from_env() in common.sh — one place, so the data
    # directory and the compose file cannot disagree about the default.
    common = (Path(__file__).resolve().parent.parent / "scripts" / "lib" / "common.sh").read_text(
        encoding="utf-8"
    )
    assert "${name:-ovnode}" in common
    lines = common.splitlines()
    start = next(i for i, ln in enumerate(lines) if ln.startswith("node_name_from_env()"))
    assert "NODE_NAME" in "\n".join(lines[start : start + 4])


def test_detect_os_preserves_app_version(tmp_path):
    """Regression: sourcing /etc/os-release must not clobber the app
    VERSION (os-release defines its own VERSION=...)."""
    fn = _extract_function("detect_os")
    assert fn, "detect_os not found"
    probe = tmp_path / "probe.sh"
    probe.write_text(
        "set -u\n"
        'VERSION="9.9.9-probe"\n'
        'die() { echo "DIE: $1" >&2; exit 1; }\n' + fn + "\ndetect_os\n"
        'echo "VERSION=$VERSION"\n',
    )
    r = subprocess.run(["bash", str(probe)], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    assert "VERSION=9.9.9-probe" in r.stdout


def test_bad_version_pin_fails_fast():
    r = sh("update", "-v", "notaversion")
    assert r.returncode == 2
    assert "Bad --version" in r.stderr


def test_version_pinning_accepts_a_suffix_and_an_optional_v():
    """A pre-release is installed by name. The tag is "v" + the version (see
    release_url), so 1.2.3-rc1 and v1.2.3-rc1 name the same release, and a bare
    semver works too. Checked against the real function rather than by running
    the installer, which would fetch over the network for every valid value."""
    accepted = [
        "1.2.3",
        "v1.2.3",
        "10.20.30",
        "v10.20.30",
        "1.2.3-rc1",
        "v1.2.3-rc1",
        "1.2.3-rc.1",
        "1.2.3+build5",
        "1.2.3-rc1+build5",
    ]
    rejected = [
        "not-a-version",
        "notaversion",
        "1.2",
        "1",
        "v",
        "1.2.3.4",
        "1.2.3-",
        "1.2.3+",
        "main",
        "1.2.3 rc1",
        "",
        "v1.2.3-rc1 ",
    ]
    script = (
        "set -u\n"
        + _extract_function("valid_release_version")
        + "\n"
        + "\n".join(
            f"valid_release_version '{v}' && echo ok || echo no" for v in accepted + rejected
        )
    )
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)
    assert r.stdout.split() == ["ok"] * len(accepted) + ["no"] * len(rejected), (
        list(zip(accepted + rejected, r.stdout.split(), strict=True)),
        r.stderr,
    )


def test_update_rolls_back_on_health_failure():
    """do_update snapshots state + code first and fails over when the
    candidate never becomes healthy (transactional update failover)."""
    content = installer_source()
    assert "snapshot_code" in content
    assert "state_safety_bundle" in content
    assert "Candidate verification failed — failing over" in content
    assert "failed over safely" in content


def test_snapshot_rotation_keeps_two(tmp_path):
    """snapshot_code keeps the newest 2 code snapshots, pruning older ones."""
    src = _extract_function("snapshot_code").replace("/var/backups", str(tmp_path))
    harness = (
        "set -Eeuo pipefail\n"
        'die() { echo "DIE: $1" >&2; exit 1; }\n'
        "render_ok() { :; }\nrender_line() { :; }\nrender_warn() { :; }\n"
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
    content = installer_source()
    assert 'interactive)  ACTION="interactive"; CMD_GIVEN=1; shift ;;' in content
    assert "INTERACTIVE=1" in content


def test_release_downloads_follow_redirects():
    """github.com/download answers 302 to release-assets — curl needs -L,
    or every release install/update breaks."""
    content = installer_source()
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
    """Pages serves the documentation, never the installer.

    The installer is bootstrapped from raw.githubusercontent.com because the
    anonysec.github.io host once served stale scripts, so install.sh and
    manager.sh must not point at it at all. README.md may link the published
    guides — and only the guides: never a script, an archive or a checksum.
    """
    import pathlib
    import re

    repo = pathlib.Path(INSTALLER).parent
    for rel in ("install.sh", "manager.sh"):
        assert "github.io" not in (repo / rel).read_text(encoding="utf-8"), rel

    readme = (repo / "README.md").read_text(encoding="utf-8")
    for url in re.findall(r"https://[\w./-]*github\.io[\w./-]*", readme):
        assert url.startswith("https://anonysec.github.io/OVManager/"), (
            f"README links a Pages host that is not the docs site: {url}"
        )
        assert not url.endswith((".sh", ".txt", ".tar.gz", ".json")), (
            f"README points at Pages for an artifact, not a guide: {url}"
        )
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
    """One menu dialect: the progress block counts, the wizard does not.

    The step counters moved out of the wizard and into render.sh's progress
    block. Two counters competing on one screen — the menu's numbers and the
    wizard's "Step 2/4" — is what made the old flow hard to read.
    """
    content = installer_source()
    assert "How do you want to install?" not in content
    assert "verified release" in content
    for retired in ("Step 1/4", "Step 4/4", "Ready — save this login", "Setup${NC}"):
        assert retired not in content, retired
    for token in ('render_begin "preflight"', 'render_card "ready" "api key"', "render_menu"):
        assert token in content, token


def test_no_source_build_paths():
    """The production installer consumes verified releases only —
    no source flags, no clone/pull logic."""
    content = installer_source()
    for token in ("--from-source", "--branch)", "git clone", "git pull", "refs/heads/"):
        assert token not in content, f"source-build remnant: {token}"
    assert 'BRANCH="${OVN_BRANCH' not in content
    # OVN_BRANCH survives only as a migration guard pointing at clones.
    assert "OVN_BRANCH was removed" in content
    assert "clone the repo and follow CONTRIBUTING.md" in content


def test_release_checksum_is_mandatory():
    """An unverified download must never be installed (was warn-and-follow)."""
    content = installer_source()
    assert "No checksum file" not in content
    assert "Release checksum file is missing" in content


def test_native_wording_is_gone_from_installer_text():
    """Host installs must not be called 'native' in user-facing text."""
    content = installer_source()
    for token in (
        "Install with safe defaults",
        "Choose every option yourself",
        "instead of v1.1.2",
        "Native —",
        "|| echo Native",
    ):
        assert token not in content, f"stale wording: {token}"
    # "host" is the word, not "native" — the mode is chosen on the front-door
    # menu now, so nothing prints the mode's name in prose any more.
    assert 'host   "install  ·  systemd on this box"' in content
    assert "systemd on this box" in content


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
    content = installer_source()
    for token in (
        "update_state",
        "state_safety_bundle",
        "state_restore",
        "UPDATE_STAGE",
        "UPDATE_PREVIOUS",
        "update_marker()",
        "operation_begin",
        "do_recover_update",
        "node_failover",
        "node_api_status",
        "identity_sha",
        "recover-update",
    ):
        assert token in content, f"missing: {token}"
    # The six update phases are six numbered progress steps, not six
    # "Step N/6" headings: one counter per run, and it lives in the block.
    for phase in ("backup", "stage", "maintenance", "activate", "verify", "commit"):
        assert f'render_begin "{phase}" 6' in content, phase


def test_docker_uses_published_image_only():
    """Docker installs pull the versioned published image — never build."""
    content = installer_source()
    assert "up -d --build" not in content
    assert "image: ${IMAGE_REPO}:${tag}" in content
    assert "docker pull" in content


def test_update_recovers_full_config_for_compose():
    """do_update must recover TLS key/cert/IPv6 from .env: the compose
    rewrite dropped SSL mounts and broke every Docker update (defect)."""
    src = installer_source()
    source = src.split("do_update()")[1].split("do_recover_update()")[0]
    for token in (
        'TLS_KEY="$(env_get SSL_KEYFILE)"',
        'TLS_CERT="$(env_get SSL_CERTFILE)"',
        "OVNODE_ENABLE_IPV6",
        'EXTRA_PORTS="$(env_get OVNODE_EXTRA_PORTS)"',
    ):
        assert token in source, f"update must recover: {token}"


def test_no_undefined_fail_helper():
    """install.sh has warn/step/info — a stray fail call dies with 127."""
    import re

    content = installer_source()
    assert not re.search(r"(^|\s)fail \"", content)


def test_installer_design_language_matches_panel():
    """Anti-divergence: the node installer shares the panel's menu/card
    language (shared tokens mirror the panel suite) plus node-only rows.
    Update both suites together."""
    content = installer_source()
    for token in (
        'host   "install  ·  systemd on this box"',
        'docker "install  ·  agent + openvpn in a container"',
        'tls_choice="$(ask "1 self-signed · 2 lets encrypt · 3 custom" "1")"',
        'render_begin "preflight"',
        'render_card "ready" "api key"',
        "render_menu",
        "verified release",
        "Options (every option has an OVN_* env equivalent; CLI wins):",
    ):
        assert token in content, f"design drift: {token}"
    for retired in (
        "How do you want to install?",
        "Installation complete!",
        "Choose every option yourself",
        "v$VERSION ($SRC)",
        "Setup${NC}",
        "1.${NC} Install",
        "Step 1/4",
        "Step 1/6",
        "Ready — save this login",
        "up and running in a few minutes",
    ):
        assert retired not in content, f"retired wording back: {retired}"


def test_the_banner_is_one_line_and_a_rule():
    """Name, version, repo — then a rule. No tagline.

    The old banner carried a second line whose only job was to advertise a fresh
    install, and it had to be suppressed on update/uninstall because "up and
    running in a few minutes" over an update reads as a lie. One line has no
    context to get wrong.
    """
    content = installer_source()
    assert 'render_banner "OVNode"' in content
    assert "subtitle" not in content
    assert "up and running in a few minutes" not in content


def test_no_extra_install_confirmation():
    """No extra question, and the review is a line rather than a card.

    A nine-row card restated every value the operator had just been asked for,
    one screen back. What was worth keeping is the part that catches a mistake —
    a mistyped port, the wrong transport — so those two are what remain.
    """
    content = installer_source()
    assert "Proceed with installation?" not in content
    assert "this will install" in content
    for retired in ('render_kv "OS"', 'render_kv "Version"', 'render_kv "Install"'):
        assert retired not in content, retired


class TestBareRunIsInteractive:
    """A run with no flags and no terminal must not decide anything itself.

    The installer used to read a missing terminal as "no questions wanted" and
    install anyway, reporting success for choices nobody made. Now it stops and
    names the flag. Two properties matter and they pull in opposite directions,
    so both are pinned here.
    """

    def test_a_bare_run_with_no_terminal_refuses(self, tmp_path):
        r = sh(env={"OVN_APP_DIR": str(tmp_path / "empty")})  # stdin closed
        assert r.returncode != 0
        assert "No interactive terminal" in r.stderr, r.stderr
        assert "-y" in r.stderr, "the refusal must name the flag that changes it"

    def test_a_bad_value_is_reported_as_the_bad_value(self, tmp_path):
        """Ordering: validate first, then complain about the terminal.

        The check sat in parse_args at first, so every validation message was
        masked by it — `OVN_TLS=none` came back as "no interactive terminal",
        which is true and useless. The thing the operator typed wrong is the
        thing they need to hear.
        """
        r = sh(
            "-p",
            "0123456789abcdef",
            env={"OVN_APP_DIR": str(tmp_path / "empty"), "OVN_TLS": "none"},
        )
        assert r.returncode == 2
        assert "Plain HTTP is not allowed" in r.stderr, r.stderr
        assert "No interactive terminal" not in r.stderr, r.stderr

    def test_yes_still_works_without_a_terminal(self, tmp_path):
        r = sh("-y", "--version", "notaversion", env={"OVN_APP_DIR": str(tmp_path / "e")})
        assert "No interactive terminal" not in r.stderr, r.stderr
