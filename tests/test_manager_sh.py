# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Behavioral tests for manager.sh (ovnode/ovn): day-to-day operations.

The manager runs against an installed tree ($APP_DIR, overridable via
OVN_APP_DIR for hermetic tests) and sources $APP_DIR/scripts/lib/common.sh.
Update/uninstall delegate to install.sh. Tests never touch the live system:
sandbox trees plus stub tools stand in for systemd/OpenVPN.
"""

import io
import os
import re
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
MANAGER = os.path.join(os.path.dirname(__file__), "..", "manager.sh")
MANAGER_PATH = Path(MANAGER)
LIB_DIR = REPO / "scripts" / "lib"
# manager.sh sources every lib it needs, so the sandbox copies the whole set
# rather than one file — a missing render.sh fails the same way on a real box.
# Every file manager.sh sources. Kept in step with the `for _lib in ...` loop in
# manager.sh: a lib missing from this list makes every sandbox test fail with a
# "not found" error instead of the assertion it was written for.
LIBS = ("common.sh", "render.sh", "doctor.sh")
INSTALLER = REPO / "install.sh"


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
    (app / "scripts" / "lib").mkdir(parents=True)
    shutil.copy(MANAGER_PATH, app / "manager.sh")
    for lib in LIBS:
        shutil.copy(LIB_DIR / lib, app / "scripts" / "lib" / lib)
    (app / "install.sh").write_text('#!/bin/sh\necho "STUB-INSTALLER $@"\n', encoding="utf-8")
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
        "status",
        "update",
        "restart",
        "restart core",
        "logs",
        "backup",
        "tls",
        "auth",
        "uninstall",
        "ovn",
    ):
        assert token in output, f"help missing {token}"


def test_bare_run_prints_the_command_list():
    """Bare `ovn` lists and exits 0, tty or not — the same as `ovm`.

    It used to open an interactive menu on a tty and die without one. Both were
    wrong: a bare invocation in a provisioning script must not wait for input,
    and dying with "No terminal" made the tool look broken in a pipeline.
    """
    r = mgr()
    assert r.returncode == 0
    assert "USAGE" in r.stderr
    assert "Select" not in r.stderr, "nothing may prompt"


def test_unknown_option_fails():
    r = mgr("--nonsense-flag")
    assert r.returncode == 2


def test_every_core_op_is_reachable_without_a_menu():
    """The menu was a second hand-maintained list of the tool's own commands.

    It had ten entries against thirteen verbs, and one arm still called a
    function that had been deleted — a runtime failure no test caught. So the
    requirement is now the inverse: every core op is a verb, and there is no
    menu to fall out of step.
    """
    with open(MANAGER, encoding="utf-8") as f:
        content = f.read()
    assert "manager_menu" not in content
    help_out = mgr("help")
    text = help_out.stdout + help_out.stderr
    for label in ("status", "update", "restart", "logs", "backup", "tls", "doctor", "uninstall"):
        assert f"ovn {label}" in text, f"no verb for {label}"


def test_update_delegates_to_installer(tmp_path):
    """`ovn update` execs install.sh update, forwarding its flags."""
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


def test_status_not_installed_reports_and_exits_4(tmp_path):
    # OVN_APP_DIR points at an empty dir so this holds on machines that
    # already host a node (dev boxes, this repo's own CI sandbox, prod).
    r = mgr("status", env={**os.environ, "OVN_APP_DIR": str(tmp_path / "empty")})
    assert r.returncode == 4  # EX_NOTINSTALLED
    # A failure line, not a row. "Installed: no" read as one more fact on a
    # working node, and the exit code is what a script checks anyway.
    failed = [ln for ln in r.stderr.splitlines() if ln.strip().startswith("\u2717 not installed")]
    assert failed, r.stderr
    assert r.stdout == ""


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


def test_completion_installs_a_script_for_ovn(tmp_path):
    """`ovn completion` writes the completion file and prints how to load it
    in the current shell — a file nobody sourced is a file nobody uses."""
    env, app = sandbox(tmp_path)
    target = tmp_path / "bash_completion.d"
    env = {**env, "OVN_COMPLETION_DIR": str(target)}
    r = mgr_sb(env, app, "completion")
    assert r.returncode == 0, r.stderr
    assert r.stdout == ""

    body = (target / "ovn").read_text(encoding="utf-8")
    assert "complete -F _ovn_completions ovn" in body
    assert "complete -F _ovn_completions ovnode" in body
    for cmd in ("status", "credentials", "update", "restore", "doctor", "uninstall"):
        assert cmd in body, f"completion misses {cmd}"
    for flag in ("--yes", "--help"):
        assert flag in body, f"completion misses {flag}"
    assert f"source {target}/ovn" in r.stderr


def test_completion_reports_an_unwritable_target(tmp_path):
    """A write command that cannot write must say so, naming the fix."""
    env, app = sandbox(tmp_path)
    env = {**env, "OVN_COMPLETION_DIR": str(tmp_path / "missing" / "nested" / "blocked")}
    (tmp_path / "missing").write_text("not a directory", encoding="utf-8")
    r = mgr_sb(env, app, "completion")
    assert r.returncode == 1, r.stderr
    assert "run as root" in r.stderr


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
        for path in (MANAGER_PATH, *(LIB_DIR / lib for lib in LIBS))
        for name, tail, line in tails(path)
        if re.match(r"^\[\[.*\]\]\s*&&", tail)
    ]
    assert not offenders, offenders


def test_doctor_checks_agent_vpn_disk_api_cert_backups():
    """doctor covers the node-critical checks, each with its fix hint.

    Read from scripts/lib/doctor.sh, where the checks now live, not manager.sh.
    The split was deliberate: the report is a self-contained unit and the file
    was the one thing in this tool that kept growing past the point where a
    reader could hold it.
    """
    with open(LIB_DIR / "doctor.sh", encoding="utf-8") as f:
        content = f.read()
    assert "do_doctor()" in content
    for token in ("Certificate", "Backup", "Disk", "Agent", "OpenVPN", "API", "PKI"):
        assert token in content, f"doctor missing {token}"
    for fix in ("ovn restart", "ovn backup", "ovn tls", "ovn logs"):
        assert fix in content, f"doctor missing fix hint {fix}"
    assert '"$FIX" -eq 1' in content


def test_rollback_restores_newest_snapshot():
    """do_rollback restores the newest code snapshot and re-verifies health."""
    with open(MANAGER, encoding="utf-8") as f:
        content = f.read()
    assert "do_rollback()" in content
    assert "latest_snapshot node" in content
    assert "Rolled back and healthy" in content


def test_doctor_and_rollback_dispatch_past_parse(tmp_path):
    """Regression: every main-branch verb must exist in parse_args too
    (doctor/rollback once died as 'Unknown option' in parse)."""
    env = {**os.environ, "OVN_APP_DIR": str(tmp_path / "missing")}
    for cmd in ("doctor", "rollback"):
        r = mgr(cmd, env=env)
        assert "Unknown option" not in r.stderr, cmd
        assert "Not installed" in r.stderr, (cmd, r.stderr)


def test_recover_update_delegates_to_installer():
    """ovn recover-update must reach install.sh (interrupted tx recovery)."""
    import re

    content = MANAGER_PATH.read_text(encoding="utf-8")
    assert "recover-update" in content
    assert "run_installer recover-update" in content
    assert re.search(r"recover-update\) ACTION=", content)


def test_doctor_covers_update_snapshot_pki():
    """doctor must see interrupted transactions, snapshot validity and
    VPN PKI expiry — not just agent/disk/API."""
    content = (LIB_DIR / "doctor.sh").read_text(encoding="utf-8")
    tokens = (
        # `ovn update`, not the retired `ovn recover-update`: a fix hint naming
        # a name that is no longer in the help is a dead end for whoever follows
        # it, and `ovn update` recovers an interrupted one before starting.
        "ovn update",
        "latest_snapshot node",
        "PKI",
        ".operation.lock",
        "repair-unit",
    )
    for token in tokens:
        assert token in content, f"doctor missing: {token}"


def test_rollback_refuses_during_interrupted_update():
    """Rollback must not fight an interrupted transaction."""
    content = MANAGER_PATH.read_text(encoding="utf-8")
    assert "update-maintenance" in content.split("do_rollback()")[1].split("# ──")[0]


def test_status_is_concise_and_all_is_opt_in():
    """status answers 'is it up?'; node/mode/port/TLS need --all."""
    with open(MANAGER, encoding="utf-8") as f:
        content = f.read()
    src = content.split("do_status()")[1].split("\n}")[0]
    assert '[[ "$SHOW_ALL" -eq 1 ]]' in src
    assert "-a|--all" in content
    rows = ('render_kv "Agent"', 'render_kv "Health"', 'render_kv "Version"', 'render_kv "OpenVPN"')
    for row in rows:
        assert row in src, row
    # The rows a task-ordered success card offloads: operator paths live behind
    # --all, not on the card. Both must sit inside the SHOW_ALL block.
    after_guard = src.split('"$SHOW_ALL" -eq 1')[1]
    assert 'render_kv "Data"' in after_guard and 'render_kv "OpenVPN cfg"' in after_guard, (
        "the offloaded rows must live inside the SHOW_ALL block"
    )


def test_there_is_no_menu_to_clear_between_screens():
    """The menu is gone, so there is nothing to clear.

    It was a second hand-maintained list of the tool's own commands: ten
    entries against thirteen verbs, with one arm still calling a deleted
    function. Bare `ovn` prints the list and exits, exactly like `ovm`.
    """
    with open(MANAGER, encoding="utf-8") as f:
        content = f.read()
    assert "manager_menu" not in content
    assert "backup_submenu" not in content
    r = mgr()
    assert r.returncode == 0 and "USAGE" in r.stderr


def test_credentials_reports_not_installed_without_needing_root(tmp_path):
    """A missing install is worth reporting to anyone, so that check runs before
    the root gate — otherwise a non-root user is told "must run as root" about a
    box that has nothing on it, and this test could not run unprivileged."""
    env, app = sandbox(tmp_path)
    r = mgr_sb(env, app, "credentials")
    assert r.returncode == 4, r.stderr
    assert "not installed" in r.stderr


@pytest.mark.skipif(os.geteuid() != 0, reason="the key lives in a root-only .env")
def test_credentials_prints_the_registration_values(tmp_path):
    env, app = sandbox(tmp_path)
    (app / ".env").write_text(
        "NODE_NAME=eu-1\nSERVICE_PORT=2083\nTLS_METHOD=selfsigned\n"
        "API_KEY=0123456789abcdef0123456789abcdef\n",
        encoding="utf-8",
    )
    r = mgr_sb(env, app, "credentials")
    assert r.returncode == 0, r.stderr
    # field() writes to stderr, like every other ovn command.
    assert "eu-1" in r.stderr
    assert "0123456789abcdef0123456789abcdef" in r.stderr
    assert "ovnode://eu-1@" in r.stderr
    assert "tls=1" in r.stderr


def test_the_ready_card_note_reads_the_generation_flag():
    """The card says "(generated — save this)" only when that is true, so a new
    site that mints the key directly would make the card lie."""
    content = INSTALLER.read_text(encoding="utf-8")
    helper = content.split("generate_api_key() {")[1].split("\n}")[0]
    assert "KEY_GENERATED=1" in helper
    # The assignment form only: the same words appear in the "at least 16
    # characters" error text, which is not a mint site.
    assert 'API_KEY="$(openssl rand' not in content.replace(helper, ""), (
        "the key is minted outside generate_api_key, so KEY_GENERATED never gets set"
    )


def test_the_generated_note_is_conditional_on_that_flag():
    """A supplied key is not news; a generated one is the only copy there is."""
    source = INSTALLER.read_text(encoding="utf-8")
    card = source.split("node_success_card()")[1].split("\n# ── ")[0]
    assert 'if [[ "${KEY_GENERATED:-0}" -eq 1 ]]' in card
    assert "generated — save this" in card
    assert "the key you supplied" in card


def test_the_api_key_is_printed_whatever_the_output_mode():
    """-q no longer suppresses the card, and must not suppress the key.

    The old -q path printed the card's shape without the key and added a line
    naming `ovn credentials`. That is a credential nobody ever saw, on a run
    that was explicit about being unattended: the key exists nowhere else. One
    renderer, one output, and the key is in it.
    """
    source = INSTALLER.read_text(encoding="utf-8")
    # Everything up to the next top-level definition, not to the update section:
    # the card is one function and must be read as one.
    card = source.split("node_success_card()")[1].split("\n# ── ")[0]
    assert "QUIET" not in card, "the card must not depend on the output mode"
    assert 'render_card "ready" "api key"' in card
    # And the reprint path is named, since the key is the only credential and a
    # lost one has to be recoverable without a reinstall.
    assert "%s credentials" in card, card


@pytest.mark.skipif(
    os.geteuid() == 0,
    reason="root can read a mode-0000 file, so the unreadable case cannot be reproduced",
)
def test_readonly_commands_refuse_an_unreadable_env(tmp_path):
    """A read-only command that cannot read .env must say so. Falling back to
    defaults made a healthy node report itself broken and exit 0 — worse than an
    error, because it invites someone to repair a working box."""
    env, app = sandbox(tmp_path)
    envfile = app / ".env"
    envfile.write_text(
        "NODE_NAME=eu-1\nSERVICE_PORT=2083\nTLS_METHOD=selfsigned\nAPI_KEY=x\n",
        encoding="utf-8",
    )
    envfile.chmod(0o000)
    for command in ("status", "doctor"):
        r = mgr_sb(env, app, command)
        assert r.returncode != 0, f"{command} guessed instead of reporting: {r.stderr}"
        assert "Cannot read" in r.stderr, (command, r.stderr)


# ── restore ─────────────────────────────────────────────────────────────
# `restore` is the one command that writes over the node's state, so its
# sandbox sends every path it touches to tmp_path — the backup root as well
# as the data and PKI roots — and stubs systemctl/curl, because a restore
# stops and starts services and then asks for /sync/health. Nothing in these
# tests reaches the host's /var/backups, /var/lib/ovnode or /etc/openvpn.

HOST_BACKUP_ROOT = "/var/backups"


def restore_sandbox(tmp_path):
    """(env, app, backups, data, ovpn) with every path a restore writes."""
    backups = tmp_path / "var-backups"
    # Named like the real roots on purpose: backup_dir archives a directory
    # under its own basename, so the layout inside the tarball — and therefore
    # what the tests can assert — is production's.
    data = tmp_path / "var-lib" / "ovnode"
    ovpn = tmp_path / "etc-openvpn"
    for path in (backups, data, ovpn):
        path.mkdir(parents=True)
    env, app = sandbox(tmp_path)
    copies = (
        (
            app / "manager.sh",
            (
                ('DATA_BASE="/var/lib/ovnode"', f'DATA_BASE="{data}"'),
                ('OPENVPN_ROOT="/etc/openvpn"', f'OPENVPN_ROOT="{ovpn}"'),
            ),
        ),
        # backup_dir — the helper that takes the safety copy — resolves the
        # backup root itself, so the lib needs the same redirection or the
        # test would write to the host's /var/backups.
        *((app / "scripts" / "lib" / lib, ()) for lib in LIBS),
    )
    for path, replacements in copies:
        text = path.read_text(encoding="utf-8")
        for old, new in replacements:
            assert text.count(old) == 1, f"{path.name}: {old} not found exactly once"
            text = text.replace(old, new)
        path.write_text(text.replace(HOST_BACKUP_ROOT, str(backups)), encoding="utf-8")

    # check_root lives in the lib; neutered so the suite also runs unprivileged
    # (CI), and so these tests are about the restore and not about privilege.
    lib = app / "scripts" / "lib" / "common.sh"
    text = lib.read_text(encoding="utf-8")
    needle = 'check_root() { [[ "$EUID" -eq 0 ]] || die "Must run as root."; }'
    assert needle in text, "check_root moved: restore_sandbox no longer neuters the root gate"
    lib.write_text(
        text.replace(needle, "check_root() { :; }  # neutered by the test suite"), encoding="utf-8"
    )

    for path in (app / "manager.sh", lib):
        assert HOST_BACKUP_ROOT not in path.read_text(encoding="utf-8"), (
            f"{path.name} still writes to the host"
        )
    return env, app, backups, data, ovpn


def stub_service_tools(tmp_path):
    """systemctl/curl stand-ins for a sandbox restore (no init, no network)."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    marker = tmp_path / "systemctl.log"
    (bin_dir / "systemctl").write_text(
        "#!/bin/sh\n"
        'echo "SYSTEMCTL $*" >> "$SYSTEMCTL_LOG"\n'
        'case "${1:-}" in show) echo loaded ;; esac\n'
        "exit 0\n",
        encoding="utf-8",
    )
    (bin_dir / "curl").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    for name in ("systemctl", "curl"):
        (bin_dir / name).chmod(0o755)
    return bin_dir, marker


def write_tar(path, member, payload: bytes):
    """A real gzip'd tar: restore inspects the archive before it acts."""
    with tarfile.open(path, "w:gz") as archive:
        info = tarfile.TarInfo(member)
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))


def test_restore_without_a_name_lists_the_backups(tmp_path):
    """A bare `ovn restore` is the listing — a read, never an action."""
    env, app, backups, data, ovpn = restore_sandbox(tmp_path)
    older = backups / "node-ovnode-20260101-000000.tar.gz"
    newer = backups / "node-ovnode-20260102-000000.tar.gz"
    for path in (older, newer):
        write_tar(path, "ovnode/state.json", b"x" * 4096)

    r = mgr_sb(env, app, "restore")
    assert r.returncode == 0, r.stderr
    for name in (older.name, newer.name):
        assert name in r.stderr, (name, r.stderr)
    assert re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}", r.stderr), r.stderr  # a date
    assert re.search(r"\d+(\.\d+)?[KMGT]?B?", r.stderr), r.stderr  # a size
    # Lowercase, like the panel's hint rows: it is an instruction, not a heading.
    assert "restore one with: ovn restore <name>" in r.stderr

    # Listing changes nothing anywhere: no safety copy, no data, no PKI.
    assert sorted(path.name for path in backups.iterdir()) == sorted([older.name, newer.name])
    assert list(data.iterdir()) == []
    assert list(ovpn.iterdir()) == []


def test_restore_refuses_without_confirmation(tmp_path):
    """No terminal and no -y is a NO: nothing is replaced, nothing is copied."""
    env, app, backups, data, ovpn = restore_sandbox(tmp_path)
    (data / "ovnode").mkdir()
    (data / "ovnode" / "state.json").write_text("current", encoding="utf-8")
    name = "node-ovnode-20260101-000000.tar.gz"
    # The layout a real `ovn backup` writes: data base under its own basename,
    # the node's data directory inside it.
    write_tar(backups / name, "ovnode/ovnode/state.json", b"restored")

    r = mgr_sb(env, app, "restore", name)
    assert r.returncode != 0
    assert "Cancelled" in r.stderr
    assert (data / "ovnode" / "state.json").read_text(encoding="utf-8") == "current"
    assert [path.name for path in backups.iterdir()] == [name], (
        "a refused restore must not take a safety copy"
    )


def test_restore_takes_a_safety_copy_before_replacing_the_state(tmp_path):
    """The state as it is now is backed up first, so the restore can be undone."""
    env, app, backups, data, ovpn = restore_sandbox(tmp_path)
    (data / "ovnode").mkdir()
    (data / "ovnode" / "state.json").write_text("current", encoding="utf-8")
    pki = ovpn / "server" / "pki"
    pki.mkdir(parents=True)
    (pki / "ca.crt").write_text("current-ca", encoding="utf-8")
    name = "node-ovnode-20260101-000000.tar.gz"
    write_tar(backups / name, "ovnode/ovnode/state.json", b"restored")
    bin_dir, marker = stub_service_tools(tmp_path)
    env = {**env, "PATH": f"{bin_dir}:{env['PATH']}", "SYSTEMCTL_LOG": str(marker)}

    r = mgr_sb(env, app, "restore", name, "-y")
    assert r.returncode == 0, (r.stdout, r.stderr)

    # Both halves of what `ovn backup` saves were copied, and the copies hold
    # the state as it was BEFORE the restore.
    state_copy = [path for path in backups.iterdir() if path.name.startswith("node-pre-restore-")]
    assert len(state_copy) == 1, [path.name for path in backups.iterdir()]
    with tarfile.open(state_copy[0]) as archive:
        assert archive.extractfile("ovnode/ovnode/state.json").read() == b"current"
    pki_copy = [path for path in backups.iterdir() if path.name.startswith("node-pki-pre-restore-")]
    assert len(pki_copy) == 1, [path.name for path in backups.iterdir()]
    with tarfile.open(pki_copy[0]) as archive:
        assert archive.extractfile("pki/ca.crt").read() == b"current-ca"
    assert "node-pre-restore-" in r.stderr, "the safety copies must be reported"

    # ... and the named backup is what is live now.
    assert (data / "ovnode" / "state.json").read_text(encoding="utf-8") == "restored"
    assert (pki / "ca.crt").read_text(encoding="utf-8") == "current-ca"
    assert "Restore finished and the node is healthy" in r.stderr
    calls = marker.read_text(encoding="utf-8")
    assert "SYSTEMCTL stop ovnode.service" in calls, calls
    assert "SYSTEMCTL restart ovnode.service" in calls, calls
