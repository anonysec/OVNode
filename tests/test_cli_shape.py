"""`ovn` and `ovm` are the same tool with different nouns.

The node's help was twenty-one commands, one per line, plus a paragraph about
the installer's own version. The panel's was twenty-seven. Neither fitted a
screen, so both were skipped rather than read.

What is pinned here is the shape, not the wording: eleven verbs on one screen,
the rest behind `help --all`, a bare grouped command that lists its own options,
and a `.env` the software never edits. If the two drift, the drift is visible in
a diff rather than in a support ticket.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
MANAGER = REPO / "manager.sh"
COMMON = REPO / "scripts" / "lib" / "common.sh"
PANEL_HELP_RE = re.compile(r"ovm (\w[\w-]*)")

# The verbs on the node's short list. Order is the reading order: what is it,
# what is wrong with it, what do I change, what do I throw away.
SHORT_LIST = (
    "status",
    "logs",
    "doctor",
    "restart",
    "restart core",
    "enable | disable",
    "auth",
    "tls",
    "backup",
    "restore",
    "update",
    "rollback",
    "uninstall",
)


def _short_help() -> str:
    return _run("help")


def _full_help() -> str:
    return _run("help", "--all")


def _run(*args: str, check: bool = True) -> str:
    out = subprocess.run(
        ["bash", str(MANAGER), *args],
        capture_output=True,
        text=True,
        timeout=60,
        env={**os.environ, "OVN_APP_DIR": "/nonexistent", "CI": "1"},
    )
    if check:
        assert out.returncode == 0, out.stderr
    return out.stdout + out.stderr


LIB = REPO / "scripts" / "lib" / "doctor.sh"


def _body(name: str, path: Path = MANAGER) -> str:
    text = path.read_text(encoding="utf-8")
    match = re.search(rf"^{re.escape(name)}\(\) \{{(.*?)^\}}", text, re.M | re.DOTALL)
    assert match, f"{name}() not found in {path.name}"
    return match.group(1)


# ── Every verb actually dispatches ──────────────────────────────────────

# The regression this file exists for. Three commands shipped in f77cf87 that
# never worked, and every test passed, because the tests read the source rather
# than running the command. `ovn backup schedule` was in both help screens and
# answered "Unknown option" — two `backup)` arms, the first winning, the second
# dead code. This list is the version that actually runs.
ALL_VERBS = (
    "status",
    "logs",
    "doctor",
    "restart",
    "restart core",
    "enable",
    "disable",
    "auth",
    "auth key",
    "auth rotate",
    "tls",
    "tls selfsigned",
    "tls le 10.0.0.1",
    "backup",
    "backup schedule",
    "restore",
    "update",
    "rollback",
    "uninstall",
    "config",
    "help",
    "completion",
)

# Old name → what replaced it. Silent, not warned: a deprecation line on every
# cron job that calls `ovn auto-backup` is noise, not notice.
RETIRED_VERBS = (
    "credentials",
    "restart-vpn",
    "auto-backup status",
    "recover-update",
    "start",
    "stop",
)


def _no_dispatch_failure(command: str) -> None:
    combined = _run(*command.split(), check=False)
    # "Not installed" is correct on a box with no install — the command found
    # itself and had nothing to work on. What must never appear is the parser
    # failing to recognise a command the help advertises.
    assert "Unknown option" not in combined, f"ovn {command} does not dispatch:\n{combined}"
    assert "command not found" not in combined, (
        f"ovn {command} calls something that no longer exists:\n{combined}"
    )


def test_every_advertised_verb_dispatches():
    for command in ALL_VERBS:
        _no_dispatch_failure(command)


def test_every_retired_verb_still_dispatches():
    for command in RETIRED_VERBS:
        _no_dispatch_failure(command)


def test_there_is_no_menu():
    """The menu was a second hand-maintained list of this tool's own commands.

    It had ten items against thirteen verbs, and one arm still called a function
    that had been deleted — a runtime failure that no test caught, because every
    test asserted on the function that existed rather than the arm that did not.
    """
    source = MANAGER.read_text(encoding="utf-8")
    assert "manager_menu" not in source
    assert "backup_submenu" not in source
    assert "is_tty" not in _body("main"), "bare ovn must not branch on a terminal"


def test_bare_ovn_prints_the_list_and_exits_zero():
    """Same as `ovm`, with or without a terminal.

    A bare invocation in a script that opens a menu and waits is how a
    provisioning run hangs at two in the morning.
    """
    import subprocess

    out = subprocess.run(
        ["bash", str(MANAGER)],
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, "OVN_APP_DIR": "/nonexistent", "CI": "1"},
    )
    assert out.returncode == 0, out.stderr
    assert "USAGE" in out.stdout + out.stderr


def test_no_dispatch_arm_is_defined_twice():
    """The one mechanism behind all three shipped defects.

    Bash takes the first matching arm and silently ignores the rest, so a
    duplicated arm is not an error — it is a command that quietly does the old
    thing. `backup` shipped that way, and so did `credentials`.
    """
    source = MANAGER.read_text(encoding="utf-8")
    body = source[source.index("parse_args() {") : source.index("\n# ── Main")]
    arms = re.findall(r"^\s{12}([-\w|]+)\)", body, re.M)
    seen, dupes = set(), set()
    for arm in arms:
        (dupes if arm in seen else seen).add(arm)
    assert not dupes, f"duplicate dispatch arms: {sorted(dupes)}"


# ── doctor: failures first ──────────────────────────────────────────────


def test_a_clean_doctor_is_one_line_and_a_hint():
    """Thirteen passing checks used to spend sixteen lines saying "ok".

    That is the screen nobody reads, because everything looked equally urgent
    and so nothing did.
    """
    source = LIB.read_text(encoding="utf-8")
    assert "no problems — ${passed} checks passed" in source
    assert "other checks passed — detail: ovn doctor --all" in source


def test_doctor_collects_before_it_prints():
    """Nothing is printed until every check has run.

    Two things fall out of that. Failures can be listed first, and a check that
    dies mid-way no longer leaves a half-printed report that reads like a
    result.
    """
    body = _body("do_doctor", LIB)
    first_render = min(
        (body.find(tok) for tok in ("render_rule", "doctor_render") if tok in body), default=-1
    )
    checks = body.count("doctor_check ")
    assert checks >= 10, f"only {checks} checks registered"
    assert first_render > 0, "doctor_render must be called"
    # doctor_render is the only thing that prints the report; the check calls
    # come first and are silent.
    assert body.rindex("doctor_check ") < first_render, "a check is registered after the report"


def test_doctor_fix_rechecks_rather_than_assuming():
    """A repair is not a repair until the check agrees.

    The old code decremented a counter and kept the failing row, so `doctor
    --fix` reported a problem it had just fixed and a fix that had not worked as
    if it had.
    """
    body = _body("doctor_check", LIB)
    assert body.count('"$check_fn"') >= 3, "the check must run again after a repair"
    assert "— fixed" in body, "a successful repair is marked as one"


def test_doctor_exits_non_zero_on_problems():
    """So a monitoring check can use it.

    It was always zero, which meant a script could not tell a healthy box from a
    broken one without parsing the prose.
    """
    body = _body("do_doctor", LIB)
    assert "doctor_render || rc=1" in body
    with open(MANAGER, encoding="utf-8") as f:
        assert 'doctor) do_doctor || rc=$?; exit "$rc" ;;' in f.read()


def test_doctor_survives_the_err_trap():
    """manager.sh runs under an ERR trap that any failing command trips.

    The checks run in command substitutions, which inherit the trap — so a check
    whose verdict is a failing test used to kill its own subshell before the
    detail was flushed, and the report came out with empty rows.
    """
    body = _body("doctor_check", LIB)
    assert "trap - ERR" in body, "checks must not run under the caller's ERR trap"


# ── Rows go through the renderer ─────────────────────────────────────────


def test_no_hand_built_rows_remain():
    """The bug class, pinned.

    A row built by hand drifts in indent, in width, and in how a failure is
    spelled. Five of them did: a 44-wide 2-space printf in the backup listing,
    and four `Label: value` lines that were not `render_kv` at all.
    """
    source = MANAGER.read_text(encoding="utf-8")
    # `printf '  %-…'` is a hand-built row. For render_line, the shape that
    # matters is a short `Label: value` pair — a sentence containing a colon is
    # prose, and the two are distinguished by there being no verb in the label.
    offenders = [
        line.strip()
        for line in source.splitlines()
        if line.lstrip().startswith("printf '  ") and "%-" in line
    ]
    for line in source.splitlines():
        m = re.match(r'^\s*render_line "([A-Z][A-Za-z ]*):\s', line)
        if m and " " not in m.group(1).strip():
            offenders.append(line.strip())
    assert not offenders, f"hand-built rows: {offenders}"


def test_the_backup_listing_uses_a_measured_column():
    """At the shared fixed width of 14, a 40-character filename printed whole
    and dropped its date a column right of every other row's."""
    body = _body("list_data_backups")
    assert "render_kv_w" in body
    assert "width=$RENDER_LABEL_W" in body and "width=${#name}" in body


def test_render_kv_w_exists_in_the_shared_renderer():
    """Both repos must carry it, or one of them has a column the other cannot
    express."""
    render_sh = REPO / "scripts" / "lib" / "render.sh"
    assert "render_kv_w()" in render_sh.read_text(encoding="utf-8")


# ── No retired name in text a user reads ────────────────────────────────


def test_no_fix_hint_names_a_retired_command():
    """`ovn recover-update` was a fix hint after it left the help.

    Anyone who follows it gets the right behaviour by accident, via the alias,
    but they were told to use a name the tool does not advertise.
    """
    stale = ((LIB, "recover-update"), (LIB, "auto-backup on"), (MANAGER, "auto-backup on"))
    for path, needle in stale:
        source = path.read_text(encoding="utf-8")
        for line in source.splitlines():
            if needle in line and not line.lstrip().startswith("#"):
                assert "die(" not in line or needle not in line, f"stale usage: {line.strip()}"


def test_the_schedule_hint_uses_the_current_spelling():
    body = _body("auto_backup_cli")
    assert "backup schedule on" in body
    # Comments are allowed to name the old spelling — that is how the change is
    # explained. What must not survive is a command the user would run.
    commands = [ln for ln in body.splitlines() if not ln.lstrip().startswith("#")]
    assert not any("auto-backup on" in ln for ln in commands)


# ── The short list ──────────────────────────────────────────────────────


def test_the_short_help_is_one_screen():
    """Twenty-one commands was the problem. The whole point is that this fits."""
    lines = _short_help().splitlines()
    assert len(lines) < 30, f"short help is {len(lines)} lines"


def test_the_short_help_carries_every_verb():
    text = _short_help()
    for verb in SHORT_LIST:
        assert f"ovn {verb}" in text, f"short help missing ovn {verb}"


def test_the_short_help_does_not_carry_the_flag_list():
    """Inline hints are fine — `--keep N` on the backup line is one of them.

    What must not be here is a separate section enumerating them: a screen that
    lists both the verbs and the options lists neither. The full reference is
    one flag away, and it is where the enumeration lives.
    """
    text = _short_help()
    for section in ("OPTIONS", "ENVIRONMENT", "RETIRED NAMES", "FLAGS"):
        assert section not in text, f"short help carries a {section} section"
    for token in ("OVN_YES", "OVN_PURGE", "-q, --quiet"):
        assert token not in text, f"short help carries {token}"


def test_the_short_help_points_at_the_full_one():
    assert "ovn help --all" in _short_help()


# ── The full reference ──────────────────────────────────────────────────


def test_the_full_reference_carries_what_the_short_one_drops():
    text = _full_help()
    for token in (
        "auto-backup",
        "recover-update",
        "--keep",
        "--purge",
        "RETIRED NAMES",
        ".env",
    ):
        assert token in text, f"help --all missing {token}"


def test_every_retired_name_says_what_replaced_it():
    """A retired name with no successor is just a removal with extra steps."""
    text = _full_help()
    retired = text.split("RETIRED NAMES")[1]
    for line in retired.splitlines():
        if line.strip().startswith("ovn "):
            assert "→" in line, f"no successor named: {line.strip()}"


def test_the_short_help_is_not_the_full_one():
    """If the two were the same, one of them should not exist."""
    assert _short_help() != _full_help()


# ── Grouped commands ────────────────────────────────────────────────────


def test_a_bare_group_command_lists_its_own_options():
    """`ovn tls` with no subcommand tells you what `ovn tls` can do.

    The same rule as the panel's tls/auth/url, and the reason it replaced the
    numbered menu: the menu needed a terminal, and a script that needs a
    certificate is a script that was going to hang.
    """
    body = _body("node_tls")
    assert "ovn tls selfsigned" in body
    assert "ovn tls le IP|DOMAIN" in body
    assert "ovn tls custom CERT KEY" in body


def test_a_bare_tls_reports_before_it_offers():
    """State first, then options — the same order the panel's auth uses."""
    body = _body("node_tls")
    assert body.index("Key file") < body.index("ovn tls selfsigned")
    assert body.index("Cert file") < body.index("ovn tls selfsigned")


def test_tls_has_no_interactive_prompt_left():
    """No `ask`, no menu, no waiting.

    The one thing a certificate command must never do is block on a prompt in
    the middle of a provisioning run.
    """
    assert "ask " not in _body("node_tls")
    assert "Select" not in _body("node_tls")


def test_a_domain_or_an_ip_is_one_field():
    """One free-text value decides the kind, rather than asking the operator.

    They do not know or care which ACME flow their address is eligible for, and
    making them choose turns a working command into a question.
    """
    body = _body("node_tls")
    assert "is_ip_literal" in body
    assert "letsencrypt-ip" in body and "letsencrypt" in body


def test_an_unknown_tls_option_says_what_is_valid():
    body = _body("node_tls")
    assert "see: ovn tls" in body, "a typo must point at the list, not the help"


# ── `.env` is not written ───────────────────────────────────────────────


def test_env_set_is_gone():
    """The single writer of `.env` has been deleted, not deprecated.

    Left in place it is one call away from being used again, and its whole
    purpose was to make a file the operator owns into one the software also
    owns. The node has no reason for a second writer that the panel does not
    also have.
    """
    assert not re.search(r"^env_set\(\)", COMMON.read_text(encoding="utf-8"), re.M)
    # Match the call, not the word: the comments explaining the deletion name
    # it deliberately, and a substring check would forbid documenting it.
    for path in (MANAGER, REPO / "install.sh"):
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"^[^#]*\benv_set\s+\"", text, re.M), (
            f"{path.name} still calls env_set"
        )


def test_tls_installs_to_the_declared_paths():
    """The certificate goes where `.env` says, or nowhere new.

    Recording the path instead is what produced two locations and a node
    serving a certificate the operator could not see.
    """
    body = _body("node_tls_install_to_declared")
    assert "SSL_KEYFILE" in body and "SSL_CERTFILE" in body
    assert "env_set" not in body


# ── The credential ──────────────────────────────────────────────────────


def test_the_api_key_is_shown_as_a_credential():
    """It is the one value on this screen that gets copied out of it.

    Printed at the same weight as every other row it was read past — and it is
    not recoverable from the panel.
    """
    body = _body("do_auth")
    assert 'render_key "API key"' in body
    assert 'render_url "Bundle"' in body


def test_the_api_key_is_never_printed_where_it_does_not_belong():
    """`ovn config` reports it as set and says where to see it.

    A value that appears in two commands is a value that ends up in a
    screenshot, and this one grants access to the node's API.
    """
    body = _body("do_config")
    assert "see: ovn credentials" in body
    # The control flow, not a string: API_KEY has to be matched before the
    # branch that prints every other value, or the guarantee is only a comment.
    api_key_arm = body.index("API_KEY)")
    fallback = body.index("*)")
    assert api_key_arm < fallback, "the API_KEY arm must come before the print-everything branch"


def test_config_says_env_is_not_edited():
    body = _body("do_config")
    assert "never by this tool" in body


# ── update absorbs recover-update ───────────────────────────────────────


def test_update_finishes_an_interrupted_one_first():
    """`update` is what an operator reaches for when something looks wrong.

    So it is the command that should fix the thing — which is what lets
    `recover-update` leave the short list while the same code runs underneath.
    """
    body = _body("delegate_update")
    assert "recover-update" in body
    assert "update-state.json" in body


def test_a_failed_recovery_stops_the_update():
    """Carrying on after a failed recovery would update on top of a broken tree."""
    body = _body("delegate_update")
    assert "nothing was changed" in body


def test_recovery_detection_needs_no_python():
    """It runs on the failure path, where the least can be assumed.

    A missing python3 is exactly the kind of state that leaves an install stuck,
    and a recovery check that needs it would never run in the case it exists for.
    """
    body = _body("node_update_needs_recovery")
    assert "python" not in body
    assert "grep" in body


# ── enable / disable ────────────────────────────────────────────────────


def test_autostart_is_systemd_only_and_says_so():
    """A compose container starts with docker; there is nothing to enable.

    Pretending otherwise leaves the operator believing the node comes back after
    a reboot when it does not.
    """
    body = _body("node_autostart")
    assert "is_docker_node" in body
    assert "nothing to enable" in body.lower()


# ── The docs must teach the commands that exist ──────────────────────────

# The README documented `ovn credentials`, `ovn restart-vpn` and
# `ovn auto-backup` as current while the short help listed neither.

README = REPO / "README.md"


def _prose_only(text: str) -> str:
    if "### Retired names" in text:
        return text.split("### Retired names")[0] + text.split("### `.env` is yours")[-1]
    return text


def test_the_readme_does_not_teach_retired_commands():
    prose = _prose_only(README.read_text(encoding="utf-8"))
    for name in ("ovn credentials", "ovn restart-vpn", "ovn auto-backup", "ovn recover-update"):
        assert name not in prose, f"README still teaches `{name}`"


def test_the_readme_documents_the_grouped_commands():
    text = README.read_text(encoding="utf-8")
    for name in ("ovn auth", "ovn auth key", "ovn auth rotate", "ovn restart core"):
        assert name in text, f"README never mentions `{name}`"


def test_the_readme_states_the_env_rule():
    # Whitespace-normalised: the sentence is wrapped, and a line break in the
    # middle of it must not decide whether the rule is documented.
    text = " ".join(README.read_text(encoding="utf-8").split())
    assert "ever edits it again" in text
    assert "ovn config" in text
    # And the reason a rotate prints instead of writing.
    assert "prints the new key" in text


def test_the_readme_does_not_claim_there_is_a_menu():
    """Bare `ovn` prints a list and exits. A README that says otherwise sends
    people looking for a menu that stopped existing."""
    text = README.read_text(encoding="utf-8")
    assert "numbered menu" not in text
