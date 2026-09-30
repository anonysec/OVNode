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

import re
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
    "enable | disable",
    "restart-vpn",
    "credentials",
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


def _run(*args: str) -> str:
    import subprocess

    out = subprocess.run(
        ["bash", str(MANAGER), *args], capture_output=True, text=True, timeout=30
    )
    assert out.returncode == 0, out.stderr
    return out.stdout + out.stderr


def _body(name: str, path: Path = MANAGER) -> str:
    text = path.read_text(encoding="utf-8")
    match = re.search(rf"^{re.escape(name)}\(\) \{{(.*?)^\}}", text, re.M | re.DOTALL)
    assert match, f"{name}() not found in {path.name}"
    return match.group(1)


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
    for path in (MANAGER, REPO / "install.sh"):
        text = path.read_text(encoding="utf-8")
        assert "env_set" not in text, f"{path.name} still calls env_set"


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
    body = _body("do_credentials")
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
    fallback = body.index('*)')
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
