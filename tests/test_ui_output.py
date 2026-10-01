"""render.sh is the only thing that decides what the installers look like.

These are golden transcripts: exact bytes for a terminal, and exact bytes for a
pipe. They exist because the output is generated — the fade repaints, the
spinner rewrites its own row, the cursor arithmetic is mine and nobody reading
the diff can check it by eye. A regression here is a mangled terminal, not a
wrong character, so the assertions are about the whole rendered stream rather
than a substring.

Two rules are pinned as behaviour rather than style:

  1. A piped run produces the same TEXT as a terminal run. The animation, the
     fade and the cursor moves are motion and colour only. If that ever stops
     being true, a CI log describes a different run than a watched one.
  2. Colour never carries meaning alone. Every coloured thing also has a glyph
     or a word, so NO_COLOR=1 and LANG=C lose nothing.
"""

import os
import pty
import re
import subprocess
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
LIB = REPO / "scripts" / "lib"
PANEL = REPO.parent / "OVManager"

# Braille, box drawing and block characters all live above U+00FF; a terminal
# or locale that cannot show them gets the ASCII set instead.
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def _probe(script: str, *, promptable: bool) -> str:
    """A bash file with the libs sourced and one snippet appended."""
    return (
        "set -Eeuo pipefail\n"
        f'. "{LIB / "common.sh"}"\n'
        f'. "{LIB / "render.sh"}"\n'
        f"can_prompt() {{ return {0 if promptable else 1}; }}\n"
        f"{script}\n"
    )


def run(script: str, *, tty: bool, **env: str) -> str:
    """Run a snippet WITHOUT a terminal and return raw stderr.

    This is the pipe path: no -t 2, so no colour and no animation. Pass
    tty=False for it — the flag is kept only so the intent reads at the call
    site, because a test that thinks it has a terminal but does not is exactly
    how the fade tests came to assert nothing.
    """
    assert not tty, "use run_pty for anything that needs a real terminal"
    full = _probe(script, promptable=False)
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "probe.sh"
        path.write_text(full, encoding="utf-8")
        r = subprocess.run(
            ["bash", str(path)],
            capture_output=True,
            text=True,
            timeout=60,
            env={**os.environ, **env},
            stdin=subprocess.DEVNULL,
        )
    assert r.returncode == 0, r.stderr
    return r.stderr


def run_pty(script: str, *, stdin_pipe: bool = False, **env: str) -> str:
    """Run a snippet WITH a terminal on stderr, and return what it drew.

    A pty is the only way to get -t 2 true, and -t 2 is what gates colour,
    animation and the whole repaint path. Without this the fade, the spinner
    and the cursor accounting are untested code that only runs on a developer's
    terminal.

    stdin_pipe=True models `curl … | bash`: stdin is a pipe, stderr is still the
    operator's terminal.
    """
    full = _probe(script, promptable=True)
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "probe.sh"
        path.write_text(full, encoding="utf-8")
        master, slave = pty.openpty()
        proc = subprocess.Popen(
            ["bash", str(path)],
            stdin=subprocess.PIPE if stdin_pipe else subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=slave,
            env={**os.environ, **env},
        )
        os.close(slave)
        chunks = []
        try:
            while True:
                try:
                    data = os.read(master, 65536)
                except OSError:
                    break
                if not data:
                    break
                chunks.append(data)
        finally:
            os.close(master)
            proc.wait(timeout=60)
        if proc.stdin and not proc.stdin.closed:
            proc.stdin.close()
    assert proc.returncode == 0, b"".join(chunks).decode("utf-8", "replace")
    return b"".join(chunks).decode("utf-8", "replace")


def strip(text: str) -> str:
    return ANSI.sub("", text)


def screen(raw: str) -> list[str]:
    """Replay a terminal stream and return the final screen contents.

    Enough of a VT: cursor-up, erase-to-end, carriage return, newline. Any
    escape it does not model is dropped, which is fine — this is about what the
    operator ends up looking at, not about the bytes on the wire.
    """
    rows: list[str] = []
    row = 0
    col = 0
    i = 0
    while i < len(raw):
        m = re.match(r"\x1b\[(\d*)A", raw[i:])
        if m:
            row = max(0, row - int(m.group(1) or 1))
            col = 0
            i += m.end()
            continue
        m = re.match(r"\x1b\[J", raw[i:])
        if m:
            del rows[row:]
            col = 0
            i += m.end()
            continue
        m = re.match(r"\x1b\[K", raw[i:])
        if m:
            while len(rows) <= row:
                rows.append("")
            rows[row] = rows[row][:col]
            i += m.end()
            continue
        m = re.match(r"\x1b\[[0-9;]*[A-Za-z]", raw[i:])
        if m:
            i += m.end()
            continue
        ch = raw[i]
        if ch == "\n":
            row += 1
            col = 0
            i += 1
            continue
        if ch == "\r":
            col = 0
            i += 1
            continue
        while len(rows) <= row:
            rows.append("")
        rows[row] = rows[row][:col].ljust(col) + ch
        col += 1
        i += 1
    return [strip(r).rstrip() for r in rows]


# ── Banner ──────────────────────────────────────────────────────────────


def test_banner_is_name_version_repo_then_a_rule():
    out = strip(run('render_banner "OVManager" "v1.0.0"', tty=False))
    assert out.splitlines() == [
        "  OVManager  v1.0.0  · anonysec",
        "  " + "─" * 46,
    ]


def test_the_rule_is_ascii_without_a_utf8_locale():
    out = strip(run('render_banner "OVNode" "v2.0.0"', tty=False, LANG="C", LC_ALL="C"))
    assert "─" not in out
    assert "-" * 46 in out


# ── Progress block ───────────────────────────────────────────────────────

STEPS = """
render_begin "preflight" 3; render_done "debian 12 · 14G free" 412
render_begin "release" 3;   render_done "38.0 MB · sha256 ok" 9100
render_begin "health" 3;    render_done "200 in 41ms" 6900
"""


def test_a_finished_run_is_three_numbered_steps():
    lines = [ln for ln in strip(run(STEPS, tty=False)).splitlines() if ln.strip()]
    assert len(lines) == 3
    assert [ln.split()[0] for ln in lines] == ["[1/3]", "[2/3]", "[3/3]"]


def test_the_glyph_says_what_the_colour_says():
    lines = [ln for ln in strip(run(STEPS, tty=False)).splitlines() if ln.strip()]
    for ln in lines:
        assert "✓" in ln


def test_no_colour_output_keeps_the_glyph_and_drops_the_escape():
    raw = run(STEPS, tty=False, NO_COLOR="1")
    assert "\x1b[" not in raw
    assert "✓" in strip(raw)


def test_ascii_output_keeps_the_meaning():
    lines = [ln for ln in strip(run(STEPS, tty=False, LC_ALL="C")).splitlines() if ln.strip()]
    for ln in lines:
        assert "ok" in ln, ln
        assert "✓" not in ln


def test_the_time_is_right_aligned_in_its_own_column():
    lines = [ln for ln in strip(run(STEPS, tty=False)).splitlines() if ln.strip()]
    ends = [ln.rstrip()[-7:].strip() for ln in lines]
    assert ends == ["0.4s", "9.1s", "6.9s"]


def test_a_long_run_reports_minutes():
    out = strip(run('render_begin "release" 1; render_done "" 125000', tty=False))
    assert "2m05s" in out


def test_the_total_grows_rather_than_overcounting():
    """A step the caller did not count must not print [4/3].

    The denominator is a floor. A counter that overruns its own total is worse
    than no counter — it reads as a bug in the installer, and it is the kind of
    bug nobody reports because they assume they miscounted.
    """
    script = (
        'render_begin "a" 2; render_done "" 100\n'
        'render_begin "b" 2; render_done "" 100\n'
        'render_begin "c" 2; render_done "" 100\n'
    )
    out = strip(run(script, tty=False))
    assert "[3/3]" in out
    assert "[3/2]" not in out


def test_a_single_step_drops_the_counter():
    """[1/1] is noise. One step, no counter."""
    out = strip(run('render_begin "uninstall" 1; render_done "" 100', tty=False))
    assert "[1/1]" not in out
    assert "[1/" not in out


def test_the_block_is_never_duplicated_in_a_terminal():
    """Repaint in place, not append.

    This is the whole reason RENDER_TOP is tracked: a repaint that lands one row
    too low leaves a second copy of the block under the first, and no amount of
    reading the source reveals it — it only shows up when a step animated.
    """
    script = (
        'render_begin "a" 3; render_done "" 100\n'
        'render_begin "b" 3; render_watch; sleep 0.35; render_done "" 200\n'
        'render_begin "c" 3; render_watch; sleep 0.35; render_done "" 300\n'
    )
    rows = screen(run_pty(script))
    steps = [r for r in rows if "[1/3]" in r or "[2/3]" in r or "[3/3]" in r]
    assert len(steps) == 3, rows
    assert [r.split()[0] for r in steps] == ["[1/3]", "[2/3]", "[3/3]"]


def test_the_block_stays_below_the_banner():
    script = (
        'render_banner "OVManager" "v1.0.0"\n'
        'render_begin "a" 2; render_watch; sleep 0.35; render_done "" 100\n'
        'render_begin "b" 2; render_done "" 200\n'
    )
    rows = screen(run_pty(script))
    assert "OVManager" in rows[0]
    assert any("[1/2]" in r for r in rows[1:])
    # Nothing above the banner may have been eaten by a repaint.
    assert rows[0].strip().startswith("OVManager")


def test_a_plain_line_between_the_block_and_the_card_keeps_the_block_intact():
    """A blank or a warning between the run and the card moves the cursor.

    The block does not know about that on its own, so every plain writer calls
    _render_cursor_advanced. Without it the final repaint lands a row low and
    duplicates the last step — the failure this accounting exists for.
    """
    script = (
        'render_begin "a" 2; render_done "" 100\n'
        'render_begin "b" 2; render_watch; sleep 0.35; render_done "" 200\n'
        "render_blank\n"
        'render_warn "a caveat"\n'
        'render_card "ready" "setup key" "K" "logs|ovm logs -f"\n'
    )
    rows = screen(run_pty(script))
    steps = [r for r in rows if r.strip().startswith("[")]
    assert len(steps) == 2, rows
    assert any("ready" in r for r in rows)


def test_the_finished_block_recedes_and_the_card_does_not():
    """Three greys, deepest for the oldest step, and the card at full weight.

    Checked as colour codes: the point is that finished steps get LESS weight
    over time, which is invisible in stripped text.
    """
    script = (
        'render_begin "a" 3; render_done "" 100\n'
        'render_begin "b" 3; render_watch; sleep 0.3; render_done "" 200\n'
        'render_begin "c" 3; render_done "" 300\n'
    )
    raw = run_pty(script)
    assert re.search(r"\x1b\[\d+A", raw), "no repaint happened at all"
    # Each step line emits its depth colour three times (counter, body open,
    # body close), so the last nine emissions are the final repaint: three per
    # line, lines in order, oldest first.
    greys = re.findall(r"38;5;(240|244|250)", raw)
    assert len(greys) >= 9, greys
    final = greys[-9:]
    per_line = [final[i] for i in (0, 3, 6)]
    # Oldest step faintest, newest step freshest: the block recedes behind
    # itself as the run goes on.
    assert per_line == ["240", "244", "250"], greys


def test_the_card_settles_the_block_to_faint():
    script = (
        'render_begin "a" 2; render_watch; sleep 0.3; render_done "" 100\n'
        'render_begin "b" 2; render_done "" 200\n'
        'render_card "ready" "setup key" "K" "logs|ovm logs -f"\n'
    )
    raw = run_pty(script)
    settle = raw[raw.rindex("\x1b[2A") :] if "\x1b[2A" in raw else ""
    assert "38;5;240" in settle, "the block did not settle"
    rows = screen(raw)
    card_at = next(i for i, r in enumerate(rows) if r.strip() == "ready")
    step_at = next(i for i, r in enumerate(rows) if r.strip().startswith("[1/2]"))
    assert step_at < card_at


# ── Transfers ───────────────────────────────────────────────────────────


# Two steps, so the counter is present and the release line is findable: a
# single-step run drops [1/1] as noise, which is its own tested rule.
_TRANSFER = (
    'render_begin "preflight" 2; render_done "ok" 400\n'
    'render_begin "release" 2; render_watch; '
    '_render_bytes {have} {total} {rate}; render_unwatch; render_done "" 9000'
)


def _transfer_row(**env) -> str:
    script = _TRANSFER.format(
        have=env.pop("have", "5000000"),
        total=env.pop("total", '""'),
        rate=env.pop("rate", "412"),
    )
    rows = screen(run_pty(script, **env))
    return next(r for r in rows if "[2/2]" in r)


def test_a_transfer_without_a_total_shows_a_growing_count():
    line = _transfer_row()
    assert "4.8 MB" in line
    assert "412 MB/s" in line
    assert "░" not in line, "a bar appeared without a total to draw against"


def test_a_transfer_with_a_total_shows_a_bar():
    line = _transfer_row(have="13002342", total="38002342", rate="4100")
    assert "12.4/36 MB" in line
    assert "█" in line and "░" in line
    # 12.4 of 36 is a third, so roughly a third of the bar: 5 of 16.
    assert line.count("█") == 5, line
    assert line.count("░") == 11, line


def test_a_more_than_half_full_download_fills_more_of_the_bar():
    line = _transfer_row(have="30000000", total="38002342", rate="4100")
    assert "28.6/36 MB" in line
    assert line.count("█") == 13, line


def test_the_bar_width_is_fixed_regardless_of_progress():
    """A bar that grows with progress makes the line jump as bytes arrive."""
    early = _transfer_row(have="2000000", total="38002342", rate="100")
    late = _transfer_row(have="37000000", total="38002342", rate="100")
    assert early.count("█") + early.count("░") == late.count("█") + late.count("░")


def test_the_bar_is_ascii_without_utf8():
    line = _transfer_row(have="13002342", total="38002342", rate="4100", LC_ALL="C")
    assert "#" in line and "." in line
    assert "█" not in line and "░" not in line


# ── Failure ─────────────────────────────────────────────────────────────


def test_a_failure_is_one_line_with_the_cause():
    out = strip(
        run(
            'render_begin "health" 3; render_done "" 100\n'
            'render_begin "verify" 3; render_fail "verify" "service exited 1 after 1.6s"',
            tty=False,
        )
    )
    lines = [ln for ln in out.splitlines() if ln.strip()]
    fail = [ln for ln in lines if "✗" in ln]
    assert len(fail) == 1, out
    assert "verify" in fail[0]
    assert "exited 1 after 1.6s" in fail[0]


def test_failure_is_ascii_too():
    out = strip(run('render_begin "v" 1; render_fail "v" "boom"', tty=False, LC_ALL="C"))
    assert "XX" in out
    assert "boom" in out


def test_the_next_line_is_two_runnable_commands():
    out = strip(
        run(
            'render_begin "h" 1; render_fail "h" "no answer"\n'
            'render_next "ovm logs 50" '
            '"bash <(curl -sSL https://x/install.sh) uninstall --purge -y"',
            tty=False,
        )
    )
    line = next(ln for ln in out.splitlines() if "next" in ln)
    assert "ovm logs 50" in line
    assert "uninstall --purge -y" in line


# ── Card ────────────────────────────────────────────────────────────────


CARD = 'render_card "ready" "setup key" "4f9c-2a71" "panel|https://h:2095/setup" "logs|ovm logs -f"'


def test_the_card_puts_the_key_on_its_own_line_and_the_rows_under_it():
    lines = [ln for ln in strip(run(CARD, tty=False)).splitlines() if ln.strip()]
    assert lines[0].strip() == "ready"
    key = next(i for i, ln in enumerate(lines) if "setup key" in ln)
    panel = next(i for i, ln in enumerate(lines) if "panel" in ln)
    assert key < panel
    # Nothing that could be a credential in the rows.
    assert all("password" not in ln.lower() for ln in lines)


def test_card_rows_skip_an_empty_label():
    """A caller with no secret must not get a blank bold row."""
    out = strip(run('render_card "ready" "" "" "logs|ovm logs -f"', tty=False))
    assert "setup key" not in out
    assert "ovm logs -f" in out


def test_the_card_label_column_is_fixed():
    """Rows are one deeper than the title, and all at the same depth.

    Without a fixed label column, every row's value starts wherever its label
    ends and the card reads as a list of unrelated fragments.
    """
    lines = [ln for ln in strip(run(CARD, tty=False)).splitlines() if ln.strip()]
    title, rule, *rows = lines
    assert title.startswith("  ") and not title.startswith("   ")
    depths = {len(ln) - len(ln.lstrip()) for ln in rows}
    assert depths == {3}, rows
    # The values start at the same column: the label field is padded to a fixed
    # width, so a long label does not push its own value right.
    # All single-word labels, so the value column is unambiguous.
    out = strip(
        run(
            'render_card "ready" "" "" "panel|u" "logs|l" "data|d"',
            tty=False,
        )
    )
    card_rows = [ln for ln in out.splitlines() if ln.startswith("   ")]
    assert card_rows, out
    for ln in card_rows:
        # 3 indent + 14 label field + 1 space. Comparing the fixed slice
        # directly is what makes this readable: "data" starting with 'd' is why
        # searching the whole row for the value finds the label instead.
        assert ln[3:17].strip() == ln.split()[0], ln
        assert ln[17] == " ", ln
        assert ln[18] == ln.split()[1], ln


# ── Ask ─────────────────────────────────────────────────────────────────


def test_the_ask_puts_the_default_in_brackets_before_the_colon():
    out = strip(run('render_ask "port" "2095"', tty=False))
    assert out.endswith("[2095]: ")


def test_the_menu_draws_numbers_and_a_pointer():
    """Every row is numbered, the current one carries the pointer.

    Checked in the piped form, which is the path that must also be readable: a CI
    log has no arrow keys, so the numbers are what it has to go on.
    """
    rows = screen(
        run(
            'render_menu "" native "install  ·  systemd" '
            'docker "install  ·  containerized" quit "exit"',
            tty=False,
        )
    )
    text = "\n".join(rows)
    assert "1  install  ·  systemd" in text
    assert "2  install  ·  containerized" in text
    assert "3  exit" in text
    assert "▸" in text, "no pointer row when the menu cannot be interacted with"


def test_the_menu_pointer_starts_on_the_first_item():
    rows = screen(run('render_menu "" a "one" b "two"', tty=False))
    pointer = next(r for r in rows if "▸" in r)
    assert "one" in pointer
    assert "1" in pointer


def test_the_menu_is_not_drawn_as_a_whiptail_box():
    """No second menu renderer.

    tui_select used to prefer whiptail when installed, so the same menu looked
    like a boxed dialog on one box and a coloured list on another, and the two
    disagreed about which item was selected.
    """
    lib = (LIB / "common.sh").read_text(encoding="utf-8")
    assert 'tui_select() { render_menu "$@"; }' in lib
    code = "\n".join(ln for ln in lib.splitlines() if not ln.lstrip().startswith("#"))
    assert "whiptail" not in code


def test_a_typed_number_clamps_into_range():
    """9 on a three-item menu is the last item, not a crash and not item 1."""
    out = strip(
        run(
            'render_menu "" a "one" b "two" c "three" <<< "9"',
            tty=False,
        )
    )
    assert "three" in out


# ── Colour discipline ───────────────────────────────────────────────────


def test_colour_is_gated_on_stderr_being_a_terminal():
    """Every renderer writes to fd 2, so the gate must test fd 2.

    [[ -t 1 ]] passed on `2>install.log` from a terminal and wrote escape codes
    into the log, and failed on `>/dev/null` and stripped colour from a terminal
    that could show it.
    """
    raw = run(STEPS, tty=False)
    assert "\x1b[" not in raw


def test_no_color_removes_the_sgr_codes_but_keeps_the_motion():
    """NO_COLOR is a request about colour, not about cursor movement.

    A terminal that declined colour still repaints, and losing the repaint would
    turn every intermediate state into a permanent duplicate line. What must not
    survive is the colour: no SGR at all.
    """
    raw = run_pty(STEPS, NO_COLOR="1")
    assert not re.search(r"\x1b\[[0-9;]*m", raw), "an SGR code survived NO_COLOR"
    assert "\x1b[1A" in raw, "the repaint went away with the colour"
    rows = screen(raw)
    assert len([r for r in rows if r.strip().startswith("[")]) == 3


def test_dumb_terminal_gets_no_colour():
    raw = run_pty(STEPS, TERM="dumb")
    assert "\x1b[" not in raw


def test_a_piped_stdin_still_gets_the_animated_output():
    """`curl -sSL URL | sudo bash -s` has a pipe on stdin and a terminal on stderr.

    Gating animation on stdin meant the documented install path produced the
    degraded output — no spinner, no fade, no live byte count — on exactly the
    machine where an operator was watching and waiting. Only stderr is consulted.
    """
    raw = run_pty(STEPS, stdin_pipe=True)
    assert "\x1b[" in raw, "a terminal on stderr must animate even with a pipe on stdin"
    rows = screen(raw)
    assert len([r for r in rows if r.strip().startswith("[")]) == 3


def test_a_pipe_gets_no_animation():
    """Non-TTY must not spawn a spinner, must not move the cursor.

    Not just for tidiness: the cursor codes would land in a CI artifact, and the
    spinner would be a background process with nothing to draw on.
    """
    raw = run(
        'render_begin "a" 2; render_watch; sleep 0.3; render_done "" 100\n'
        'render_begin "b" 2; render_done "" 200',
        tty=False,
    )
    assert "\x1b[" not in raw
    assert "\r" not in raw


def test_non_tty_text_matches_tty_text_exactly():
    """Rule 1 of the design: a pipe describes the same run a terminal shows.

    Both sides are stripped of colour and motion. If this ever fails, a CI log
    and a watched install disagree, and only one of them is believed.
    """
    script = (
        'render_begin "preflight" 3; render_done "debian 12 · 14G free" 412\n'
        'render_begin "release" 3; render_watch; sleep 0.3; render_done "38.0 MB" 9100\n'
        'render_begin "health" 3; render_done "200 in 41ms" 6900\n'
        f"{CARD}\n"
    )
    piped = [ln.rstrip() for ln in strip(run(script, tty=False)).splitlines() if ln.strip()]
    drawn = [ln.rstrip() for ln in screen(run_pty(script)) if ln.strip()]
    assert piped == drawn, (piped, drawn)


def test_render_takes_no_arguments_that_could_be_injected():
    """Values are arguments, never format strings.

    A secret that reached a printf format would be a shell-injection surface in
    the one place a secret is printed.
    """
    render = (LIB / "render.sh").read_text(encoding="utf-8")
    fns = ("render_kv", "render_kv_w", "render_key", "render_card", "render_note", "render_warn")
    for fn in fns:
        start = render.index(f"{fn}() {{")
        end = render.index("\n}\n", start)
        body = render[start:end]
        assert "eval" not in body, fn


def test_render_kv_w_takes_the_column_it_is_given():
    """A fixed width only works while every label is shorter than it.

    At 14, a 40-character backup filename printed whole and dropped its value a
    column right of every other row's — the same failure ``Service account``
    caused in the CLI, in the other direction. A caller that knows its own
    labels passes the width they need.
    """
    text = strip(run("render_kv_w 30 short x\nrender_kv_w 30 a-much-longer-label y", tty=False))
    rows = [ln for ln in text.splitlines() if ln.strip()]
    assert len(rows) == 2, text
    # The value is the last word on the row, so its offset is the column.
    columns = {ln.rindex(ln.split()[-1]) for ln in rows}
    assert len(columns) == 1, f"values do not share a column: {rows}"


def test_render_sh_is_byte_identical_to_the_panels():
    """One renderer, two installers, one file.

    This is the whole point of moving the output into scripts/lib. The node card
    and the panel card used to be two copies of one idea written at different
    times, and they had drifted: different label widths, different glyphs, a
    spinner that only one of them had.

    This file is a copy of the panel's, which is why the same assertions pass in
    both repos without edits. That only stays true if the renderer does too.
    """
    import pytest as _pytest

    if not PANEL.is_dir():
        _pytest.skip("OVManager checkout not beside this repo")
    here = (LIB / "render.sh").read_text(encoding="utf-8")
    there = (PANEL / "scripts" / "lib" / "render.sh").read_text(encoding="utf-8")
    if here == there:
        return
    # A deliberate change must be made in both places in one commit, and said so
    # here. Until then, this is the failure.
    import difflib

    diff = "\n".join(
        list(
            difflib.unified_diff(
                there.splitlines(),
                here.splitlines(),
                "panel/render.sh",
                "node/render.sh",
                lineterm="",
                n=1,
            )
        )[:40]
    )
    raise AssertionError(f"render.sh has drifted between the two installers:\n{diff}")
