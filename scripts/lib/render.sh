#!/usr/bin/env bash
# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT
#
# Part of scripts/lib: sourced by manager.sh, and fetched and sourced by
# install.sh at startup (curl-pipe standalone). One definition per helper —
# tests/test_lib_sourcing.py enforces that.
#
# Every character this project puts on a terminal. It knows how a line looks;
# it never knows what happened, which service was started, or whether a port is
# free. That split is the whole reason it is a separate file: install.sh owns
# the sequence, render.sh owns the rendering, and either can be replaced alone.
#
# Everything writes to fd 2, for the same reason it always has: stdout stays
# parseable (`ovm status --all`, `install.sh version-script`) while progress
# goes to the terminal, so `install.sh ... > file` still logs.
#
# Design rules, in the order they matter:
#   1. Non-TTY output is byte-identical to TTY output. The animation, the
#      fade and the cursor moves are colour and motion only — never content.
#      A piped CI log must not describe a different run than a watched one.
#   2. Colour never carries meaning alone. Every coloured thing also has a
#      glyph or a word, so NO_COLOR=1 and LANG=C lose nothing.
#   3. Bold is reserved for things a human might type or copy back: the
#      selected menu number, a URL, a secret.
#   4. Every redraw is best-effort. A terminal that cannot do it gets the
#      static form and a slower install, never a failed one.

# ── Capability detection ───────────────────────────────────────────────
# One decision, made once, read everywhere. Resolved at source time so the
# helpers below are branch-free.
#
# The colour gate tests fd 2, not fd 1: every helper here writes to fd 2, and
# `install.sh 2>install.log` from a terminal used to pass [[ -t 1 ]] and write
# escape codes into the log. The node side already tests -t 2; this matches it.
if [[ -t 2 && -z "${NO_COLOR:-}" && "${TERM:-dumb}" != "dumb" ]]; then
    RENDER_COLOR=1
else
    RENDER_COLOR=0
fi

# Braille is the only widely-available frame set that reads as continuous
# rotation without shifting the line. LANG=C and a non-UTF-8 SSH client get the
# dot frames, which are the same visual idea in one column.
if [[ "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" == *[Uu][Tt][Ff]* ]]; then
    RENDER_SPINNER_UNICODE=1
else
    RENDER_SPINNER_UNICODE=0
fi

# Animation is motion on a screen nobody is watching, and cursor-up-and-rewrite
# is the one thing in this file that can fail a `set -e` shell. It therefore
# runs only when stderr is a terminal.
#
# Deliberately NOT also gated on stdin: `curl -sSL URL | sudo bash -s -- --yes`
# is the documented install path and its stdin is the pipe, yet its stderr is
# the operator's terminal. Requiring a tty on stdin meant the most common way
# to install the panel got the degraded output. The menu is the one thing that
# genuinely needs keystrokes, and render_menu checks for /dev/tty itself.
# A dumb terminal honours no escapes at all — not SGR, not cursor motion — so
# it gets the static form as well as no colour. NO_COLOR is narrower: it is a
# request about colour specifically, and a terminal that declined colour still
# repaints fine, so the motion stays.
if [[ -t 2 && "${TERM:-dumb}" != "dumb" ]]; then
    RENDER_ANIMATE=1
else
    RENDER_ANIMATE=0
fi

# Three depths, not more: a terminal that can show three greys reliably shows
# them, and a fourth is indistinguishable from the third on most palettes.
RENDER_FADE_0=$'\033[38;5;250m'   # finished, still fresh
RENDER_FADE_1=$'\033[38;5;244m'   # one step further back
RENDER_FADE_2=$'\033[38;5;240m'   # the rest of the run

# ── Primitives ──────────────────────────────────────────────────────────

# Every glyph in one place, ASCII and Unicode pairs. Callers never type a
# character directly, so LANG=C output stays coherent.
if [[ "$RENDER_SPINNER_UNICODE" -eq 1 ]]; then
    RENDER_FRAMES='⣾⣽⣻⢿⡿⣟⣯⣷'
    RENDER_POINTER='▸'
    RENDER_OK='✓'
    RENDER_BAD='✗'
    RENDER_RULE='──────────────────────────────────────────────'
    RENDER_BAR_FULL='█'
    RENDER_BAR_EMPTY='░'
else
    RENDER_FRAMES='-\|/-\'
    RENDER_POINTER='>'
    RENDER_OK='ok'
    RENDER_BAD='XX'
    RENDER_RULE='----------------------------------------------'
    RENDER_BAR_FULL='#'
    RENDER_BAR_EMPTY='.'
fi

_render_paint() {  # _render_paint <colour> <text> — no-op when colour is off
    if [[ "$RENDER_COLOR" -eq 1 ]]; then printf '%b%s%b' "$1" "$2" "${NC:-}"; else printf '%s' "$2"; fi
}

_render_out() { printf '  %b\n' "$*" >&2; }

# Note that output was written BELOW the progress block without repainting it.
#
# Every plain line — a blank, a card row, a warning — pushes the cursor one row
# further from the block's first row, and the next repaint has to know that or
# it lands a row too low and leaves a duplicate step line behind. Anything that
# writes while a block is on screen goes through here.
_render_cursor_advanced() {
    [[ "$RENDER_ANIMATE" -eq 1 ]] || return 0
    [[ "${RENDER_TOP:-0}" -gt 0 ]] || return 0
    RENDER_TOP=$(( RENDER_TOP + 1 ))
    return 0
}

# Milliseconds → a fixed-width human duration. Sub-second steps read as "0.4s"
# rather than vanishing: the right column is the answer to "why did this take
# twenty seconds", so it must never be the one thing that is blank.
_render_ms() {
    [[ -n "${1:-}" ]] || { printf ''; return 0; }
    awk -v ms="${1}" 'BEGIN { s = ms / 1000; if (s >= 60) printf "%dm%02ds", int(s/60), s%60; else if (s >= 10) printf "%.0fs", s; else printf "%.1fs", s }' | tr -d '\n' | awk '{ printf "%7s", $0 }'
}

_render_bar() {  # _render_bar <fraction 0-1> <width>
    local filled width="${2:-24}" frac="$1" i bar=""
    filled="$(awk -v f="$frac" -v w="$width" 'BEGIN { n = int(f * w + 0.5); print (n < 0 ? 0 : (n > w ? w : n)) }')"
    for (( i = 0; i < width; i++ )); do
        if (( i < filled )); then bar+="$RENDER_BAR_FULL"; else bar+="$RENDER_BAR_EMPTY"; fi
    done
    printf '%s' "$bar"
}

# ── Banner / screen ─────────────────────────────────────────────────────

render_banner() {  # render_banner <name> <version>
    local name="$1" version="$2"
    _render_out "$(_render_paint "$B" "$name")  $version  $(_render_paint "$GY" "· anonysec")"
    render_rule
}

render_rule() { _render_out "$(_render_paint "$GY" "$RENDER_RULE")"; }

# Wipe between wizard steps. TTY only: `clear` in a pipe writes form feeds into
# the log and destroys the record of what was chosen. A caller that reaches the
# wizard has already been proven able to prompt, so this is belt-and-braces
# rather than the primary check.
render_screen() {
    [[ "$RENDER_ANIMATE" -eq 1 ]] || return 0
    # `clear 2>/dev/null`, not `command clear >/dev/null 2>&1`. `clear` clears
    # by *printing* escape codes, so redirecting its stdout to /dev/null threw
    # the codes away and the screen was never cleared — the exact opposite of
    # what that redirection looks like it is doing. Only stderr is silenced, to
    # keep "terminal not found" out of the output. The printf fallback still
    # covers a host where `clear` is missing or non-functional.
    clear 2>/dev/null || printf '\033[H\033[2J\033[3J' >&2 || true
    return 0
}

# ── Menu ───────────────────────────────────────────────────────────────
#
# The pointer and the number on the input line are the same thing. Arrows do
# not "select" separately: they move the cursor and rewrite the digits, and
# Enter always reads back what is visible. One source of truth means no branch
# where the pointer and the number disagree, which is the bug every hand-rolled
# arrow menu grows.
#
# render_menu <title> <tag> <label> [<tag> <label> ...] → prints the tag.
# Falls back to a plain numbered read when there is no terminal to draw on.

render_menu() {
    shift    # title is the caller's; the banner already said what this is
    local -a tags=() labels=()
    while [[ $# -ge 2 ]]; do tags+=("$1"); labels+=("$2"); shift 2; done
    local count=${#tags[@]}
    [[ "$count" -gt 0 ]] || return 1

    _menu_draw() {  # reads _MENU_TAGS/_MENU_LABELS/_MENU_CUR
        local i=0 n=${#_MENU_TAGS[@]}
        while (( i < n )); do
            if (( i == _MENU_CUR )); then
                printf '  %b%s%b  %b%d%b  %s\n' \
                    "$OR" "$RENDER_POINTER" "$NC" "$B" "$(( i + 1 ))" "$NC" "${_MENU_LABELS[$i]}"
            else
                printf '    %b%d%b  %s\n' "$GY" "$(( i + 1 ))" "$NC" "${_MENU_LABELS[$i]}"
            fi
            i=$(( i + 1 ))
        done
    }

    _MENU_TAGS=("${tags[@]}"); _MENU_LABELS=("${labels[@]}"); _MENU_CUR=0

    if [[ "$RENDER_ANIMATE" -ne 1 || ! -e /dev/tty || ! -r /dev/tty ]]; then
        _menu_draw >&2
        local n
        n="$(ask "choice" "1")"
        [[ "$n" =~ ^[0-9]+$ ]] || n=1
        printf '%s' "${tags[$(( (n - 1) % count ))]}"
        return 0
    fi

    # Own fd for the drawing. The keystroke reader must not see the menu's own
    # writes on the same descriptor, and the prompt line is rewritten in place,
    # so the two are kept apart from here down.
    exec 3>&2
    local frame=$(( count + 3 )) ch c1 c2 reply="" digits=""
    local hint='↑↓ move · ⏎ confirm'
    [[ "$RENDER_SPINNER_UNICODE" -eq 1 ]] || hint='type a number · ↑↓ move'
    while true; do
        printf '\033[%dA\033[J' "$frame" >&3 2>/dev/null || true
        _menu_draw >&3
        printf '  %b%s%b\n' "$GY" "$hint" "$NC" >&3
        printf '  %bchoice [%s%d%s]%b: ' "$NC" "$B" "$(( _MENU_CUR + 1 ))" "$NC" "$NC" >&3

        # One keystroke, no Enter. Every read is timed: a pasted line, a closed
        # terminal or a tmux that lost the pane must not wedge the installer
        # mid-menu with a half-drawn frame on screen.
        if ! IFS= read -rsn1 -t 2 ch < /dev/tty; then
            # Timed out with nothing typed. Fall back to a plain line read so a
            # keystroke-free session (a CI runner with a pty, a flaky tmux) still
            # completes instead of redrawing forever.
            # The newline ends the prompt line above, and `ask` would print that
            # same prompt a second time — so every run that took the fallback
            # showed "choice [1]:" twice, once with the cursor already past it.
            # Read the line directly: the prompt is on screen and we have just
            # moved off it, and the default is applied by the next line either
            # way.
            printf '\n' >&3
            IFS= read -r digits || digits=""
            [[ "$digits" =~ ^[0-9]+$ ]] || digits=$(( _MENU_CUR + 1 ))
            reply=$(( (10#$digits - 1) % count + 1 ))
            break
        fi
        # A bare newline comes back from `read -n1` as an empty string with a
        # zero status: the delimiter was consumed and there was nothing left.
        # Without this, Enter would redraw the menu and wait again.
        [[ -z "$ch" ]] && ch=$'\n'
        case "$ch" in
            $'\n'|$'\r'|$'\x04')
                reply=$(( _MENU_CUR + 1 )); break ;;
            $'\033')
                # CSI is three bytes: ESC [ <final>. Read the two that follow
                # with a short timeout — an ESC alone (a bare Escape keypress)
                # times out here and is ignored, which is the wanted behaviour.
                if IFS= read -rsn1 -t 0.3 c1 < /dev/tty && IFS= read -rsn1 -t 0.3 c2 < /dev/tty; then
                    case "$c2" in
                        A) (( _MENU_CUR > 0 )) && _MENU_CUR=$(( _MENU_CUR - 1 )) ;;
                        B) (( _MENU_CUR < count - 1 )) && _MENU_CUR=$(( _MENU_CUR + 1 )) ;;
                    esac
                fi ;;
            $'\x7f'|$'\b')
                digits="${digits%?}"
                (( _MENU_CUR > 0 )) || _MENU_CUR=0 ;;
            [0-9])
                digits="$ch"
                _MENU_CUR=$(( 10#$ch - 1 ))
                (( _MENU_CUR >= count )) && _MENU_CUR=$(( count - 1 )) ;;
        esac
    done
    exec 3>&-
    printf '%s' "${tags[$(( reply - 1 ))]}"
}

# ── Progress ───────────────────────────────────────────────────────────
#
# A step is one line: [n/6] ✓ label   detail   time. The counter is the only
# header — phase names were a second, competing way of saying where you are,
# and the indentation that came with them cost more than they explained.
#
# Finished lines recede: a step holds full weight for one beat, then drops a
# grey per beat, so the eye has a moving edge to follow and the whole run reads
# as faint history once it ends. That trail is left in the scrollback, which is
# why it survives into a piped log — the colours differ, the text does not.
#
# Non-TTY never redraws and never animates: each step prints once, the moment
# it finishes, in order. Identical text, no cursor movement, so a CI log reads
# as a plain record of the run.

RENDER_TOTAL=0
RENDER_LABELS=()
RENDER_DETAILS=()
RENDER_TIMES=()
RENDER_DONE=0
RENDER_NOW=0
RENDER_DRAWN=0
RENDER_TOP=0
RENDER_SETTLE=0

_render_ms_since() {  # ms since RENDER_NOW, as a plain integer
    local now="${1:-}" tail
    now="$(date +%s%N 2>/dev/null || printf '')"
    [[ "$now" == *N* ]] || now="$(date +%s 2>/dev/null || printf 0)000000000"
    tail="${now##*.}"; [[ "$tail" =~ ^[0-9]+$ ]] || tail=0
    tail=$(( 10#$tail / 1000000 ))
    local start="${RENDER_NOW##*.}"; [[ "$start" =~ ^[0-9]+$ ]] || start=0
    start=$(( 10#$start / 1000000 ))
    local d=$(( tail - start ))
    (( d < 0 )) && d=0
    printf '%s' "$d"
}

_render_now() {
    local now
    now="$(date +%s%N 2>/dev/null || printf '')"
    [[ "$now" == *N* ]] || now="$(date +%s 2>/dev/null || printf 0)000000000"
    printf '%s' "$now"
}

# Grey by steps-back. Three depths only: a terminal that renders three reliably
# renders them, and a fourth is indistinguishable from the third on most
# palettes. Without colour every depth is the same — which is the point, the
# glyph still says which step is running.
#
# RENDER_SETTLE overrides all of it: once the run is over there is no "current"
# step left to point at, so the whole block drops to the faintest depth and the
# card that follows is the only thing on screen at full weight.
_render_depth_colour() {
    local back="$1"
    [[ "$RENDER_COLOR" == 1 ]] || { printf ''; return 0; }
    [[ "${RENDER_SETTLE:-0}" == 1 ]] && { printf '%s' "$RENDER_FADE_2"; return 0; }
    [[ "$back" -le 0 ]] && { printf ''; return 0; }
    [[ "$back" == 1 ]] && { printf '%s' "$RENDER_FADE_0"; return 0; }
    [[ "$back" == 2 ]] && { printf '%s' "$RENDER_FADE_1"; return 0; }
    printf '%s' "$RENDER_FADE_2"
}

# Column widths, so the block reads as a table: counter, glyph, label, detail,
# time. Everything is padded to the widest value seen so far, which is why a
# label set early does not make later lines jitter.
_render_widths() {  # sets _W_LABEL _W_DETAIL
    local i n=${#RENDER_LABELS[@]} l d
    _W_LABEL=0; _W_DETAIL=0
    for (( i = 0; i < n; i++ )); do
        l=${#RENDER_LABELS[$i]}
        d=${#RENDER_DETAILS[$i]}
        (( l > _W_LABEL )) && _W_LABEL=$l
        (( d > _W_DETAIL )) && _W_DETAIL=$d
    done
    (( _W_LABEL < 8 )) && _W_LABEL=8
    (( _W_DETAIL < 10 )) && _W_DETAIL=10
    return 0
}

_render_step_line() {  # _render_step_line <index> <frame> [no-newline]
    local i="$1" frame="${2:-}" nl="${3:-}" running=0
    (( i == RENDER_DONE )) && running=1
    _render_widths
    local back=$(( RENDER_DONE - i ))
    local c="$(_render_depth_colour "$back")"
    local label="${RENDER_LABELS[$i]}" detail="${RENDER_DETAILS[$i]}" time="${RENDER_TIMES[$i]}"
    # The spinner is a separate process holding a snapshot of the arrays, so it
    # hands the live detail over in a variable instead. One detail, whichever
    # process is painting it.
    [[ -n "${RENDER_DETAILS_SNAPSHOT:-}" ]] && detail="$RENDER_DETAILS_SNAPSHOT"
    local counter="" glyph glyph_c body
    if (( RENDER_TOTAL > 1 )); then
        counter="$(printf '%b[%d/%d]%b' "$c" "$(( i + 1 ))" "$RENDER_TOTAL" "$NC")"
    fi
    if (( running )); then
        # The running step is the only full-weight line on screen. Its clock
        # ticks, because a step that has said nothing for a minute is
        # indistinguishable from a hung installer.
        glyph="${frame:-$RENDER_POINTER}"; glyph_c="$OR"
        body="$(printf '%b%-*s%b  %-*s' "$OR" "$_W_LABEL" "$label" "$NC" "$_W_DETAIL" "$detail")"
        time="$(_render_ms_since "$RENDER_NOW")"
    else
        glyph="$RENDER_OK"; glyph_c="$GR"
        body="$(printf '%-*s  %-*s' "$_W_LABEL" "$label" "$_W_DETAIL" "$detail")"
    fi
    if [[ -n "$nl" ]]; then
        printf '  %b%s%b %b%s%b %b%s%b %7s' \
            "$c" "$counter" "$NC" \
            "$glyph_c" "$glyph" "$NC" \
            "$c" "$body" "$NC" \
            "$(_render_ms "$time")"
    else
        printf '  %b%s%b %b%s%b %b%s%b %7s\n' \
            "$c" "$counter" "$NC" \
            "$glyph_c" "$glyph" "$NC" \
            "$c" "$body" "$NC" \
            "$(_render_ms "$time")"
    fi
}

_render_repaint() {  # repaint the whole block in place
    [[ "$RENDER_ANIMATE" -eq 1 ]] || return 0
    local total=${#RENDER_LABELS[@]} i
    (( total > 0 )) || return 0
    # The block's first row, tracked rather than derived.
    #
    # A step that animated leaves a half-drawn line behind it, so the cursor is
    # not simply one past the block's last row: the repaint has to reach further
    # back to find the top. RENDER_TOP is the distance from the cursor to that
    # first row, and the spinner's own row is part of it — which is why unwatch
    # adds one.
    (( RENDER_TOP > 0 )) && printf '\033[%dA\033[J' "$RENDER_TOP" >&2 2>/dev/null || true
    for (( i = 0; i < total; i++ )); do
        _render_step_line "$i" >&2 2>/dev/null || true
    done
    RENDER_DRAWN="$total"
    RENDER_TOP="$total"
    return 0
}

# render_begin <label> <total> — open a step.
#
# The number is the caller's position, so a mode that skips a step (docker has
# no uv to install) still numbers honestly. The total is a floor, not a cap: if
# more steps open than were declared — a conditional branch the caller did not
# count — the denominator grows to match rather than printing [7/6]. A counter
# that overcounts is worse than no counter.
render_begin() {
    RENDER_NOW="$(_render_now)"
    local next=$(( ${#RENDER_LABELS[@]} + 1 ))
    if (( next > ${2:-1} )); then RENDER_TOTAL="$next"; else RENDER_TOTAL="$2"; fi
    RENDER_LABELS+=("$1")
    RENDER_DETAILS+=("")
    RENDER_TIMES+=("")
    RENDER_DONE=$(( ${#RENDER_LABELS[@]} - 1 ))
    RENDER_SPIN_PID=""
    RENDER_SPIN_FLAG=""
    return 0
}

# render_watch [detail] — start animating the running step. Separate from
# render_begin so a caller doing something quick does not spawn a subshell for
# it, and so non-TTY spawns nothing at all.
render_watch() {
    [[ "$RENDER_ANIMATE" -eq 1 ]] || return 0
    local idx="$RENDER_DONE" detail="${1:-${RENDER_DETAILS[$RENDER_DONE]:-}}"
    RENDER_SPIN_DETAIL="$(_render_flagfile)"
    RENDER_SPIN_FLAG="$(_render_flagfile)"
    printf '%s' "$detail" > "$RENDER_SPIN_DETAIL" 2>/dev/null || true
    render_spin "$idx" "$RENDER_SPIN_DETAIL" "$RENDER_SPIN_FLAG" &
    RENDER_SPIN_PID=$!
    disown 2>/dev/null || true
    return 0
}

_render_flagfile() {
    local f
    f="$(mktemp "${TMPDIR:-/tmp}/render-spin.XXXXXX" 2>/dev/null)" || f=""
    [[ -n "$f" ]] || return 0
    rm -f "$f"
    printf '%s' "$f"
}

# Stop the animation and account for the row it left behind. Safe to call when
# it was never started.
#
# The spinner ended mid-row (no trailing newline), so the cursor is parked at
# the end of that line. The newline here closes it and turns it into a real row
# the block's next repaint has to include.
render_unwatch() {
    [[ -n "${RENDER_SPIN_PID:-}" ]] || return 0
    kill "$RENDER_SPIN_PID" 2>/dev/null || true
    wait "$RENDER_SPIN_PID" 2>/dev/null || true
    if [[ -n "${RENDER_SPIN_FLAG:-}" && -e "$RENDER_SPIN_FLAG" ]]; then
        printf '\n' >&2
        RENDER_DRAWN=$(( RENDER_DRAWN + 1 ))
        RENDER_TOP=$(( RENDER_TOP + 1 ))
    fi
    [[ -n "${RENDER_SPIN_FLAG:-}" ]] && rm -f "$RENDER_SPIN_FLAG" 2>/dev/null
    [[ -n "${RENDER_SPIN_DETAIL:-}" ]] && rm -f "$RENDER_SPIN_DETAIL" 2>/dev/null
    RENDER_SPIN_PID=""
    RENDER_SPIN_FLAG=""
    RENDER_SPIN_DETAIL=""
    return 0
}

# render_bytes <have> <total> <kb_per_s> — the detail line for a transfer.
# With a total it is a bar, without one it is a plain count that grows. The
# bar appears the moment the size is known and not before, so the one number on
# screen is never a fiction.
_render_bytes() {
    local have="${1:-0}" total="${2:-}" rate="${3:-0}"
    if [[ "$total" =~ ^[0-9]+$ ]] && (( total > 0 )); then
        local frac mb_have mb_total
        frac="$(awk -v h="$have" -v t="$total" 'BEGIN{print h/t}')"
        mb_have="$(awk -v b="$have" 'BEGIN{printf "%.1f", b/1048576}')"
        mb_total="$(awk -v b="$total" 'BEGIN{printf "%.0f", b/1048576}')"
        render_note "$(printf '%s  %s/%s MB · %s MB/s' "$(_render_bar "$frac" 16)" "$mb_have" "$mb_total" "$rate")"
    else
        render_note "$(awk -v b="$have" 'BEGIN{printf "%.1f MB · %s MB/s", b/1048576, '"$rate"'}')"
    fi
    return 0
}

# render_note <detail> — annotate the running step. Free to call repeatedly;
# only the last call before render_done survives.
#
# With no step open it prints instead of swallowing the text: a lib helper
# (tls.sh, backup.sh) can be called outside a numbered step — from a wizard, a
# repair, or `ovm tls` — and its message must not vanish into a step that does
# not exist.
render_note() {
    local last=$(( ${#RENDER_DETAILS[@]} - 1 ))
    if (( last < 0 )); then
        render_line "$1"
        return 0
    fi
    RENDER_DETAILS[$last]="$1"
    # A running spinner reads its detail from a file; updating it here is what
    # makes the running line change instead of sitting on its first value.
    if [[ -n "${RENDER_SPIN_DETAIL:-}" && -n "${RENDER_SPIN_PID:-}" ]]; then
        printf '%s' "$1" > "$RENDER_SPIN_DETAIL" 2>/dev/null || true
    fi
    return 0
}

# render_spin <index> <detail-file> <painted-flag> — animate one line until
# killed. A no-op without a terminal, so a non-TTY run spawns nothing at all.
#
# The detail arrives through a FILE, not through the step arrays. The spinner is
# a background subshell: it inherited a snapshot of RENDER_DETAILS when it
# forked and would otherwise repaint the same text for the whole step, so a
# health check that reports "attempt 7/40" would sit there saying "attempt 1/40".
# Reading a file each frame is what makes a long step show progress.
#
# <painted-flag> lets the parent know whether anything reached the screen: a
# step that failed instantly never painted, and counting a line that is not
# there makes every later repaint drift up one row.
render_spin() {
    [[ "$RENDER_ANIMATE" -eq 1 ]] || return 0
    local idx="$1" dfile="${2:-}" flag="${3:-}"
    local frames="$RENDER_FRAMES"
    local n=${#frames} i=0 detail=""
    while :; do
        detail=""
        [[ -n "$dfile" && -r "$dfile" ]] && detail="$(cat "$dfile" 2>/dev/null)"
        RENDER_DETAILS_SNAPSHOT="$detail"
        _render_spin_line "$idx" "${frames:$(( i % n )):1}" >&2 2>/dev/null || true
        [[ -n "$flag" ]] && : > "$flag" 2>/dev/null || true
        sleep 0.12
        i=$(( i + 1 ))
    done
}

# One spinner frame, on ONE row, forever.
#
# The frame is written without a trailing newline and every iteration starts by
# returning to the start of that row and clearing it. With a newline the cursor
# walks down a row per frame, and after a few seconds the animation is a column
# of stale frames instead of one line that spins — which is exactly what the
# first version did.
#
# RENDER_DRAWN is deliberately untouched: this is a separate process with its
# own copy of that counter, and the parent owns the block's accounting. It
# learns that one extra row exists from the painted-flag file.
_render_spin_line() {
    local idx="$1" frame="$2"
    printf '\r\033[K' >&2 2>/dev/null || true
    _render_step_line "$idx" "$frame" no-newline >&2
    return 0
}

# render_done <detail> [ms] — close the running step as ok. In a terminal it
# rewrites the line in place; everywhere else it appends it once.
render_done() {
    local last=$(( ${#RENDER_LABELS[@]} - 1 ))
    (( last >= 0 )) || return 0
    [[ -n "${1:-}" ]] && RENDER_DETAILS[$last]="$1"
    RENDER_TIMES[$last]="${2:-$(_render_ms_since "$RENDER_NOW")}"
    render_unwatch
    RENDER_DONE=$(( last + 1 ))
    if [[ "$RENDER_ANIMATE" -eq 1 ]]; then
        # Repaint: the step that just finished was the running one, so it now
        # recedes a grey and the block shifts a shade down with it.
        _render_repaint
    else
        _render_step_line "$last" >&2
    fi
    return 0
}

# render_settle — the run is over. Repaints the block one last time with
# everything at the faintest depth, so the card below it is the only thing on
# screen that pulls the eye. A no-op without a terminal, where the block was
# printed once and is already in the scrollback.
render_settle() {
    [[ "$RENDER_ANIMATE" -eq 1 ]] || return 0
    render_unwatch
    RENDER_SETTLE=1
    _render_repaint
    RENDER_SETTLE=0
    return 0
}

# Leave the block in the scrollback and stop painting over it. Called before
# anything else prints, so a card never lands on top of a half-drawn step.
render_flush() { RENDER_DRAWN=0; RENDER_TOP=0; return 0; }

# ── Plain lines ─────────────────────────────────────────────────────────
# Everything that is not a numbered step. One place, so there is exactly one
# answer to "how is ordinary output indented and coloured".

render_line() { _render_out "$*"; _render_cursor_advanced; }
render_blank() { printf '\n' >&2; _render_cursor_advanced; }

# render_ok <text> — a completed thing that is not one of the numbered steps.
# The green check is the same glyph the progress block uses, so "done" looks
# the same everywhere in the installer.
render_ok() {
    printf '  %b%s%b  %s\n' "$GR" "$RENDER_OK" "$NC" "$1" >&2
    _render_cursor_advanced
}

# render_warn <text> — a caveat. Yellow, no glyph: a mid-run warning marker on
# its own line is the thing operators learn to skip, so the colour carries it
# and the text carries the meaning.
render_warn() {
    printf '  %b%s%b\n' "$YL" "$1" "$NC" >&2
    _render_cursor_advanced
}

# Card rows share one label width, so every value starts in the same column.
# 14 is the longest label either card uses ("install name" is 12, "setup key"
# and "not written" are shorter) — wide enough for the node card's labels, and
# not so wide that a short value sits in the middle of the screen.
RENDER_LABEL_W=14

# render_kv <label> <value> — a label/value row.
render_kv() {
    printf '   %b%-*s%b %s\n' "$GY" "$RENDER_LABEL_W" "$1" "$NC" "$2" >&2
    _render_cursor_advanced
}

# render_kv_w <width> <label> <value> — a row in a column this caller computed.
#
# A fixed width only works when every label is shorter than it. At 14, a
# 44-character backup filename printed whole and dropped its date a column right
# of every other row's, so a table of timestamps lined up with nothing. Pass the
# width the set actually needs and the values line up.
render_kv_w() {
    printf '   %b%-*s%b %s\n' "$GY" "$1" "$2" "$NC" "$3" >&2
    _render_cursor_advanced
}

# render_key — a secret. The only thing in the installer that gets bold white,
# because it is the only thing that must not be skimmed past.
render_key() {
    printf '   %b%-*s%b %b%s%b\n' "$GY" "$RENDER_LABEL_W" "$1" "$NC" "$B" "$2" "$NC" >&2
    _render_cursor_advanced
}

# render_url — bold for the same reason as render_key: it gets copied.
render_url() { render_kv "$1" "$(_render_paint "$B" "$2")"; }

# ── Card ───────────────────────────────────────────────────────────────
#
# The finish card fades in line by line, and the secret is passed in second so
# it is on screen before the lines that explain it: an operator who interrupts
# at the second line has the one thing they must not lose.
#
# render_card <title> <secret-label> <secret> <row>... — rows are "label|value".
# The uninstall line is added by render_card_undo, not here, so a caller that
# has no uninstall command does not print a broken one.

render_card() {
    local title="$1" secret_label="$2" secret="$3"; shift 3
    render_settle
    render_flush
    render_blank
    _render_out "$(_render_paint "$B" "$title")"
    render_rule
    [[ -n "$secret_label" ]] && render_key "$secret_label" "$secret"
    local row
    for row in "$@"; do
        [[ "$row" == *"|"* ]] || continue
        render_kv "${row%%|*}" "${row#*|}"
    done
    render_blank
    return 0
}

# render_card_undo <url> — the removal command, spelled out in full. An operator
# who wants it later is reading a log or a terminal scrollback, not the source.
render_card_undo() {
    render_blank
    _render_out "$(printf '%buninstall:%b %s' "$GY" "$NC" "$1")"
    render_blank
}

# ── Failure ────────────────────────────────────────────────────────────
#
# One line, then one way out. The gap between what was promised and what
# happened is the thing an operator actually needs, and it fits in a line — the
# rest of the old error prose was the same information at four times the length.

render_fail() {  # render_fail <label> <cause>
    local last=$(( ${#RENDER_LABELS[@]} - 1 ))
    if (( last >= 0 )); then
        render_unwatch
        RENDER_TIMES[$last]="${RENDER_TIMES[$last]:-$(_render_ms_since "$RENDER_NOW")}"
        RENDER_DONE=$(( last + 1 ))
    fi
    render_settle
    render_flush
    printf '  %b%s%b %b%s%b  %s\n' "$RD" "$RENDER_BAD" "$NC" "$B" "$1" "$NC" "$2" >&2
    return 0
}

render_next() {  # render_next <how to look> <how to remove>
    printf '  %bnext%b  %s · uninstall: %s\n' "$GY" "$NC" "$1" "$2" >&2
    _render_cursor_advanced
    return 0
}

# ── Ask ─────────────────────────────────────────────────────────────────
# Styled to match the menu: the default is bold, the label is dim, and the
# colon sits after the bracket so the answer's position never moves.

render_ask() {  # render_ask <label> <default>
    printf '  %b%s%b %b[%s]%b: ' "$GY" "$1" "$NC" "$B" "$2" "$NC" >&2
}

render_ask_note() { _render_out "$(_render_paint "$GY" "$1")"; }
