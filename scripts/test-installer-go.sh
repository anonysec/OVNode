#!/usr/bin/env bash
# shellcheck disable=SC2034
# SPDX-License-Identifier: MIT
#
# Go-side installer harness: runs `ovnode install|update|uninstall` (the same
# install.sh now execs) with TestFakeRunner=1. The fake runner records every
# external command and skips systemd, and SystemdDir keeps anyNodeUnit()
# inside the temp tree so this box's real /etc/systemd/system/ovnode.service
# cannot flip a fresh-box case to unit-only. The installer still writes host
# files under /etc (sysctl, logrotate, cron), so the harness runs as root;
# CI invokes it with sudo.
#
# Run: bash scripts/test-installer-go.sh
set -uo pipefail   # no -e: a failing case is data, not a reason to stop

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$HERE")"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/ovnode-installer-go-test.XXXXXX")"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

PASS=0 FAIL=0
section() { printf '\n=== %s ===\n' "$1"; }
ok()  { printf '  ok    %s\n' "$1"; PASS=$((PASS + 1)); }
bad() {
    printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1))
    [[ -n "${2:-}" ]] && printf '%s\n' "$2" | sed 's/^/        | /'
    return 0
}
expect_status() {
    if [[ "$1" == "$2" ]]; then ok "$3 (exit $2)"; else bad "$3 (want exit $1, got $2)"; fi
}
expect_in() {
    if grep -qF -- "$2" "$1"; then ok "$3"; else bad "$3 — '$2' not in output" "$(cat "$1" 2>/dev/null)"; fi
}
expect_not_in() {
    if grep -qF -- "$2" "$1"; then bad "$3 — '$2' should not appear" "$(cat "$1" 2>/dev/null)"; else ok "$3"; fi
}
expect_eq() {
    if [[ "$1" == "$2" ]]; then ok "$3"; else bad "$3 (want '$1', got '$2')"; fi
}

# Build the real Go binary — this is the code install.sh execs.
BIN="$WORK/ovnode"
if ! (cd "$ROOT_DIR" && go build -o "$BIN" ./cmd/ovnode); then
    echo "go build ./cmd/ovnode failed" >&2
    exit 1
fi

# go_case <name> <appdir> <fake-log> -- <ovnode args...>
# Extra OVN_* env vars go in the calling shell environment before the call
# (export ApiKey=...; go_case ... -- install -y), so env(1) never sees
# them as program arguments.
go_case() {
    local name="$1" appdir="$2" fakelog="$3"; shift 3
    # consume leading -- separator
    [[ "${1:-}" == "--" ]] && shift
    rm -f "$fakelog"
    env TestFakeRunner=1 TestFakeLog="$fakelog" \
        "AppDir=$appdir" "DataDir=$WORK/$name/data" \
        "SystemdDir=$WORK/$name/units" "BinDir=$WORK/$name/bin" \
        "Version=2.0.0" \
        "$BIN" "$@" < /dev/null > "$WORK/$name.log" 2>&1
    RC=$?
    return 0
}

# ── Fresh install (-y) reaches the install step ─────────────────────
section "fresh install, non-interactive (-y)"
FRESH_APP="$WORK/fresh/app"
mkdir -p "$FRESH_APP" "$WORK/fresh/units" "$WORK/fresh/bin"
cp "$BIN" "$FRESH_APP/ovnode"; chmod 0755 "$FRESH_APP/ovnode"
export ApiKey=0123456789abcdef0123456789abcdef
go_case fresh "$FRESH_APP" "$WORK/fresh-fake.log" -- install -y
expect_status 0 "$RC" "fresh install with -y succeeds"
expect_in "$WORK/fresh.log" "Installation complete" "the install success card is printed"
if [[ -f "$FRESH_APP/.env" ]]; then
    ok ".env was written"
else
    bad ".env was not written" "$(cat "$WORK/fresh.log")"
fi

# ── Existing node exits 3 with no downstream calls ───────────────────
section "existing node, non-interactive (-y)"
EXIST_APP="$WORK/existing/app"
mkdir -p "$EXIST_APP" "$WORK/existing/units" "$WORK/existing/bin"
cp "$BIN" "$EXIST_APP/ovnode"; chmod 0755 "$EXIST_APP/ovnode"
printf 'Instance=eu-1\nApiKey=keep-me\nApiPort=2083\n' > "$EXIST_APP/.env"
chmod 600 "$EXIST_APP/.env"
printf 'unit\n' > "$WORK/existing/units/ovnode.service"
export ApiKey=0123456789abcdef0123456789abcdef
go_case existing "$EXIST_APP" "$WORK/existing-fake.log" -- install -y
expect_status 3 "$RC" "an existing node with -y exits 3"
expect_in "$WORK/existing.log" "Already installed" "it says the node is already installed"
expect_not_in "$WORK/existing.log" "Installation complete" "it never installs over the node"
expect_not_in "$WORK/existing-fake.log" "ca init" "no bootstrap commands run after the gate"

# ── Panel allowlist: flag path ───────────────────────────────────────
section "panel allowlist, --panel-ip flag"
PFLAG_APP="$WORK/pflag/app"
mkdir -p "$PFLAG_APP" "$WORK/pflag/units" "$WORK/pflag/bin"
cp "$BIN" "$PFLAG_APP/ovnode"; chmod 0755 "$PFLAG_APP/ovnode"
export ApiKey=0123456789abcdef0123456789abcdef
go_case pflag "$PFLAG_APP" "$WORK/pflag-fake.log" -- install --panel-ip 203.0.113.9 -y
expect_status 0 "$RC" "install with --panel-ip succeeds"
expect_in "$PFLAG_APP/.env" 'ApiAllowedCidrs=203.0.113.9' "--panel-ip writes ApiAllowedCidrs to .env"
expect_in "$WORK/pflag.log" 'Panel    allow 203.0.113.9' "the summary names the allowlisted IP"

# ── Panel allowlist: env path ────────────────────────────────────────
section "panel allowlist, PanelIp env"
PENV_APP="$WORK/penv/app"
mkdir -p "$PENV_APP" "$WORK/penv/units" "$WORK/penv/bin"
cp "$BIN" "$PENV_APP/ovnode"; chmod 0755 "$PENV_APP/ovnode"
export ApiKey=0123456789abcdef0123456789abcdef
export PanelIp=203.0.113.9
go_case penv "$PENV_APP" "$WORK/penv-fake.log" -- install -y
expect_status 0 "$RC" "install with PanelIp succeeds"
expect_in "$PENV_APP/.env" 'ApiAllowedCidrs=203.0.113.9' "PanelIp writes ApiAllowedCidrs to .env"
unset PanelIp

# ── Short-key warning ────────────────────────────────────────────────
section "short API key warning"
PSHORT_APP="$WORK/pshort/app"
mkdir -p "$PSHORT_APP" "$WORK/pshort/units" "$WORK/pshort/bin"
cp "$BIN" "$PSHORT_APP/ovnode"; chmod 0755 "$PSHORT_APP/ovnode"
export ApiKey=sixteen-char-key
go_case pshort "$PSHORT_APP" "$WORK/pshort-fake.log" -- install -y
expect_status 0 "$RC" "a 16-char key is still accepted"
expect_in "$WORK/pshort.log" 'API key is shorter than 32 characters' "a key under 32 chars warns at start"
export ApiKey=0123456789abcdef0123456789abcdef

# ── Uninstall on a fresh box exits 4 with no downloads ──────────────
section "uninstall on a fresh box"
FRESH2_APP="$WORK/fresh2/app"
mkdir -p "$WORK/fresh2/units" "$WORK/fresh2/bin"
# Intentionally no .env / binary in AppDir: absent state.
go_case fresh2 "$FRESH2_APP" "$WORK/fresh2-fake.log" -- uninstall -y
expect_status 4 "$RC" "uninstall on a fresh box exits 4 (not installed)"
expect_in "$WORK/fresh2.log" "Not installed" "it says nothing is installed"
expect_not_in "$WORK/fresh2-fake.log" "systemctl" "no systemctl calls are made"

# ── No-panel open-allowlist semantic: .env has no allowlist ─────────
section "panel allowlist, no allowlist set"
PNONE_APP="$WORK/pnone/app"
mkdir -p "$PNONE_APP" "$WORK/pnone/units" "$WORK/pnone/bin"
cp "$BIN" "$PNONE_APP/ovnode"; chmod 0755 "$PNONE_APP/ovnode"
export ApiKey=0123456789abcdef0123456789abcdef
go_case pnone "$PNONE_APP" "$WORK/pnone-fake.log" -- install -y
expect_status 0 "$RC" "install with no allowlist succeeds"
expect_not_in "$PNONE_APP/.env" 'ApiAllowedCidrs' "no allowlist line when unset"
expect_not_in "$WORK/pnone.log" 'Panel    allow 203.0.113.9' "no allowlist claim when unset"

# ── Summary ──────────────────────────────────────────────────────────
printf '\n%s passed, %s failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]] || exit 1
exit 0
