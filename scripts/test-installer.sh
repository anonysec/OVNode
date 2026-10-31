#!/usr/bin/env bash
# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT
#
# Installer regression tests: does install.sh install on a fresh server, and
# does it refuse to touch a box that already runs a node?
#
# The bug these exist for: main called load_helpers before asking whether
# APP_DIR existed. load_helpers downloads the release binary *into* APP_DIR, so
# on a fresh box it created the directory the old check then found, and every
# first install answered "already installed" (exit 3). The tests therefore run
# main for real — bootstrap, download, verification and all — and stub only
# do_install, so "reached the install step" is an observable fact instead of an
# inference from a log line.
#
# Nothing here touches the box: no network, no root, no /etc, no /var.
#   · the release is a local fixture (scripts/testdata/fake-ovnode.sh), served
#     through a `curl` shim that refuses any other URL;
#   · APP_DIR, BIN_DIR and the systemd unit directory live in a temp tree;
#   · the install itself is a stub that prints a marker.
#
# Run: bash scripts/test-installer.sh
set -uo pipefail   # no -e: a failing case is data, not a reason to stop

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$HERE")"
INSTALL_SH="$ROOT_DIR/install.sh"
FAKE_BIN="$HERE/testdata/fake-ovnode.sh"

case "$(uname -m)" in
    x86_64|amd64)  ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) echo "unsupported architecture for these tests: $(uname -m)" >&2; exit 1 ;;
esac
ASSET="ovnode-linux-$ARCH"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/ovnode-installer-test.XXXXXX")"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

PASS=0 FAIL=0
section() { printf '\n=== %s ===\n' "$1"; }
ok()  { printf '  ok    %s\n' "$1"; PASS=$((PASS + 1)); }
skip() { printf '  skip  %s\n' "$1"; }
bad() {
    printf '  FAIL  %s\n' "$1"; FAIL=$((FAIL + 1))
    [[ -n "${2:-}" ]] && printf '%s\n' "$2" | sed 's/^/        | /'
    return 0
}
# expect_status <want> <got> <label>
expect_status() {
    if [[ "$1" == "$2" ]]; then ok "$3 (exit $2)"; else bad "$3 (want exit $1, got $2)"; fi
}
# expect_eq <want> <got> <label>
expect_eq() {
    if [[ "$1" == "$2" ]]; then ok "$3"; else bad "$3 (want '$1', got '$2')"; fi
}
# expect_in <file> <literal> <label>
expect_in() {
    if grep -qF -- "$2" "$1"; then ok "$3"; else bad "$3 — '$2' not in output" "$(cat "$1")"; fi
}
expect_not_in() {
    if grep -qF -- "$2" "$1"; then bad "$3 — '$2' should not appear" "$(cat "$1")"; else ok "$3"; fi
}

# ── Fixtures ───────────────────────────────────────────────────────────
# The published release: the bare binary plus its .sha256 sidecar, exactly the
# two files fetch_release_binary expects to find.
RELEASE_DIR="$WORK/release"
publish_release() {
    mkdir -p "$RELEASE_DIR"
    cp "$FAKE_BIN" "$RELEASE_DIR/$ASSET"
    chmod 0755 "$RELEASE_DIR/$ASSET"
    ( cd "$RELEASE_DIR" && sha256sum "$ASSET" > "$ASSET.sha256" )
}

# The curl shim. A release URL becomes the local fixture; anything else is a
# failure, so a test can never quietly reach for the network.
SHIM_DIR="$WORK/shim"
CURL_LOG="$WORK/curl.log"
make_shim() {
    mkdir -p "$SHIM_DIR"
    cat > "$SHIM_DIR/curl" << SHIM
#!/usr/bin/env bash
url=""
for a in "\$@"; do
    case "\$a" in https://*|http://*) url="\$a" ;; esac
done
printf '%s\n' "\${url:-<no url>}" >> "${CURL_LOG}"
case "\$url" in
    */releases/download/*) ;;
    *) printf 'curl shim: unexpected request %s\n' "\$url" >&2; exit 22 ;;
esac
args=()
for a in "\$@"; do
    case "\$a" in
        */releases/download/*) args+=("file://${RELEASE_DIR}/\${a##*/}") ;;
        *)                     args+=("\$a") ;;
    esac
done
exec "${REAL_CURL}" "\${args[@]}"
SHIM
    chmod 0755 "$SHIM_DIR/curl"
}
REAL_CURL="$(command -v curl)" || { echo "curl is required for these tests" >&2; exit 1; }

# The driver runs main() with the install itself stubbed. Sourcing install.sh
# defines everything and runs nothing (see the guard at its end), which is what
# makes it possible to exercise the real ordering without performing an
# install.
DRIVER="$WORK/driver.sh"
cat > "$DRIVER" << 'DRIVER'
#!/usr/bin/env bash
. "$INSTALL_SH"
do_install()   { printf 'MARK-reached-do_install\n' >&2; }
do_update()    { printf 'MARK-reached-do_update\n' >&2; }
do_uninstall() { printf 'MARK-reached-do_uninstall\n' >&2; }
main "$@"
DRIVER
chmod 0755 "$DRIVER"

# The ordering itself, without depending on what load_helpers does with the
# directory: this driver replaces load_helpers with an observer, so the only
# thing it can report is whether the state was already known when the bootstrap
# point in main was reached. This is the regression the bug was.
ORDER_DRIVER="$WORK/order-driver.sh"
cat > "$ORDER_DRIVER" << 'DRIVER'
#!/usr/bin/env bash
. "$INSTALL_SH"
do_install() { printf 'MARK-reached-do_install\n' >&2; }
load_helpers() {
    printf 'MARK-load_helpers-state=%s\n' "$INSTALL_STATE" >&2
    # The helpers the bootstrap would have written, from the checkout: this
    # driver observes the ordering, it does not re-test the download.
    # shellcheck disable=SC1091
    . "$FAKE_OVNODE_ASSETS/lib.sh"
}
main "$@"
DRIVER
chmod 0755 "$ORDER_DRIVER"

# run_installer <log> <app dir> <systemd dir> [--tty <answers>] -- <args...>
# Leaves the combined output in <log> and the exit code in RC.
run_installer() {
    local log="$1" appdir="$2" unitdir="$3"; shift 3
    local tty_answer="" args=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --tty) tty_answer="$2"; shift 2 ;;
            --)    shift; args=("$@"); break ;;
            *)     args+=("$1"); shift ;;
        esac
    done
    : > "$CURL_LOG"
    local -a envv=(
        "PATH=$SHIM_DIR:$PATH"
        "INSTALL_SH=$INSTALL_SH"
        "OVN_APP_DIR=$appdir"
        "OVN_BIN_DIR=$WORK/bin"
        "OVN_SYSTEMD_DIR=$unitdir"
        "FAKE_RELEASE_DIR=$RELEASE_DIR"
        "FAKE_OVNODE_ASSETS=$ROOT_DIR"
        "CURL_LOG=$CURL_LOG"
        "NO_COLOR=1"
    )
    local driver="${RUN_DRIVER:-$DRIVER}"
    if [[ -n "$tty_answer" ]]; then
        # A real pty: is_tty() is true, so the interactive path is the code
        # under test rather than the no-terminal fallback.
        printf '%s\n' "$tty_answer" \
            | script -q -e -c "env ${envv[*]} bash '$driver' ${args[*]}" /dev/null \
            > "$log" 2>&1
        RC=$?
    else
        env "${envv[@]}" bash "$driver" "${args[@]}" < /dev/null > "$log" 2>&1
        RC=$?
    fi
    return 0
}

# run_case <name> <app dir> [--tty <answers>] -- <args...> — the common shape:
# the temp unit directory, output under $WORK/<name>.log.
run_case() {
    local name="$1" appdir="$2"; shift 2
    run_installer "$WORK/$name.log" "$appdir" "$WORK/units" "$@"
}

curl_calls() { wc -l < "$CURL_LOG" | tr -d ' '; }

publish_release
make_shim

# ── Fresh install, non-interactive (-y) ────────────────────────────────
# The reported bug, exactly: on a fresh box this used to exit 3 with
# "already installed" before installing anything.
section "fresh install, non-interactive (-y)"
FRESH_APP="$WORK/fresh/app"
rm -rf "$WORK/fresh"; mkdir -p "$WORK/fresh"
run_case fresh-y "$FRESH_APP" -- -y
expect_status 0 "$RC" "fresh install with -y succeeds"
expect_in "$WORK/fresh-y.log" "MARK-reached-do_install" "-y reached the install step"
expect_not_in "$WORK/fresh-y.log" "Already installed" "-y did not report an existing node"
expect_not_in "$WORK/fresh-y.log" "already installed" "-y did not print the exit-3 card"
if [[ "$(curl_calls)" -ge 1 ]]; then ok "the release was fetched ($(curl_calls) request(s))"; else bad "-y never fetched the release"; fi
expect_not_in "$WORK/fresh-y.log" "interrupted bootstrap" "a missing APP_DIR is not called debris"
if [[ -f "$FRESH_APP/.env" ]]; then bad "the stub install wrote .env — it must not"; else ok "the stub install performed no real install"; fi

# The state is read before the bootstrap, not after it. Asserted on its own
# because the fresh-install cases above would also pass if the capture merely
# happened early enough by accident somewhere else.
section "install state is captured before the bootstrap"
ORDER_APP="$WORK/order/app"
rm -rf "$WORK/order"; mkdir -p "$WORK/order"
RUN_DRIVER="$ORDER_DRIVER" run_case order "$ORDER_APP" -- -y
expect_status 0 "$RC" "the driver runs"
expect_in "$WORK/order.log" "MARK-load_helpers-state=absent" "load_helpers is entered with the state already known"

# ── Fresh install, interactive (a terminal) ────────────────────────────
# The same bug hit the wizard: a human on a TTY was shown the already-installed
# menu on a server that had never had a node. Answer 1 (host) at the front door.
section "fresh install, interactive (pty)"
if ! command -v script >/dev/null 2>&1; then
    skip "no util-linux 'script' on this host — the terminal path is not exercised"
else
    INT_APP="$WORK/int/app"
    rm -rf "$WORK/int"; mkdir -p "$WORK/int"
    run_case fresh-tty "$INT_APP" --tty 1
    expect_status 0 "$RC" "fresh install from a terminal succeeds"
    expect_in "$WORK/fresh-tty.log" "MARK-reached-do_install" "the terminal path reached the install step"
    expect_not_in "$WORK/fresh-tty.log" "already installed" "the terminal path did not report an existing node"
    if [[ "$(curl_calls)" -ge 1 ]]; then ok "the release was fetched on the terminal path"; else bad "the release was never fetched on the terminal path"; fi
fi

# The wizard (`interactive`), not just the express menu: a human answering the
# two questions must reach the install too. Answers: port, then TLS choice 1.
section "fresh install, wizard (pty)"
if ! command -v script >/dev/null 2>&1; then
    skip "no util-linux 'script' on this host — the wizard is not exercised"
else
    WIZ_APP="$WORK/wizard/app"
    rm -rf "$WORK/wizard"; mkdir -p "$WORK/wizard"
    run_case fresh-wizard "$WIZ_APP" --tty $'2083\n1' -- interactive
    expect_status 0 "$RC" "the wizard installs on a fresh server"
    expect_in "$WORK/fresh-wizard.log" "MARK-reached-do_install" "the wizard reached the install step"
    expect_not_in "$WORK/fresh-wizard.log" "already installed" "the wizard did not report an existing node"
fi

# ── Existing installation, non-interactive (-y) ────────────────────────
# A real node: .env (the identity and the API key) plus the verified binary.
section "existing installation, non-interactive (-y)"
EXIST_APP="$WORK/existing/app"
rm -rf "$WORK/existing"; mkdir -p "$EXIST_APP"
cp "$RELEASE_DIR/$ASSET" "$EXIST_APP/ovnode"; chmod 0755 "$EXIST_APP/ovnode"
printf 'NODE_NAME=eu-1\nAPI_KEY=keep-me\nSERVICE_PORT=2083\n' > "$EXIST_APP/.env"
chmod 600 "$EXIST_APP/.env"
env_sum="$(sha256sum "$EXIST_APP/.env" | awk '{print $1}')"
run_case existing-y "$EXIST_APP" -- -y
expect_status 3 "$RC" "an existing node with -y exits 3"
expect_in "$WORK/existing-y.log" "Already installed" "it says the node is already installed"
expect_not_in "$WORK/existing-y.log" "MARK-reached-do_install" "it never reinstalls over the node"
expect_eq 0 "$(curl_calls)" "it downloads nothing"
expect_eq "$env_sum" "$(sha256sum "$EXIST_APP/.env" | awk '{print $1}')" "the node identity is untouched"
if [[ -x "$EXIST_APP/ovnode" ]]; then ok "the installed binary is untouched"; else bad "the installed binary was replaced or removed"; fi

# ── Existing installation, interactive ─────────────────────────────────
# On a terminal the operator gets the menu, not an error. Answer 3 = quit:
# nothing updated, nothing removed.
section "existing installation, interactive (pty)"
EXIST_TTY_APP="$WORK/existing-tty/app"
rm -rf "$WORK/existing-tty"; mkdir -p "$EXIST_TTY_APP"
cp "$RELEASE_DIR/$ASSET" "$EXIST_TTY_APP/ovnode"; chmod 0755 "$EXIST_TTY_APP/ovnode"
printf 'NODE_NAME=eu-1\nAPI_KEY=keep-me\n' > "$EXIST_TTY_APP/.env"
if ! command -v script >/dev/null 2>&1; then
    skip "no util-linux 'script' on this host — the terminal path is not exercised"
else
    run_case existing-tty "$EXIST_TTY_APP" --tty 3
    expect_status 0 "$RC" "quitting the already-installed menu exits 0"
    expect_in "$WORK/existing-tty.log" "already installed" "the menu says the node is already installed"
    expect_not_in "$WORK/existing-tty.log" "MARK-reached-do_install" "it never reinstalls over the node"
    expect_not_in "$WORK/existing-tty.log" "MARK-reached-do_update" "answering quit updates nothing"
    expect_not_in "$WORK/existing-tty.log" "MARK-reached-do_uninstall" "answering quit removes nothing"
fi

# ── A node whose binary was deleted ────────────────────────────────────
# .env is still the identity of a live node. load_helpers would otherwise
# download a fresh binary straight over it, which is a reinstall nobody asked
# for — refuse instead, and download nothing.
section "existing node, binary missing from APP_DIR"
HALF_APP="$WORK/half/app"
rm -rf "$WORK/half"; mkdir -p "$HALF_APP"
printf 'NODE_NAME=eu-1\nAPI_KEY=keep-me\n' > "$HALF_APP/.env"
half_sum="$(sha256sum "$HALF_APP/.env" | awk '{print $1}')"
run_case half-y "$HALF_APP" -- -y
expect_status 3 "$RC" "a node with only .env left still exits 3"
expect_in "$WORK/half-y.log" "Already installed" "it is reported as already installed"
expect_not_in "$WORK/half-y.log" "MARK-reached-do_install" "it is not reinstalled over"
expect_eq 0 "$(curl_calls)" "nothing is downloaded into it"
expect_eq "$half_sum" "$(sha256sum "$HALF_APP/.env" | awk '{print $1}')" "its .env is untouched"

# ── Debris from an interrupted bootstrap ───────────────────────────────
# A directory left by a download that died between mkdir and .env. There is no
# way to tell it from a node whose .env was deleted by hand, so it is reported,
# installed over, and never deleted: the leftover file must still be there.
section "leftover bootstrap directory"
DEBRIS_APP="$WORK/debris/app"
rm -rf "$WORK/debris"; mkdir -p "$DEBRIS_APP"
printf 'partial download\n' > "$DEBRIS_APP/ovnode"   # not executable: the interrupted fetch
printf 'unrelated payload\n' > "$DEBRIS_APP/leftover.dat"
run_case debris-y "$DEBRIS_APP" -- -y
expect_status 0 "$RC" "an interrupted bootstrap does not stop the install"
expect_in "$WORK/debris-y.log" "interrupted bootstrap" "the leftover directory is named, not mistaken for a node"
expect_in "$WORK/debris-y.log" "leftover.dat" "the report lists what was there"
expect_not_in "$WORK/debris-y.log" "Already installed" "it is not reported as an existing node"
expect_in "$WORK/debris-y.log" "MARK-reached-do_install" "the install proceeds"
if [[ -f "$DEBRIS_APP/leftover.dat" ]]; then ok "the leftover file was not deleted"; else bad "the leftover file was deleted"; fi
if [[ -x "$DEBRIS_APP/ovnode" ]]; then ok "the interrupted download was replaced by a complete binary"; else bad "the bootstrap did not recover a runnable binary"; fi

# ── Unit files left from an earlier install ────────────────────────────
# The app directory is gone but the units are still on the box. Installing is
# refused (a second identity would be minted); uninstall is allowed, because
# cleaning exactly this up is what it is for.
section "OVNode unit files, no node in APP_DIR"
UNIT_APP="$WORK/unitonly/app"
UNIT_DIR="$WORK/unitonly/units"
rm -rf "$WORK/unitonly"; mkdir -p "$UNIT_APP" "$UNIT_DIR"
printf 'unit\n' > "$UNIT_DIR/ovnode.service"
run_case_unit() { run_installer "$WORK/$1.log" "$UNIT_APP" "$UNIT_DIR" -- "${@:2}"; }
run_case_unit unitonly-install -y
expect_status 3 "$RC" "install over leftover units exits 3"
expect_in "$WORK/unitonly-install.log" "unit files remains" "it names the leftover units"
expect_not_in "$WORK/unitonly-install.log" "MARK-reached-do_install" "it does not install over them"
expect_eq 0 "$(curl_calls)" "it downloads nothing"
if [[ -f "$UNIT_DIR/ovnode.service" ]]; then ok "the leftover unit was not deleted"; else bad "the leftover unit was deleted"; fi
scratch_before="$(ls -d "${TMPDIR:-/tmp}"/ovnode.helpers.* 2>/dev/null | wc -l)"
run_case_unit unitonly-uninstall uninstall -y
expect_status 0 "$RC" "uninstall is still allowed with only units left"
expect_in "$WORK/unitonly-uninstall.log" "MARK-reached-do_uninstall" "uninstall reaches its step"
expect_eq "$scratch_before" "$(ls -d "${TMPDIR:-/tmp}"/ovnode.helpers.* 2>/dev/null | wc -l)" "its scratch directory is removed"
expect_eq "ovnode.service " "$(ls -A "$UNIT_DIR" | tr '\n' ' ')" "the unit is still there — the real do_uninstall was stubbed"

# ── Node data with no node around it ───────────────────────────────────
# What a half-finished uninstall (or a hand-cleaned APP_DIR) leaves: the data
# directory and its PKI, no .env. Installing would mint a second identity and
# a second API key beside a CA that may still be serving, so it refuses — and
# removes nothing.
section "node data at DATA_BASE, no node in APP_DIR"
DATA_APP="$WORK/nodedata/app"
DATA_STORE="$WORK/nodedata/data"
rm -rf "$WORK/nodedata"; mkdir -p "$DATA_APP/data" "$DATA_STORE"
printf 'ca-key
' > "$DATA_APP/data/ca.key"
printf 'ca-key
' > "$DATA_STORE/ca.key"
data_sum="$(sha256sum "$DATA_STORE/ca.key" | awk '{print $1}')"
run_case nodedata-y "$DATA_APP" -- -y
expect_status 3 "$RC" "node data without a node exits 3"
expect_in "$WORK/nodedata-y.log" "node data remains at" "it names the node data"
expect_not_in "$WORK/nodedata-y.log" "MARK-reached-do_install" "it does not install over the data"
if [[ -f "$DATA_APP/data/ca.key" ]]; then ok "the data beside APP_DIR was not deleted"; else bad "the data beside APP_DIR was deleted"; fi
if [[ "$(ls -A "$DATA_APP" | tr '\n' ' ')" == "data " ]]; then ok "APP_DIR was not written into"; else bad "APP_DIR was written into: $(ls -A "$DATA_APP")"; fi

# ── A command that acts on an installed node does not bootstrap one ────
# `uninstall` on a fresh box used to download a release and write a binary into
# APP_DIR before reporting "not installed": a box changed by a command that had
# already decided it could do nothing. It must refuse before fetching.
section "uninstall on a fresh box"
NOOP_APP="$WORK/noop/app"
rm -rf "$WORK/noop"; mkdir -p "$WORK/noop"
run_case noop-uninstall "$NOOP_APP" -- uninstall -y
expect_status 4 "$RC" "uninstall on a fresh box exits 4 (not installed)"
expect_eq 0 "$(curl_calls)" "uninstall bootstraps nothing"
if [[ -e "$NOOP_APP" ]]; then bad "uninstall created $NOOP_APP"; else ok "nothing was written to the filesystem"; fi

# ── ...and still runs on a box that has one ────────────────────────────
# The other half of the guard: an installed node's commands must not be
# refused by it.
section "uninstall on an installed box"
UN_APP="$WORK/uninstalled/app"
rm -rf "$WORK/uninstalled"; mkdir -p "$UN_APP"
cp "$RELEASE_DIR/$ASSET" "$UN_APP/ovnode"; chmod 0755 "$UN_APP/ovnode"
printf 'NODE_NAME=eu-1\nAPI_KEY=keep-me\n' > "$UN_APP/.env"
run_case un-installed "$UN_APP" -- uninstall -y
expect_status 0 "$RC" "uninstall on an installed box is allowed through"
expect_in "$WORK/un-installed.log" "MARK-reached-do_uninstall" "it reaches the uninstall step"

# ── Local build still bypasses the installed check ─────────────────────
# The dev loop rsyncs into APP_DIR on every run, so "already installed" must
# not stop it. No go toolchain here: reaching "go is required" is the proof
# that do_local_build ran and the run did not exit 3 first.
section "local build (--local) behaviour preserved"
LOCAL_APP="$WORK/local/app"
SRC_FAKE="$WORK/local/src"
rm -rf "$WORK/local"; mkdir -p "$LOCAL_APP" "$SRC_FAKE"
printf 'NODE_NAME=eu-1\nAPI_KEY=keep-me\n' > "$LOCAL_APP/.env"     # looks installed
printf 'module ovnode\n\ngo 1.27\n' > "$SRC_FAKE/go.mod"
if ! command -v rsync >/dev/null 2>&1 || ! command -v go >/dev/null 2>&1; then
    run_case local-y "$LOCAL_APP" -- --local "$SRC_FAKE" -y
    expect_status 1 "$RC" "a local build without its toolchain fails on the toolchain"
    expect_in "$WORK/local-y.log" "required for a local install" "it failed inside do_local_build"
    expect_not_in "$WORK/local-y.log" "Already installed" "--local is not blocked by an installed node"
else
    skip "this host has rsync and go, so the missing-toolchain case cannot be reproduced"
    skip "--local with a toolchain would build the real binary"
fi

# ── The predicates themselves ──────────────────────────────────────────
# install_state_of is the whole fix in one function; check every state it can
# return, including the ones the end-to-end cases cannot cheaply build.
section "install_state_of"
state_of() {  # state_of <app dir> [<systemd dir>]
    ( set +Eeuo pipefail
      . "$INSTALL_SH"
      APP_DIR="$1"
      SYSTEMD_DIR="${2:-$WORK/no-units}"
      install_state_of "$APP_DIR" ) 2>/dev/null
}
probe="$WORK/probe"; rm -rf "$probe"; mkdir -p "$probe/empty" "$probe/installed" "$probe/units" "$probe/unitonly"
printf 'x\n' > "$probe/installed/.env"
printf 'unit\n' > "$probe/units/ovnode.service"
printf 'not a dir\n' > "$probe/afile"

mkdir -p "$probe/binok" "$probe/truncated" "$probe/withdata/data"
printf '#!/bin/sh\ntrue\n' > "$probe/binok/ovnode"; chmod 0755 "$probe/binok/ovnode"
printf 'partial\n' > "$probe/truncated/ovnode"
printf 'pk\n' > "$probe/withdata/data/ca.key"

expect_eq absent   "$(state_of "$probe/missing")"        "a missing directory is absent"
expect_eq bootstrap "$(state_of "$probe/empty")"          "an empty directory is bootstrap debris"
expect_eq installed "$(state_of "$probe/installed")"      ".env makes it an installed node"
expect_eq installed "$(state_of "$probe/binok")"          "a runnable binary makes it an installed node"
expect_eq unit-only "$(state_of "$probe/unitonly" "$probe/units")" "an OVNode unit with no node is unit-only"
expect_eq bootstrap "$(state_of "$probe/truncated")"      "a truncated, non-executable binary is bootstrap debris"
expect_eq node-data "$(state_of "$probe/withdata")"       "node data with no node is node-data"
expect_eq not-a-directory "$(state_of "$probe/afile")"    "a file at APP_DIR is not an install"

# ── Summary ────────────────────────────────────────────────────────────
printf '\n%s passed, %s failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]] || exit 1
exit 0
