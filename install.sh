#!/usr/bin/env bash
# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT
#
# OVNode — OpenVPN node agent installer.
#
#   zero-question: bash <(curl -Ls URL)
#   wizard       : bash <(curl -Ls URL) interactive
#   no terminal  : OVN_KEY=... OVN_VPN_PORTS=1194,443 bash <(curl -Ls URL) -y
#
# Commands: install (default) | update | recover-update | repair-unit |
#           uninstall | interactive | version-script | help
# Modes   : host (systemd, default) | --docker (see scripts/compose/entrypoint.sh)
#           | --local (build from a checkout, fetch nothing)
# Day-to-day ops (status, logs, backup, TLS, completion) live in the operator
# CLI: ovnode.
#
# Non-interactive: -y never prompts, OVN_* env vars mirror
# every setting, CLI wins. Exit codes: 0 ok · 1 error · 2 usage ·
# 3 already installed · 4 not installed. Everything else is in --help.

set -Eeuo pipefail

# ── Configuration ──────────────────────────────────────────────────────────
VERSION="1.3.0"
# Forks: point source downloads (and update pulls) at your own repo.
REPO="${OVN_REPO:-anonysec/OVNode}"
# Versioned GitHub Release tarballs only: verified checksum, no git needed.
SRC="release"
# OVN_APP_DIR lets tests run status/uninstall on a box already hosting a node.
APP_DIR="${OVN_APP_DIR:-/opt/ovnode}"
DATA_BASE="/var/lib/ovnode"
OPENVPN_ROOT="/etc/openvpn"
# The agent and the OpenVPN hook are the same Go binary. It lives where the
# server.conf writer points the hooks, so there is exactly one copy of it.
AGENT_BIN="${OPENVPN_ROOT}/ovnode/scripts/ovnode"
DEFAULT_PORT=2083
DEFAULT_VPN=1194
SYSTEMD_SERVICE="ovnode.service"
NAT_SERVICE="ovnode-nat.service"
OPENVPN_SERVICE="ovnode-openvpn.service"
CLEANUP_SERVICE="ovnode-cleanup.service"
CLEANUP_TIMER="ovnode-cleanup.timer"
NAT_SCRIPT="/usr/local/sbin/ovnode-nat.sh"
NAT_CONF="/etc/default/ovnode-nat"
SYSCTL_CONF="/etc/sysctl.d/99-ovnode.conf"
LOGROTATE_CONF="/etc/logrotate.d/ovnode"
BIN_DIR="${OVN_BIN_DIR:-/usr/local/bin}"
CLI_NAME="ovnode"

# Exit codes (documented in --help; stable for automation)
EX_OK=0 EX_ERROR=1 EX_USAGE=2 EX_ALREADY=3 EX_NOTINSTALLED=4

# ── Defaults ───────────────────────────────────────────────────────────
ACTION="install"
PORT="${OVN_PORT:-}"
API_KEY="${OVN_KEY:-}"
VPN_PORTS="${OVN_VPN_PORTS:-}"
VPN_PROTO="${OVN_PROTO:-}"
NODE_NAME="${OVN_NAME:-}"
TLS_METHOD="${OVN_TLS:-selfsigned}"
TLS_DOMAIN="${OVN_TLS_DOMAIN:-}"
TLS_KEY="${OVN_TLS_KEY:-}"
TLS_CERT="${OVN_TLS_CERT:-}"
DOCKER="${OVN_DOCKER:-0}"
IPV6="${OVN_IPV6:-0}"
NO_NAT="${OVN_NO_NAT:-0}"
YES="${OVN_YES:-0}"
PURGE="${OVN_PURGE:-0}"
QUIET="${OVN_QUIET:-0}"
LOCAL="${OVN_LOCAL:-0}"
SRC_DIR="${OVN_SRC_DIR:-$PWD}"
DEST_DIR="${OVN_DEST_DIR:-}"
PIN="${OVN_VERSION:-}"
# 1 when the caller passed a CLI flag (env defaults do not count).
CLI_FLAGS=0
CMD_GIVEN=0
INTERACTIVE=0
# Set by the start menu: 1 = Express (no further questions).
EXPRESS=0
LOGS_ARG=""
AUTO_BACKUP_ACTION="" BACKUP_TIME="" BACKUP_KEEP=""
# Any OVN_* input present (mirrors CLI flags for early validation / no menu).
ENV_INPUTS=0
for _ovn_var in OVN_PORT OVN_KEY OVN_VPN_PORTS OVN_PROTO OVN_NAME OVN_TLS \
                OVN_TLS_DOMAIN OVN_TLS_KEY OVN_TLS_CERT OVN_DOCKER OVN_IPV6 OVN_NO_NAT; do
    if [[ -n "${!_ovn_var:-}" ]]; then ENV_INPUTS=1; fi
done
unset _ovn_var
# Derived by validate_input:
VPN_PORT="" EXTRA_PORTS=""

# ── Output helpers ─────────────────────────────────────────────────────
# All human-readable output goes to stderr, so stdout stays clean for callers.
NC=$'\033[0m'; B=$'\033[1m'
WH=$'\033[97m'; GR=$'\033[32m'; RD=$'\033[31m'
YL=$'\033[33m'; CY=$'\033[36m'; GY=$'\033[90m'
[[ -t 2 ]] || { NC=''; B=''; WH=''; GR=''; RD=''; YL=''; CY=''; GY=''; }

# ── Bootstrap ──────────────────────────────────────────────────────────
# The helpers this installer needs live in lib.sh, and lib.sh lives inside the
# binary the installer is about to fetch. So the fetch comes first and the
# helpers come out of the binary that was just verified: the scripts on a box
# are the ones the binary shipped, not the ones a branch happened to carry
# when the installer was written.
#
# Until then the installer has exactly one helper of its own. `die` arrives
# with lib.sh; `fail` is the same error path for the window before it.
fail() { printf '\n  %bError:%b %s\n\n' "${RD:-}" "${NC:-}" "$1" >&2; exit "${2:-$EX_ERROR}"; }

trap 'echo -e "\n  ${RD}Interrupted.${NC}" >&2; exit 130' INT TERM
trap 'render_warn "Command failed near line $LINENO (running: ${BASH_COMMAND:0:80})"' ERR

# ── Dependency checks ──────────────────────────────────────────────────
OS_ID="" OS_NAME="" PKG_INSTALL="" PKG_UPDATE=""

detect_os() {
    [[ -f /etc/os-release ]] || die "Unsupported OS — no /etc/os-release found."
    # /etc/os-release defines its own VERSION — keep the app version.
    local _app_version="$VERSION"
    # shellcheck disable=SC1091
    . /etc/os-release
    VERSION="$_app_version"
    OS_ID="${ID:-}"; OS_NAME="${PRETTY_NAME:-$OS_ID}"
    case "$OS_ID" in
        debian|ubuntu)      PKG_UPDATE="apt-get update -qq";  PKG_INSTALL="apt-get install -y -qq" ;;
        rhel|centos|rocky|almalinux|fedora)
            if command -v dnf >/dev/null 2>&1; then
                PKG_UPDATE="dnf -q makecache"; PKG_INSTALL="dnf install -y -q"
            else
                PKG_UPDATE="yum -q makecache"; PKG_INSTALL="yum install -y -q"
            fi ;;
        arch)               PKG_UPDATE="pacman -Sy --noconfirm"; PKG_INSTALL="pacman -S --noconfirm" ;;
        alpine)             PKG_UPDATE="apk update -q";          PKG_INSTALL="apk add -q" ;;
        *) die "Unsupported distribution: ${OS_ID:-unknown}" ;;
    esac
}

pkg_install() {
    render_line "Installing: $*"
    $PKG_UPDATE >/dev/null 2>&1 || true
    $PKG_INSTALL "$@" >/dev/null 2>&1 || die "Failed to install: $*"
}

# ── Preconditions ──────────────────────────────────────────────────────
check_deps() {
    local missing=() cmd
    for cmd in curl tar openssl git; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    [[ ${#missing[@]} -eq 0 ]] || pkg_install "${missing[@]}"
    if [[ "$DOCKER" -eq 0 ]] && ! command -v openvpn >/dev/null 2>&1; then
        render_line "Installing OpenVPN + easy-rsa (for client PKI)..."
        pkg_install openvpn easy-rsa
    fi
    render_ok "System dependencies present"
}

# ── Validation ─────────────────────────────────────────────────────────

# MAJOR.MINOR.PATCH, optional leading v, optional pre-release or build suffix
# (1.2.3-rc1, 1.2.3+build5). The tag it resolves to is "v" + this (see
# release_url), so both spellings of the same release work.
valid_release_version() {
    [[ "$1" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]
}

# Splits VPN_PORTS ("1194,443,8443") into VPN_PORT (primary listener) and
# EXTRA_PORTS (comma separated, redirected to the primary).
parse_vpn_ports() {
    local raw="${VPN_PORTS:-$DEFAULT_VPN}" seen=" " port
    VPN_PORT="" EXTRA_PORTS=""
    IFS=',' read -ra _ports <<< "${raw// /}"
    for port in "${_ports[@]}"; do
        [[ -z "$port" ]] && continue
        is_port "$port" || die "Invalid OpenVPN port: '$port'" "$EX_USAGE"
        [[ "$seen" == *" $port "* ]] && continue
        seen+="$port "
        if [[ -z "$VPN_PORT" ]]; then
            VPN_PORT="$port"
        else
            EXTRA_PORTS="${EXTRA_PORTS:+$EXTRA_PORTS,}$port"
        fi
    done
    [[ -n "$VPN_PORT" ]] || die "At least one OpenVPN port is required" "$EX_USAGE"
}

# One place mints the key, so the Ready card cannot claim "generated" for a
# key the operator supplied.
generate_api_key() {
    API_KEY="$(openssl rand -hex 32)"
    KEY_GENERATED=1
}

validate_input() {
    is_port "$PORT" || die "Invalid service port: '$PORT'" "$EX_USAGE"
    parse_vpn_ports
    [[ "$VPN_PORT" == "$PORT" ]] && die "OpenVPN port and service port must differ" "$EX_USAGE"
    # Normalized early so every consumer sees tcp|udp only (default udp).
    VPN_PROTO="$(echo "${VPN_PROTO:-udp}" | tr '[:upper:]' '[:lower:]')"
    case "$VPN_PROTO" in
        udp|tcp) ;;
        *) die "Invalid transport '$VPN_PROTO' (use udp or tcp)" "$EX_USAGE" ;;
    esac
    [[ -n "$NODE_NAME" ]] || NODE_NAME="ovnode"
    [[ "$NODE_NAME" =~ ^[A-Za-z0-9_-]{1,64}$ ]] || die "Invalid node name" "$EX_USAGE"
    [[ -n "$API_KEY" ]] || generate_api_key
    [[ ${#API_KEY} -ge 16 ]] || die "API key must be at least 16 characters (openssl rand -hex 32)" "$EX_USAGE"
    case "$TLS_METHOD" in
        letsencrypt|letsencrypt-ip|selfsigned|custom) ;;
        none) die "Plain HTTP is not allowed — pick selfsigned (default), letsencrypt, letsencrypt-ip or custom" "$EX_USAGE" ;;
        *) die "Invalid TLS method: '$TLS_METHOD'" "$EX_USAGE" ;;
    esac
    if [[ "$TLS_METHOD" == "letsencrypt" || "$TLS_METHOD" == "letsencrypt-ip" ]]; then
        [[ -n "$TLS_DOMAIN" ]] || die "--tls-domain is required for Let's Encrypt" "$EX_USAGE"
    fi
    if [[ "$TLS_METHOD" == "custom" ]]; then
        [[ -f "$TLS_KEY" && -f "$TLS_CERT" ]] || die "Custom TLS key/cert files not found" "$EX_USAGE"
    fi
}

port_in_use() {
    command -v ss >/dev/null 2>&1 || return 1
    ss -ltn 2>/dev/null | awk -v p=":${1}$" '$4 ~ p {exit 0} END {exit 1}'
}

find_free_port() {
    local port="${1:-$DEFAULT_PORT}"
    while port_in_use "$port"; do ((port++)); done
    echo "$port"
}

vpn_ports_label() {
    if [[ -n "$EXTRA_PORTS" ]]; then
        echo "${VPN_PORT} (+ redirects: ${EXTRA_PORTS})"
    else
        echo "$VPN_PORT"
    fi
}

# ── Release fetch with retry ───────────────────────────────────────────
# The release publishes bare per-platform binaries, each with a .sha256
# sidecar. Nothing else: no tarball, no source tree, no helper scripts to
# fetch. The installer downloads the product and its checksum, and the product
# carries everything else it needs.
detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)  printf 'amd64' ;;
        aarch64|arm64) printf 'arm64' ;;
        *) fail "Unsupported architecture: $(uname -m) (need x86_64 or aarch64)" ;;
    esac
}

release_asset() { printf 'ovnode-linux-%s' "$(detect_arch)"; }

release_url() {
    printf 'https://github.com/%s/releases/download/v%s/%s' \
        "$REPO" "$VERSION" "$(release_asset)"
}

release_checksum_url() { printf '%s.sha256' "$(release_url)"; }

IMAGE_REPO="ghcr.io/${REPO,,}"

# ── Transactional update state ────────────────────────────────────────
# Journal and lock live beside node state (host paths in both modes: Docker
# bind-mounts DATA_BASE). The maintenance marker lives inside the node's data
# dir so the agent sees the same file the installer writes. Staging and
# previous live beside the app.
UPDATE_STATE="${DATA_BASE}/update-state.json"
update_marker() { printf '%s/update-maintenance' "$(node_data_dir)"; }
UPDATE_STAGE="$(dirname "$APP_DIR")/.ovnode.staging"
UPDATE_PREVIOUS="$(dirname "$APP_DIR")/.ovnode.previous"
OP_LOCK="${DATA_BASE}/.operation.lock"
OP_LOCK_HELD=0

operation_begin() {
    local name="$1" owner=""
    mkdir -p "$DATA_BASE"
    if ! mkdir "$OP_LOCK" 2>/dev/null; then
        owner="$(cat "$OP_LOCK/pid" 2>/dev/null || true)"
        if [[ "$owner" =~ ^[0-9]+$ ]] && ! kill -0 "$owner" 2>/dev/null; then
            render_warn "Removing stale operation lock from process $owner"
            rm -rf "$OP_LOCK"
            mkdir "$OP_LOCK" || die "Another maintenance operation is running" "$EX_ERROR"
        else
            die "Another maintenance operation is running${owner:+ (process $owner)}. Try again later." "$EX_ERROR"
        fi
    fi
    printf '%s\n' "$$" > "$OP_LOCK/pid"
    printf '%s\n' "$name" > "$OP_LOCK/action"
    chmod 700 "$OP_LOCK"
    OP_LOCK_HELD=1
}

operation_end() {
    [[ "$OP_LOCK_HELD" -eq 1 ]] || return 0
    rm -rf "$OP_LOCK"
    OP_LOCK_HELD=0
}

# Persist one transaction phase atomically at 0600, so a crash cannot leave a
# half-written journal.
update_state() {
    local phase="$1" from="${2:-unknown}" target="${3:-$VERSION}" backup="${4:-}" identity="${5:-}"
    mkdir -p "$DATA_BASE"
    "$AGENT_BIN" state write "$UPDATE_STATE" "$phase" "$from" "$target" "$backup" "$identity"
}

# sha256(node-name + API key): proves identity survived activation without
# ever persisting a secret in the journal.
identity_sha() {
    "$AGENT_BIN" identity-sha "$1" "$2"
}

# fetch_release_binary <dir>: download this platform's binary and its checksum,
# verify it, and install it as <dir>/ovnode. The .sha256 sidecar is mandatory:
# unverified code is never installed, so a missing sidecar is a failure and
# never a fallback to "install it anyway".
fetch_release_binary() {
    local dest="$1" work asset retries=0
    asset="$(release_asset)"
    work="$(mktemp -d /tmp/ovn.XXXXXX)"
    trap 'rm -rf "$work"' EXIT

    # Retry up to 3 times with exponential backoff. A release asset can be
    # visible on the web page before the CDN has it everywhere, and a single
    # 404 at that moment is not a reason to fail an install.
    while true; do
        if curl -fsSL --max-time 60 --retry 3 --retry-delay 2 --retry-max-time 120 \
            -o "$work/$asset" "$(release_url)" 2>/dev/null; then
            break
        fi
        retries=$((retries + 1))
        if [[ $retries -ge 3 ]]; then
            rm -rf "$work"
            trap - EXIT
            fail "No release file for v$VERSION — see https://github.com/$REPO/releases"
        fi
        sleep $((2 ** retries))
    done

    curl -fsSL --max-time 30 --retry 2 -o "$work/$asset.sha256" "$(release_checksum_url)" \
        || { rm -rf "$work"; trap - EXIT; fail "Release checksum file is missing for v$VERSION"; }
    ( cd "$work" && sha256sum -c "$asset.sha256" >/dev/null ) \
        || { rm -rf "$work"; trap - EXIT; fail "Release checksum mismatch for v$VERSION — possible tampering or incomplete download"; }
    mkdir -p "$dest"
    install -m 0755 "$work/$asset" "$dest/ovnode"
    rm -rf "$work"
    trap - EXIT
    printf '  ok    release v%s verified and installed\n' "$VERSION" >&2
}

# Safety snapshot of every persistent state needed for rollback: identity
# (.env), node data dir, OpenVPN state, API TLS files. One manifest-linked
# tarball; state_restore consumes it after verification.
state_safety_bundle() {
    local from_version="$1" backup_root="/var/backups"
    local node_data; node_data="$(node_data_dir)"
    mkdir -p "$backup_root" "$node_data"
    "$AGENT_BIN" installer bundle "$APP_DIR" "$node_data" "$OPENVPN_ROOT" "$backup_root" "$NODE_NAME" "$from_version"
    # Retention for safety bundles.
    ls -t "$backup_root"/ovnode-state-pre-update-*.tar.gz 2>/dev/null | tail -n +6 | xargs -r rm -f
    return $?
}

# Restore state after a failed activation. Fails closed on any manifest or
# checksum problem; never extracts unsafe member names.
state_restore() {
    local bundle="$1"
    [[ -f "$bundle" ]] || return 1
    "$AGENT_BIN" installer restore "$bundle" "$APP_DIR" "$DATA_BASE" "$OPENVPN_ROOT"
}

# Authenticated "version openvpn_running" from the agent. Empty output means
# unreachable or rejected (identity broken).
node_api_status() {
    local key="$1" port="$2" tls="$3" scheme="http"
    [[ "$tls" != "none" ]] && scheme="https"
    curl -fskS --max-time 5 "${scheme}://127.0.0.1:${port}/sync/status" \
        -H "key: ${key}" 2>/dev/null \
        | grep -o '"version": *"[^"]*"' | head -1 | sed 's/.*"//;s/"$//' 2>/dev/null || true
}

write_env() {
    # TUNNEL_ADDRESS is deliberately not written here: the panel pushes it
    # via /sync/config.
    #
    # DATA_DIR is resolved through node_data_dir() so the file, the Docker
    # volume and the installer's own bookkeeping cannot disagree about the path.
    # On a fresh install there is no .env yet, so the helper falls back to the
    # base — which is the flat layout this now uses.
    cat > "$APP_DIR/.env" << EOF
NODE_NAME=${NODE_NAME}
DATA_DIR=$(node_data_dir)
SERVICE_PORT=${PORT}
API_KEY=${API_KEY}
OPENVPN_PORT=${VPN_PORT}
OVNODE_PROTO=${VPN_PROTO:-tcp}
TLS_METHOD=${TLS_METHOD}
$( if [[ -n "$EXTRA_PORTS" ]]; then echo "OVNODE_EXTRA_PORTS=${EXTRA_PORTS}"; fi )
$( if [[ "$IPV6" -eq 1 ]]; then echo "OVNODE_ENABLE_IPV6=1"; fi )
$( if [[ -n "$TLS_KEY" ]]; then echo "SSL_KEYFILE=${TLS_KEY}"; fi )
$( if [[ -n "$TLS_CERT" ]]; then echo "SSL_CERTFILE=${TLS_CERT}"; fi )
EOF
    chmod 600 "$APP_DIR/.env"
    render_ok ".env written"
}

# write_install_result <path>: the facts of this install, machine-readable.
#
# The output on the terminal is for a human; this file is for a program. A
# provisioning run that cannot see the terminal still needs the port, the
# service and the key. The values are escaped with %q so the file is safe to
# source even when one of them contains a space or a quote.
write_install_result() {
    local path="$1"
    mkdir -p "$(dirname "$path")"
    {
        printf 'OVNODE_VERSION=%q\n' "$VERSION"
        printf 'OVNODE_NAME=%q\n' "$NODE_NAME"
        printf 'OVNODE_API_PORT=%q\n' "$PORT"
        printf 'OVNODE_VPN_PORT=%q\n' "$VPN_PORT"
        printf 'OVNODE_VPN_EXTRA_PORTS=%q\n' "$EXTRA_PORTS"
        printf 'OVNODE_VPN_PROTO=%q\n' "$VPN_PROTO"
        printf 'OVNODE_TLS_METHOD=%q\n' "$TLS_METHOD"
        printf 'OVNODE_API_KEY=%q\n' "$API_KEY"
        printf 'OVNODE_DATA_DIR=%q\n' "$(node_data_dir)"
        printf 'OVNODE_SERVICE=%q\n' "$SYSTEMD_SERVICE"
        printf 'OVNODE_DOCKER=%q\n' "$DOCKER"
    } > "$path"
    chmod 600 "$path"
    render_ok "install result written to $path"
}

# ── The agent binary ───────────────────────────────────────────────────
#
# OpenVPN calls one connect hook and one disconnect hook, and the agent
# binary answers both — there is no second implementation to choose from.
# The server.conf writer points the hooks at that path, so the binary has to
# be there before OpenVPN starts.
#
# Docker sees the same file: the OpenVPN root is bind-mounted into the
# container, so the container calls the binary the host installed.
install_agent_binary() {
    mkdir -p "$(dirname "$AGENT_BIN")"
    [[ -x "${APP_DIR}/ovnode" ]] || return 1
    install -m 0755 "${APP_DIR}/ovnode" "$AGENT_BIN" || return 1
    render_ok "agent binary installed ($AGENT_BIN)"
}

# ── OpenVPN scaffolding ────────────────────────────────────────────────
ensure_openvpn_dirs() {
    mkdir -p "$OPENVPN_ROOT/server" "$OPENVPN_ROOT/ccd" \
             "$OPENVPN_ROOT/ovnode/users" "$OPENVPN_ROOT/ovnode/sessions" \
             "$OPENVPN_ROOT/ovnode/scripts" "$OPENVPN_ROOT/ovnode/usage"
    # Arch lacks the "nogroup" group the generated server.conf references.
    getent group nogroup >/dev/null 2>&1 || groupadd -r nogroup 2>/dev/null || true
    if [[ ! -e /dev/net/tun ]]; then
        mkdir -p /dev/net
        modprobe tun 2>/dev/null || true
        mknod /dev/net/tun c 10 200 2>/dev/null || true
        chmod 600 /dev/net/tun 2>/dev/null || true
    fi
    if [[ -e /dev/net/tun ]]; then
        render_ok "OpenVPN directories ready ($OPENVPN_ROOT), /dev/net/tun present"
    else
        render_warn "/dev/net/tun is missing — OpenVPN cannot start (Docker: mount it, bare-metal: modprobe tun)"
    fi
}

write_openvpn_unit() {
    cat > "/etc/systemd/system/$OPENVPN_SERVICE" << UNIT
[Unit]
Description=OVNode OpenVPN daemon
After=network-online.target
Wants=network-online.target
Documentation=https://github.com/anonysec/OVNode

[Service]
Type=simple
ExecStart=/usr/sbin/openvpn --config $OPENVPN_ROOT/server/server.conf
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
RuntimeDirectory=ovnode-openvpn
RuntimeDirectoryMode=0755

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable "$OPENVPN_SERVICE" >/dev/null 2>&1 || true
}

start_openvpn_service() {
    # The agent generates server.conf + PKI on first boot.
    if has_systemd; then
        write_openvpn_unit
        systemctl restart "$OPENVPN_SERVICE" >/dev/null 2>&1 && \
            render_ok "OpenVPN server service started" || \
            render_warn "Could not start $OPENVPN_SERVICE — check: journalctl -u $OPENVPN_SERVICE -n 50"
    elif command -v rc-service >/dev/null 2>&1; then
        rc-update add openvpn default >/dev/null 2>&1 || true
        rc-service openvpn start >/dev/null 2>&1 && render_ok "OpenVPN started (OpenRC)" || render_warn "Start OpenVPN manually"
    else
        render_warn "No init system detected — start OpenVPN manually: openvpn --config $OPENVPN_ROOT/server/server.conf"
    fi
}

write_cleanup_units() {
    # The purge runs the same implementation as the hooks: the agent binary.
    local purge_cmd="${AGENT_BIN} hook purge-stale"
    cat > "/etc/systemd/system/$CLEANUP_SERVICE" << UNIT
[Unit]
Description=OVNode stale session marker purge

[Service]
Type=oneshot
ExecStart=${purge_cmd}
UNIT
    cat > "/etc/systemd/system/$CLEANUP_TIMER" << UNIT
[Unit]
Description=Daily OVNode stale session purge

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
UNIT
    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable --now "$CLEANUP_TIMER" >/dev/null 2>&1 \
        && render_ok "Stale session purge scheduled ($CLEANUP_TIMER)" \
        || render_warn "Could not enable $CLEANUP_TIMER"
}

# Docker mode post-flight: a native daemon holding 1194/7505 on the shared host
# network namespace crash-loops the container's OpenVPN (mgmt bind EADDRINUSE)
# while the agent health check stays green.
check_container_openvpn() {
    local cid=""
    cid="$(docker compose -f "$(compose_file)" ps -q 2>/dev/null | head -n 1)"
    if [[ -n "$cid" ]] && docker exec "$cid" pgrep -x openvpn >/dev/null 2>&1; then
        render_ok "OpenVPN running in container"
    else
        render_warn "OpenVPN not detected in container — check: docker logs ${NODE_NAME}; host stray check: ss -tlnp | grep -E '1194|7505'"
    fi
}

stop_native_openvpn() {
    # Docker mode only: a native daemon holding 1194/7505 crash-loops the
    # container's OpenVPN on the shared host network namespace. Host installs
    # are untouched — start_openvpn_service owns that path.
    if has_systemd; then
        if systemctl is-active --quiet openvpn-server@server 2>/dev/null; then
            run "Stopping conflicting native openvpn-server@server (Docker mode)" \
                systemctl stop openvpn-server@server
        fi
        systemctl disable openvpn-server@server >/dev/null 2>&1 || true
    elif command -v rc-service >/dev/null 2>&1; then
        rc-service openvpn stop >/dev/null 2>&1 || true
    fi
}

# ── Systemd units ──────────────────────────────────────────────────────
write_systemd_unit() {
    # ExecStart runs the Go binary that also answers the OpenVPN hooks.
    local exec_start="${AGENT_BIN} serve"
    cat > "/etc/systemd/system/$SYSTEMD_SERVICE" << UNIT
[Unit]
Description=OVNode OpenVPN Node Agent (${NODE_NAME})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${APP_DIR}
EnvironmentFile=${APP_DIR}/.env
ExecStart=${exec_start}
Restart=on-failure
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable "$SYSTEMD_SERVICE" >/dev/null 2>&1
    render_ok "systemd unit written: /etc/systemd/system/$SYSTEMD_SERVICE"
}

# ── Forwarding / NAT / multi-port redirects ────────────────────────────
# IP forwarding is a host sysctl in both modes (a container usually cannot
# write /proc/sys). The iptables rules live in one idempotent script owned by a
# oneshot unit, host mode only; Docker's entrypoint applies them itself.
write_sysctl() {
    cat > "$SYSCTL_CONF" << 'SYSCTL'
# OVNode: allow OpenVPN clients to route through this host
net.ipv4.ip_forward = 1
SYSCTL
    if [[ "$IPV6" -eq 1 ]]; then
        echo "net.ipv6.conf.all.forwarding = 1" >> "$SYSCTL_CONF"
    fi
    sysctl -p "$SYSCTL_CONF" >/dev/null 2>&1 || true
    render_ok "IP forwarding enabled ($SYSCTL_CONF)"
}

write_nat_files() {
    cat > "$NAT_CONF" << CONF
# OVNode NAT configuration (managed by install.sh)
VPN_PRIMARY_PORT=${VPN_PORT}
VPN_EXTRA_PORTS=${EXTRA_PORTS}
CONF

    cat > "$NAT_SCRIPT" << 'NAT'
#!/bin/bash
# OVNode NAT: masquerade VPN client traffic through the default uplink and
# redirect the extra VPN ports to the OpenVPN listener. Idempotent.
# Usage: ovnode-nat.sh [apply|cleanup]
set -u
CONF="/etc/default/ovnode-nat"
VPN_PRIMARY_PORT="" VPN_EXTRA_PORTS="" VPN_SUBNET="10.8.0.0/24" VPN_TUN_DEV="tun0"
# shellcheck disable=SC1090
[[ -f "$CONF" ]] && . "$CONF"

rule() {  # rule <add|del> <table> <chain> <args...>
    local op="$1" table="$2" chain="$3"; shift 3
    if [[ "$op" == "add" ]]; then
        iptables -t "$table" -C "$chain" "$@" 2>/dev/null || iptables -t "$table" -A "$chain" "$@"
    else
        iptables -t "$table" -D "$chain" "$@" 2>/dev/null || true
    fi
}

each_redirect() {  # each_redirect <add|del>
    local op="$1" port proto
    [[ -n "$VPN_PRIMARY_PORT" && -n "$VPN_EXTRA_PORTS" ]] || return 0
    for port in ${VPN_EXTRA_PORTS//,/ }; do
        for proto in tcp udp; do
            rule "$op" nat PREROUTING -p "$proto" --dport "$port" \
                -j REDIRECT --to-ports "$VPN_PRIMARY_PORT"
        done
    done
}

IFACE="$(ip route show default 2>/dev/null | awk '{print $5; exit}')"

# Docker and other hardening set FORWARD policy DROP, which kills masqueraded
# client traffic after POSTROUTING. Accept the VPN subnet through the
# DOCKER-USER admin hook (evaluated before Docker's own jumps; recreated
# empty by Docker, so re-added here on every apply).
forward_rules() {  # forward_rules <add|del>
    local op="$1"
    iptables -L DOCKER-USER -n >/dev/null 2>&1 || return 0
    rule "$op" filter DOCKER-USER -s "$VPN_SUBNET" -i "$VPN_TUN_DEV" -o "$IFACE" -j ACCEPT
    rule "$op" filter DOCKER-USER -i "$IFACE" -o "$VPN_TUN_DEV" \
        -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
}

case "${1:-apply}" in
    apply)
        if [[ -z "$IFACE" ]]; then echo "ovnode-nat: no default interface found" >&2; exit 1; fi
        rule add nat POSTROUTING -o "$IFACE" -j MASQUERADE
        each_redirect add
        forward_rules add
        ;;
    cleanup)
        [[ -n "$IFACE" ]] && rule del nat POSTROUTING -o "$IFACE" -j MASQUERADE
        each_redirect del
        [[ -n "$IFACE" ]] && forward_rules del
        ;;
    *) echo "usage: $0 [apply|cleanup]" >&2; exit 2 ;;
esac
NAT
    chmod +x "$NAT_SCRIPT"

    cat > "/etc/systemd/system/$NAT_SERVICE" << UNIT
[Unit]
Description=OVNode NAT (masquerade + VPN port redirects)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$NAT_SCRIPT apply
ExecStop=$NAT_SCRIPT cleanup

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable "$NAT_SERVICE" >/dev/null 2>&1
    if systemctl restart "$NAT_SERVICE" >/dev/null 2>&1; then
        if [[ -n "$EXTRA_PORTS" ]]; then
            render_ok "NAT enabled, ports ${EXTRA_PORTS} → ${VPN_PORT}"
        else
            render_ok "NAT enabled"
        fi
    else
        render_warn "Could not start NAT service — VPN clients may not route traffic"
    fi
}

setup_nat() {
    if [[ "$NO_NAT" -eq 1 ]]; then render_line "Skipping NAT setup (--no-nat)"; return 0; fi
    write_sysctl
    if [[ "$DOCKER" -eq 1 ]]; then
        render_line "Docker mode: NAT/redirect rules are applied inside the container (CAP_NET_ADMIN)"
        return 0
    fi
    if ! command -v iptables >/dev/null 2>&1; then
        pkg_install iptables iproute2
    fi
    write_nat_files
}

# ── Firewall ───────────────────────────────────────────────────────────
# Every VPN port opens both protocols: the panel can switch udp/tcp at runtime,
# and the extra-port redirects cover both.
open_firewall_ports() {
    local vpn_all="$VPN_PORT ${EXTRA_PORTS//,/ }" p
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow "$PORT/tcp" >/dev/null 2>&1
        for p in $vpn_all; do
            ufw allow "$p/udp" >/dev/null 2>&1
            ufw allow "$p/tcp" >/dev/null 2>&1
        done
        render_ok "UFW: allowed $PORT/tcp + VPN port(s) ${vpn_all// /, }"
    elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port="$PORT/tcp" >/dev/null 2>&1
        for p in $vpn_all; do
            firewall-cmd --permanent --add-port="$p/udp" >/dev/null 2>&1
            firewall-cmd --permanent --add-port="$p/tcp" >/dev/null 2>&1
        done
        firewall-cmd --reload >/dev/null 2>&1
        render_ok "firewalld: allowed $PORT/tcp + VPN port(s) ${vpn_all// /, }"
    fi
}

# Mirror of open_firewall_ports for uninstall, using the installed .env values
# (flags may differ from install time). Best-effort.
close_firewall_ports() {
    local env_get; env_get() { grep -E "^$1=" "$APP_DIR/.env" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"' || true; }
    local svc vpn extras p vpn_all
    svc="$(env_get SERVICE_PORT)"; : "${svc:=$DEFAULT_PORT}"
    vpn="$(env_get OPENVPN_PORT)"; : "${vpn:=$DEFAULT_VPN}"
    extras="$(env_get OVNODE_EXTRA_PORTS)"
    vpn_all="$vpn ${extras//,/ }"
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw delete allow "$svc/tcp" >/dev/null 2>&1 || true
        for p in $vpn_all; do
            ufw delete allow "$p/udp" >/dev/null 2>&1 || true
            ufw delete allow "$p/tcp" >/dev/null 2>&1 || true
        done
        render_ok "UFW: removed $svc/tcp + VPN port(s) ${vpn_all// /, }"
    elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --permanent --remove-port="$svc/tcp" >/dev/null 2>&1 || true
        for p in $vpn_all; do
            firewall-cmd --permanent --remove-port="$p/udp" >/dev/null 2>&1 || true
            firewall-cmd --permanent --remove-port="$p/tcp" >/dev/null 2>&1 || true
        done
        firewall-cmd --reload >/dev/null 2>&1 || true
        render_ok "firewalld: removed $svc/tcp + VPN port(s) ${vpn_all// /, }"
    fi
}

# ── Log rotation ───────────────────────────────────────────────────────
# `log-append openvpn.log` grows without bound and eventually fills a small
# VPS disk. Host installs SIGHUP the daemon (clean reopen, no teardown); Docker
# needs copytruncate because the daemon's PID namespace is unreachable from a
# host postrotate.
setup_logrotate() {
    if ! command -v logrotate >/dev/null 2>&1; then
        if [[ -n "$PKG_INSTALL" ]]; then
            pkg_install logrotate
        else
            render_warn "logrotate not found — install it so openvpn.log gets rotated"
            return 0
        fi
    fi
    if [[ "${DOCKER:-0}" -eq 1 ]]; then
        cat > "$LOGROTATE_CONF" << ROTATE
${OPENVPN_ROOT}/server/openvpn.log {
    size 10M
    rotate 3
    compress
    missingok
    notifempty
    copytruncate
}
ROTATE
    else
        cat > "$LOGROTATE_CONF" << ROTATE
${OPENVPN_ROOT}/server/openvpn.log {
    size 10M
    rotate 3
    compress
    missingok
    notifempty
    postrotate
        systemctl kill -s HUP $OPENVPN_SERVICE >/dev/null 2>&1 || true
    endscript
}
ROTATE
    fi
    cat >> "$LOGROTATE_CONF" << 'ROTATE'

/var/log/ovnode/hook-events.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    create 0640 root root
    postrotate
        # OpenVPN hooks continue to append to the new file; no signal needed
    endscript
}
ROTATE
    render_ok "Log rotation configured ($LOGROTATE_CONF)"
}

# ── Dev install from source ────────────────────────────────────────────
# Install from a checkout instead of a release: rsync the tree, build the
# binary, and run the same install the release path runs. Nothing is
# fetched, so nothing is verified — this is the dev loop, not what a server
# should run.
do_local_build() {
    local dest="${DEST_DIR:-$APP_DIR}"
    [[ -d "$SRC_DIR" ]] || fail "no source directory: $SRC_DIR"
    [[ -f "$SRC_DIR/go.mod" ]] || fail "no go.mod under $SRC_DIR — --local needs an OVNode checkout"
    command -v rsync >/dev/null 2>&1 || fail "rsync is required for a local install"
    command -v go >/dev/null 2>&1 || fail "go is required for a local install"
    [[ -n "$dest" && "$dest" != "/" ]] || fail "refusing to install into '$dest'"
    APP_DIR="$dest"
    DATA_BASE="$dest/data"
    mkdir -p "$dest"
    # --delete only reaches files not excluded, so a dest .env is never
    # transferred in and never deleted.
    rsync -a --delete --exclude '.git' --exclude '.slim' --exclude '.env' \
        "$SRC_DIR/" "$dest/"
    ( cd "$SRC_DIR" && go build -o "$dest/ovnode" ./cmd/ovnode ) \
        || fail "go build failed" "$EX_ERROR"
    # The renderer is not on disk yet: the binary that carries it is the one
    # this call is about to build.
    printf '  ok    built %s/ovnode from %s\n' "$dest" "$SRC_DIR" >&2
}

# load_helpers: put the shell helpers on disk and source them.
#
# For an install the binary is fetched first, because that is where the
# helpers come from. Every other action uses the installed binary: an update
# must not replace the binary it is running from, and an uninstall must not
# download anything in order to remove a node.
load_helpers() {
    if [[ ! -x "$APP_DIR/ovnode" ]]; then
        command -v curl >/dev/null 2>&1 || fail "curl is required to download the release"
        command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required to verify the release"
        fetch_release_binary "$APP_DIR"
    fi
    "$APP_DIR/ovnode" assets write --dest "$APP_DIR" >/dev/null \
        || fail "Could not write the installer helpers into $APP_DIR"
    # shellcheck disable=SC1091
    . "$APP_DIR/lib.sh"
}

# ── Docker ─────────────────────────────────────────────────────────────

ensure_docker() {
    if ! command -v docker >/dev/null 2>&1; then
        render_line "Installing Docker Engine..."
        if [[ "$PKG_INSTALL" == apt* ]]; then
            $PKG_UPDATE >/dev/null 2>&1 || true
            $PKG_INSTALL docker.io >/dev/null 2>&1 \
                || $PKG_INSTALL docker-ce >/dev/null 2>&1 \
                || die "Could not install Docker via apt. Install manually: https://docs.docker.com/engine/install/"
        else
            pkg_install docker docker-compose-plugin >/dev/null 2>&1 || pkg_install docker
        fi
        command -v docker >/dev/null 2>&1 || die "Docker binary not found"
    fi
    docker compose version >/dev/null 2>&1 || command -v docker-compose >/dev/null 2>&1 \
        || die "Docker Compose v2 is required (docker compose plugin)"
    render_ok "Docker present"
}

setup_docker() {
    ensure_docker

    # The image's entrypoint runs OpenVPN; the host needs only tun present.
    modprobe tun >/dev/null 2>&1 || true
    if [[ ! -c /dev/net/tun ]]; then
        mkdir -p /dev/net && mknod /dev/net/tun c 10 200 2>/dev/null || true
    fi
    [[ -c /dev/net/tun ]] || render_warn "/dev/net/tun missing — the VPN cannot start until the tun module is available"

    write_compose_file

    run "Pulling published OVNode image" \
        docker pull "${IMAGE_REPO}:${IMAGE_TAG:-$VERSION}"
    run "Starting container" \
        docker compose -f "$(compose_file)" up -d
}

# IMAGE_TAG overrides VERSION so updates and failovers can pin a release.
# Never builds locally: Docker installs consume published images only.
write_compose_file() {
    local compose tag
    compose="$(compose_file)"
    tag="${IMAGE_TAG:-$VERSION}"
    mkdir -p "$(node_data_dir)"

    # TLS material lives on host paths; mount read-only or the agent cannot
    # serve HTTPS. Let's Encrypt needs the whole tree: live/ symlinks archive/.
    local tls_mounts="" d f
    for f in "$TLS_KEY" "$TLS_CERT"; do
        [[ -n "$f" ]] || continue
        case "$f" in
            /etc/letsencrypt/*) d="/etc/letsencrypt" ;;
            *) d="$(dirname "$f")" ;;
        esac
        [[ "$tls_mounts" == *"- ${d}:${d}:ro"* ]] || tls_mounts+="      - ${d}:${d}:ro"$'\n'
    done

    cat > "$compose" << COMPOSE
services:
  ovnode:
    image: ${IMAGE_REPO}:${tag}
    container_name: ovnode-${NODE_NAME}
    restart: unless-stopped
    network_mode: host
    environment:
      SERVICE_PORT: ${PORT}
      API_KEY: ${API_KEY}
      DATA_DIR: /app/data
      OPENVPN_PORT: ${VPN_PORT}
      TLS_METHOD: ${TLS_METHOD}
      OVNODE_OPENVPN_ROOT: /etc/openvpn
$( if [[ -n "$EXTRA_PORTS" ]]; then echo "      OVNODE_EXTRA_PORTS: \"${EXTRA_PORTS}\""; fi )
$( if [[ "$IPV6" -eq 1 ]]; then echo "      OVNODE_ENABLE_IPV6: 1"; fi )
$( [[ -n "$TLS_KEY" ]] && echo "      SSL_KEYFILE: ${TLS_KEY}" )
$( [[ -n "$TLS_CERT" ]] && echo "      SSL_CERTFILE: ${TLS_CERT}" )
    volumes:
      - ${OPENVPN_ROOT}:/etc/openvpn
      - $(node_data_dir):/app/data
      - /dev/net/tun:/dev/net/tun
$( [[ -n "$tls_mounts" ]] && printf '%s' "$tls_mounts" )
    cap_add:
      - NET_ADMIN
    logging:
      options:
        max-size: "5m"
        max-file: "3"
COMPOSE
    # The compose file embeds the API key — keep it root-only, like .env.
    chmod 600 "$compose"
    render_ok "Compose file written: $compose (image ${IMAGE_REPO}:${tag})"
}

# ── Main install ───────────────────────────────────────────────────────
do_install() {
    render_stage "[1/7] Preflight"
    check_root
    check_deps
    render_ok "$(preflight_summary)"

    render_stage "[2/7] Download"
    if [[ "$LOCAL" -eq 0 ]]; then
        fetch_release_binary "$APP_DIR"
    else
        render_ok "built from checkout"
    fi

    render_stage "[3/7] Certificate"
    if [[ "$DOCKER" -eq 0 ]]; then
        cd "$APP_DIR"
        render_note "$(tls_summary)"
    fi
    setup_tls
    write_env
    render_ok "$(tls_summary)"

    local scheme="http"
    [[ "$TLS_METHOD" != "none" ]] && scheme="https"
    local host; host="$(primary_ip)"

    mkdir -p "$(node_data_dir)"
    ensure_openvpn_dirs
    install_agent_binary || die "The ovnode binary could not be installed" "$EX_ERROR"

    # The agent serves TLS from the node PKI and refuses to start without it,
    # so bootstrap the PKI before the unit starts. Idempotent: a re-install
    # on a box that already has a CA is a no-op.
    run "Generating node PKI" "$AGENT_BIN" ca init

    render_stage "[4/7] Runtime"
    if [[ "$DOCKER" -eq 1 ]]; then
        setup_docker
        render_ok "container"
    else
        if ! has_systemd; then
            render_ok "no systemd — start the agent by hand"
            render_warn "systemd not found — start the agent manually: $AGENT_BIN serve"
        else
            write_systemd_unit
            render_note "$SYSTEMD_SERVICE"
            systemctl_bounded restart "$SYSTEMD_SERVICE" >/dev/null 2>&1 \
                || die "Could not start $SYSTEMD_SERVICE"
            render_ok "active"
        fi
    fi

    # First boot generates the PKI + server.conf, so wait for /sync/health
    # before bringing up OpenVPN.
    render_stage "[5/7] Health"
    if ! wait_health_live "${scheme}://127.0.0.1:${PORT}/sync/health" 60; then
        render_fail "health" "no answer on /sync/health after 60s"
        render_next "ovnode logs 50" "$(installer_uninstall_command)"
        return 1
    fi
    render_ok "200"
    [[ "$DOCKER" -eq 1 ]] && check_container_openvpn

    render_stage "[6/7] VPN"
    # Docker runs the daemon inside the container (entrypoint-supervised) and
    # evicts any host daemon holding the VPN/management ports.
    if [[ "$DOCKER" -eq 0 ]]; then
        start_openvpn_service
        write_cleanup_units
    else
        stop_native_openvpn
    fi
    setup_nat
    setup_logrotate
    open_firewall_ports
    render_ok "$(vpn_ports_label)/$VPN_PROTO"

    render_stage "[7/7] Command"
    install_cli
    render_ok "$BIN_DIR/$CLI_NAME"

    write_install_result "$DATA_BASE/install-result.env"
    node_success_card "$scheme" "$host"
}

# The machine's own state, as the first line of the run. Nobody chose any of it
# and it decides whether the install can succeed, which is exactly what the
# preflight line is for. The port and TLS mode the operator DID choose are on
# the wizard's own screens.
preflight_summary() {
    local os="${OS_NAME:-linux}" free
    free="$(df -h --output=avail /opt 2>/dev/null | tail -1 | tr -d ' ')"
    printf '%s · %s free at /opt · :%s free' "$os" "${free:-?}" "$PORT"
}

installer_uninstall_command() {
    printf 'bash <(curl -sSL https://raw.githubusercontent.com/%s/main/install.sh) uninstall --purge -y' "$REPO"
}

node_success_card() {
    local scheme="$1" host="$2" tls_flag=0 key_note bundle where
    [[ "$TLS_METHOD" != "none" ]] && tls_flag=1
    bundle="ovnode://${host}:${PORT}?key=${API_KEY}&tls=${tls_flag}"
    # Name what the panel will reach: the public IP, or the domain when the
    # certificate names one. A node has no URL of its own — it is an address, a
    # key, and a place to read logs — so the card says exactly that.
    if [[ -n "${TLS_DOMAIN:-}" && "$TLS_METHOD" == "letsencrypt" ]]; then
        where="$TLS_DOMAIN:$PORT"
    else
        where="$host:$PORT"
    fi
    if [[ "${KEY_GENERATED:-0}" -eq 1 ]]; then
        key_note="  $(printf '%sgenerated — save this%s' "$GY" "$NC")"
    else
        key_note="  $(printf '%sthe key you supplied%s' "$GY" "$NC")"
    fi
    render_card "ready" "api key" "${API_KEY}${key_note}" \
        "node|$where" \
        "tls|$(tls_summary)" \
        "data|$(node_data_dir)" \
        "logs|$CLI_NAME logs -f"
    render_line "  $(printf '%slost it?  %s credentials%s' "$GY" "$CLI_NAME" "$NC")"
    render_line "  $(printf '%bpanel%s  Nodes → Add Node → paste the bundle below' "$GY" "$NC")"
    render_kv "bundle" "$bundle"
    render_line "  uninstall: $(installer_uninstall_command)"
    render_blank
}

tls_summary() {
    case "$TLS_METHOD" in
        selfsigned)     printf 'self-signed · turn TLS on in the panel' ;;
        letsencrypt)    printf "lets encrypt · %s" "$TLS_DOMAIN" ;;
        letsencrypt-ip) printf 'lets encrypt · %s · short-lived' "$TLS_DOMAIN" ;;
        custom)         printf 'custom · %s' "$TLS_CERT" ;;
        none)           printf 'none' ;;
        *)              printf '%s' "$TLS_METHOD" ;;
    esac
}

# ── Update ─────────────────────────────────────────────────────────────
# Transactional: safety bundle + code snapshot, staged candidate, maintenance
# marker, atomic rename, verified commit or automatic failover. Identity
# (name + API key) comes from .env, never regenerated here.
do_update() {
    [[ -d "$APP_DIR" ]] || die "Not installed ($APP_DIR missing)" "$EX_NOTINSTALLED"
    # The journal, the identity hash and the state bundle all run through the
    # installed binary; without it there is nothing to update.
    [[ -x "$AGENT_BIN" ]] || die "The node agent binary is missing ($AGENT_BIN) — reinstall instead of updating" "$EX_ERROR"
    check_root
    operation_begin update
    trap operation_end EXIT

    # Flatten the data directory, before the .env is re-read or the safety
    # bundle is taken. Both need to see the new location, and the bundle is the
    # last thing standing between a failed migration and a lost node — so it has
    # to be taken after, not before.
    #
    # Done here, in the installer, rather than in `ovn`: install.sh is what owns
    # .env, and the operator CLI never edits it.
    node_env_before_migration="$(env_get "$APP_DIR/.env" DATA_DIR)"
    flat_migration_needed=0
    if [[ -n "$node_env_before_migration" && "$node_env_before_migration" != "$DATA_BASE" ]]; then
        flat_migration_needed=1
    fi
    if (( flat_migration_needed )); then
        render_stage "Migrate data"
        if migrate_flat_data_dir; then
            render_ok "data directory flattened"
        else
            render_end
            die "Could not move the node data to $DATA_BASE — nothing was changed"
        fi
    fi

    # Recover install parameters from .env so `update` never silently changes
    # the configuration.
    local env_get; env_get() { grep -E "^$1=" "$APP_DIR/.env" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"' || true; }
    [[ -n "$NODE_NAME" ]] || NODE_NAME="$(env_get NODE_NAME)"
    : "${NODE_NAME:=ovnode}"
    [[ -n "$PORT" ]] || PORT="$(env_get SERVICE_PORT)"
    : "${PORT:=$DEFAULT_PORT}"
    [[ -n "$API_KEY" ]] || API_KEY="$(env_get API_KEY)"
    [[ -n "$API_KEY" ]] || die "Installed .env has no API key — refusing to rotate identity (restore .env or reinstall)" "$EX_ERROR"
    if [[ -z "$VPN_PORTS" ]]; then
        VPN_PORT="$(env_get OPENVPN_PORT)"; : "${VPN_PORT:=$DEFAULT_VPN}"
        EXTRA_PORTS="$(env_get OVNODE_EXTRA_PORTS)"
    else
        parse_vpn_ports
    fi
    # Keep the install's existing TLS mode: read it from .env unless the caller
    # passed --tls. Legacy nodes recording "none" still work.
    if [[ "$CLI_FLAGS" -eq 0 && -z "${OVN_TLS:-}" ]]; then
        TLS_METHOD="$(env_get TLS_METHOD)"
    fi
    : "${TLS_METHOD:=selfsigned}"
    # Recover everything not passed as a flag, so a refresh never drops TLS
    # mounts, extra ports or IPv6.
    [[ -n "$TLS_KEY" ]] || TLS_KEY="$(env_get SSL_KEYFILE)"
    [[ -n "$TLS_CERT" ]] || TLS_CERT="$(env_get SSL_CERTFILE)"
    if [[ -z "${OVN_IPV6:-}" && "$IPV6" -eq 0 ]]; then
        [[ "$(env_get OVNODE_ENABLE_IPV6)" == "1" ]] && IPV6=1
    fi

    render_line ""; render_line "Updating OVNode to v${VERSION}…"
    detect_os
    # A compose file means the install was --docker, even when `update` is
    # called without the flag.
    if [[ -f "$(compose_file)" ]]; then
        DOCKER=1
        render_line "Detected Docker deployment (compose file present)"
    fi
    local from_version safety snapshot scheme activated=0 identity
    from_version="$("$AGENT_BIN" version 2>/dev/null || true)"
    : "${from_version:=unknown}"
    identity="$(identity_sha "$NODE_NAME" "$API_KEY")"
    scheme="http"; [[ "$TLS_METHOD" != "none" ]] && scheme="https"
    update_state preflight "$from_version" "$VERSION" "" "$identity"

    render_stage "[1/6] Backup"
    safety="$(state_safety_bundle "$from_version")" || die "Could not create the mandatory state safety snapshot" "$EX_ERROR"
    [[ -n "$safety" && -f "$safety" ]] || die "The state safety snapshot was not created" "$EX_ERROR"
    snapshot="$(snapshot_code "$APP_DIR" "node" 2)"
    render_ok "$(basename "$safety" 2>/dev/null)"
    update_state staging "$from_version" "$VERSION" "$safety" "$identity"

    render_stage "[2/6] Stage"
    rm -rf "$UPDATE_STAGE"
    mkdir -p "$UPDATE_STAGE"
    if [[ "$DOCKER" -eq 1 ]]; then
        ensure_docker
        run "Pulling published OVNode image" \
            docker pull "ghcr.io/${REPO,,}:${VERSION}" \
            || die "Could not pull ghcr.io/${REPO,,}:${VERSION}" "$EX_ERROR"
    else
        fetch_release_binary "$UPDATE_STAGE"
        # The staged release carries the helpers too: the operator CLI on the
        # box must be the one that matches the binary it sits beside.
        "$UPDATE_STAGE/ovnode" assets write --dest "$UPDATE_STAGE" >/dev/null \
            || die "Could not stage the installer helpers; the current version is still running" "$EX_ERROR"
        cp -p "$APP_DIR/.env" "$UPDATE_STAGE/.env" || die "Could not preserve configuration" "$EX_ERROR"
        chmod 600 "$UPDATE_STAGE/.env"
        staged="$("$UPDATE_STAGE/ovnode" version 2>/dev/null || true)"
        [[ "$staged" == "$VERSION" ]] || die "Staged release reports '$staged', expected $VERSION" "$EX_ERROR"
    fi
    render_ok ""

    render_stage "[3/6] Maintenance"
    : > "$(update_marker)"
    chmod 600 "$(update_marker)"
    update_state activating "$from_version" "$VERSION" "$safety" "$identity"
    if [[ "$DOCKER" -eq 1 ]]; then
        ( cd "$APP_DIR" && docker compose -f "$(compose_file)" down ) >/dev/null 2>&1 || true
    else
        # The OpenVPN daemon keeps serving clients; only the agent stops.
        systemctl_bounded stop "$SYSTEMD_SERVICE" >/dev/null 2>&1 || true
    fi
    render_ok "agent paused"

    render_stage "[4/6] Activate"
    if [[ "$DOCKER" -eq 1 ]]; then
        IMAGE_TAG="$VERSION" write_compose_file
        ( cd "$APP_DIR" && docker compose -f "$(compose_file)" up -d ) >/dev/null 2>&1 \
            || { update_state recovery_required "$from_version" "$VERSION" "$safety" "$identity"; die "Could not start the candidate container. Writes remain blocked; run: ovnode recover-update" "$EX_ERROR"; }
        activated=1
    else
        rm -rf "$UPDATE_PREVIOUS"
        if mv "$APP_DIR" "$UPDATE_PREVIOUS" && mv "$UPDATE_STAGE" "$APP_DIR"; then
            activated=1
        else
            if [[ -d "$APP_DIR" ]] || { [[ -d "$UPDATE_PREVIOUS" ]] && mv "$UPDATE_PREVIOUS" "$APP_DIR"; }; then
                rm -f "$(update_marker)"
                update_state failed_over "$from_version" "$VERSION" "$safety" "$identity"
                operation_end
                die "Could not activate the staged release; the previous release remains active and state was not changed" "$EX_ERROR"
            fi
            update_state recovery_required "$from_version" "$VERSION" "$safety" "$identity"
            operation_end
            die "Could not activate or restore release files. Writes remain blocked; run: ovnode recover-update" "$EX_ERROR"
        fi
    fi

    local start_ok=0
    if [[ "$DOCKER" -eq 1 ]]; then
        start_ok=1
    else
        has_systemd && write_systemd_unit
        # The ovnode binary lives outside the app dir, so a release must
        # refresh it explicitly — otherwise the node keeps running the
        # previous version's hook. A failure here is not fatal: the old
        # binary still works.
        install_agent_binary || render_warn "The node keeps the previous ovnode binary"
        run "Candidate agent started" systemctl_bounded restart "$SYSTEMD_SERVICE" && start_ok=1 || true
    fi
    render_ok ""

    render_stage "[5/6] Verify"
    update_state verifying "$from_version" "$VERSION" "$safety" "$identity"
    if [[ "$start_ok" -eq 1 ]] && wait_health "${scheme}://127.0.0.1:${PORT}/sync/health" 60; then
        local reported vpn_ok ident_ok
        read -r reported vpn_ok < <(node_api_status "$API_KEY" "$PORT" "$TLS_METHOD") || true
        ident_ok="$(identity_sha "$(env_get_after NODE_NAME)" "$(env_get_after API_KEY)")"
        if [[ "$reported" == "$VERSION" && "$vpn_ok" == "true" && "$ident_ok" == "$identity" ]]; then
            start_ok=1
        else
            render_warn "Candidate verification mismatch (version='${reported:-unknown}' openvpn='${vpn_ok:-unknown}' identity-preserved=$([[ "$ident_ok" == "$identity" ]] && echo yes || echo no))"
            start_ok=0
        fi
    else
        start_ok=0
    fi

    if [[ "$start_ok" -ne 1 ]]; then
        render_warn "Candidate verification failed — failing over to v${from_version}"
        update_state failing_over "$from_version" "$VERSION" "$safety" "$identity"
        node_failover "$from_version" "$VERSION" "$safety" "$identity" "$snapshot"
    fi

    render_stage "[6/6] Commit"
    rm -f "$(update_marker)"
    if [[ "$DOCKER" -eq 0 ]]; then
        setup_nat
        setup_logrotate
    fi
    if ! wait_health "${scheme}://127.0.0.1:${PORT}/sync/health" 60; then
        : > "$(update_marker)"; chmod 600 "$(update_marker)"
        update_state recovery_required "$from_version" "$VERSION" "$safety" "$identity"
        operation_end
        die "Candidate passed verification but failed its final check. Writes are blocked; run: ovnode recover-update" "$EX_ERROR"
    fi
    update_state committed "$from_version" "$VERSION" "$safety" "$identity"
    render_ok "v${from_version} → v${VERSION}"
    operation_end
    install_cli
    [[ "$DOCKER" -eq 1 ]] || render_line "  rollback: $CLI_NAME rollback"
    render_blank
}

# Read a key from the CURRENT (possibly just activated) install .env.
env_get_after() { grep -E "^$1=" "$APP_DIR/.env" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"' || true; }

# Failover to the pre-update release + state; always dies after journaling the
# terminal state.
node_failover() {
    local from_version="$1" target="$2" safety="$3" identity="$4" snapshot="$5"
    if [[ "$DOCKER" -eq 1 ]]; then
        ( cd "$APP_DIR" && docker compose -f "$(compose_file)" down ) >/dev/null 2>&1 || true
        state_restore "$safety" \
            || { update_state recovery_required "$from_version" "$target" "$safety" "$identity"; operation_end; die "Previous container stopped but state could not be restored. Run: ovnode recover-update" "$EX_ERROR"; }
        IMAGE_TAG="$from_version" write_compose_file
        ( cd "$APP_DIR" && docker compose -f "$(compose_file)" up -d ) >/dev/null 2>&1 \
            || { update_state recovery_required "$from_version" "$target" "$safety" "$identity"; operation_end; die "Previous image could not be restarted. Run: ovnode recover-update" "$EX_ERROR"; }
    else
        systemctl_bounded stop "$SYSTEMD_SERVICE" >/dev/null 2>&1 || true
        rm -rf "$UPDATE_STAGE"
        mv "$APP_DIR" "$UPDATE_STAGE" || true
        mv "$UPDATE_PREVIOUS" "$APP_DIR" \
            || { update_state recovery_required "$from_version" "$target" "$safety" "$identity"; operation_end; die "Automatic failover could not restore the previous release. Snapshot: $snapshot" "$EX_ERROR"; }
        state_restore "$safety" \
            || { update_state recovery_required "$from_version" "$target" "$safety" "$identity"; operation_end; die "Previous code was restored but state could not be restored" "$EX_ERROR"; }
        run "Previous agent restarted" systemctl_bounded restart "$SYSTEMD_SERVICE" \
            || { update_state recovery_required "$from_version" "$target" "$safety" "$identity"; operation_end; die "Previous release restored but will not start" "$EX_ERROR"; }
    fi
    local scheme="http"; [[ "$TLS_METHOD" != "none" ]] && scheme="https"
    if wait_health "${scheme}://127.0.0.1:${PORT}/sync/health" 60; then
        rm -f "$(update_marker)"
        update_state failed_over "$from_version" "$target" "$safety" "$identity"
        operation_end
        die "Update failed over safely to v${from_version}. State was restored from $safety. Check logs before retrying." "$EX_ERROR"
    fi
    update_state recovery_required "$from_version" "$target" "$safety" "$identity"
    operation_end
    die "Failover did not restore health either — state backup at $safety, code snapshot at $snapshot. Check logs." "$EX_ERROR"
}

do_recover_update() {
    if [[ ! -f "$UPDATE_STATE" ]]; then
        [[ -f "$(update_marker)" ]] && die "Update maintenance marker exists but its state journal is missing" "$EX_ERROR"
        render_ok "No interrupted update needs recovery"
        return 0
    fi
    local phase from target safety identity
    read -r phase from target safety identity < <("$AGENT_BIN" state read "$UPDATE_STATE") || die "Update state journal is unreadable" "$EX_ERROR"
    case "$phase" in
        committed|failed_over)
            if [[ ! -f "$(update_marker)" ]]; then
                render_ok "No interrupted update needs recovery"
                return 0
            fi
            ;;
        preflight|staging)
            # Activation had not begun: release and state are untouched.
            check_root
            operation_begin recover-update
            trap operation_end EXIT
            rm -rf "$UPDATE_STAGE"
            rm -f "$(update_marker)"
            update_state failed_over "$from" "$target" "$safety" "$identity"
            operation_end
            render_ok "Cleared an interrupted pre-activation update; v${from} remains active"
            return 0
            ;;
        activating|verifying|failing_over|recovery_required) ;;
        *) die "Update journal has unknown phase '$phase'; writes remain blocked" "$EX_ERROR" ;;
    esac
    check_root
    operation_begin recover-update
    trap operation_end EXIT
    if [[ ! -f "$(update_marker)" ]]; then
        : > "$(update_marker)"
        chmod 600 "$(update_marker)"
        render_warn "Re-created the missing update maintenance marker"
    fi
    [[ -f "$(compose_file)" ]] && DOCKER=1 || DOCKER=0
    local env_get; env_get() { grep -E "^$1=" "$APP_DIR/.env" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"' || true; }
    [[ -n "$NODE_NAME" ]] || NODE_NAME="$(env_get NODE_NAME)"
    : "${NODE_NAME:=ovnode}"
    [[ -n "$PORT" ]] || PORT="$(env_get SERVICE_PORT)"
    : "${PORT:=$DEFAULT_PORT}"
    local api_key
    api_key="$(env_get API_KEY)"
    [[ -n "$api_key" ]] || die "Installed .env has no API key — cannot verify identity. Restore .env from $safety, then retry." "$EX_ERROR"
    TLS_METHOD="$(env_get TLS_METHOD)"; : "${TLS_METHOD:=selfsigned}"
    local scheme="http"; [[ "$TLS_METHOD" != "none" ]] && scheme="https"
    local reported vpn_ok ident_ok
    if wait_health "${scheme}://127.0.0.1:${PORT}/sync/health" 5; then
        read -r reported vpn_ok < <(node_api_status "$api_key" "$PORT" "$TLS_METHOD") || true
        ident_ok="$(identity_sha "$(env_get NODE_NAME)" "$api_key")"
    fi
    if [[ "${reported:-}" == "$target" && "${vpn_ok:-}" == "true" && "${ident_ok:-}" == "$identity" ]]; then
        rm -f "$(update_marker)"
        update_state committed "$from" "$target" "$safety" "$identity"
        operation_end
        render_ok "Recovered update journal — v${target} is healthy"
        return 0
    fi
    if [[ "${reported:-}" == "$from" && "${vpn_ok:-}" == "true" && "${ident_ok:-}" == "$identity" && ! -d "$UPDATE_PREVIOUS" ]]; then
        rm -f "$(update_marker)"
        update_state failed_over "$from" "$target" "$safety" "$identity"
        operation_end
        render_ok "Recovered update journal — previous v${from} is healthy"
        return 0
    fi
    if [[ ! -d "$UPDATE_PREVIOUS" ]]; then
        # Activation never swapped the trees: restart the intact install.
        rm -rf "$UPDATE_STAGE"
        if [[ "$DOCKER" -eq 1 ]]; then
            ( cd "$APP_DIR" && docker compose -f "$(compose_file)" up -d ) >/dev/null 2>&1 || true
        else
            systemctl_bounded restart "$SYSTEMD_SERVICE" >/dev/null 2>&1 || systemctl start "$SYSTEMD_SERVICE" >/dev/null 2>&1 || true
        fi
        if wait_health "${scheme}://127.0.0.1:${PORT}/sync/health" 60; then
            rm -f "$(update_marker)"
            update_state failed_over "$from" "$target" "$safety" "$identity"
            operation_end
            render_ok "Interrupted update never activated — v${from} restarted, staging discarded"
            return 0
        fi
        update_state recovery_required "$from" "$target" "$safety" "$identity"
        operation_end
        die "Interrupted update never activated and v${from} does not answer health. Run: ovnode logs 100" "$EX_ERROR"
    fi
    render_line "Interrupted candidate is unhealthy — failing over to v${from}"
    if [[ "$DOCKER" -eq 1 ]]; then
        ( cd "$APP_DIR" && docker compose -f "$(compose_file)" down ) >/dev/null 2>&1 || true
        [[ -n "$safety" ]] && state_restore "$safety" \
            || die "Previous container stopped, but state could not be restored" "$EX_ERROR"
        IMAGE_TAG="$from" write_compose_file
        ( cd "$APP_DIR" && docker compose -f "$(compose_file)" up -d ) >/dev/null 2>&1 \
            || die "Previous image could not be restarted" "$EX_ERROR"
    else
        systemctl_bounded stop "$SYSTEMD_SERVICE" >/dev/null 2>&1 || true
        rm -rf "$UPDATE_STAGE"
        [[ -d "$APP_DIR" ]] && mv "$APP_DIR" "$UPDATE_STAGE"
        mv "$UPDATE_PREVIOUS" "$APP_DIR" || die "Could not restore the previous release directory" "$EX_ERROR"
        [[ -n "$safety" ]] && state_restore "$safety" \
            || die "Previous release restored, but state could not be restored" "$EX_ERROR"
        systemctl_bounded restart "$SYSTEMD_SERVICE" >/dev/null 2>&1 \
            || die "Previous release restored but will not start" "$EX_ERROR"
    fi
    if wait_health "${scheme}://127.0.0.1:${PORT}/sync/health" 60; then
        rm -f "$(update_marker)"
        update_state failed_over "$from" "$target" "$safety" "$identity"
        operation_end
        render_ok "Interrupted update failed over safely to v${from}"
        return 0
    fi
    update_state recovery_required "$from" "$target" "$safety" "$identity"
    operation_end
    die "Previous release was restored but is not healthy. Run: ovnode logs 100" "$EX_ERROR"
}

# Regenerate host integration files from the installed release + .env: unit,
# NAT, logrotate. No restart, no re-enrollment.
do_repair_unit() {
    [[ -d "$APP_DIR" ]] || die "Not installed ($APP_DIR missing)" "$EX_NOTINSTALLED"
    check_root
    operation_begin repair-unit
    trap operation_end EXIT
    local env_get; env_get() { grep -E "^$1=" "$APP_DIR/.env" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"' || true; }
    NODE_NAME="$(env_get NODE_NAME)"; : "${NODE_NAME:=ovnode}"
    PORT="$(env_get SERVICE_PORT)"; : "${PORT:=$DEFAULT_PORT}"
    API_KEY="$(env_get API_KEY)"
    [[ -n "$API_KEY" ]] || die "Installed .env has no API key — restore .env first" "$EX_ERROR"
    VPN_PORT="$(env_get OPENVPN_PORT)"; : "${VPN_PORT:=$DEFAULT_VPN}"
    EXTRA_PORTS="$(env_get OVNODE_EXTRA_PORTS)"
    TLS_METHOD="$(env_get TLS_METHOD)"; : "${TLS_METHOD:=selfsigned}"
    TLS_KEY="$(env_get SSL_KEYFILE)"; TLS_CERT="$(env_get SSL_CERTFILE)"
    [[ "$(env_get OVNODE_ENABLE_IPV6)" == "1" ]] && IPV6=1 || IPV6=0
    detect_os
    if [[ -f "$(compose_file)" ]]; then
        DOCKER=1
        ensure_docker
        write_compose_file
        render_ok "Compose file regenerated (image ${IMAGE_REPO}:${IMAGE_TAG:-$VERSION})"
    else
        DOCKER=0
        has_systemd || die "systemd not found — cannot install the agent unit" "$EX_ERROR"
        write_systemd_unit
        write_openvpn_unit
        write_cleanup_units
        run "Generating node PKI" "$AGENT_BIN" ca init
        setup_nat
        setup_logrotate
    fi
    operation_end
    render_ok "Host integration repaired — restart the agent if it is stopped: ovnode restart"
}

# ── Uninstall ──────────────────────────────────────────────────────────
do_uninstall() {
    [[ -d "$APP_DIR" ]] || die "Not installed ($APP_DIR missing)" "$EX_NOTINSTALLED"
    check_root
    operation_begin uninstall
    trap operation_end EXIT
    [[ -n "$NODE_NAME" ]] || NODE_NAME="$(grep -E '^NODE_NAME=' "$APP_DIR/.env" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"' || true)"
    : "${NODE_NAME:=ovnode}"
    # The list of what goes comes before the question, and the question is not
    # yes/no: the destructive answer is a word, so a stray Enter keeps the PKI.
    # A y/N prompt put "yes, delete the CA" one keystroke from the default.
    render_screen
    render_line "  $(printf '%bthis removes%b' "$B" "$NC")"
    render_rule
    render_kv "services" "$SYSTEMD_SERVICE, $NAT_SERVICE, $OPENVPN_SERVICE, $CLEANUP_TIMER"
    render_kv "files" "$(dir_size "$APP_DIR")   $APP_DIR"
    if [[ "$PURGE" -eq 1 ]]; then
        render_kv "data" "$(printf '%s%s%s   %s← users, keys, the CA private key' "$RD" "$DATA_BASE" "$NC" "$GY")"
        render_kv "openvpn" "$(printf '%s%s%s   %s← server config and every issued client cert' "$RD" "$OPENVPN_ROOT" "$NC" "$GY")"
    else
        render_kv "data" "$(dir_size "$DATA_BASE")   $DATA_BASE"
        render_kv "openvpn" "$(dir_size "$OPENVPN_ROOT")   $OPENVPN_ROOT"
    fi
    render_rule
    confirm_word "delete the data and the PKI as well? type purge" "purge" && PURGE=1
    confirm "remove the app and stop all services?" n || die "Cancelled."

    render_stage "[1/1] Uninstall"
    # Stopping the NAT unit runs its ExecStop cleanup (rules removed).
    systemctl_bounded stop "$SYSTEMD_SERVICE"
    systemctl_bounded stop "$NAT_SERVICE"
    systemctl_bounded stop "$OPENVPN_SERVICE"
    systemctl disable --now "$CLEANUP_TIMER" >/dev/null 2>&1 || true
    systemctl disable "$SYSTEMD_SERVICE" "$NAT_SERVICE" "$OPENVPN_SERVICE" 2>/dev/null || true
    rm -f "/etc/systemd/system/$SYSTEMD_SERVICE" "/etc/systemd/system/$NAT_SERVICE" \
          "/etc/systemd/system/$OPENVPN_SERVICE" "/etc/systemd/system/$CLEANUP_SERVICE" \
          "/etc/systemd/system/$CLEANUP_TIMER"
    systemctl daemon-reload 2>/dev/null || true

    if command -v docker >/dev/null 2>&1 && [[ -f "$(compose_file)" ]]; then
        ( cd "$APP_DIR" && docker compose -f "$(compose_file)" down ) >/dev/null 2>&1 || true
        docker rm -f "ovnode-$NODE_NAME" >/dev/null 2>&1 || true
    fi

    rm -f "$NAT_SCRIPT" "$NAT_CONF" "$SYSCTL_CONF" "$LOGROTATE_CONF"
    remove_cli
    close_firewall_ports
    rm -rf "$APP_DIR"
    if [[ "$PURGE" -eq 1 ]]; then
        backup_dir "$DATA_BASE" "node-pre-purge"
        rm -rf "$DATA_BASE"
        backup_dir "$OPENVPN_ROOT" "openvpn-pre-purge"
        rm -rf "$OPENVPN_ROOT"
        render_ok "data and PKI removed · backups in /var/backups"
    else
        render_ok "app removed · data kept at $DATA_BASE"
    fi
    render_blank
}

# Sizes a directory for the uninstall list. Present because "210 MB" and "84 MB"
# read very differently, and an operator deciding whether to purge needs the
# number in front of them, not after.
dir_size() {
    local kb
    kb="$(du -sk "$1" 2>/dev/null | awk '{print $1}')"
    if [[ -n "$kb" ]]; then
        awk -v k="$kb" 'BEGIN { printf "%.0f MB", k/1024 }'
    fi
    return 0
}

# ── Interactive setup (humans on a TTY) ────────────────────────────────
# Two questions: the port the agent answers on, and the certificate. Everything
# else — the VPN transport, the deployment mode — is either chosen on the front
# door menu or owned by the panel.
#
# The transport used to be asked here and got UDP when a person answered and TCP
# when nobody did. One question with two possible defaults is a question with a
# bug in it, and the panel can change the transport on a live node (POST
# /sync/config rewrites proto and restarts OpenVPN), so the installer only has to
# write something valid to start from.
interactive_setup() {
    render_screen
    render_line "  $(printf '%bport%s' "$B" "$NC")"
    PORT="$(ask "" "${PORT:-$(find_free_port "$DEFAULT_PORT")}")"

    render_screen
    render_line "  $(printf '%btls%s' "$B" "$NC")"
    local tls_choice
    tls_choice="$(ask "1 self-signed · 2 lets encrypt · 3 custom" "1")"
    case "${tls_choice:-1}" in
        2) ask_lets_encrypt ;;
        3) TLS_METHOD="custom"
            TLS_CERT="$(ask "cert" "${TLS_CERT:-}")"
            TLS_KEY="$(ask "key" "${TLS_KEY:-}")"
            [[ -f "$TLS_CERT" && -f "$TLS_KEY" ]] || die "Custom TLS files not found" ;;
        *) TLS_METHOD="selfsigned" ;;
    esac
    return 0
}

# One free-text field for Let's Encrypt. The old wizard asked "domain or this
# IP?" as its own question, which made the operator decide a distinction the
# installer can make for itself: what they type says which it is.
ask_lets_encrypt() {
    local here detected others answer resolved
    here="$(public_ip || true)"
    detected="${TLS_DOMAIN:-${here:-}}"
    others="$(public_ips)"
    if [[ -n "$others" && "$others" != "$here" && "$others" != "$here "* ]]; then
        render_ask_note "this box answers on ${others// /, }"
    fi
    render_ask_note "Let's Encrypt sees whatever you type here — an IP gets a short-lived cert, a name gets a normal one"
    answer="$(ask "ip or domain" "$detected")"
    [[ -n "$answer" ]] || answer="$detected"
    [[ -n "$answer" ]] || die "Let's Encrypt needs an IP or a domain"

    if is_ip_literal "$answer"; then
        TLS_METHOD="letsencrypt-ip"; TLS_DOMAIN="$answer"
        return 0
    fi
    TLS_METHOD="letsencrypt"; TLS_DOMAIN="$answer"
    # Say what the name resolves to before spending a rate-limited issuance on
    # it. A wrong record fails the request and burns one of Let's Encrypt's
    # weekly attempts, which is the expensive way to learn a typo.
    resolved="$(resolve_host "$answer")"
    if [[ -z "$resolved" ]]; then
        render_warn "$answer does not resolve yet — DNS has to point here before the certificate can be issued"
    elif [[ -n "$here" && "$resolved" != "$here" ]]; then
        render_warn "$answer resolves to $resolved, not $here — Let's Encrypt will refuse it"
    fi
    return 0
}

# Express install: safe defaults, no further questions. TLS is always on.
apply_express_defaults() {
    : "${PORT:=$(find_free_port "$DEFAULT_PORT")}"
    : "${VPN_PORTS:=$DEFAULT_VPN}"
    : "${NODE_NAME:=ovnode}"
    : "${VPN_PROTO:=udp}"
    TLS_METHOD="selfsigned"
    [[ -n "$API_KEY" ]] || generate_api_key
    EXPRESS=1
}

# Friendly front door: shown only for a bare interactive invocation.
# Host install is the default; Docker is the explicit second choice.
# The front door. The deployment mode is chosen here and nowhere else — the
# wizard used to ask it again as "Step 3/4", so the answer could be given twice
# and the two did not always agree.
start_menu() {
    local tag
    tag="$(render_menu "" \
        host   "install  ·  systemd on this box" \
        docker "install  ·  agent + openvpn in a container" \
        quit   "exit")"
    case "$tag" in
        host)   apply_express_defaults ;;
        docker) DOCKER=1; apply_express_defaults ;;
        *)      render_line "  cancelled — nothing was changed"; exit "$EX_OK" ;;
    esac
}


# ── Terminal command (TUI) ─────────────────────────────────────────────
# install_cli() copies manager.sh to $BIN_DIR as "ovnode" (+ "ovn"), so a bare
# `ovnode` opens the menu. Every action is also a subcommand for scripts.

# systemd waits up to TimeoutStopSec for a stuck unit; bound the wait so an
# uninstall/update never looks frozen, then force the unit.
STOP_TIMEOUT="${OVN_STOP_TIMEOUT:-20}"

installed_menu() {
    render_warn "OVNode is already installed at $APP_DIR"
    if ! is_tty; then
        # Exit 3, the documented "already installed" code, not die's 1: this is a
        # state the caller asked about, so a provisioning script can tell it
        # apart from a real failure.
        render_fail "already installed" "$APP_DIR — re-run with: $0 update"
        exit "$EX_ALREADY"
    fi
    local tag
    tag="$(render_menu "" \
        update    "update to v${VERSION}" \
        uninstall "uninstall" \
        quit      "quit")"
    case "$tag" in
        update)    do_update || render_warn "update failed" ;;
        uninstall) do_uninstall ;;
        *)         render_line "  nothing was changed" ;;
    esac
}

install_cli() {
    # Refreshed on every update, so a box whose ovnode is an old copy gets swapped.
    local src="${APP_DIR}/ovnode.sh"
    [[ -f "$src" ]] || return 0
    mkdir -p "$BIN_DIR" 2>/dev/null || { render_warn "Could not create $BIN_DIR"; return 0; }
    if cp -f "$src" "$BIN_DIR/$CLI_NAME" 2>/dev/null && chmod 0755 "$BIN_DIR/$CLI_NAME"; then
        render_ok "Command  ${BIN_DIR}/${CLI_NAME}"
    else
        render_warn "Could not install the $CLI_NAME command into $BIN_DIR"
    fi
}

remove_cli() {
    rm -f "$BIN_DIR/$CLI_NAME" 2>/dev/null || true
    # `ovnode completion` writes this; a leftover completes a command that is gone.
    rm -f "${OVN_COMPLETION_DIR:-/etc/bash_completion.d}/ovnode" 2>/dev/null || true
}

# ── Help / args ────────────────────────────────────────────────────────
# Goes to stderr, not line()/warn(): those are silenced by --quiet and by a
# non-TTY, and a deprecation nobody sees is not a deprecation.
deprecated() {  # deprecated <flag> <what to do instead>
    printf '  %s⚠%s %s is deprecated; %s\n' "$YL" "$NC" "$1" "$2" >&2
}

# printf, not field(): field() is silenced by --quiet, and this command exists
# to be read back by somebody else. A stale copy is normal (the raw CDN caches
# for minutes); the commit prints only when something stamped it.
print_script_version() {
    printf '  %-18s %s\n' "Installer" "install.sh v${VERSION}" >&2
    printf '  %-18s %s\n' "Commit" \
        "${OVN_SCRIPT_COMMIT:-not recorded (this installer carries no commit stamp)}" >&2
    exit "$EX_OK"
}

show_help() {
    cat << EOF >&2
  OVNode installer — host (systemd) or Docker. Interactive unless you pass -y.

  Usage:
    bash <(curl -Ls URL) [command] [flags]

  No command? Zero-question install with safe generated values.
  The start menu offers Install (host service) or Install with Docker.
  The \`interactive\` command opens the numbered wizard instead.
  Installs use safe defaults (ovnode, UDP, self-signed TLS,
  generated API key). Plain HTTP is not offered.

  Commands: (default: install)
    update                Fetch the verified release and restart (state
                          safety snapshot + code snapshot first,
                          auto-rollback on failure)
    recover-update        Recover an interrupted update transaction
    repair-unit           Regenerate systemd unit / NAT / logrotate
    uninstall             Remove OVNode (data kept unless OVN_PURGE=1)
    interactive, -i       Numbered install wizard (Enter = default)
    version-script        Print this installer's own version and commit
    help                  This help

  Everything else (status, logs, backup, restore, TLS, completion) lives
  in the operator CLI: ovnode.

  Options (every option has an OVN_* env equivalent; CLI wins):
    -y, --yes             Never prompt, accept defaults       [OVN_YES=1]
    --docker              Deploy in Docker (container runs agent + OpenVPN,
                          host networking)                    [OVN_DOCKER=1]
    --local [DIR]         Install from a checkout (default: this directory):
                           rsync + go build + the same install the release
                           path runs. Fetches nothing.       [OVN_LOCAL=1]
    --src DIR             with --local: the checkout to install from
    --dest DIR            with --local: the install destination

  -h, --help              This help  (no env equivalent)

  Deprecated (still works) — each flag is removed next release. Set the
  OVN_* variable instead:
    -p, --key KEY         API key, min 16 chars (generated if omitted)
                                                              [OVN_KEY]
    --name NAME           Node name                  [OVN_NAME, ovnode]
    --port PORT           Sync API port                     [OVN_PORT, 2083]
    --vpn-ports LIST      OpenVPN ports, comma separated [OVN_VPN_PORTS, 1194]
                          First = listener; the rest are redirected to it and
                          included in every .ovpn (client failover).
    --proto PROTO         VPN transport: udp (default, faster) or tcp
                          (fallback where UDP is blocked)          [OVN_PROTO]
    --tls 1|2|3|4         1 selfsigned (default), 2 letsencrypt,
                          3 letsencrypt-ip, 4 custom               [OVN_TLS]
                          Plain HTTP ("none") is rejected.
    --tls-domain DOM      Domain/IP for Let's Encrypt      [OVN_TLS_DOMAIN]
    --tls-key  FILE       Private key (--tls 4)             [OVN_TLS_KEY]
    --tls-cert FILE       Certificate (--tls 4)            [OVN_TLS_CERT]
    --ipv6                Enable IPv6 on the VPN            [OVN_IPV6=1]
    --no-nat              Skip forwarding/NAT/redirects     [OVN_NO_NAT=1]
    --purge               With uninstall: remove data too   [OVN_PURGE=1]
    --quiet | -q          Suppress progress logs (errors still shown)
                                                           [OVN_QUIET=1]
    -v, --version vX.Y.Z  Install/update this release instead of v${VERSION}
                                                          [OVN_VERSION]

  Exit codes:
    0 success · 1 error · 2 usage error · 3 already installed ·
    4 not installed

  Without a terminal (never prompts; branch on the exit code):
    OVN_KEY="\$API_KEY" bash install.sh -y
EOF
    exit "$EX_OK"
}

parse_args() {
    local need2='[[ $# -ge 2 ]] || fail "$1 needs a value" "$EX_USAGE"'
    while [[ $# -gt 0 ]]; do
        case "$1" in
            update)       ACTION="update"; CMD_GIVEN=1; shift ;;
            uninstall) ACTION="uninstall"; CMD_GIVEN=1; shift ;;
            recover-update) ACTION="recover-update"; CMD_GIVEN=1; shift ;;
            repair-unit) ACTION="repair-unit"; CMD_GIVEN=1; shift ;;
            version-script|script-version) print_script_version ;;
            help|--help|-h) show_help ;;
            --port)       eval "$need2"; deprecated "--port" "set OVN_PORT instead"; PORT="$2"; CLI_FLAGS=1; shift 2 ;;
            -p|--key)       eval "$need2"; deprecated "$1" "set OVN_KEY instead"; API_KEY="$2"; CLI_FLAGS=1; shift 2 ;;
            -v|--version)   eval "$need2"; deprecated "$1" "set OVN_VERSION instead"; PIN="$2"; CLI_FLAGS=1; shift 2 ;;
            -i)             ACTION="interactive"; CMD_GIVEN=1; shift ;;
            --vpn-ports|--vpn-port) eval "$need2"; deprecated "$1" "set OVN_VPN_PORTS instead"; VPN_PORTS="$2"; CLI_FLAGS=1; shift 2 ;;
            --proto) eval "$need2"; deprecated "--proto" "set OVN_PROTO instead"; VPN_PROTO="$2"; CLI_FLAGS=1; shift 2 ;;
            --name)       eval "$need2"; deprecated "--name" "set OVN_NAME instead"; NODE_NAME="$2"; CLI_FLAGS=1; shift 2 ;;
            --tls)        eval "$need2"; deprecated "--tls" "set OVN_TLS instead"; CLI_FLAGS=1
                          case "$2" in
                              1|selfsigned) TLS_METHOD="selfsigned" ;;
                              2|letsencrypt) TLS_METHOD="letsencrypt" ;;
                              3|letsencrypt-ip) TLS_METHOD="letsencrypt-ip" ;;
                              4|custom) TLS_METHOD="custom" ;;
                              *) fail "Invalid --tls '$2' (use 1, 2, 3 or 4)" "$EX_USAGE" ;;
                          esac
                          shift 2 ;;
            --tls-domain) eval "$need2"; deprecated "--tls-domain" "set OVN_TLS_DOMAIN instead"; TLS_DOMAIN="$2"; CLI_FLAGS=1; shift 2 ;;
            --tls-key)    eval "$need2"; deprecated "--tls-key" "set OVN_TLS_KEY instead"; TLS_KEY="$2"; CLI_FLAGS=1; shift 2 ;;
            --tls-cert)   eval "$need2"; deprecated "--tls-cert" "set OVN_TLS_CERT instead"; TLS_CERT="$2"; CLI_FLAGS=1; shift 2 ;;
            --docker)     DOCKER=1; CLI_FLAGS=1; shift ;;
            --local)      LOCAL=1; CLI_FLAGS=1; shift
                           if [[ $# -ge 1 && "$1" != -* ]]; then SRC_DIR="$1"; shift; fi ;;
            --src)        [[ $# -ge 2 ]] || fail "--src needs a value" "$EX_USAGE"; SRC_DIR="$2"; shift 2 ;;
            --dest)       [[ $# -ge 2 ]] || fail "--dest needs a directory" "$EX_USAGE"; DEST_DIR="$2"; shift 2 ;;
            --ipv6)       deprecated "--ipv6" "set OVN_IPV6=1 instead"; IPV6=1; CLI_FLAGS=1; shift ;;
            --no-nat)     deprecated "--no-nat" "set OVN_NO_NAT=1 instead"; NO_NAT=1; CLI_FLAGS=1; shift ;;
            --yes|-y)     YES=1; CLI_FLAGS=1; shift ;;
            --purge)      deprecated "--purge" "set OVN_PURGE=1 instead"; PURGE=1; CLI_FLAGS=1; shift ;;
            --quiet|-q)   deprecated "$1" "set OVN_QUIET=1 instead"; QUIET=1; shift ;;
            status|start|stop|restart|restart-vpn|logs|backup|auto-backup|tls)
                          fail "'$1' moved to the manager — use: ovnode $1" "$EX_USAGE" ;;
            menu)         fail "The menu lives in the manager — run: ovnode" "$EX_USAGE" ;;
            install)      fail "'install' is the default — just drop the word" "$EX_USAGE" ;;
            interactive)  ACTION="interactive"; CMD_GIVEN=1; shift ;;
            *)            fail "Unknown option: $1 (--help for usage)" "$EX_USAGE" ;;
        esac
    done
}

# ── Main ───────────────────────────────────────────────────────────────
main() {
    parse_args "$@"
    if [[ -n "$PIN" ]]; then
        valid_release_version "$PIN" \
            || fail "Bad --version '$PIN' (use 1.2.3, v1.2.3, 1.2.3-rc1)" "$EX_USAGE"
        VERSION="${PIN#v}"
    fi
    # A local build replaces the download: the checkout is the release.
    [[ "$LOCAL" -eq 1 ]] && do_local_build
    load_helpers
    # Defaults and validation must run before the install, local or not.
    if [[ "$CLI_FLAGS" -eq 1 || "$ENV_INPUTS" -eq 1 || "$LOCAL" -eq 1 ]]; then
        [[ -n "$PORT" ]]      || PORT="$DEFAULT_PORT"
        [[ -n "$TLS_METHOD" ]]|| TLS_METHOD="selfsigned"
        [[ -n "$VPN_PORTS" ]] || VPN_PORTS="$DEFAULT_VPN"
        [[ -n "$NODE_NAME" ]] || NODE_NAME="ovnode"
        validate_input
    fi
    # A local build always proceeds to install: the dev loop rsyncs and
    # rebuilds, so "already installed" is not an error there.
    if [[ "$LOCAL" -eq 1 ]]; then
        do_install
        exit "$EX_OK"
    fi
    [[ -n "${OVN_SRC:-}" && "${OVN_SRC}" != "release" ]] && die "Source installs were removed — the installer consumes verified releases only (developers: clone the repo)" "$EX_USAGE"
    [[ -n "${OVN_BRANCH:-}" ]] && die "OVN_BRANCH was removed with source installs — developers: git checkout the branch in a clone" "$EX_USAGE"
    case "$SRC" in
        release) ;;
        *) die "Invalid source '$SRC' (releases only)" "$EX_USAGE" ;;
    esac
    # render_screen, not a bare `clear`: no escape-sequence fallback here, so a
    # host without terminfo silently skipped the wipe and the installer drew
    # itself over whatever was already on the terminal.
    render_screen
    render_banner "OVNode" "v${VERSION}"

    case "$ACTION" in
        uninstall) do_uninstall; exit "$EX_OK" ;;
        update)    confirm "Update OVNode now?" || exit "$EX_OK"; do_update; exit "$EX_OK" ;;
        recover-update) do_recover_update; exit "$EX_OK" ;;
        repair-unit) do_repair_unit; exit "$EX_OK" ;;
        interactive) INTERACTIVE=1 ;;
    esac

    # install
    if [[ -d "$APP_DIR" ]]; then
        if [[ "$YES" -eq 1 ]]; then
            die "Already installed ($APP_DIR exists). Run 'update' to refresh or 'uninstall' first." "$EX_ALREADY"
        fi
        installed_menu
        exit "$EX_OK"
    fi

    # Bare interactive invocation gets the start menu; flags and OVN_* inputs
    # keep the original machine path.
    if [[ "$CMD_GIVEN" -eq 0 && "$CLI_FLAGS" -eq 0 && "$ENV_INPUTS" -eq 0 && "$YES" -eq 0 ]] && is_tty; then
        start_menu
    fi

    detect_os
    if [[ "${INTERACTIVE:-0}" -eq 1 ]] || { [[ "$YES" -eq 0 ]] && is_tty && [[ -z "$PORT" || -z "$API_KEY" ]]; }; then
        interactive_setup
    else
        : "${PORT:=$(find_free_port "$DEFAULT_PORT")}"
        : "${VPN_PORTS:=$DEFAULT_VPN}"
        : "${NODE_NAME:=ovnode}"
        : "${TLS_METHOD:=selfsigned}"
        : "${VPN_PROTO:=udp}"
        [[ -n "$API_KEY" ]] || generate_api_key
    fi
    validate_input

    # A bare run is interactive, full stop. It used to be "no questions because
    # there is no terminal", and that inference installed things nobody chose and
    # then reported success — the one outcome a silent default must never
    # produce. With no terminal there is nobody to answer, so say so and name the
    # flag rather than deciding on their behalf.
    #
    # After validate_input on purpose. A bad value should be reported as the bad
    # value: `OVN_TLS=none` with no terminal is a plain-HTTP error, not a
    # complaint about the terminal. Checked in parse_args it masked every
    # validation message behind this one.
    # A run with no terminal never prompts: every setting comes from its
    # OVN_* variable or its default, and the choice is printed before
    # anything on the box changes. The installer is a program a human can
    # watch, not a script that needs a keyboard.
    #
    # The destructive path is not affected. confirm and confirm_word refuse
    # to answer without a terminal, so a cron run can never delete a PKI.
    if [[ "$YES" -eq 0 ]] && ! is_tty; then
        YES=1
    fi

    # One line, not a nine-row card. A mistyped port or the wrong transport is
    # the thing worth catching before the box changes, and both fit in a line
    # the operator can read at a glance; the rest restated the wizard's own
    # answers one screen back.
    render_line "  $(printf '%bthis will install%b' "$B" "$NC")"
    render_kv "node" "$(printf '%s· systemd on this box' "$PORT")"
    render_kv "vpn" "$(vpn_ports_label)/$VPN_PROTO"
    render_kv "tls" "$TLS_METHOD"
    render_kv "data" "$(node_data_dir)"
    render_blank

    do_install
}

main "$@"
