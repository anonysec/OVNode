#!/bin/bash
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
# Modes   : host (systemd, default) | --docker (see docker/entrypoint.sh)
# Day-to-day ops (status, logs, backup, TLS, completion) live in the manager: ovn.
#
# Non-interactive: -y never prompts, OVN_* env vars mirror
# every setting, CLI wins. Exit codes: 0 ok · 1 error · 2 usage ·
# 3 already installed · 4 not installed. Everything else is in --help.

set -Eeuo pipefail

# ── Constants ──────────────────────────────────────────────────────────
VERSION="1.0.44"
# Forks: point source downloads (and update pulls) at your own repo.
REPO="${OVN_REPO:-anonysec/OVNode}"
# Versioned GitHub Release tarballs only: verified checksum, no git needed.
SRC="release"
# OVN_APP_DIR lets tests run status/uninstall on a box already hosting a node.
APP_DIR="${OVN_APP_DIR:-/opt/ovnode}"
DATA_BASE="/var/lib/ovnode"
OPENVPN_ROOT="/etc/openvpn"
DEFAULT_PORT=2083
DEFAULT_VPN=1194
SYSTEMD_SERVICE="ovnode.service"
NAT_SERVICE="ovnode-nat.service"
NAT_SCRIPT="/usr/local/sbin/ovnode-nat.sh"
NAT_CONF="/etc/default/ovnode-nat"
SYSCTL_CONF="/etc/sysctl.d/99-ovnode.conf"
LOGROTATE_CONF="/etc/logrotate.d/ovnode"
BIN_DIR="${OVN_BIN_DIR:-/usr/local/bin}"
CLI_NAME="ovnode"
CLI_ALIAS="ovn"

# Exit codes (documented in --help; stable for automation)
EX_OK=0 EX_ERROR=1 EX_USAGE=2 EX_ALREADY=3 EX_NOTINSTALLED=4

# ── Settings (env defaults OVN_*, overridden by CLI flags) ─────────────
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

# ── Output ─────────────────────────────────────────────────────────────
# All human-readable output goes to stderr, so stdout stays clean for callers.
NC=$'\033[0m'; B=$'\033[1m'
WH=$'\033[97m'; GR=$'\033[32m'; RD=$'\033[31m'
YL=$'\033[33m'; CY=$'\033[36m'; GY=$'\033[90m'
[[ -t 2 ]] || { NC=''; B=''; WH=''; GR=''; RD=''; YL=''; CY=''; GY=''; }

# ── Shared helpers (scripts/lib) ───────────────────────────────────────
# Output, prompts and the shared probes are defined only in scripts/lib/*.sh,
# never copied here. A copy beside this script is used when there is one (an
# installed node, a checkout); the curl-piped installer has none and fetches
# from GitHub.
#
# The ref is the subtlety: the installer's own tag should pin the libs, but a
# curl-piped installer comes from a branch and may name a tag whose lib predates
# helpers this file needs. Tag first, main as fallback, result checked.
# doctor.sh is the health check. The installer never calls it, but keeping one
# directory and one rule beats a second source path: a lib here is fetchable by
# name, and tests/test_no_duplicate_functions.py holds both repos to it.
LIB_FILES=(common.sh render.sh doctor.sh)   # one entry per file in scripts/lib
# render_menu, not tui_select: the alias survives for older callers, and a lib set
# that only defines the old name means the libs predate this renderer.
LIBS_NEEDED=(die render_banner render_card render_line render_ok render_warn render_menu
             ask confirm check_root compose_file has_systemd is_docker_node)
LIB_REFS=("v${VERSION}" main)

_libs_are_usable() {  # _libs_are_usable <dir> → 0 when it defines what we call
    # Subshell on purpose: an unusable candidate must not leave half its
    # definitions behind for the next candidate to layer onto.
    (
        for _l in "${LIB_FILES[@]}"; do
            # shellcheck disable=SC1090
            . "$1/$_l" || exit 1
        done
        for _f in "${LIBS_NEEDED[@]}"; do
            declare -F "$_f" >/dev/null || exit 1
        done
    )
}

# The documented pipe form (`cat install.sh | bash -s --`) leaves BASH_SOURCE
# empty and `set -u` turns that into "unbound variable" before setup runs, so
# there is no local lib to look for: skip straight to the fetch.
LIB_DIR=""
if [[ -n "${BASH_SOURCE[0]:-}" ]]; then
    LIB_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)/scripts/lib"
    for _lib in "${LIB_FILES[@]}"; do
        [[ -f "$LIB_DIR/$_lib" ]] || LIB_DIR=""
    done
fi
if [[ -z "$LIB_DIR" ]]; then
    LIB_DIR=""
    for _ref in "${LIB_REFS[@]}"; do
        _url="https://raw.githubusercontent.com/${REPO}/${_ref}/scripts/lib"
        _try="$(mktemp -d /tmp/ovn-lib.XXXXXX)"
        _ok=1
        for _lib in "${LIB_FILES[@]}"; do
            curl -fsSL -o "$_try/$_lib" "$_url/$_lib" 2>/dev/null || { _ok=0; break; }
        done
        if [[ "$_ok" -eq 1 ]] && _libs_are_usable "$_try"; then
            LIB_DIR="$_try"
            break
        fi
        rm -rf "$_try"
    done
    if [[ -z "$LIB_DIR" ]]; then
        echo -e "\n  ${RD}Error:${NC} no usable scripts/lib for v${VERSION} or main — the installer cannot run without it. Re-bootstrap with the latest installer: bash <(curl -sSL https://raw.githubusercontent.com/${REPO}/main/install.sh)\n" >&2
        exit "$EX_ERROR"
    fi
fi
for _lib in "${LIB_FILES[@]}"; do
    # shellcheck disable=SC1090
    . "$LIB_DIR/$_lib"
done
[[ "$LIB_DIR" == /tmp/ovn-lib.* ]] && rm -rf "$LIB_DIR"
unset _lib _try _ref _url _ok _l _f

trap 'echo -e "\n  ${RD}Interrupted.${NC}" >&2; exit 130' INT TERM
trap 'render_warn "Command failed near line $LINENO (running: ${BASH_COMMAND:0:80})"' ERR

# ── OS / package manager ───────────────────────────────────────────────
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

# ── Help / args ────────────────────────────────────────────────────────
# Goes to stderr, like all human-readable output, so stdout stays clean for
# callers; a deprecation nobody sees is not a deprecation.
deprecated() {  # deprecated <flag> <what to do instead>
    printf '  %s⚠%s %s is deprecated; %s\n' "$YL" "$NC" "$1" "$2" >&2
}

# printf, not a renderer: this command exists to be read back by somebody else.
# A stale copy is normal (the raw CDN caches for minutes); the commit prints
# only when something stamped it.
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
  in the manager: ovn  (installed as ovnode/ovn).

  Options (every option has an OVN_* env equivalent; CLI wins):
    -y, --yes             Never prompt, accept defaults       [OVN_YES=1]
    --docker              Deploy in Docker (container runs agent + OpenVPN,
                          host networking)                    [OVN_DOCKER=1]

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
    -v, --version vX.Y.Z  Install/update this release instead of v${VERSION}
                                                          [OVN_VERSION]
    --from-release        Download the versioned release file [default]
                          [no replacement — verified releases are the only
                          source now, so just drop the flag]

  Exit codes:
    0 success · 1 error · 2 usage error · 3 already installed ·
    4 not installed

  Without a terminal (never prompts; branch on the exit code):
    OVN_KEY="\$API_KEY" bash install.sh -y
EOF
    exit "$EX_OK"
}

parse_args() {
    local need2='[[ $# -ge 2 ]] || die "$1 needs a value" "$EX_USAGE"'
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
                              *) die "Invalid --tls '$2' (use 1, 2, 3 or 4)" "$EX_USAGE" ;;
                          esac
                          shift 2 ;;
            --tls-domain) eval "$need2"; deprecated "--tls-domain" "set OVN_TLS_DOMAIN instead"; TLS_DOMAIN="$2"; CLI_FLAGS=1; shift 2 ;;
            --tls-key)    eval "$need2"; deprecated "--tls-key" "set OVN_TLS_KEY instead"; TLS_KEY="$2"; CLI_FLAGS=1; shift 2 ;;
            --tls-cert)   eval "$need2"; deprecated "--tls-cert" "set OVN_TLS_CERT instead"; TLS_CERT="$2"; CLI_FLAGS=1; shift 2 ;;
            --docker)     DOCKER=1; CLI_FLAGS=1; shift ;;
            --from-release) deprecated "--from-release" "verified releases are the only source now, so just drop it"; SRC="release"; CLI_FLAGS=1; shift ;;
            --ipv6)       deprecated "--ipv6" "set OVN_IPV6=1 instead"; IPV6=1; CLI_FLAGS=1; shift ;;
            --no-nat)     deprecated "--no-nat" "set OVN_NO_NAT=1 instead"; NO_NAT=1; CLI_FLAGS=1; shift ;;
            --yes|-y)     YES=1; CLI_FLAGS=1; shift ;;
            --purge)      deprecated "--purge" "set OVN_PURGE=1 instead"; PURGE=1; CLI_FLAGS=1; shift ;;
            status|start|stop|restart|restart-vpn|logs|backup|auto-backup|tls)
                          die "'$1' moved to the manager — use: ovn $1" "$EX_USAGE" ;;
            menu)         die "The menu lives in the manager — run: ovn" "$EX_USAGE" ;;
            install)      die "'install' is the default — just drop the word" "$EX_USAGE" ;;
            interactive)  ACTION="interactive"; CMD_GIVEN=1; shift ;;
            *)            die "Unknown option: $1 (--help for usage)" "$EX_USAGE" ;;
        esac
    done
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

# ── Toolchain ──────────────────────────────────────────────────────────
UV_BIN=""
ensure_uv() {
    if command -v uv >/dev/null 2>&1; then
        UV_BIN="$(command -v uv)"; render_ok "uv found: $UV_BIN"; return
    fi
    render_line "Installing uv (Python package manager)..."
    curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null 2>&1 || \
        python3 -m pip install --quiet uv >/dev/null 2>&1 || \
        die "Could not install uv."
    UV_BIN="$(command -v uv 2>/dev/null || true)"
    [[ -n "$UV_BIN" ]] || UV_BIN="$HOME/.local/bin/uv"
    [[ -x "$UV_BIN" ]] || die "uv not found after install"
    render_ok "uv installed: $UV_BIN"
}

# Reproducible dependency install: the lockfile pins exact versions.
# Fall back to a fresh resolve only when the lock cannot be honored.
uv_sync() {
    "$UV_BIN" sync --frozen --no-dev --quiet 2>/dev/null \
        || "$UV_BIN" sync --no-dev --quiet
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
        systemctl kill -s HUP openvpn-server@server >/dev/null 2>&1 || true
    endscript
}
ROTATE
    fi
    render_ok "Log rotation configured ($LOGROTATE_CONF)"
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

start_openvpn_service() {
    # The agent generates server.conf + PKI on first boot.
    if has_systemd; then
        systemctl enable openvpn-server@server >/dev/null 2>&1 || true
        systemctl restart openvpn-server@server >/dev/null 2>&1 && \
            render_ok "OpenVPN server service started" || \
            render_warn "Could not start openvpn-server@server — check: journalctl -u openvpn-server@server -n 50"
    elif command -v rc-service >/dev/null 2>&1; then
        rc-update add openvpn default >/dev/null 2>&1 || true
        rc-service openvpn start >/dev/null 2>&1 && render_ok "OpenVPN started (OpenRC)" || render_warn "Start OpenVPN manually"
    else
        render_warn "No init system detected — start OpenVPN manually: openvpn --config $OPENVPN_ROOT/server/server.conf"
    fi
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

# ── Systemd unit ───────────────────────────────────────────────────────
write_systemd_unit() {
    # ExecStart runs the venv interpreter directly: no uv resolution at boot.
    cat > "/etc/systemd/system/$SYSTEMD_SERVICE" << UNIT
[Unit]
Description=OVNode OpenVPN Node Agent (${NODE_NAME})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${APP_DIR}
Environment="PATH=${APP_DIR}/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
EnvironmentFile=${APP_DIR}/.env
ExecStart=${APP_DIR}/.venv/bin/python ${APP_DIR}/main.py
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

# ── Source / environment ───────────────────────────────────────────────
release_base() { printf 'ovnode-%s' "$VERSION"; }

release_url() {
    printf 'https://github.com/%s/releases/download/v%s/%s.tar.gz' \
        "$REPO" "$VERSION" "$(release_base)"
}

release_checksum_url() {
    printf 'https://github.com/%s/releases/download/v%s/%s.sha256' \
        "$REPO" "$VERSION" "$(release_base)"
}

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
    python3 - "$UPDATE_STATE" "$phase" "$from" "$target" "$backup" "$identity" <<'PY'
import json, os, sys, tempfile, time
path, phase, old, target, backup, identity = sys.argv[1:]
data = {"phase": phase, "from_version": old, "to_version": target,
        "safety_backup": backup or None, "identity_sha": identity or None,
        "updated_at": int(time.time()), "pid": os.getppid()}
fd, tmp = tempfile.mkstemp(prefix=".update-state-", dir=os.path.dirname(path))
try:
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=2); f.write("\n"); f.flush(); os.fsync(f.fileno())
    os.chmod(tmp, 0o600); os.replace(tmp, path)
finally:
    try: os.unlink(tmp)
    except FileNotFoundError: pass
PY
}

# sha256(node-name + API key): proves identity survived activation without
# ever persisting a secret in the journal.
identity_sha() {
    python3 - "$1" "$2" <<'PY'
import hashlib, sys
print(hashlib.sha256(("|".join(sys.argv[1:])).encode()).hexdigest())
PY
}

# A redirect stub or proxy block page must fail here, not later as a checksum
# mismatch.
is_release_archive() { tar -tzf "$1" >/dev/null 2>&1; }

# Download the versioned release file into $1 (an existing directory).
# The .sha256 sidecar is mandatory: unverified code is never installed.
fetch_release() {
    local dest="$1" work base
    base="$(release_base)"
    work="$(mktemp -d /tmp/ovn.XXXXXX)"
    run "Downloading release v${VERSION}" \
        curl -fsSL -o "$work/$base.tar.gz" "$(release_url)" \
        || { rm -rf "$work"; die "No release file for v${VERSION}" "$EX_ERROR"; }
    is_release_archive "$work/$base.tar.gz" \
        || { rm -rf "$work"; die "Download for v${VERSION} is not a release archive (stale installer or blocked download?). Re-bootstrap with the latest installer:  bash <(curl -sSL https://raw.githubusercontent.com/${REPO}/main/install.sh)" "$EX_ERROR"; }
    curl -fsSL -o "$work/$base.sha256" "$(release_checksum_url)" 2>/dev/null \
        || { rm -rf "$work"; die "Release checksum file is missing for v${VERSION}" "$EX_ERROR"; }
    ( cd "$work" && sha256sum -c "$base.sha256" >/dev/null ) \
        || { rm -rf "$work"; die "Release checksum mismatch for v${VERSION}" "$EX_ERROR"; }
    render_ok "Checksum ok"
    mkdir -p "$dest"
    # --no-same-owner: an archive from an older release still carries whatever
    # uid built it, and extracting as root would restore that. The install runs
    # as root, so honouring the archive's numeric ids is exactly backwards.
    tar --no-same-owner -xzf "$work/$base.tar.gz" -C "$dest" >/dev/null 2>&1 || { rm -rf "$work"; die "Extract failed" "$EX_ERROR"; }
    # Root-owned explicitly, so the tree does not depend on how it was built.
    chown -R root:root "$dest"
    rm -rf "$work"
    render_ok "Release extracted"
}

# Safety snapshot of every persistent state needed for rollback: identity
# (.env), node data dir, OpenVPN state, API TLS files. One manifest-linked
# tarball; state_restore consumes it after verification.
state_safety_bundle() {
    local from_version="$1" backup_root="/var/backups"
    local node_data; node_data="$(node_data_dir)"
    mkdir -p "$backup_root" "$node_data"
    python3 - "$APP_DIR" "$node_data" "$OPENVPN_ROOT" "$backup_root" "$NODE_NAME" "$from_version" <<'PY' || return 1
import hashlib, json, os, sys, tarfile, tempfile
from datetime import datetime, timezone
app_dir, node_data, ovpn_root, backup_root, node, from_version = sys.argv[1:]
members = {}
def add_tree(archive, src, arc):
    for root, _dirs, files in os.walk(src):
        for name in sorted(files):
            if name in ("update-maintenance", "update-state.json"):
                continue  # live transaction artifacts must never restore
            full = os.path.join(root, name)
            if not os.path.isfile(full) or os.path.islink(full) and not os.path.exists(full):
                continue
            rel = os.path.join(arc, os.path.relpath(full, src))
            archive.add(full, arcname=rel, recursive=False)
            digest = hashlib.sha256()
            with open(full, "rb") as f:
                for chunk in iter(lambda: f.read(1048576), b""):
                    digest.update(chunk)
            members[rel] = digest.hexdigest()
def add_file(archive, src, arc):
    if os.path.isfile(src):
        archive.add(src, arcname=arc, recursive=False)
        digest = hashlib.sha256()
        with open(src, "rb") as f:
            for chunk in iter(lambda: f.read(1048576), b""):
                digest.update(chunk)
        members[arc] = digest.hexdigest()
now = datetime.now(timezone.utc)
stamp = now.strftime("%Y%m%d_%H%M%S")
final = os.path.join(backup_root, "ovnode-state-pre-update-%s.tar.gz" % stamp)
fd, tmp = tempfile.mkstemp(prefix=".ovnode-state-", suffix=".part", dir=backup_root)
os.close(fd); os.chmod(tmp, 0o600)
try:
    with tempfile.TemporaryDirectory(prefix="ovnode-state-") as stage:
        with tarfile.open(tmp, "w:gz", format=tarfile.PAX_FORMAT) as archive:
            add_file(archive, os.path.join(app_dir, ".env"), "node.env")
            add_tree(archive, node_data, "data")
            for sub in ("server", "ccd", "ovnode"):
                add_tree(archive, os.path.join(ovpn_root, sub), "openvpn/%s" % sub)
            try:
                with open(os.path.join(app_dir, ".env"), encoding="utf-8") as f:
                    env = dict(line.strip().split("=", 1) for line in f if "=" in line and not line.startswith("#"))
                for key in ("SSL_KEYFILE", "SSL_CERTFILE"):
                    target = env.get(key, "")
                    if target and os.path.isfile(target):
                        add_file(archive, target, "tls/%s" % os.path.basename(target))
            except OSError:
                pass
            manifest = {"format": "ovnode-state", "format_version": 1, "node": node,
                        "from_version": from_version, "created_at": now.isoformat(), "members": members}
            manifest_path = os.path.join(stage, "manifest.json")
            with open(manifest_path, "w", encoding="utf-8") as f:
                json.dump(manifest, f, sort_keys=True, indent=2); f.write("\n")
            archive.add(manifest_path, arcname="manifest.json", recursive=False)
        with tarfile.open(tmp, "r:gz") as archive:
            names = {m.name for m in archive.getmembers() if m.isfile()}
            if "manifest.json" not in names:
                raise SystemExit("bundle verification failed: no manifest")
            if any(n.startswith("/") or ".." in n.split("/") for n in names):
                raise SystemExit("bundle verification failed: unsafe member")
            seen = json.load(archive.extractfile("manifest.json"))
            if seen.get("format") != "ovnode-state":
                raise SystemExit("bundle verification failed: bad manifest")
    os.replace(tmp, final); os.chmod(final, 0o600)
finally:
    try: os.unlink(tmp)
    except FileNotFoundError: pass
print(final)
PY
    # Retention for safety bundles (backup pruning covers node-*/node-pki-*).
    ls -t "$backup_root"/ovnode-state-pre-update-*.tar.gz 2>/dev/null | tail -n +6 | xargs -r rm -f
    return 0
}

# Restore state after a failed activation. Fails closed on any manifest or
# checksum problem; never extracts unsafe member names.
state_restore() {
    local bundle="$1"
    [[ -f "$bundle" ]] || return 1
    python3 - "$bundle" "$APP_DIR" "$DATA_BASE" "$OPENVPN_ROOT" <<'PY' || return 1
import hashlib, json, os, sys, tarfile, tempfile
bundle, app_dir, data_base, ovpn_root = sys.argv[1:]
roots = {"node.env": app_dir, "data/": data_base, "openvpn/": ovpn_root, "tls/": None, "manifest.json": None}
with tarfile.open(bundle, "r:gz") as archive:
    infos = [m for m in archive.getmembers() if m.isfile()]
    names = {m.name for m in infos}
    if "manifest.json" not in names:
        raise SystemExit("unsafe state backup: no manifest")
    if any(n.startswith("/") or ".." in n.split("/") for n in names):
        raise SystemExit("unsafe state backup: unsafe member")
    manifest = json.load(archive.extractfile("manifest.json"))
    if manifest.get("format") != "ovnode-state":
        raise SystemExit("unsafe state backup: bad manifest")
    expected = manifest.get("members", {})
    staged = tempfile.mkdtemp(prefix="ovnode-restore-")
    try:
        archive.extractall(path=staged, members=infos)
        for rel, digest in expected.items():
            with open(os.path.join(staged, rel), "rb") as f:
                actual = hashlib.sha256(f.read()).hexdigest()
            if actual != digest:
                raise SystemExit("state backup checksum mismatch: %s" % rel)
        import shutil
        for rel in expected:
            if rel == "node.env":
                dst = os.path.join(app_dir, ".env")
            elif rel.startswith("data/"):
                dst = os.path.join(data_base, os.path.relpath(rel, "data"))
            elif rel.startswith("openvpn/"):
                dst = os.path.join(ovpn_root, os.path.relpath(rel, "openvpn"))
            elif rel.startswith("tls/"):
                continue  # certs restore via repair flow, never auto-overwritten
            else:
                raise SystemExit("unsafe state backup: unknown member %s" % rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix=".ovnode-restore-", dir=os.path.dirname(dst))
            try:
                with os.fdopen(fd, "wb") as f, open(os.path.join(staged, rel), "rb") as s:
                    shutil.copyfileobj(s, f, 1048576)
                if dst.endswith(".env"):
                    os.chmod(tmp, 0o600)
                os.replace(tmp, dst)
            finally:
                try: os.unlink(tmp)
                except FileNotFoundError: pass
    finally:
        shutil.rmtree(staged, ignore_errors=True)
print("state restored")
PY
}

# Authenticated "version openvpn_running" from the agent. Empty output means
# unreachable or rejected (identity broken).
node_api_status() {
    local key="$1" port="$2" tls="$3" scheme="http"
    [[ "$tls" != "none" ]] && scheme="https"
    curl -fskS --max-time 5 "${scheme}://127.0.0.1:${port}/sync/status" \
        -H "key: ${key}" 2>/dev/null \
        | python3 -c 'import json,sys; d=(json.load(sys.stdin).get("data") or {}); print(d.get("version",""), str(d.get("openvpn_running","")).lower())' 2>/dev/null || true
}

write_env() {
    # TUNNEL_ADDRESS is deliberately not written here: the node's pydantic
    # Settings rejects extra env fields, and the panel pushes it via /sync/config.
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

# ── Install ────────────────────────────────────────────────────────────
do_install() {
    check_root
    check_deps
    [[ "$DOCKER" -eq 1 ]] || ensure_uv

    render_begin "preflight" 6
    render_done "$(preflight_summary)"

    render_begin "release" 6
    fetch_release "$APP_DIR"

    render_begin "certificate" 6
    if [[ "$DOCKER" -eq 0 ]]; then
        cd "$APP_DIR"
        render_note "python dependencies"
        uv_sync >/dev/null 2>&1 || die "Could not install the node agent's Python packages"
        render_note "$(tls_summary)"
    fi
    setup_tls
    write_env
    render_done "$(tls_summary)"

    local scheme="http"
    [[ "$TLS_METHOD" != "none" ]] && scheme="https"
    local host; host="$(primary_ip)"

    mkdir -p "$(node_data_dir)"
    ensure_openvpn_dirs

    render_begin "runtime" 6
    if [[ "$DOCKER" -eq 1 ]]; then
        setup_docker
        render_done "container"
    else
        if ! has_systemd; then
            render_done "no systemd — start the agent by hand"
            render_warn "systemd not found — start the agent manually: cd $APP_DIR && .venv/bin/python main.py"
        else
            write_systemd_unit
            render_note "$SYSTEMD_SERVICE"
            systemctl_bounded restart "$SYSTEMD_SERVICE" >/dev/null 2>&1 \
                || die "Could not start $SYSTEMD_SERVICE"
            render_done "active"
        fi
    fi

    # First boot generates the PKI + server.conf, so wait for /sync/health
    # before bringing up OpenVPN.
    render_begin "health" 6
    if ! wait_health_live "${scheme}://127.0.0.1:${PORT}/sync/health" 60; then
        render_fail "health" "no answer on /sync/health after 60s"
        render_next "ovn logs 50" "$(installer_uninstall_command)"
        return 1
    fi
    render_done "200"
    [[ "$DOCKER" -eq 1 ]] && check_container_openvpn

    render_begin "vpn" 6
    # Docker runs the daemon inside the container (entrypoint-supervised) and
    # evicts any host daemon holding the VPN/management ports.
    if [[ "$DOCKER" -eq 0 ]]; then
        start_openvpn_service
    else
        stop_native_openvpn
    fi
    setup_nat
    setup_logrotate
    open_firewall_ports
    render_done "$(vpn_ports_label)/$VPN_PROTO"

    render_begin "command" 6
    install_cli
    render_done "$BIN_DIR/$CLI_ALIAS"

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
        "logs|$CLI_ALIAS logs -f"
    render_line "  $(printf '%slost it?  %s credentials%s' "$GY" "$CLI_ALIAS" "$NC")"
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
        render_begin "migrate data" 6
        if migrate_flat_data_dir; then
            render_done "data directory flattened"
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
    from_version="$(grep -Eo '"[0-9]+\.[0-9]+\.[0-9]+"' "$APP_DIR/core/version.py" 2>/dev/null | head -1 | tr -d '"' || true)"
    : "${from_version:=unknown}"
    identity="$(identity_sha "$NODE_NAME" "$API_KEY")"
    scheme="http"; [[ "$TLS_METHOD" != "none" ]] && scheme="https"
    update_state preflight "$from_version" "$VERSION" "" "$identity"

    render_begin "backup" 6
    safety="$(state_safety_bundle "$from_version")" || die "Could not create the mandatory state safety snapshot" "$EX_ERROR"
    [[ -n "$safety" && -f "$safety" ]] || die "The state safety snapshot was not created" "$EX_ERROR"
    snapshot="$(snapshot_code "$APP_DIR" "node" 2)"
    render_done "$(basename "$safety" 2>/dev/null)"
    update_state staging "$from_version" "$VERSION" "$safety" "$identity"

    render_begin "stage" 6
    rm -rf "$UPDATE_STAGE"
    mkdir -p "$UPDATE_STAGE"
    if [[ "$DOCKER" -eq 1 ]]; then
        ensure_docker
        run "Pulling published OVNode image" \
            docker pull "ghcr.io/${REPO,,}:${VERSION}" \
            || die "Could not pull ghcr.io/${REPO,,}:${VERSION}" "$EX_ERROR"
    else
        fetch_release "$UPDATE_STAGE"
        cp -p "$APP_DIR/.env" "$UPDATE_STAGE/.env" || die "Could not preserve configuration" "$EX_ERROR"
        chmod 600 "$UPDATE_STAGE/.env"
        ensure_uv
        ( cd "$UPDATE_STAGE" && run "Staged Python dependencies" uv_sync ) \
            || die "Could not prepare the staged release; current version is still running" "$EX_ERROR"
        [[ -f "$UPDATE_STAGE/core/version.py" ]] || die "Staged release is incomplete" "$EX_ERROR"
    fi
    render_done ""

    render_begin "maintenance" 6
    : > "$(update_marker)"
    chmod 600 "$(update_marker)"
    update_state activating "$from_version" "$VERSION" "$safety" "$identity"
    if [[ "$DOCKER" -eq 1 ]]; then
        ( cd "$APP_DIR" && docker compose -f "$(compose_file)" down ) >/dev/null 2>&1 || true
    else
        # The OpenVPN daemon keeps serving clients; only the agent stops.
        systemctl_bounded stop "$SYSTEMD_SERVICE" >/dev/null 2>&1 || true
    fi
    render_done "agent paused"

    render_begin "activate" 6
    if [[ "$DOCKER" -eq 1 ]]; then
        IMAGE_TAG="$VERSION" write_compose_file
        ( cd "$APP_DIR" && docker compose -f "$(compose_file)" up -d ) >/dev/null 2>&1 \
            || { update_state recovery_required "$from_version" "$VERSION" "$safety" "$identity"; die "Could not start the candidate container. Writes remain blocked; run: ovn recover-update" "$EX_ERROR"; }
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
            die "Could not activate or restore release files. Writes remain blocked; run: ovn recover-update" "$EX_ERROR"
        fi
    fi

    local start_ok=0
    if [[ "$DOCKER" -eq 1 ]]; then
        start_ok=1
    else
        has_systemd && write_systemd_unit
        run "Candidate agent started" systemctl_bounded restart "$SYSTEMD_SERVICE" && start_ok=1 || true
    fi
    render_done ""

    render_begin "verify" 6
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

    render_begin "commit" 6
    rm -f "$(update_marker)"
    if [[ "$DOCKER" -eq 0 ]]; then
        setup_nat
        setup_logrotate
    fi
    if ! wait_health "${scheme}://127.0.0.1:${PORT}/sync/health" 60; then
        : > "$(update_marker)"; chmod 600 "$(update_marker)"
        update_state recovery_required "$from_version" "$VERSION" "$safety" "$identity"
        operation_end
        die "Candidate passed verification but failed its final check. Writes are blocked; run: ovn recover-update" "$EX_ERROR"
    fi
    update_state committed "$from_version" "$VERSION" "$safety" "$identity"
    render_done "v${from_version} → v${VERSION}"
    operation_end
    install_cli
    [[ "$DOCKER" -eq 1 ]] || render_line "  rollback: $CLI_ALIAS rollback"
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
            || { update_state recovery_required "$from_version" "$target" "$safety" "$identity"; operation_end; die "Previous container stopped but state could not be restored. Run: ovn recover-update" "$EX_ERROR"; }
        IMAGE_TAG="$from_version" write_compose_file
        ( cd "$APP_DIR" && docker compose -f "$(compose_file)" up -d ) >/dev/null 2>&1 \
            || { update_state recovery_required "$from_version" "$target" "$safety" "$identity"; operation_end; die "Previous image could not be restarted. Run: ovn recover-update" "$EX_ERROR"; }
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
    read -r phase from target safety identity < <(python3 - "$UPDATE_STATE" <<'PY'
import json, sys
x = json.load(open(sys.argv[1]))
print(x.get("phase", "unknown"), x.get("from_version", "unknown"),
      x.get("to_version", "unknown"), x.get("safety_backup") or "", x.get("identity_sha") or "")
PY
) || die "Update state journal is unreadable" "$EX_ERROR"
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
        die "Interrupted update never activated and v${from} does not answer health. Run: ovn logs 100" "$EX_ERROR"
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
    die "Previous release was restored but is not healthy. Run: ovn logs 100" "$EX_ERROR"
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
        setup_nat
        setup_logrotate
    fi
    operation_end
    render_ok "Host integration repaired — restart the agent if it is stopped: ovn restart"
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
    render_kv "services" "$SYSTEMD_SERVICE, $NAT_SERVICE, openvpn-server@server"
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

    render_begin "uninstall" 1
    # Stopping the NAT unit runs its ExecStop cleanup (rules removed).
    systemctl_bounded stop "$SYSTEMD_SERVICE"
    systemctl_bounded stop "$NAT_SERVICE"
    systemctl_bounded stop openvpn-server@server
    systemctl disable "$SYSTEMD_SERVICE" "$NAT_SERVICE" openvpn-server@server 2>/dev/null || true
    rm -f "/etc/systemd/system/$SYSTEMD_SERVICE" "/etc/systemd/system/$NAT_SERVICE"
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
        render_done "data and PKI removed · backups in /var/backups"
    else
        render_done "app removed · data kept at $DATA_BASE"
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
    # Refreshed on every update, so a box whose ovn is an old copy gets swapped.
    local src="${APP_DIR}/manager.sh"
    [[ -f "$src" ]] || return 0
    mkdir -p "$BIN_DIR" 2>/dev/null || { render_warn "Could not create $BIN_DIR"; return 0; }
    if cp -f "$src" "$BIN_DIR/$CLI_NAME" 2>/dev/null && chmod 0755 "$BIN_DIR/$CLI_NAME"; then
        ln -sf "$CLI_NAME" "$BIN_DIR/$CLI_ALIAS" 2>/dev/null || true
        render_ok "Command  ${BIN_DIR}/${CLI_NAME}  (alias: ${CLI_ALIAS})"
    else
        render_warn "Could not install the $CLI_NAME command into $BIN_DIR"
    fi
}

remove_cli() {
    rm -f "$BIN_DIR/$CLI_NAME" "$BIN_DIR/$CLI_ALIAS" 2>/dev/null || true
    # `ovn completion` writes this; a leftover completes a command that is gone.
    rm -f "${OVN_COMPLETION_DIR:-/etc/bash_completion.d}/ovn" 2>/dev/null || true
}

# ── Preconditions ──────────────────────────────────────────────────────
check_deps() {
    local missing=() cmd
    for cmd in curl tar openssl git; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    # Docker bundles agent + OpenVPN in the image; a host install needs python3.
    if [[ "$DOCKER" -eq 0 ]]; then
        command -v python3 >/dev/null 2>&1 || missing+=("python3")
    fi
    [[ ${#missing[@]} -eq 0 ]] || pkg_install "${missing[@]}"
    if [[ "$DOCKER" -eq 0 ]] && ! command -v openvpn >/dev/null 2>&1; then
        render_line "Installing OpenVPN + easy-rsa (for client PKI)..."
        pkg_install openvpn easy-rsa
    fi
    render_ok "System dependencies present"
}

# ── Main ───────────────────────────────────────────────────────────────
main() {
    parse_args "$@"
    [[ -n "${OVN_SRC:-}" && "${OVN_SRC}" != "release" ]] && die "Source installs were removed — the installer consumes verified releases only (developers: clone the repo and follow CONTRIBUTING.md)" "$EX_USAGE"
    [[ -n "${OVN_BRANCH:-}" ]] && die "OVN_BRANCH was removed with source installs — developers: git checkout the branch in a clone" "$EX_USAGE"
    if [[ -n "$PIN" ]]; then
        valid_release_version "$PIN" \
            || die "Bad --version '$PIN' (use 1.2.3, v1.2.3, 1.2.3-rc1)" "$EX_USAGE"
        VERSION="${PIN#v}"
    fi
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

    # Must precede the already-installed guard: `install --port abc` should be
    # exit 2 with the usage message, not exit 3 (Already installed).
    if [[ "$CLI_FLAGS" -eq 1 || "$ENV_INPUTS" -eq 1 ]]; then
        [[ -n "$PORT" ]]      || PORT="$DEFAULT_PORT"
        [[ -n "$TLS_METHOD" ]]|| TLS_METHOD="selfsigned"
        [[ -n "$VPN_PORTS" ]] || VPN_PORTS="$DEFAULT_VPN"
        [[ -n "$NODE_NAME" ]] || NODE_NAME="ovnode"
        validate_input
    fi

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
    if [[ "$YES" -eq 0 ]] && ! is_tty; then
        die "No interactive terminal. The default install asks questions; pass -y to accept the defaults without them." "$EX_USAGE"
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
