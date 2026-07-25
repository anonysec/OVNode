#!/bin/bash
# OVNode — OpenVPN Node Agent Installer
# Usage: bash <(curl -Ls https://anonysec.github.io/OVNode/install.sh)

set -uo pipefail

# ═══════════════════════════════════════
#  C O N F I G
# ═══════════════════════════════════════
REPO="anonysec/OVNode"
INSTALL_DIR="/opt/ovnode"
DEFAULT_PORT=2083
DEFAULT_VPN=1194
SYSTEMD_SERVICE="ovnode.service"
VERSION="2.0"

# ═══════════════════════════════════════
#  C O L O R S
# ═══════════════════════════════════════
NC=$'\033[0m'; B=$'\033[1m'; D=$'\033[2m'
WH=$'\033[97m'; GR=$'\033[32m'; RD=$'\033[31m'
YL=$'\033[33m'; CY=$'\033[36m'; GY=$'\033[90m'

# ═══════════════════════════════════════
#  U I
# ═══════════════════════════════════════
line()   { echo -e "  $1"; }
step()   { line "${GR}  ✓${NC} $1"; }
info()   { line "${CY}  →${NC} $1"; }
sep()    { line "${GY}$(printf '%.0s─' {1..52})${NC}"; }
field()  { printf "  ${GY}%-16s${NC} %s\n" "$1" "$2"; }

spinner() {
    local msg="$1" pid=$2 chars='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏' i=0
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r  ${CY}%s${NC} %-48s" "${chars:$((i%9)):1}" "$msg"
        sleep 0.1; ((i++))
    done
    wait "$pid" 2>/dev/null
    local rc=$?
    printf "\r\033[K"
    [[ $rc -eq 0 ]] && step "$msg" || { line "${RD}  ✗${NC} $msg"; return 1; }
}

prompt_val() {
    local var="$1" label="$2" default="$3" hidden="${4:-}"
    local val=""
    if [[ -t 0 ]]; then
        if [[ "$hidden" == "h" ]]; then
            printf "  ${WH}%-16s${NC} ${GY}[%s]${NC} : " "$label" "$default"
            read -rs val; printf "\n"
        else
            printf "  ${WH}%-16s${NC} ${GY}[%s]${NC} : " "$label" "$default"
            read -r val
        fi
    fi
    [[ -z "$val" ]] && val="$default"
    eval "$var='$val'"
}

die() { echo -e "\n  ${RD}Error:${NC} $1\n"; exit 1; }
trap 'echo -e "\n  ${RD}Interrupted.${NC}"; exit 1' INT TERM

show_help() {
    cat << 'EOF'
  Usage:
    bash <(curl -Ls https://anonysec.github.io/OVNode/install.sh)
    bash <(curl -Ls URL) update
    bash <(curl -Ls URL) uninstall

  Commands:
    (none)              Install or update OVNode
    update              Pull latest changes and restart
    uninstall           Remove OVNode completely

  Flags:
    --port PORT     Service port (default: 2083)
    --api-key KEY   API key (auto-generated if empty)
    --vpn-port PORT OpenVPN port (default: 1194)
    --help          Show this help
EOF
    exit 0
}

PORT="" API_KEY="" VPN_PORT="" ACTION="install"

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --port)      PORT="$2"; shift 2 ;;
            --api-key)   API_KEY="$2"; shift 2 ;;
            --vpn-port)  VPN_PORT="$2"; shift 2 ;;
            --uninstall) ACTION="uninstall"; shift ;;
            --help|-h)   show_help ;;
            uninstall)   ACTION="uninstall"; shift ;;
            update)      ACTION="update"; shift ;;
            *)           die "Unknown option: $1. Use --help for usage." ;;
        esac
    done
}

interactive_setup() {
    prompt_val PORT      "Service port" "$DEFAULT_PORT"
    prompt_val API_KEY   "API key"      "$(python3 -c 'import uuid;print(uuid.uuid4().hex)' 2>/dev/null || openssl rand -hex 16)"
    prompt_val VPN_PORT  "OpenVPN port" "$DEFAULT_VPN"
    sep
    field "Install dir" "$INSTALL_DIR"
    sep
    if [[ -t 0 ]]; then
        printf "  Proceed with installation? [${GR}Y${NC}/n] : "
        read -r c; [[ "$c" =~ ^[Nn]$ ]] && die "Cancelled."
    fi
}

check_root() {
    [[ "$EUID" -ne 0 ]] && die "Must run as root."
}

check_deps() {
    local missing=()
    for cmd in curl tar openssl git; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        info "Installing missing dependencies: ${missing[*]}"
        apt-get update -qq >/dev/null && apt-get install -y -qq "${missing[@]}" >/dev/null \
            || die "Failed to install: ${missing[*]}"
    fi
    step "All system dependencies are available"

    if ! command -v openvpn >/dev/null 2>&1; then
        info "Installing OpenVPN and easy-rsa for PKI management..."
        apt-get install -y -qq openvpn easy-rsa >/dev/null 2>&1 \
            || warn "OpenVPN install failed — manual PKI setup may be needed"
    else
        step "OpenVPN is already installed"
    fi
}

do_install() {
    [[ -d "$INSTALL_DIR" ]] && die "Already installed. Use --uninstall first."

    sep
    info "Cloning OVNode repository..."
    if command -v git >/dev/null 2>&1; then
        git clone --depth 1 --branch main "https://github.com/${REPO}.git" "$INSTALL_DIR" >/dev/null 2>&1 &
        spinner "Cloning repository" $!
    else
        curl -sSLo /tmp/ovn.tar.gz "https://github.com/${REPO}/archive/refs/heads/main.tar.gz" >/dev/null 2>&1 &
        spinner "Downloading tarball" $!
        tar -xzf /tmp/ovn.tar.gz -C /opt/ >/dev/null 2>&1
        mv "/opt/OVNode-main" "$INSTALL_DIR" 2>/dev/null || die "Extract failed"
        rm -f /tmp/ovn.tar.gz
    fi

    info "Installing Python packages with uv..."
    cd "$INSTALL_DIR"
    uv sync --quiet 2>&1 &
    spinner "Python packages installed" $!

    info "Writing .env configuration..."
    cat > "$INSTALL_DIR/.env" << ENVEOF
SERVICE_PORT=${PORT}
API_KEY=${API_KEY}
OPENVPN_PORT=${VPN_PORT}
ENVEOF
    step "Configuration saved to $INSTALL_DIR/.env"

    info "Setting up systemd service..."
    local real_uv; real_uv=$(command -v uv)
    cat > "/etc/systemd/system/${SYSTEMD_SERVICE}" << SVCEOF
[Unit]
Description=OVNode OpenVPN Node Agent
After=network.target openvpn.service

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
Environment="PATH=${INSTALL_DIR}/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=${real_uv} run main.py
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
SVCEOF
    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable "$SYSTEMD_SERVICE" >/dev/null 2>&1
    systemctl restart "$SYSTEMD_SERVICE" >/dev/null 2>&1 &
    spinner "Service started" $!

    sep
    line ""
    step "${B}Installation complete!${NC}"
    line ""
    line "  ${WH}Health:${NC}  http://$(hostname -I | awk '{print $1}'):${PORT}/sync/health"
    line "  ${WH}API key:${NC} ${GR}${API_KEY}${NC}"
    line ""
    line "  ${GY}Manage:${NC}  systemctl status ${SYSTEMD_SERVICE}"
    line "  ${GY}Logs:${NC}    journalctl -u ${SYSTEMD_SERVICE} -f"
    line ""
}

do_update() {
    [[ ! -d "$INSTALL_DIR" ]] && die "Not installed"
    line ""
    info "Updating OVNode..."
    cd "$INSTALL_DIR"
    git pull origin main 2>&1 &
    spinner "Pulling latest changes" $!
    uv sync --quiet 2>&1 &
    spinner "Updating Python dependencies" $!
    systemctl restart "$SYSTEMD_SERVICE" >/dev/null 2>&1 &
    spinner "Service restarted" $!
    step "Update complete"
    line ""
}

do_uninstall() {
    if [[ -t 0 ]]; then
        printf "  Remove OVNode and stop service? [y/N] : "; read -r c
        [[ ! "$c" =~ ^[Yy]$ ]] && die "Cancelled."
    fi
    systemctl stop "$SYSTEMD_SERVICE" 2>/dev/null
    systemctl disable "$SYSTEMD_SERVICE" 2>/dev/null
    rm -f "/etc/systemd/system/${SYSTEMD_SERVICE}"
    systemctl daemon-reload 2>/dev/null
    rm -rf "$INSTALL_DIR"
    step "Uninstalled"
    line ""
}

main() {
    parse_args "$@"
    clear

    line ""
    line "  ${B}OVNode${NC} — OpenVPN Node Agent Installer ${GY}v${VERSION}${NC}"
    sep
    line ""

    case "$ACTION" in
        uninstall) do_uninstall; exit 0 ;;
        update)    do_update; exit 0 ;;
    esac

    if [[ -d "$INSTALL_DIR" ]]; then
     warn "OVNode is already installed"
     line ""
     cd "$INSTALL_DIR" 2>/dev/null
     git fetch origin main --quiet 2>/dev/null
     local LOCAL=$(git rev-parse HEAD 2>/dev/null)
     local REMOTE=$(git rev-parse origin/main 2>/dev/null)
     local HAS_UPDATE=0
     [[ "$LOCAL" != "$REMOTE" ]] && HAS_UPDATE=1

     if [[ -t 0 ]]; then
         if [[ $HAS_UPDATE -eq 1 ]]; then
             line "  ${GR}1${NC})  Update to latest version"
         fi
         line "  ${RD}2${NC})  Reinstall (remove and install fresh)"
         line "  ${GY}3${NC})  Quit"
         line ""
         printf "  Select [${GR}1${NC}] : "
         read -r choice
         if [[ $HAS_UPDATE -eq 1 ]]; then
             case "${choice:-1}" in
                 1|"") do_update; exit 0 ;;
                 2)    do_uninstall; do_install ;;
                 *)    line ""; exit 0 ;;
             esac
         else
             case "${choice:-2}" in
                 2)    do_uninstall; do_install ;;
                 *)    line ""; exit 0 ;;
             esac
         fi
     else
         [[ $HAS_UPDATE -eq 1 ]] && { info "New version available, updating..."; do_update; exit 0; }
         info "Already up to date."
         exit 0
     fi
 fi

    if [[ -z "$PORT" && -z "$API_KEY" ]]; then
        interactive_setup
    else
        : "${PORT:=$DEFAULT_PORT}"
        : "${API_KEY:=$(python3 -c 'import uuid;print(uuid.uuid4().hex)' 2>/dev/null || openssl rand -hex 16)}"
        : "${VPN_PORT:=$DEFAULT_VPN}"
        field "Service port" "$PORT"
        field "API key"      "${API_KEY:0:8}..."
        field "OpenVPN port" "$VPN_PORT"
        field "Install dir"  "$INSTALL_DIR"
        sep
    fi

    check_root
    check_deps
    do_install
}

main "$@"
