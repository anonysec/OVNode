#!/bin/bash
# OVNode OpenVPN Node Agent Installer — TUI Edition
# Usage: bash <(curl -Ls https://anonysec.github.io/OVNode/install.sh)
#        curl -Ls URL | bash -s -- --port 2083 --api-key KEY

set -uo pipefail

# ══════════════════════════════════════════════════
#  C O N F I G
# ══════════════════════════════════════════════════
REPO="anonysec/OVNode"
INSTALL_DIR="/opt/ovnode"
DEFAULT_PORT=2083
DEFAULT_VPN_PORT=1194
SYSTEMD_SERVICE="ovnode.service"

# ══════════════════════════════════════════════════
#  C O L O R S
# ══════════════════════════════════════════════════
C='\033'
R="${C}[0m"
BOLD="${C}[1m"
DIM="${C}[2m"
RED="${C}[31m"
GREEN="${C}[32m"
YELLOW="${C}[33m"
BLUE="${C}[34m"
CYAN="${C}[36m"
WHITE="${C}[97m"
BG_BLUE="${C}[44m"
BG_GREEN="${C}[42m"
BG_RED="${C}[41m"

# ══════════════════════════════════════════════════
#  H E L P E R S
# ══════════════════════════════════════════════════
clear_line() { printf "\r\033[K"; }
spin_chars='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'

spinner() {
    local msg="$1" pid=$2 logfile="${3:-}"
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r  ${CYAN}%s${R} %s" "${spin_chars:$((i%10)):1}" "$msg"
        sleep 0.1
        ((i++))
    done
    wait "$pid" 2>/dev/null
    local rc=$?
    clear_line
    if [[ $rc -eq 0 ]]; then
        printf "  ${GREEN}✓${R} %s\n" "$msg"
    else
        printf "  ${RED}✗${R} %s (exit code: %d)\n" "$msg" "$rc"
        return 1
    fi
    return 0
}

step_ok()   { echo -e "  ${GREEN}✓${R} $1"; }
step_warn() { echo -e "  ${YELLOW}⚠${R} $1"; }
step_fail() { echo -e "  ${RED}✗${R} $1"; }
step_info() { echo -e "  ${BLUE}●${R} $1"; }
step_dim()  { echo -e "  ${DIM}$1${R}"; }

box_line() { echo -e "  ${CYAN}│${R} $1"; }

banner() {
    clear
    printf "\n"
    printf "  ${BG_BLUE}${WHITE}${BOLD}                                                              ${R}\n"
    printf "  ${BG_BLUE}${WHITE}${BOLD}    ██████╗ ███████╗██╗   ██╗██╗  ███████╗██╗   ██╗███████╗  ${R}\n"
    printf "  ${BG_BLUE}${WHITE}${BOLD}    ██╔══██╗██╔════╝██║   ██║██║  ██╔════╝╚██╗ ██╔╝██╔════╝  ${R}\n"
    printf "  ${BG_BLUE}${WHITE}${BOLD}    ██║  ██║█████╗  ██║   ██║██║  █████╗   ╚████╔╝ ███████╗  ${R}\n"
    printf "  ${BG_BLUE}${WHITE}${BOLD}    ██║  ██║██╔══╝  ╚██╗ ██╔╝██║  ██╔══╝    ╚██╔╝  ╚════██║  ${R}\n"
    printf "  ${BG_BLUE}${WHITE}${BOLD}    ██████╔╝███████╗ ╚████╔╝ ██║  ███████╗   ██║   ███████║  ${R}\n"
    printf "  ${BG_BLUE}${WHITE}${BOLD}    ╚═════╝ ╚══════╝  ╚═══╝  ╚═╝  ╚══════╝   ╚═╝   ╚══════╝  ${R}\n"
    printf "  ${BG_BLUE}${WHITE}${BOLD}                                                              ${R}\n"
    printf "\n"
    printf "  ${DIM}OpenVPN Node Agent Installer${R}  ${DIM}v2.0${R}\n"
    printf "  ${DIM}https://github.com/${REPO}${R}\n"
    printf "\n"
}

divider() {
    printf "  ${DIM}──────────────────────────────────────────────────────────────${R}\n"
}

header() {
    printf "\n  ${BOLD}${BLUE}┌──────────────────────────────────────┐${R}\n"
    printf "  ${BOLD}${BLUE}│${R}  ${BOLD}${WHITE}%-36s${R}  ${BOLD}${BLUE}│${R}\n" "$1"
    printf "  ${BOLD}${BLUE}└──────────────────────────────────────┘${R}\n\n"
}

# ══════════════════════════════════════════════════
#  E R R O R   H A N D L I N G
# ══════════════════════════════════════════════════
die() {
    printf "\n  ${BG_RED}${WHITE}${BOLD} ERROR ${R} %s\n\n" "$1" >&2
    exit 1
}

trap 'die "Installation interrupted by user"' INT TERM

# ══════════════════════════════════════════════════
#  H E L P
# ══════════════════════════════════════════════════
show_help() {
    cat << 'EOF'

  OVNode OpenVPN Node Agent Installer

  Usage:
    bash <(curl -Ls https://anonysec.github.io/OVNode/install.sh)
    curl -Ls URL | bash -s -- --port 2083 --api-key KEY

  Flags:
    --port PORT         Service port (default: 2083)
    --api-key KEY       API key for panel connection (auto-generated if empty)
    --vpn-port PORT     OpenVPN port (default: 1194)
    --uninstall         Remove OVNode
    --help              Show this help

EOF
    exit 0
}

# ══════════════════════════════════════════════════
#  P A R S E   A R G S
# ══════════════════════════════════════════════════
PORT="" API_KEY="" VPN_PORT="" UNINSTALL=0

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --port)      PORT="$2"; shift 2 ;;
            --api-key)   API_KEY="$2"; shift 2 ;;
            --vpn-port)  VPN_PORT="$2"; shift 2 ;;
            --uninstall) UNINSTALL=1; shift ;;
            --help|-h)   show_help ;;
            *)           die "Unknown option: $1" ;;
        esac
    done
}

# ══════════════════════════════════════════════════
#  I N T E R A C T I V E   M E N U
# ══════════════════════════════════════════════════
prompt_value() {
    local var_name="$1" label="$2" default="$3" hidden="${4:-}"
    local val=""
    if [[ -t 0 ]]; then
        if [[ "$hidden" == "hidden" ]]; then
            printf "  ${WHITE}%-18s${R} [${DIM}%s${R}]: " "$label" "$default"
            read -rs val
            printf "\n"
        else
            printf "  ${WHITE}%-18s${R} [${DIM}%s${R}]: " "$label" "$default"
            read -r val
        fi
    fi
    [[ -z "$val" ]] && val="$default"
    eval "$var_name='$val'"
}

interactive_setup() {
    header "Configuration"

    prompt_value PORT "Service port" "$DEFAULT_PORT"
    prompt_value API_KEY "API key" "$(python3 -c 'import uuid;print(uuid.uuid4().hex)' 2>/dev/null || openssl rand -hex 16)"
    prompt_value VPN_PORT "OpenVPN port" "$DEFAULT_VPN_PORT"

    divider
    printf "\n  ${BOLD}Summary:${R}\n"
    box_line "Service port: ${CYAN}${PORT}${R}"
    box_line "API key:      ${CYAN}${API_KEY}${R}"
    box_line "VPN port:     ${CYAN}${VPN_PORT}${R}"
    box_line "Install dir:  ${CYAN}${INSTALL_DIR}${R}"
    printf "\n"

    if [[ -t 0 ]]; then
        printf "  ${BOLD}Proceed with installation?${R} [${GREEN}Y${R}/n]: "
        read -r confirm
        if [[ "$confirm" =~ ^[Nn]$ ]]; then
            die "Installation cancelled."
        fi
    fi
}

# ══════════════════════════════════════════════════
#  D E P S
# ══════════════════════════════════════════════════
check_root() {
    [[ "$EUID" -ne 0 ]] && die "Must run as root. Use: sudo bash <(curl -Ls URL)"
}

check_deps() {
    local missing=()
    for cmd in curl tar openssl git; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        step_warn "Installing missing deps: ${missing[*]}"
        apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq "${missing[@]}" >/dev/null 2>&1 \
            || die "Failed to install: ${missing[*]}"
        step_ok "Dependencies installed"
    else
        step_ok "All dependencies found"
    fi

    # OpenVPN (for PKI)
    if ! command -v openvpn >/dev/null 2>&1; then
        step_warn "Installing OpenVPN..."
        apt-get install -y -qq openvpn easy-rsa >/dev/null 2>&1 \
            || step_warn "OpenVPN install failed — PKI will need manual setup"
        step_ok "OpenVPN installed"
    else
        step_ok "OpenVPN found"
    fi
}

# ══════════════════════════════════════════════════
#  I N S T A L L
# ══════════════════════════════════════════════════
do_install() {
    [[ -d "$INSTALL_DIR" ]] && die "Already installed at $INSTALL_DIR. Run with --uninstall first."

    header "Installing OVNode"

    # 1. Source
    step_info "Downloading source..."
    if command -v git >/dev/null 2>&1; then
        git clone --depth 1 --branch main "https://github.com/${REPO}.git" "$INSTALL_DIR" >/dev/null 2>&1 &
        spinner "Cloning repository" $!
    else
        curl -sSLo /tmp/ovnode.tar.gz "https://github.com/${REPO}/archive/refs/heads/main.tar.gz" >/dev/null 2>&1 &
        spinner "Downloading tarball" $!
        tar -xzf /tmp/ovnode.tar.gz -C /opt/ 2>/dev/null
        mv "/opt/$(basename ${REPO})-main" "$INSTALL_DIR" 2>/dev/null || \
        mv "/opt/OVNode-main" "$INSTALL_DIR" 2>/dev/null || \
        die "Failed to extract"
        rm -f /tmp/ovnode.tar.gz
    fi

    # 2. Backend
    step_info "Setting up backend..."
    cd "$INSTALL_DIR"
    uv sync --quiet 2>&1 &
    spinner "Installing Python dependencies" $!

    # 3. Config
    step_info "Writing configuration..."
    local env_file="$INSTALL_DIR/.env"
    if [[ -f "$INSTALL_DIR/.env.example" ]]; then
        cp "$INSTALL_DIR/.env.example" "$env_file"
    else
        : > "$env_file"
    fi
    cat > "$env_file" << ENVEOF
SERVICE_PORT=${PORT}
API_KEY=${API_KEY}
OPENVPN_PORT=${VPN_PORT}
ENVEOF
    step_ok "Configuration written"

    # 4. Service
    step_info "Creating systemd service..."
    local real_uv
    real_uv=$(command -v uv)
    cat > "/etc/systemd/system/${SYSTEMD_SERVICE}" << SVCEOF
[Unit]
Description=OVNode OpenVPN Node Agent
After=network.target
After=openvpn.service

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
Environment="PATH=${INSTALL_DIR/.venv/bin}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=${real_uv} run main.py
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
SVCEOF

    # Fix: escape . in path for sed
    local escaped_venv="${INSTALL_DIR}/.venv/bin"
    sed -i "s|{INSTALL_DIR/.venv/bin}|${escaped_venv}|" "/etc/systemd/system/${SYSTEMD_SERVICE}"

    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable "$SYSTEMD_SERVICE" >/dev/null 2>&1
    systemctl restart "$SYSTEMD_SERVICE" >/dev/null 2>&1 &
    spinner "Starting ovnode service" $!

    # Done
    divider
    printf "\n"
    printf "  ${BG_GREEN}${WHITE}${BOLD}  ✓  INSTALLED SUCCESSFULLY  ${R}\n\n"
    printf "  ${BOLD}Service:${R}  ${CYAN}http://$(hostname -I | awk '{print $1}'):${PORT}/sync/health${R}\n"
    printf "  ${BOLD}API key:${R}  ${GREEN}${API_KEY}${R}\n\n"
    printf "  ${DIM}Connect from OVManager panel:${R}\n"
    printf "    ${DIM}Node URL: http://$(hostname -I | awk '{print $1}'):${PORT}${R}\n"
    printf "    ${DIM}API Key:  ${API_KEY}${R}\n\n"
    printf "  ${DIM}Commands:${R}\n"
    printf "    ${DIM}systemctl status ${SYSTEMD_SERVICE}${R}\n"
    printf "    ${DIM}systemctl restart ${SYSTEMD_SERVICE}${R}\n"
    printf "    ${DIM}journalctl -u ${SYSTEMD_SERVICE} -f${R}\n\n"
}

# ══════════════════════════════════════════════════
#  U P D A T E
# ══════════════════════════════════════════════════
do_update() {
    [[ ! -d "$INSTALL_DIR" ]] && die "Not installed at $INSTALL_DIR"
    header "Updating OVNode"
    cd "$INSTALL_DIR"
    git pull origin main 2>&1 &
    spinner "Pulling latest changes" $!
    uv sync 2>&1 | tail -1 &
    spinner "Updating Python dependencies" $!
    systemctl restart "$SYSTEMD_SERVICE" >/dev/null 2>&1 &
    spinner "Restarting service" $!
    divider
    printf "  ${BG_GREEN}${WHITE}${BOLD}  ✓  UPDATED  ${R}\n\n"
}

# ══════════════════════════════════════════════════
#  U N I N S T A L L
# ══════════════════════════════════════════════════
do_uninstall() {
    header "Uninstalling OVNode"
    if [[ -t 0 ]]; then
        printf "  ${RED}Remove ${INSTALL_DIR} and stop service?${R} [y/N]: "
        read -r confirm
        [[ ! "$confirm" =~ ^[Yy]$ ]] && die "Cancelled."
    fi
    systemctl stop "$SYSTEMD_SERVICE" 2>/dev/null
    systemctl disable "$SYSTEMD_SERVICE" 2>/dev/null
    rm -f "/etc/systemd/system/${SYSTEMD_SERVICE}"
    systemctl daemon-reload 2>/dev/null
    rm -rf "$INSTALL_DIR"
    step_ok "Service removed"
    step_ok "Installation directory removed"
    divider
    printf "  ${BG_GREEN}${WHITE}${BOLD}  ✓  UNINSTALLED  ${R}\n\n"
}

# ══════════════════════════════════════════════════
#  M A I N
# ══════════════════════════════════════════════════
main() {
    parse_args "$@"
    banner

    if [[ $UNINSTALL -eq 1 ]]; then
        do_uninstall
        exit 0
    fi

    if [[ -z "$PORT" && -z "$API_KEY" ]]; then
        interactive_setup
    else
        : "${PORT:=$DEFAULT_PORT}"
        : "${API_KEY:=$(python3 -c 'import uuid;print(uuid.uuid4().hex)' 2>/dev/null || openssl rand -hex 16)}"
        : "${VPN_PORT:=$DEFAULT_VPN_PORT}"
    fi

    check_root
    check_deps
    do_install
}

main "$@"
