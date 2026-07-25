#!/bin/bash
# OVNode OpenVPN Node Agent Installer
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

# ═══════════════════════════════════════
#  C O L O R S
# ═══════════════════════════════════════
NC=$'\033[0m'
B=$'\033[1m'
WH=$'\033[97m'
GR=$'\033[32m'
RD=$'\033[31m'
YL=$'\033[33m'
BL=$'\033[34m'
CY=$'\033[36m'
GY=$'\033[90m' 

# ═══════════════════════════════════════
#  U I   H E L P E R S
# ═══════════════════════════════════════
W=58

box_top()    { echo -e "  ${BL}┌$(printf '─%.0s' $(seq 1 $W))┐${NC}"; }
box_mid()    { echo -e "  ${BL}├$(printf '─%.0s' $(seq 1 $W))┤${NC}"; }
box_bot()    { echo -e "  ${BL}└$(printf '─%.0s' $(seq 1 $W))┘${NC}"; }
box_line()   { printf "  ${BL}│${NC} %-$((W-2))s${BL}│${NC}\n" "$1"; }
box_empty()  { echo -e "  ${BL}│${NC}$(printf '%*s' $W '')${BL}│${NC}"; }

title() {
    box_empty
    box_line "  ${B}$1${NC}"
    [[ -n "${2:-}" ]] && box_line "  ${GY}$2${NC}"
    box_empty
}

field() {
    local label="$1" value="$2"
    printf "  ${BL}│${NC}   ${GY}%-14s${NC}%s${BL}│${NC}\n" "$label" "$value"
}

step() {
    printf "  ${BL}│${NC}  %s %-$((W-4))s${BL}│${NC}\n" "$1" "$2"
}

spinner() {
    local msg="$1" pid=$2 chars='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏' i=0
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r  ${BL}│${NC}  ${CY}%s${NC} %-$((W-4))s${BL}│${NC}" "${chars:$((i%9)):1}" "$msg"
        sleep 0.1; ((i++))
    done
    wait "$pid" 2>/dev/null
    local rc=$?
    printf "\r\033[K"
    [[ $rc -eq 0 ]] && step "${GR}✓${NC}" "$msg" || { step "${RD}✗${NC}" "$msg"; return 1; }
}

prompt_val() {
    local var="$1" label="$2" default="$3" hidden="${4:-}"
    local val=""
    if [[ -t 0 ]]; then
        if [[ "$hidden" == "h" ]]; then
            printf "  ${BL}│${NC}   ${WH}%-14s${NC} ${GY}[${default}]${NC} : " "$label"
            read -rs val; printf "\n"
        else
            printf "  ${BL}│${NC}   ${WH}%-14s${NC} ${GY}[${default}]${NC} : " "$label"
            read -r val
        fi
    fi
    [[ -z "$val" ]] && val="$default"
    eval "$var='$val'"
}

die() { echo -e "\n  ${RD}ERROR:${NC} $1\n"; exit 1; }
trap 'echo -e "\n  ${RD}Interrupted.${NC}"; exit 1' INT TERM

# ═══════════════════════════════════════
#  H E L P / A R G S
# ═══════════════════════════════════════
show_help() {
    cat << 'EOF'
  Usage:
    bash <(curl -Ls https://anonysec.github.io/OVNode/install.sh)
    curl -Ls URL | bash -s -- --port 2083 --api-key KEY

  Flags:
    --port PORT     Service port (default: 2083)
    --api-key KEY   API key (auto-generated if empty)
    --vpn-port PORT OpenVPN port (default: 1194)
    --uninstall     Remove OVNode
    --help          Show this help
EOF
    exit 0
}

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

# ═══════════════════════════════════════
#  I N T E R A C T I V E
# ═══════════════════════════════════════
interactive_setup() {
    prompt_val PORT      "Service port" "$DEFAULT_PORT"
    prompt_val API_KEY   "API key"      "$(python3 -c 'import uuid;print(uuid.uuid4().hex)' 2>/dev/null || openssl rand -hex 16)"
    prompt_val VPN_PORT  "OpenVPN port" "$DEFAULT_VPN"

    box_mid
    field "Install dir" "$INSTALL_DIR"
    box_mid

    if [[ -t 0 ]]; then
        printf "  ${BL}│${NC}   Proceed? [${GR}Y${NC}/n] : "
        read -r c; [[ "$c" =~ ^[Nn]$ ]] && die "Cancelled."
    fi
}

# ═══════════════════════════════════════
#  D E P S
# ═══════════════════════════════════════
check_root() {
    [[ "$EUID" -ne 0 ]] && die "Must run as root."
}

check_deps() {
    local missing=()
    for cmd in curl tar openssl git; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        step "${YL}↓${NC}" "Installing: ${missing[*]}"
        apt-get update -qq >/dev/null && apt-get install -y -qq "${missing[@]}" >/dev/null \
            || die "Failed: ${missing[*]}"
    fi
    step "${GR}✓${NC}" "Dependencies OK"

    if ! command -v openvpn >/dev/null 2>&1; then
        step "${YL}↓${NC}" "Installing OpenVPN"
        apt-get install -y -qq openvpn easy-rsa >/dev/null 2>&1 \
            || step "${YL}⚠${NC}" "OpenVPN install failed — manual PKI setup needed"
    else
        step "${GR}✓${NC}" "OpenVPN found"
    fi
}

# ═══════════════════════════════════════
#  I N S T A L L
# ═══════════════════════════════════════
do_install() {
    [[ -d "$INSTALL_DIR" ]] && die "Already installed. Use --uninstall first."

    box_empty; box_mid; box_empty
    box_line "  ${B}${WH}Installing${NC}"
    box_empty

    # Source
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

    # Backend
    cd "$INSTALL_DIR"
    uv sync --quiet 2>&1 &
    spinner "Installing dependencies" $!

    # Config
    cat > "$INSTALL_DIR/.env" << ENVEOF
SERVICE_PORT=${PORT}
API_KEY=${API_KEY}
OPENVPN_PORT=${VPN_PORT}
ENVEOF
    step "${GR}✓${NC}" "Configuration written"

    # Service
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
    spinner "Starting service" $!

    # Done
    box_mid; box_empty
    box_line "  ${GR}${B}✓  INSTALLED${NC}"
    box_empty
    box_line "  ${WH}http://$(hostname -I | awk '{print $1}'):${PORT}/sync/health${NC}"
    box_line "  ${GY}API key: ${WH}${API_KEY}${NC}"
    box_empty
    box_line "  ${GY}systemctl status ${SYSTEMD_SERVICE}${NC}"
    box_line "  ${GY}systemctl restart ${SYSTEMD_SERVICE}${NC}"
    box_empty
    box_bot
    echo ""
}

do_update() {
    [[ ! -d "$INSTALL_DIR" ]] && die "Not installed"
    cd "$INSTALL_DIR"
    git pull origin main 2>&1 &
    spinner "Pulling changes" $!
    uv sync --quiet 2>&1 &
    spinner "Updating dependencies" $!
    systemctl restart "$SYSTEMD_SERVICE" >/dev/null 2>&1 &
    spinner "Restarting service" $!
    box_empty; step "${GR}✓${NC}" "Updated"; box_bot; echo ""
}

do_uninstall() {
    if [[ -t 0 ]]; then
        printf "  Remove ${INSTALL_DIR}? [y/N] : "; read -r c
        [[ ! "$c" =~ ^[Yy]$ ]] && die "Cancelled."
    fi
    systemctl stop "$SYSTEMD_SERVICE" 2>/dev/null
    systemctl disable "$SYSTEMD_SERVICE" 2>/dev/null
    rm -f "/etc/systemd/system/${SYSTEMD_SERVICE}"
    systemctl daemon-reload 2>/dev/null
    rm -rf "$INSTALL_DIR"
    echo -e "  ${GR}✓ Uninstalled${NC}\n"
}

# ═══════════════════════════════════════
#  M A I N
# ═══════════════════════════════════════
main() {
    parse_args "$@"
    clear

    [[ $UNINSTALL -eq 1 ]] && { do_uninstall; exit 0; }

    box_top
    title "OVNode" "OpenVPN Node Agent  v2.0"

    if [[ -z "$PORT" && -z "$API_KEY" ]]; then
        interactive_setup
    else
        : "${PORT:=$DEFAULT_PORT}"
        : "${API_KEY:=$(python3 -c 'import uuid;print(uuid.uuid4().hex)' 2>/dev/null || openssl rand -hex 16)}"
        : "${VPN_PORT:=$DEFAULT_VPN}"
        field "Service port" "$PORT"
        field "API key"      "${API_KEY:0:8}..."
        field "OpenVPN port" "$VPN_PORT"
        box_mid
    fi

    check_root
    check_deps
    do_install
}

main "$@"
