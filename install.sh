#!/bin/bash
# OVNode — OpenVPN Node Agent Installer
# TLS-enabled, multi-node, Docker-aware installer
# Usage: bash <(curl -Ls URL)

set -uo pipefail

# ──────────────────────────────────────────────────────
#  C O N F I G
# ──────────────────────────────────────────────────────
REPO="anonysec/OVNode"
APP_DIR="/opt/ovnode"
DATA_BASE="/var/lib/ovnode"
DEFAULT_PORT=2083
DEFAULT_VPN=1194
SYSTEMD_SERVICE="ovnode.service"
VERSION="2.1"

# ──────────────────────────────────────────────────────
#  C O L O R S
# ──────────────────────────────────────────────────────
NC='\033[0m'; B='\033[1m'; D='\033[2m'
WH='\033[97m'; GR='\033[32m'; RD='\033[31m'
YL='\033[33m'; CY='\033[36m'; GY='\033[90m'

# ──────────────────────────────────────────────────────
#  U I
# ──────────────────────────────────────────────────────
line()   { echo -e "  $1"; }
step()   { line "${GR}  ✓${NC} $1"; }
info()   { line "${CY}  →${NC} $1"; }
warn()   { line "${YL}  ⚠${NC} $1"; }
sep()    { line "${GY}$(printf '%.0s─' {1..56})${NC}"; }
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
    --port PORT         Service port (default: 2083)
    --api-key KEY       API key (auto-generated if empty)
    --vpn-port PORT     OpenVPN port (default: 1194)
    --name NAME         Node name (default: node-1)
    --tls METHOD        TLS method: letsencrypt, letsencrypt-ip,
                        selfsigned, custom, none (default: none)
    --tls-domain DOM    Domain for Let's Encrypt
    --tls-key KEY       Path to existing TLS key
    --tls-cert CERT     Path to existing TLS cert
    --docker            Deploy with Docker
    --uninstall         Remove OVNode completely
    --help              Show this help
EOF
    exit 0
}

# ──────────────────────────────────────────────────────
#  A R G U M E N T P A R S I N G
# ──────────────────────────────────────────────────────
PORT=""; API_KEY=""; VPN_PORT=""; NODE_NAME=""
TLS_METHOD="none"; TLS_DOMAIN=""; TLS_KEY=""; TLS_CERT=""
DOCKER=0 ACTION="install"

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --port)       PORT="$2"; shift 2 ;;
            --api-key)    API_KEY="$2"; shift 2 ;;
            --vpn-port)   VPN_PORT="$2"; shift 2 ;;
            --name)       NODE_NAME="$2"; shift 2 ;;
            --tls)
                TLS_METHOD="$2"; shift 2
                if [[ "$TLS_METHOD" == "letsencrypt-ip" ]]; then
                    TLS_METHOD="letsencrypt-ip"
                fi
                ;;
            --tls-domain) TLS_DOMAIN="$2"; shift 2 ;;
            --tls-key)    TLS_KEY="$2"; shift 2 ;;
            --tls-cert)   TLS_CERT="$2"; shift 2 ;;
            --docker)     DOCKER=1; shift ;;
            --uninstall)  ACTION="uninstall"; shift ;;
            --help|-h)    show_help ;;
            uninstall)    ACTION="uninstall"; shift ;;
            update)       ACTION="update"; shift ;;
            *)            die "Unknown option: $1. Use --help for usage." ;;
        esac
    done
}

# ──────────────────────────────────────────────────────
#  H E A L T H Y  P A T H  E X T R A C T I O N
# ──────────────────────────────────────────────────────
hpath() {
    local p="$1"; shift
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "$p" | sed 's/^[~]/$HOME/' 
    else
        echo "$p" | sed 's/^[~]/$HOME/;s/^[\/]//'
    fi
}

# ──────────────────────────────────────────────────────
#  C H E C K S
# ──────────────────────────────────────────────────────
check_root() {
    [[ "$EUID" -ne 0 ]] && die "Must run as root."
}

find_free_port() {
    local start=${1:-2083}
    local port=$start
    while ss -ltn 2>/dev/null | awk -v p=":${port}$" '$4 ~ p {exit 0} END {exit 1}'; do
        ((port++))
    done
    echo "$port"
}

find_free_vpn_port() {
    local start=${1:-1194}
    local port=$start
    while ss -ltn 2>/dev/null | awk -v p=":${port}$" '$4 ~ p {exit 0} END {exit 1}'; do
        ((port++))
    done
    echo "$port"
}

port_in_use() {
    ss -ltn 2>/dev/null | awk -v p=":${1}$" '$4 ~ p {exit 0} END {exit 1}'
}

check_deps() {
    local missing=()
    for cmd in curl tar openssl git python3; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        info "Installing missing system dependencies: ${missing[*]}"
        apt-get update -qq >/dev/null && apt-get install -y -qq "${missing[@]}" >/dev/null \
            || warn "Failed to install: ${missing[*]}"
    fi
    step "System dependencies verified"

    if ! command -v openvpn >/dev/null 2>&1; then
        info "Installing OpenVPN and easy-rsa for PKI management..."
        apt-get install -y -qq openvpn easy-rsa >/dev/null 2>&1 \
            || warn "OpenVPN install failed — manual PKI setup may be needed"
    else
        step "OpenVPN is already installed"
    fi

    # Ensure acme.sh is available for Let's Encrypt
    if [[ "$TLS_METHOD" =~ ^letsencrypt ]]; then
        if [[ ! -f ~/.acme.sh/acme.sh ]]; then
            info "Installing acme.sh for Let's Encrypt..."
            curl -s https://get.acme.sh | sh >/dev/null 2>&1 \
                || die "Failed to install acme.sh. Install manually: curl -s https://get.acme.sh | sh"
        fi
        step "acme.sh is available"
    fi
}

# ──────────────────────────────────────────────────────
#  P K I  &  T L S  H E L P E R S
# ──────────────────────────────────────────────────────
generate_selfsigned_cert() {
    local cn=$(hostname -I | awk '{print $1}')
    mkdir -p /etc/ssl/self-signed
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout /etc/ssl/self-signed/privkey.pem \
        -out /etc/ssl/self-signed/fullchain.pem \
        -subj "/C=US/ST=Local/L=Local/O=OVNode/CN=${cn}" 2>/dev/null
    step "Self-signed certificate generated"
    echo "/etc/ssl/self-signed"
}

obtain_letsencrypt_cert() {
    local domain="$1"
    local outdir="/etc/letsencrypt/${domain}"
    mkdir -p "$outdir"

    # Check if valid cert already exists
    if [[ -f "$outdir/fullchain.pem" ]]; then
        local expiry=$(openssl x509 -enddate -noout -in "$outdir/fullchain.pem" 2>/dev/null | cut -d= -f2)
        local expiry_epoch=$(date -d "$expiry" +%s 2>/dev/null)
        local now_epoch=$(date +%s)
        local days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
        if [[ $days_left -gt 7 ]]; then
            step "Existing certificate valid for $days_left more days ($outdir)"
            echo "$outdir"
            return 0
        fi
        warn "Certificate expires in $days_left days — renewing..."
    fi

    local extra_args=""
    if [[ "$TLS_METHOD" == "letsencrypt-ip" ]]; then
        info "Issuing short-lived certificate for IP $domain (6 days)..."
        extra_args="--certificate-profile shortlived --days 6"
    else
        info "Issuing certificate for domain $domain..."
    fi

    # Issue cert
    ~/.acme.sh/acme.sh --issue -d "$domain" --standalone \
        $extra_args \
        --reloadcmd "true" 2>&1 | grep -E "Cert success|Error|error" \
        || die "Failed to issue Let's Encrypt certificate for $domain"

    # Install cert to target directory
    ~/.acme.sh/acme.sh --install-cert -d "$domain" \
        --key-file "$outdir/privkey.pem" \
        --fullchain-file "$outdir/fullchain.pem" \
        --reloadcmd "true" 2>&1 | tail -3 \
        || die "Failed to install certificate to $outdir"

    step "Certificate installed to $outdir"
    echo "$outdir"
}

obtain_letsencrypt_ip_cert() {
    local ip="$1"
    obtain_letsencrypt_cert "$ip"
}

# ──────────────────────────────────────────────────────
#  D O C K E R  H E L P E R S
# ──────────────────────────────────────────────────────
docker_compose_path() {
    local node_name="$1"; shift
    echo "$DATA_BASE/${node_name}/docker-compose.yml"
}

generate_docker_compose() {
    local node_name="$1"; shift
    local service_port="$1"; shift
    local vpn_port="$1"; shift
    local tls_method="$1"; shift
    local tls_domain="$1"; shift
    local tls_key="$1"; shift
    local tls_cert="$1"; shift
    local out_dir="$DATA_BASE/${node_name}"
    local compose_file="$(docker_compose_path "$node_name")"

    local env_vars=""
    if [[ "$tls_method" == "none" ]]; then
        env_vars="    - SERVICE_PORT=${service_port}\n    - API_KEY=${API_KEY}\n    - OPENVPN_PORT=${vpn_port}\n    - TLS_METHOD=none"
    elif [[ "$tls_method" == "letsencrypt-ip" || "$tls_method" == "letsencrypt" ]]; then
        local certdir="/etc/letsencrypt/${tls_domain}"
        env_vars="    - SERVICE_PORT=${service_port}\n    - API_KEY=${API_KEY}\n    - OPENVPN_PORT=${vpn_port}\n    - TLS_METHOD=letsencrypt\n    - SSL_CERTFILE=${certdir}/fullchain.pem\n    - SSL_KEYFILE=${certdir}/privkey.pem"
    elif [[ "$tls_method" == "custom" ]]; then
        env_vars="    - SERVICE_PORT=${service_port}\n    - API_KEY=${API_KEY}\n    - OPENVPN_PORT=${vpn_port}\n    - TLS_METHOD=custom\n    - SSL_CERTFILE=${tls_cert}\n    - SSL_KEYFILE=${tls_key}"
    else
        env_vars="    - SERVICE_PORT=${service_port}\n    - API_KEY=${API_KEY}\n    - OPENVPN_PORT=${vpn_port}\n    - TLS_METHOD=selfsigned\n    - SSL_CERTFILE=/etc/ssl/self-signed/fullchain.pem\n    - SSL_KEYFILE=/etc/ssl/self-signed/privkey.pem"
    fi

    cat > "$compose_file" << COMPOSEOF
version: "3.8"
services:
  ovnode:
    image: anonysec/ovnode:latest
    container_name: ovnode-${node_name}
    restart: unless-stopped
    network_mode: host
    environment:
${env_vars}
    volumes:
      - ${DATA_BASE}/${node_name}/data:/opt/ovnode/data
      - /etc/letsencrypt:/etc/letsencrypt:ro
      - /etc/ssl/self-signed:/etc/ssl/self-signed:ro
    logging:
      opts:
        max-size: "1m"
        max-file: "3"
COMPOSEOF
    step "Docker Compose generated: ${compose_file}"
}

# ──────────────────────────────────────────────────────
#  I N S T A L L A T I O N
# ──────────────────────────────────────────────────────
do_install() {
    [[ -d "$APP_DIR" ]] && die "Already installed. Use --uninstall first."
    [[ -z "$NODE_NAME" ]] && NODE_NAME="node-1"
    [[ -z "$PORT" ]] && PORT=$(find_free_port "$DEFAULT_PORT")
    [[ -z "$VPN_PORT" ]] && VPN_PORT=$(find_free_vpn_port "$DEFAULT_VPN")

    # Ensure data directory base exists
    mkdir -p "$DATA_BASE"

    local server_ip=$(hostname -I | awk '{print $1}')
    sep
    field "Server IP"     "$server_ip"
    field "Node name"     "$NODE_NAME"
    field "Service port"  "$PORT"
    field "OpenVPN port"  "$VPN_PORT"
    field "TLS method"    "$TLS_METHOD"
    if [[ "$TLS_METHOD" =~ ^letsencrypt ]]; then
        if [[ "$TLS_METHOD" == "letsencrypt-ip" ]]; then
            field "TLS IP"     "$TLS_DOMAIN"
        else
            field "TLS domain" "$TLS_DOMAIN"
        fi
    elif [[ "$TLS_METHOD" == "custom" ]]; then
        field "TLS key path"   "$TLS_KEY"
        field "TLS cert path"  "$TLS_CERT"
    fi
    sep
    if [[ "$DOCKER" -eq 1 ]]; then
        info "Docker deployment enabled — will generate docker-compose.yml"
    else
        info "Direct systemd deployment"
    fi
    [[ -t 0 ]] && printf "  Proceed with installation? [${GR}Y${NC}/n] : " || printf "  Proceed with installation? [${GR}Y${NC}] "
    [[ -t 0 ]] && read -r confirm || confirm="y"
    [[ ! "$confirm" =~ ^[Nn]$ && "$confirm" != "n" ]] || { line "Cancelled."; exit 0; }

    sep
    info "Cloning OVNode repository..."
    curl -sSLo /tmp/ovn.tar.gz "https://github.com/${REPO}/archive/refs/heads/main.tar.gz" &
    spinner "Downloading repository" $!
    tar -xzf /tmp/ovn.tar.gz -C /opt/ >/dev/null 2>&1
    mv "/opt/OVNode-main" "$APP_DIR" 2>/dev/null || die "Extract failed"
    rm -f /tmp/ovn.tar.gz

    info "Installing Python dependencies via uv..."
    cd "$APP_DIR"
    uv sync --quiet 2>&1 &
    spinner "Python packages installed" $!

    # ── TLS / PKI ────────────────────────────────────────
    local certdir=""
    case "$TLS_METHOD" in
        none)
            step "TLS disabled (HTTP)"
            ;;
        selfsigned)
            certdir=$(generate_selfsigned_cert)
            ;;
        letsencrypt|letsencrypt-ip)
            if [[ "$TLS_METHOD" == "letsencrypt-ip" ]]; then
                certdir=$(obtain_letsencrypt_ip_cert "$TLS_DOMAIN")
            else
                certdir=$(obtain_letsencrypt_cert "$TLS_DOMAIN")
            fi
            ;;
        custom)
            [[ -f "$TLS_KEY" && -f "$TLS_CERT" ]] || die "Custom TLS cert/key not found"
            certdir="/etc/letsencrypt/${TLS_DOMAIN}"
            mkdir -p "$certdir"
            cp "$TLS_KEY" "$certdir/privkey.pem"
            cp "$TLS_CERT" "$certdir/fullchain.pem"
            step "Custom certificate installed"
            ;;
        *)
            warn "Unknown TLS method '$TLS_METHOD', defaulting to none"
            TLS_METHOD="none"
            ;;
    esac

    # ── .env ─────────────────────────────────────────────
    cat > "$APP_DIR/.env" << ENVEOF
NODE_NAME=${NODE_NAME}
DATA_DIR=${DATA_BASE}/${NODE_NAME}
SERVICE_PORT=${PORT}
API_KEY=${API_KEY}
OPENVPN_PORT=${VPN_PORT}
TLS_METHOD=${TLS_METHOD}
ENVEOF
    if [[ "$TLS_METHOD" != "none" && -n "$certdir" ]]; then
        echo "SSL_CERTFILE=${certdir}/fullchain.pem" >> "$APP_DIR/.env"
        echo "SSL_KEYFILE=${certdir}/privkey.pem" >> "$APP_DIR/.env"
    fi
    step ".env written"

    # ── Systemd service ──────────────────────────────────
    local real_uv; real_uv=$(command -v uv)
    cat > "/etc/systemd/system/${SYSTEMD_SERVICE}" << SVCEOF
[Unit]
Description=OVNode OpenVPN Node Agent (${NODE_NAME})
After=network.target openvpn.service

[Service]
Type=simple
User=root
WorkingDirectory=${APP_DIR}
Environment="PATH=${APP_DIR}/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=${real_uv} run main.py
Restart=on-failure
RestartSec=3
EnvironmentFile=${APP_DIR}/.env
SVCEOF
    if [[ "$DOCKER" -eq 1 ]]; then
        # Include Docker Compose overlay for systemd
        cat >> "/etc/systemd/system/${SYSTEMD_SERVICE}" << 'DOCKEREOF'
# Docker deployment is configured via docker-compose.yml in the data directory.
# This service runs the host-side compose rather than native process.
# Override in /etc/systemd/system/ovnode.service.d/override.conf if needed.
DOCKEREOF
        generate_docker_compose "$NODE_NAME" "$PORT" "$VPN_PORT" "$TLS_METHOD" "$TLS_DOMAIN" "$TLS_KEY" "$TLS_CERT"
    fi

    systemctl daemon-reload >/dev/null 2>&1
    systemctl enable "$SYSTEMD_SERVICE" >/dev/null 2>&1
    systemctl restart "$SYSTEMD_SERVICE" >/dev/null 2>&1 &
    spinner "Service started" $!

    # ── Final summary ─────────────────────────────────────
    sep
    step "${B}Installation complete!${NC}"
    sep
    line ""
    line "  Node name:        ${NODE_NAME}"
    field "Service port" "$PORT"
    field "OpenVPN port" "$VPN_PORT"
    field "TLS method"    "$TLS_METHOD"
    field "Data dir"      "$DATA_BASE/${NODE_NAME}"
    field "Systemd"      "${SYSTEMD_SERVICE}"
    line ""
    if [[ "$TLS_METHOD" != "none" ]]; then
        line "  Health:  https://$(hostname -I | awk '{print $1}'):${PORT}/sync/health"
        line "  HTTPS enforced"
    else
        line "  Health:  http://$(hostname -I | awk '{print $1}'):${PORT}/sync/health"
        line "  HTTP (no TLS)"
    fi
    line ""
    if [[ "$DOCKER" -eq 1 ]]; then
        line "  ${GY}Docker mode:${NC} docker-compose at ${DATA_BASE}/${NODE_NAME}/docker-compose.yml"
        line "  Start with:${NC} docker compose -f ${DATA_BASE}/${NODE_NAME}/docker-compose.yml up -d"
    else
        line "  ${GY}Manage:${NC}  systemctl status ${SYSTEMD_SERVICE}"
        line "  ${GY}Logs:${NC}    journalctl -u ${SYSTEMD_SERVICE} -f"
    fi
    line ""
}

# ──────────────────────────────────────────────────────
#  U P D A T E
# ──────────────────────────────────────────────────────
do_update() {
    [[ ! -d "$APP_DIR" ]] && die "Not installed"
    line ""
    info "Updating OVNode ($NODE_NAME)..."
    cd "$APP_DIR"
    git pull origin main 2>&1 &
    spinner "Pulling updates" $!
    uv sync --quiet 2>&1 &
    spinner "Updating Python deps" $!
    systemctl restart "${SYSTEMD_SERVICE}" >/dev/null 2>&1 &
    spinner "Restarting service" $!
    step "Update complete"
    line ""
}

# ──────────────────────────────────────────────────────
#  U N I N S T A L L
# ──────────────────────────────────────────────────────
do_uninstall() {
    if [[ -t 0 ]]; then
        printf "  Remove OVNode and stop service? [y/N] : "; read -r c
        [[ ! "$c" =~ ^[Yy]$ ]] && die "Cancelled."
    fi
    systemctl stop "${SYSTEMD_SERVICE}" 2>/dev/null
    systemctl disable "${SYSTEMD_SERVICE}" 2>/dev/null
    rm -f "/etc/systemd/system/${SYSTEMD_SERVICE}"
    systemctl daemon-reload 2>/dev/null
    rm -rf "$APP_DIR"
    rm -rf "$DATA_BASE/${NODE_NAME}"
    step "Uninstalled"
    line ""
}

# ──────────────────────────────────────────────────────
#  M A I N
# ──────────────────────────────────────────────────────
interactive_setup() {
    local api_default
    api_default=$(python3 -c 'import uuid;print(uuid.uuid4().hex)' 2>/dev/null || openssl rand -hex 16)
    prompt_val NODE_NAME    "Node name"     "node-1"
    prompt_val PORT         "Service port"  "$(find_free_port "$DEFAULT_PORT")"
    prompt_val VPN_PORT     "OpenVPN port"  "$(find_free_vpn_port "$DEFAULT_VPN")"
    prompt_val API_KEY      "API key"       "$api_default"

    sep
    line "  TLS:"
    line "  ${WH}1${NC})  Let's Encrypt (domain)"
    line "  ${WH}2${NC})  Let's Encrypt (IP)"
    line "  ${WH}3${NC})  Self-signed cert"
    line "  ${WH}4${NC})  Custom cert path"
    line "  ${WH}5${NC})  None (HTTP)"
    if [[ -t 0 ]]; then
        printf "  Select [${GR}2${NC}] : "
        read -r tls_choice
    else
        tls_choice=2
    fi
    case "${tls_choice:-5}" in
        1)
            TLS_METHOD="letsencrypt"
            while [[ -z "$TLS_DOMAIN" ]]; do
                if [[ -t 0 ]]; then
                    printf "  ${WH}Domain${NC} [${GY}example.com${NC}] : "
                    read -r TLS_DOMAIN
                else
                    die "Domain is required for Let's Encrypt (use --tls-domain DOMAIN)"
                fi
            done
            ;;
        2)
            TLS_METHOD="letsencrypt-ip"
            if [[ -z "$TLS_DOMAIN" ]]; then
                local real_ip=$(hostname -I | awk '{print $1}')
                if [[ -t 0 ]]; then
                    printf "  ${WH}IP${NC} [${GR}%s${NC}] : " "$real_ip"
                    read -r TLS_DOMAIN
                fi
                [[ -z "$TLS_DOMAIN" ]] && TLS_DOMAIN="$real_ip"
            fi
            ;;
        3) TLS_METHOD="selfsigned" ;;
        4) TLS_METHOD="custom"; prompt_val TLS_KEY "TLS key path" ""; prompt_val TLS_CERT "TLS cert path" "" ;;
        *) TLS_METHOD="none" ;;
    esac

    sep
    field "Node name"     "$NODE_NAME"
    field "Service port"  "$PORT"
    field "OpenVPN port"  "$VPN_PORT"
    field "Data dir"      "$DATA_BASE/$NODE_NAME"
    field "TLS method"    "$TLS_METHOD"
    sep
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

    [[ -d "$APP_DIR" ]] && {
        warn "OVNode is already installed"
        line ""
        cd "$APP_DIR" 2>/dev/null
        git fetch origin main --quiet 2>/dev/null
        LOCAL=$(git rev-parse HEAD 2>/dev/null)
        REMOTE=$(git rev-parse origin/main 2>/dev/null)
        HAS_UPDATE=0
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
    }

    [[ -z "$PORT" && -z "$API_KEY" ]] && interactive_setup

    check_root
    check_deps
    do_install
}

main "$@"