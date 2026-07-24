#!/bash
# OVNode OpenVPN Node Agent Installer
# Usage: curl -sSL https://raw.githubusercontent.com/anonysec/OVNode/main/install.sh | bash
#       curl -sSL URL | bash -s -- [--port 2083] [--api-key KEY] [--vpn-port 1194] [--docker] [--help]
# Subcommands: update, uninstall

set -euo pipefail

# ---------- Colors ----------
readonly GREEN="$(tput setaf 2)"
readonly RED="$(tput setaf 1)"
readonly YELLOW="$(tput setaf 3)"
readonly BLUE="$(tput setaf 4)"
readonly NC="$(tput sgr0)"

log_info()    { echo -e "${BLUE}[*]${NC} $*"; }
log_ok()      { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*"; }

# ---------- Defaults ----------
readonly REPO_OWNER="anonysec"
readonly REPO_NAME="OVNode"
readonly DEFAULT_SERVICE_PORT="2083"
readonly DEFAULT_VPN_PORT="1194"
INSTALL_DIR="/opt/ovnode"
ENV_FILE="${INSTALL_DIR}/.env"
ENV_EXAMPLE_FILE="${INSTALL_DIR}/.env.example"
SYSTEMD_SERVICE="ovnode.service"

# ---------- State ----------
USE_DOCKER=false
DOCKER_COMPOSE_FILE="${INSTALL_DIR}/docker-compose.yml"

# ---------- Parse Arguments ----------
parse_args() {
  PORT="${DEFAULT_SERVICE_PORT}"
  API_KEY=""
  VPN_PORT="${DEFAULT_VPN_PORT}"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --port)     PORT="$2"; shift 2 ;;
      --api-key)  API_KEY="$2"; shift 2 ;;
      --vpn-port) VPN_PORT="$2"; shift 2 ;;
      --docker)   USE_DOCKER=true; shift ;;
      --help)     show_help; exit 0 ;;
      *)          log_error "Unknown argument: $1"; show_help; exit 1 ;;
    esac
  done
}

show_help() {
  cat <<-HEREDOC
	OVNode OpenVPN Node Agent Installer

	Usage:
	  curl -sSL https://raw.githubusercontent.com/anonysec/OVNode/main/install.sh | bash
	  curl -sSL URL | bash -s -- [--port PORT] [--api-key KEY] [--vpn-port PORT] [--docker] [--help]

	Flags:
	  --port PORT       Service port (default: 2083)
	  --api-key KEY     API key (auto-generated if empty and not provided)
	  --vpn-port PORT   OpenVPN port (default: 1194)
	  --docker          Use docker-compose instead of native install
	  --help            Show this help message

	Environment Variables:
	  SERVICE_PORT      Same as --port
	  API_KEY           Same as --api-key
	  OPENVPN_PORT      Same as --vpn-port
HEREDOC
}

# ---------- Error Handling ----------
cleanup_on_error() {
  log_error "Installation failed at line $1. Attempting cleanup..."
  uninstall_cleanup_only
  exit 1
}
trap 'cleanup_on_error $LINENO' ERR

# ---------- Utilities ----------
command_exists() { command -v "$1" >/dev/null 2>&1; }

check_deps() {
  local missing=()
  for cmd in curl tar systemctl; do
    command_exists "$cmd" || missing+=("$cmd")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    log_warn "Missing required commands: ${missing[*]}"
    log_info "Attempting to install missing dependencies via apt..."
    apt-get update -qq && apt-get install -y -qq curl tar || {
      log_error "Failed to install required packages. Please install manually: curl tar systemctl"
      exit 1
    }
  fi
}

# ---------- Docker Detection ----------
detect_docker_compose() {
  if [[ "$USE_DOCKER" == false ]]; then
    if command_exists docker-compose; then
      USE_DOCKER=true
      log_info "Docker compose detected, switching to Docker mode."
    elif command_exists docker; then
      local dc_version
      dc_version=$(docker compose version --short 2>/dev/null || true)
      if [[ -n "$dc_version" ]]; then
        USE_DOCKER=true
        log_info "Docker detected (compose plugin), switching to Docker mode."
      fi
    fi
  fi
}

# ---------- OpenVPN / easy-rsa ----------
ensure_openvpn() {
  if command_exists openvpn && command_exists easyrsa; then
    log_info "OpenVPN and easy-rsa already installed."
    return 0
  fi
  log_info "Installing OpenVPN and easy-rsa..."
  if command_exists apt-get; then
    apt-get update -qq && apt-get install -y -qq openvpn easy-rsa || {
      log_error "Failed to install OpenVPN and easy-rsa via apt."
      return 1
    }
  elif command_exists yum; then
    yum install -y openvpn easy-rsa || {
      log_error "Failed to install OpenVPN and easy-rsa via yum."
      return 1
    }
  else
    log_error "Could not find package manager to install OpenVPN and easy-rsa."
    return 1
  fi
  log_ok "OpenVPN and easy-rsa installed successfully."
}

# ---------- Git or Tarball ----------
clone_or_download() {
  local repo_url="https://github.com/${REPO_OWNER}/${REPO_NAME}.git"
  local tarball_url="https://github.com/${REPO_OWNER}/${REPO_NAME}/archive/refs/heads/main.tar.gz"

  if command_exists git; then
    log_info "Cloning repository..."
    if [[ -d "${INSTALL_DIR}/.git" ]]; then
      cd "$INSTALL_DIR" && git pull --ff-only origin main 2>/dev/null || {
        log_warn "Git pull failed, re-cloning..."
        rm -rf "$INSTALL_DIR"
        git clone --depth 1 "$repo_url" "$INSTALL_DIR"
      }
    else
      git clone --depth 1 "$repo_url" "$INSTALL_DIR"
    fi
  else
    log_info "Git not found, downloading tarball..."
    ensure_openvpn || true  # tarball install may not need pki immediately
    command_exists curl || { log_error "curl required for tarball download."; exit 1; }
    local tmp_tar=$(mktemp --suffix=.tar.gz)
    log_info "Downloading tarball..."
    curl -sSLL "$tarball_url" -o "$tmp_tar"
    mkdir -p "$INSTALL_DIR"
    tar xzf "$tmp_tar" -C "$INSTALL_DIR" --strip-components=1
    rm -f "$tmp_tar"
    log_ok "Tarball extracted."
  fi

  if [[ ! -f "${INSTALL_DIR}/main.py" && ! -f "${INSTALL_DIR}/main.py" ]]; then
    log_error "Repository does not contain expected application files."
    exit 1
  fi
}

# ---------- uv ----------
ensure_uv() {
  if command_exists uv; then
    log_info "uv already installed."
    return 0
  fi
  log_info "Installing uv..."
  if command_exists pip; then
    pip install uv || {
      log_error "Failed to install uv via pip."
      return 1
    }
  elif command_exists python3; then
    python3 -m pip install uv || {
      log_error "Failed to install uv via python3 -m pip."
      return 1
    }
  else
    log_error "No python3/pip available to install uv."
    return 1
  fi
  log_ok "uv installed."
}

uv_sync() {
  log_info "Running uv sync..."
  cd "$INSTALL_DIR"
  uv sync --dev
  log_ok "uv sync complete."
}

# ---------- .env ----------
generate_api_key() {
  if command_exists python3; then
    python3 -c "import uuid; print(uuid.uuid4().hex)"
  else
    # Fallback: use /dev/urandom
    head -c 16 /dev/urandom | xxd -p | tr -d '\n'
  fi
}

write_env() {
  if [[ -f "$ENV_EXAMPLE_FILE" ]]; then
    log_info "Creating .env from example template."
    cp "$ENV_EXAMPLE_FILE" "$ENV_FILE"
  else
    log_warn ".env.example not found, creating a minimal .env manually."
    cat >"$ENV_FILE" <<EOF
SERVICE_PORT=${PORT}
API_KEY=${API_KEY:-$(generate_api_key)}
VPN_PORT=${VPN_PORT}
EOF
  fi

  # Override with provided values (overwrites example defaults)
  sed -i "s/^SERVICE_PORT=.*/SERVICE_PORT=${PORT}/" "$ENV_FILE" 2>/dev/null || \
    echo "SERVICE_PORT=${PORT}" >>"$ENV_FILE"
  sed -i "s/^API_KEY=.*/API_KEY=${API_KEY:-$(generate_api_key)}/" "$ENV_FILE" 2>/dev/null || \
    echo "API_KEY=${API_KEY:-$(generate_api_key)}" >>"$ENV_FILE"
  sed -i "s/^VPN_PORT=.*/VPN_PORT=${VPN_PORT}/" "$ENV_FILE" 2>/dev/null || \
    echo "VPN_PORT=${VPN_PORT}" >>"$ENV_FILE"

  # Prefer env var overrides from outer environment
  : "${SERVICE_PORT:=${PORT}}"
  : "${API_KEY:=}"
  : "${OPENVPN_PORT:=${VPN_PORT}}"

  if [[ -n "${SERVICE_PORT}" ]]; then
    sed -i "s/^SERVICE_PORT=.*/SERVICE_PORT=${SERVICE_PORT}/" "$ENV_FILE" 2>/dev/null || echo "SERVICE_PORT=${SERVICE_PORT}" >>"$ENV_FILE"
  fi
  if [[ -n "${API_KEY:-}" ]]; then
    sed -i "s/^API_KEY=.*/API_KEY=${API_KEY}/" "$ENV_FILE" 2>/dev/null || echo "API_KEY=${API_KEY}" >>"$ENV_FILE"
  fi
  if [[ -n "${OPENVPN_PORT:-}" ]]; then
    sed -i "s/^VPN_PORT=.*/VPN_PORT=${OPENVPN_PORT}/" "$ENV_FILE" 2>/dev/null || echo "VPN_PORT=${OPENVPN_PORT}" >>"$ENV_FILE"
  fi

  log_ok ".env written."
  cat "$ENV_FILE"
}

# ---------- Systemd ----------
install_systemd_service() {
  if [[ "$USE_DOCKER" == true ]]; then
    log_info "Docker mode selected, skipping systemd service installation."
    return 0
  fi

  local service_file="/etc/systemd/system/${SYSTEMD_SERVICE}"
  log_info "Creating systemd service: ${service_file}"

  cat >"/tmp/${SYSTEMD_SERVICE}" <<EOF
[Unit]
Description=OVNode OpenVPN Node Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=$(command -v uv run || which uv) run main.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

  cp "/tmp/${SYSTEMD_SERVICE}" "$service_file"
  systemctl daemon-reload
  systemctl enable "$SYSTEMD_SERVICE"
  systemctl restart "$SYSTEMD_SERVICE"

  if systemctl is-active --quiet "$SYSTEMD_SERVICE"; then
    log_ok "systemd service started and enabled."
  else
    log_error "systemd service failed to start. Check with: systemctl status ${SYSTEMD_SERVICE}"
    exit 1
  fi
}

install_docker_compose() {
  log_info "Creating docker-compose.yml..."
  cat >"$DOCKER_COMPOSE_FILE" <<EOF
version: '3.8'
services:
  ovnode:
    image: ovnode/ovnode:latest
    container_name: ovnode
    restart: unless-stopped
    ports:
      - "${PORT}:${PORT}/tcp"
      - "${VPN_PORT}:${VPN_PORT}/udp"
    volumes:
      - ${INSTALL_DIR}/.env:.env
      - ovnode_data:/opt/ovnode/data
    environment:
      - SERVICE_PORT=${PORT}
      - API_KEY=${API_KEY:-$(generate_api_key)}
      - VPN_PORT=${VPN_PORT}
volumes:
  ovnode_data:
EOF
  log_ok "docker-compose.yml created."

  cd "$INSTALL_DIR"
  if command_exists docker-compose; then
    docker-compose up -d
  else
    docker compose up -d
  fi
  log_ok "Docker container started."
}

# ---------- Uninstall ----------
uninstall() {
  log_warn "Running uninstall..."
  if [[ "$USE_DOCKER" == true ]] && [[ -f "$DOCKER_COMPOSE_FILE" ]]; then
    cd "$INSTALL_DIR" && (docker compose down || docker-compose down) 2>/dev/null || true
  fi
  if [[ -f "/etc/systemd/system/${SYSTEMD_SERVICE}" ]]; then
    systemctl stop "$SYSTEMD_SERVICE" 2>/dev/null || true
    systemctl disable "$SYSTEMD_SERVICE" 2>/dev/null || true
    rm -f "/etc/systemd/system/${SYSTEMD_SERVICE}"
    systemctl daemon-reload
  fi
  rm -rf "$INSTALL_DIR"
  rm -f /tmp/${SYSTEMD_SERVICE}
  log_ok "Uninstall complete."
}

uninstall_cleanup_only() {
  log_warn "Cleanup (no systemd removal)..."
  if [[ "$USE_DOCKER" == true ]] && [[ -f "$DOCKER_COMPOSE_FILE" ]]; then
    cd "$INSTALL_DIR" && (docker compose down || docker-compose down) 2>/dev/null || true
  fi
  rm -rf "$INSTALL_DIR"
  rm -f /tmp/${SYSTEMD_SERVICE}
}

# ---------- Update ----------
do_update() {
  log_info "Updating OVNode..."
  if [[ "$USE_DOCKER" == true ]]; then
    log_info "Pulling latest docker image..."
    cd "$INSTALL_DIR" && (docker compose pull || docker-compose pull) 2>/dev/null || {
      log_error "Docker compose pull failed."
      exit 1
    }
    if [[ -f "$DOCKER_COMPOSE_FILE" ]]; then
      cd "$INSTALL_DIR" && (docker compose up -d || docker-compose up -d)
    fi
  else
    if [[ -d "${INSTALL_DIR}/.git" ]]; then
      cd "$INSTALL_DIR" && git pull --ff-only origin main || {
        log_error "Git pull failed."
        exit 1
      }
    else
      log_error "Update requested but repo is not git-based. Re-run installer manually."
      exit 1
    fi
    if [[ -f "/etc/systemd/system/${SYSTEMD_SERVICE}" ]]; then
      systemctl stop "$SYSTEMD_SERVICE" || true
    fi
    uv_sync
    if [[ -f "/etc/systemd/system/${SYSTEMD_SERVICE}" ]]; then
      systemctl start "$SYSTEMD_SERVICE" || true
    fi
  fi
  log_ok "Update complete."
}

# ---------- Main ----------
main() {
  # Parse global flags before subcommands
  if [[ "${1:-}" == "--help" ]]; then
    show_help
    exit 0
  fi

  # Support inline override via env vars before parsing flags
  : "${SERVICE_PORT:=}"
  : "${API_KEY:=}"
  : "${OPENVPN_PORT:=}"

  # Determine mode
  if [[ "${1:-}" == "--docker" ]]; then
    USE_DOCKER=true
    shift
  fi

  # Check for subcommands
  if [[ "${1:-}" == "update" ]]; then
    do_update
    exit 0
  elif [[ "${1:-}" == "uninstall" ]]; then
    uninstall
    exit 0
  fi

  # Parse install flags
  parse_args "$@"

  # Port from env override
  if [[ -n "${SERVICE_PORT:-}" ]]; then
    PORT="${SERVICE_PORT}"
  fi
  if [[ -n "${OPENVPN_PORT:-}" ]]; then
    VPN_PORT="${OPENVPN_PORT}"
  fi
  if [[ -n "${API_KEY:-}" ]]; then
    API_KEY="${API_KEY}"
  fi

  check_deps
  detect_docker_compose

  log_info "OVNode OpenVPN Node Agent Installer"
  log_info "Install directory: ${INSTALL_DIR}"
  log_info "Service port: ${PORT}"
  log_info "VPN port: ${VPN_PORT}"
  log_info "Docker mode: ${USE_DOCKER}"

  if [[ "$USE_DOCKER" == true ]]; then
    install_docker_compose
  else
    if [[ -d "$INSTALL_DIR" ]]; then
      log_warn "${INSTALL_DIR} already exists. Update mode recommended."
      read -r -p "Continue and overwrite? [y/N] " response
      case "$response" in
        [yY][eE][sS]|[yY]) ;;
        *) log_info "Aborted."; exit 1 ;;
      esac
    fi

    mkdir -p "$INSTALL_DIR"
    clone_or_download
    ensure_uv
    uv_sync
    write_env
    install_systemd_service
  fi

  log_ok "OVNode installation complete!"
  log_info "Check status: systemctl status ${SYSTEMD_SERVICE}"
  log_info "Uninstall with: curl -sSL URL | bash -s -- --uninstall"
}

main "$@"