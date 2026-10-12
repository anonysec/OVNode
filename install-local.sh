#!/bin/bash
# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT
#
# install-local.sh — install OVNode straight from a checkout (fast dev loop).
# install.sh is the release path and stays frozen; this file fetches nothing.
# It rsyncs the tree at --src into --dest and does the minimum to get the
# agent running under systemd. Rerun = update.

set -Eeuo pipefail

EX_OK=0 EX_ERROR=1 EX_USAGE=2

SRC=""
DEST="/opt/ovnode"
ACTION="install"

_SELF_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# scripts/lib comes from the tree, never fetched (manager.sh:62-74 pattern):
# the copy beside this script wins; the installed copy is the fallback.
for _lib in common.sh render.sh; do
    if [[ -f "$_SELF_DIR/scripts/lib/$_lib" ]]; then
        _libdir="$_SELF_DIR/scripts/lib"
    elif [[ -f "$DEST/scripts/lib/$_lib" ]]; then
        _libdir="$DEST/scripts/lib"
    else
        echo "Error: scripts/lib/$_lib not found (looked in $_SELF_DIR/scripts/lib and $DEST/scripts/lib)" >&2
        exit "$EX_ERROR"
    fi
    # shellcheck disable=SC1091
    . "$_libdir/$_lib"
done
unset _lib _libdir

usage() {
    cat <<'EOF'
Usage: install-local.sh [--src DIR] [--dest DIR] [--uninstall] [--help]

  --src DIR      Source checkout to install    [default: this script's dir]
  --dest DIR     Install destination                     [default: /opt/ovnode]
  --uninstall    Stop the service, remove dest and unit
  --help         This help (works as non-root)

Dev loop only: rsync + .env (created once) + unit + uv sync + restart.
Nothing is fetched — openvpn, easy-rsa, rsync and uv must already exist.
EOF
    exit "$EX_OK"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --src)      [[ $# -ge 2 ]] || die "--src needs a value" "$EX_USAGE"; SRC="$2"; shift 2 ;;
        --dest)     [[ $# -ge 2 ]] || die "--dest needs a value" "$EX_USAGE"; DEST="$2"; shift 2 ;;
        --uninstall) ACTION="uninstall"; shift ;;
        --help|-h)  usage ;;
        *)          die "Unknown flag: $1 (see --help)" "$EX_USAGE" ;;
    esac
done
[[ -n "$SRC" ]] || SRC="$_SELF_DIR"

# Root-only actions guarded here; --help already exited above.
[[ "$EUID" -eq 0 ]] || die "Must run as root (sudo ./install-local.sh)" "$EX_ERROR"

check_prereqs() {
    local missing=()
    command -v openvpn >/dev/null 2>&1 || missing+=("openvpn")
    [[ -d /usr/share/easy-rsa ]] || command -v easyrsa >/dev/null 2>&1 || missing+=("easy-rsa")
    command -v rsync >/dev/null 2>&1 || missing+=("rsync")
    command -v uv >/dev/null 2>&1 || missing+=("uv")
    command -v systemctl >/dev/null 2>&1 || missing+=("systemd")
    # Dev box owns its network: no auto-install, no firewall automation.
    [[ ${#missing[@]} -eq 0 ]] || die "Missing prerequisites: ${missing[*]} — install them first (Debian/Ubuntu: apt-get install openvpn easy-rsa rsync; uv from your package manager), then rerun" "$EX_ERROR"
}

validate_src() {
    [[ -f "$SRC/main.py" ]] || die "No main.py under $SRC — --src must point at an OVNode checkout" "$EX_ERROR"
    [[ -f "$SRC/pyproject.toml" ]] || die "No pyproject.toml under $SRC — --src must point at an OVNode checkout" "$EX_ERROR"
}

do_install() {
    check_prereqs
    validate_src
    [[ -n "$DEST" && "$DEST" != "/" ]] || die "Refusing to install into '$DEST'" "$EX_ERROR"
    render_ok "rsync $SRC/ -> $DEST/"
    # --delete only reaches files not excluded, so a dest .env is never
    # transferred in and never deleted.
    rsync -a --delete --exclude '.git' --exclude '.venv' --exclude '__pycache__' \
        --exclude '.pytest_cache' --exclude '.slim' --exclude '.env' \
        "$SRC/" "$DEST/"
    if [[ ! -f "$DEST/.env" ]]; then
        local port="${OVN_PORT:-2083}" key
        key="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
        cat > "$DEST/.env" << EOF
NODE_NAME=${OVN_NAME:-ovnode}
DATA_DIR=$DEST/data
SERVICE_PORT=$port
API_KEY=$key
OPENVPN_PORT=1194
OVNODE_PROTO=tcp
TLS_METHOD=selfsigned
EOF
        chmod 600 "$DEST/.env"
        render_ok ".env created at $DEST/.env"
    else
        render_ok ".env kept — $DEST/.env is never overwritten"
    fi
    # ExecStart runs the dest venv interpreter directly: no uv at boot.
    cat > /etc/systemd/system/ovnode.service << UNIT
[Unit]
Description=OVNode OpenVPN Node Agent (local dev)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$DEST
Environment="PATH=$DEST/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
EnvironmentFile=$DEST/.env
ExecStart=$DEST/.venv/bin/python $DEST/main.py
Restart=on-failure
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT
    render_ok "systemd unit written: /etc/systemd/system/ovnode.service"
    (cd "$DEST" && uv sync)
    systemctl daemon-reload >/dev/null
    systemctl restart ovnode.service
    local port
    port="$(grep -E '^SERVICE_PORT=' "$DEST/.env" 2>/dev/null | head -1 | cut -d= -f2- || true)"
    curl -fsS -m 3 "http://127.0.0.1:${port:-2083}/health" >/dev/null 2>&1 \
        || render_warn "health not confirmed yet (agent may still be starting) — fail-open, check: systemctl status ovnode.service"
    render_ok "Installed at $DEST — rerun this script to update"
}

do_uninstall() {
    [[ -n "$DEST" && "$DEST" != "/" ]] || die "Refusing to remove '$DEST'" "$EX_ERROR"
    systemctl disable --now ovnode.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/ovnode.service
    systemctl daemon-reload >/dev/null 2>&1 || true
    rm -rf -- "$DEST"
    render_ok "Removed $DEST and ovnode.service"
}

if [[ "$ACTION" == "uninstall" ]]; then
    do_uninstall
else
    do_install
fi
