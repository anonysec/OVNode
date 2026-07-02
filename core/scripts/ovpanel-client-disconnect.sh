#!/usr/bin/env bash
# ov-panel multi-login disconnect hook. Removes the active-session marker that
# client-connect created.

set -euo pipefail

ACTIVE_DIR="/etc/openvpn/ovpanel-active"
LOCK_FILE="${ACTIVE_DIR}/.lock"
LOG_TAG="ovpanel-mlogin"

cn="${common_name:-${1:-}}"

log() { logger -t "$LOG_TAG" "$*" 2>/dev/null || true; }

sanitize() {
    printf '%s' "$1" | sed 's/[^A-Za-z0-9_.-]/_/g'
}

if [[ -z "$cn" ]]; then
    log "disconnect without common_name"
    exit 0
fi

safe_cn="$(sanitize "$cn")"
trusted_ip_s="$(sanitize "${trusted_ip:-unknown}")"
trusted_port_s="$(sanitize "${trusted_port:-unknown}")"
pool_ip_s="$(sanitize "${ifconfig_pool_remote_ip:-noip}")"
session_key="${safe_cn}.${trusted_ip_s}.${trusted_port_s}.${pool_ip_s}"
session_file="${ACTIVE_DIR}/${session_key}"

mkdir -p "$ACTIVE_DIR"
exec 9>"$LOCK_FILE"
flock -x 9

if [[ -f "$session_file" ]]; then
    rm -f "$session_file"
    log "CN=$cn disconnect removed session=$session_key"
else
    # Fallback: if pool IP is unavailable or changed, remove matching CN+remote.
    rm -f "${ACTIVE_DIR}/${safe_cn}.${trusted_ip_s}.${trusted_port_s}."* 2>/dev/null || true
    log "CN=$cn disconnect fallback cleanup session=$session_key"
fi

exit 0
