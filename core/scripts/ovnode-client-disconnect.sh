#!/usr/bin/env bash
# Copyright (c) 2025 anonysec. All rights reserved.
# Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
#
# OVManager local disconnect hook. Removes the local active-session marker.
# Markers are keyed by CN + pool IP (dynamic-IP safe); the legacy
# CN.ip.port.pool layout is cleaned up as a fallback.

set -euo pipefail

ACTIVE_DIR="/etc/openvpn/ovnode/sessions"
LOCK_FILE="${ACTIVE_DIR}/.lock"
LOG_TAG="ovnode-mlogin"

cn="${common_name:-${1:-}}"

log() { logger -t "$LOG_TAG" "$*" 2>/dev/null || true; }
sanitize() { printf '%s' "$1" | sed 's/[^A-Za-z0-9_.-]/_/g'; }

if [[ -z "$cn" ]]; then
    log "disconnect without common_name"
    exit 0
fi

safe_cn="$(sanitize "$cn")"
pool_ip="${ifconfig_pool_remote_ip:-}"
pool_ip_s="$(sanitize "${pool_ip:-noip}")"
trusted_ip_s="$(sanitize "${trusted_ip:-unknown}")"
trusted_port_s="$(sanitize "${trusted_port:-unknown}")"

if [[ -n "$pool_ip" ]]; then
    session_key="${safe_cn}.${pool_ip_s}"
else
    session_key="${safe_cn}.noip.${trusted_ip_s}.${trusted_port_s}"
fi
session_file="${ACTIVE_DIR}/${session_key}"

mkdir -p "$ACTIVE_DIR"
exec 9>"$LOCK_FILE"
flock -x 9

if [[ -f "$session_file" ]]; then
    rm -f "$session_file"
    log "CN=$cn disconnect removed session=$session_key"
else
    # Legacy layouts: CN.ip.port.pool (pre pool-IP keying).
    rm -f "${ACTIVE_DIR}/${safe_cn}."*".${pool_ip_s}" 2>/dev/null || true
    rm -f "${ACTIVE_DIR}/${safe_cn}.${trusted_ip_s}.${trusted_port_s}."* 2>/dev/null || true
    log "CN=$cn disconnect fallback cleanup session=$session_key"
fi

exit 0
