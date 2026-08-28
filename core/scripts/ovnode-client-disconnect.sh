#!/usr/bin/env bash
# Copyright (c) 2025 anonysec. All rights reserved.
# Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
#
# OVManager local disconnect hook. Removes the local active-session marker
# and banks the session's final byte counters into the per-user usage
# accumulator (OpenVPN exposes bytes_received/bytes_sent to this hook —
# without this, traffic from completed sessions would be lost between
# status-file polls).

set -euo pipefail

ACTIVE_DIR="/etc/openvpn/ovnode/sessions"
USAGE_DIR="/etc/openvpn/ovnode/usage"
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

# ── usage accounting ─────────────────────────────────────────────
# Accumulate this session's final byte counters (under the lock, so two
# simultaneous disconnects of the same CN cannot lose an update).
rx="${bytes_received:-0}"
tx="${bytes_sent:-0}"
[[ "$rx" =~ ^[0-9]+$ ]] || rx=0
[[ "$tx" =~ ^[0-9]+$ ]] || tx=0
session_total=$(( rx + tx ))
if (( session_total > 0 )) && [[ -d "$USAGE_DIR" && -w "$USAGE_DIR" ]]; then
    usage_file="${USAGE_DIR}/${safe_cn}"
    old="$(cat "$usage_file" 2>/dev/null || echo 0)"
    [[ "$old" =~ ^[0-9]+$ ]] || old=0
    echo $(( old + session_total )) > "$usage_file"
    log "CN=$cn session ended rx=$rx tx=$tx accumulated=$(( old + session_total ))"
fi

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
