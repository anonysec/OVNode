#!/usr/bin/env bash
# OVManager local max-login enforcement for OpenVPN client-connect.
#
# Designed for dynamic IP environments (mobile ISPs, Iranian providers, etc.)
# where the user's IP changes on every reconnect.
#
# Policy:
# - max_logins=1: local takeover. Kill old session, allow new one.
# - max_logins=N>1: allow up to N sessions, reject N+1.
# - max_logins=0: unlimited.
#
# Reconnection handling (dynamic IP aware):
# - Grace period matches on CN (numeric user ID) alone — NOT on IP.
#   If the same user reconnects within the grace period, their old marker
#   is removed and replaced. This works regardless of IP changes.
# - When multiple markers exist and grace triggers, the OLDEST marker is
#   removed (most likely the stale/dropped session).
# - Stale cleanup removes markers that are NOT in OpenVPN's status file.

set -euo pipefail

LIMITS_DIR="/etc/openvpn/limits"
DISABLED_DIR="/etc/openvpn/disabled"
ACTIVE_DIR="/etc/openvpn/ovnode-active"
LOCK_FILE="${ACTIVE_DIR}/.lock"
STATUS_FILE="${OVNODE_STATUS_FILE:-/etc/openvpn/server/status.log}"
MGMT_HOST="${OVNODE_MGMT_HOST:-127.0.0.1}"
MGMT_PORT="${OVNODE_MANAGEMENT_PORT:-7505}"
DEFAULT_LIMIT=1
LOG_TAG="ovnode-mlogin"
# Grace period (seconds): same-CN reconnects within this window are
# treated as the same user reconnecting (IP may have changed).
RECONNECT_GRACE="${OVNODE_RECONNECT_GRACE:-15}"

cn="${common_name:-${1:-}}"

log() { logger -t "$LOG_TAG" "$*" 2>/dev/null || echo "$LOG_TAG: $*" >&2; }
sanitize() { printf '%s' "$1" | sed 's/[^A-Za-z0-9_.-]/_/g'; }

mgmt_available() {
    python3 - "$MGMT_HOST" "$MGMT_PORT" <<'PYPROBE' >/dev/null 2>&1
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
with socket.create_connection((host, port), timeout=2):
    pass
PYPROBE
}

mgmt_send() {
    local cmd="$1"
    python3 - "$MGMT_HOST" "$MGMT_PORT" "$cmd" <<'PYMGMT' >/dev/null 2>&1 || true
import socket, sys
host, port, cmd = sys.argv[1], int(sys.argv[2]), sys.argv[3]
try:
    s = socket.create_connection((host, port), timeout=2)
    s.settimeout(2)
    try:
        s.recv(2048)
    except Exception:
        pass
    s.sendall((cmd.rstrip() + "\n").encode())
    try:
        s.recv(4096)
    except Exception:
        pass
    s.sendall(b"quit\n")
    s.close()
except Exception:
    pass
PYMGMT
}

kill_existing_sessions() {
    local target_cn="$1"
    local current_real="$2"

    # Kill by Client ID from status-version 2/3.
    if [[ -f "$STATUS_FILE" ]]; then
        while IFS=$'\t' read -r real cid; do
            [[ -n "${real:-}" ]] || continue
            [[ "$real" == "$current_real" ]] && continue
            if [[ "${cid:-}" =~ ^[0-9]+$ ]]; then
                mgmt_send "client-kill $cid max-login-takeover"
                log "CN=$target_cn takeover client-kill cid=$cid real=$real"
            else
                mgmt_send "kill $real"
                log "CN=$target_cn takeover kill real=$real"
            fi
        done < <(awk -v cn="$target_cn" '
            BEGIN { FS="\t" }
            $1 == "CLIENT_LIST" && $2 == cn { print $3 "\t" $11 }
        ' "$STATUS_FILE" 2>/dev/null || true)
    fi

    # Fallback: kill by marker IP:port
    while IFS= read -r marker; do
        [[ -f "$marker" ]] || continue
        m_ip="$(awk -F= '$1 == "trusted_ip" {print $2}' "$marker" 2>/dev/null || true)"
        m_port="$(awk -F= '$1 == "trusted_port" {print $2}' "$marker" 2>/dev/null || true)"
        [[ -n "$m_ip" && -n "$m_port" ]] || continue
        marker_real="${m_ip}:${m_port}"
        [[ "$marker_real" == "$current_real" ]] && continue
        mgmt_send "kill $marker_real"
        log "CN=$target_cn takeover kill marker_real=$marker_real"
    done < <(find "$ACTIVE_DIR" -type f -name "${safe_cn}.*" 2>/dev/null || true)
}

if [[ -z "$cn" ]]; then
    log "no common_name provided; allowing"
    exit 0
fi

safe_cn="$(sanitize "$cn")"
mkdir -p "$LIMITS_DIR" "$ACTIVE_DIR"
chmod 755 "$ACTIVE_DIR" 2>/dev/null || true

# DISABLED_DIR must exist and be readable. If it is missing or inaccessible
# we fail-closed: deny the connection rather than risk allowing a disabled user.
# The directory is created by ensure_multilogin_setup() at OVNode startup; its
# absence indicates a filesystem or permissions problem that must be fixed.
if [[ ! -d "$DISABLED_DIR" ]]; then
    log "CN=$cn DISABLED_DIR missing or not a directory — fail-closed; REJECT"
    exit 1
fi
chmod 755 "$DISABLED_DIR" 2>/dev/null || true

# A missing CCD file is not an authentication denial. Keep an explicit
# disabled marker so an already-issued certificate cannot reconnect after
# Manager disables the user.
if [[ -f "${DISABLED_DIR}/${safe_cn}" ]]; then
    log "CN=$cn is disabled; REJECT"
    exit 1
fi

limit="$DEFAULT_LIMIT"
limit_file="${LIMITS_DIR}/${cn}"
if [[ -f "$limit_file" ]]; then
    raw="$(tr -dc '0-9' < "$limit_file" || true)"
    [[ -n "$raw" ]] && limit="$raw"
fi

if [[ "$limit" -eq 0 ]]; then
    log "CN=$cn limit=unlimited; LOCAL_ALLOW"
    exit 0
fi

trusted_ip_s="$(sanitize "${trusted_ip:-unknown}")"
trusted_port_s="$(sanitize "${trusted_port:-unknown}")"
pool_ip_s="$(sanitize "${ifconfig_pool_remote_ip:-noip}")"
time_s="$(date +%s)"
session_key="${safe_cn}.${trusted_ip_s}.${trusted_port_s}.${pool_ip_s}"
session_file="${ACTIVE_DIR}/${session_key}"
current_real="${trusted_ip:-}:${trusted_port:-}"

exec 9>"$LOCK_FILE"
flock -x 9

# ── Reconnect detection (dynamic IP aware) ───────────────────────
# If ANY marker for this CN was written within the grace period,
# the user is reconnecting (their IP may have changed). Remove the
# OLDEST such marker (most likely the stale/dropped session) and
# proceed to write a fresh marker.
#
# This works for:
# - Static IPs: same user, same IP, within grace
# - Dynamic IPs: same user, different IP, within grace
# - max_logins=1: one old marker → removed → count=0 → allow
# - max_logins=2: two old markers → oldest removed → count=1 → allow
reconnected=0
oldest_marker=""
oldest_time=999999999

for old_marker in "$ACTIVE_DIR"/${safe_cn}.*; do
    [[ -f "$old_marker" ]] || continue
    created_s="$(awk -F= '$1 == "created" {print $2}' "$old_marker" 2>/dev/null || echo 0)"
    [[ "$created_s" =~ ^[0-9]+$ ]] || created_s=0
    age=$(( time_s - created_s ))
    if (( age < RECONNECT_GRACE )); then
        reconnected=1
        if (( created_s < oldest_time )); then
            oldest_time=$created_s
            oldest_marker="$old_marker"
        fi
    fi
done

if [[ "$reconnected" -eq 1 && -n "$oldest_marker" ]]; then
    rm -f "$oldest_marker" 2>/dev/null || true
    log "CN=$cn reconnect (grace=${RECONNECT_GRACE}s); removed oldest marker=$(basename "$oldest_marker")"
fi

# ── Stale marker cleanup ─────────────────────────────────────────
# Remove markers older than grace that are NOT in the OpenVPN status file.
# This handles slow reconnects (> grace) where the old session has
# already been cleared by OpenVPN.
if [[ -f "$STATUS_FILE" ]]; then
    while IFS= read -r marker; do
        [[ -f "$marker" ]] || continue
        created_s="$(awk -F= '$1 == "created" {print $2}' "$marker" 2>/dev/null || echo 0)"
        [[ "$created_s" =~ ^[0-9]+$ ]] || created_s=0
        age=$(( time_s - created_s ))
        # Keep recent markers (within grace) — handled above
        if (( age < RECONNECT_GRACE )); then
            continue
        fi
        # Old marker: check if it's still in the status file
        m_ip="$(awk -F= '$1 == "trusted_ip" {print $2}' "$marker" 2>/dev/null || true)"
        m_port="$(awk -F= '$1 == "trusted_port" {print $2}' "$marker" 2>/dev/null || true)"
        if ! awk -v cn="$cn" -v ip="$m_ip" -v port="$m_port" '
            BEGIN { FS="\t"; found=0 }
            $1 == "CLIENT_LIST" && $2 == cn {
                split($3, a, ":"); p=a[length(a)]; sub(":" p "$", "", $3);
                if ($3 == ip && p == port) found=1
            }
            END { exit(found ? 0 : 1) }
        ' "$STATUS_FILE" 2>/dev/null; then
            rm -f "$marker" 2>/dev/null || true
            log "CN=$cn removed_stale_marker=$(basename "$marker") age=${age}s"
        fi
    done < <(find "$ACTIVE_DIR" -type f -name "${safe_cn}.*" 2>/dev/null)
fi

# ── Count active sessions ────────────────────────────────────────
status_count=0
if [[ -f "$STATUS_FILE" ]]; then
    status_count="$(awk -v cn="$cn" '
        BEGIN { FS="\t" }
        $1 == "CLIENT_LIST" && $2 == cn { c++ }
        END { print c+0 }
    ' "$STATUS_FILE" 2>/dev/null || echo 0)"
fi

active_files="$(find "$ACTIVE_DIR" -type f -name "${safe_cn}.*" 2>/dev/null | wc -l | tr -d ' ')"
cur="$active_files"
if [[ "$status_count" -gt "$cur" ]]; then cur="$status_count"; fi

if (( cur >= limit )); then
    if [[ "$limit" -eq 1 ]]; then
        # Takeover must fail closed if the management socket is unavailable;
        # otherwise the old session can remain connected while the new one is
        # accepted, violating the single-login policy.
        if ! mgmt_available; then
            log "CN=$cn limit=1 active=$active_files status=$status_count; management unavailable; REJECT"
            exit 1
        fi
        log "CN=$cn limit=1 active=$active_files status=$status_count; TAKEOVER"
        kill_existing_sessions "$cn" "$current_real"
        sleep 0.3
        remaining=0
        if [[ -f "$STATUS_FILE" ]]; then
            remaining="$(awk -v cn="$cn" -v current="$current_real" '
                BEGIN { FS="\t" }
                $1 == "CLIENT_LIST" && $2 == cn && $3 != current { c++ }
                END { print c+0 }
            ' "$STATUS_FILE" 2>/dev/null || echo 1)"
        fi
        if [[ "$remaining" -gt 0 ]]; then
            log "CN=$cn takeover could not verify old session termination; REJECT"
            exit 1
        fi
        rm -f "${ACTIVE_DIR}/${safe_cn}."* 2>/dev/null || true
    else
        log "CN=$cn limit=$limit active=$active_files status=$status_count; REJECT"
        exit 1
    fi
fi

cat > "$session_file" <<EOF
common_name=$cn
trusted_ip=${trusted_ip:-}
trusted_port=${trusted_port:-}
ifconfig_pool_remote_ip=${ifconfig_pool_remote_ip:-}
created=$time_s
EOF
chmod 600 "$session_file" 2>/dev/null || true

log "CN=$cn limit=$limit active=$active_files status=$status_count; ALLOW session=$session_key"
exit 0
