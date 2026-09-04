#!/usr/bin/env bash
# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT
#
# OVManager local max-login enforcement for OpenVPN client-connect.
#
# Designed for dynamic IP environments (mobile ISPs, CGNAT, etc.) where the
# user's real IP:port changes on every reconnect. Session identity is
# therefore CN + VPN pool IP (ifconfig_pool_remote_ip) — stable for the
# session lifetime — and enforcement actions target the management Client ID
# (CID), never the real address. Real IP/port are recorded as metadata only.
#
# Policy:
# - max_logins=1: local takeover. Kill old session (by CID), allow new one.
# - max_logins=N>1: allow up to N sessions, reject N+1.
# - max_logins=0: unlimited.
#
# Reconnection handling:
# - Grace period matches on CN alone — NOT on IP. A same-CN reconnect within
#   the grace window replaces the OLDEST marker (the dropped session).
# - Stale cleanup removes markers whose (CN, pool IP) is absent from the
#   status file (status-version 3, tab-separated).

set -euo pipefail

# Per-user state lives in one folder per user (see core/openvpn/store.py):
#   users/<cn>/limit     max simultaneous logins (0 = unlimited)
#   users/<cn>/disabled  marker — exists = reject the connection
# Session markers live in sessions/ (one file per live session).
USERS_DIR="/etc/openvpn/ovnode/users"
ACTIVE_DIR="/etc/openvpn/ovnode/sessions"
LOCK_FILE="${ACTIVE_DIR}/.lock"
STATUS_FILE="${OVNODE_STATUS_FILE:-/etc/openvpn/server/status.log}"
MGMT_HOST="${OVNODE_MANAGEMENT_HOST:-${OVNODE_MGMT_HOST:-127.0.0.1}}"
MGMT_PORT="${OVNODE_MANAGEMENT_PORT:-7505}"
# Management password file: must match core/openvpn/sessions.py::_mgmt_password()
# (canonical path first, $OVNODE_MGMT_PASS_FILE override second).
OPENVPN_ROOT="${OVNODE_OPENVPN_ROOT:-/etc/openvpn}"
MGMT_PASS_FILE="${OVNODE_MGMT_PASS_FILE:-$OPENVPN_ROOT/server/mgmt-pass}"
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
    python3 - "$MGMT_HOST" "$MGMT_PORT" "$cmd" "$MGMT_PASS_FILE" <<'PYMGMT' >/dev/null 2>&1 || true
import socket, sys
host, port, cmd, pass_file = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
try:
    s = socket.create_connection((host, port), timeout=2)
    s.settimeout(2)
    try:
        banner = s.recv(2048).decode(errors="ignore")
    except Exception:
        banner = ""
    # Authenticate when the daemon challenges (pki.py writes
    # "management 127.0.0.1 <port> <mgmt-pass>"); legacy passwordless
    # daemons skip this entirely.
    upper = banner.upper()
    if "ENTER PASSWORD" in upper or "PASSWORD:" in upper:
        pw = ""
        try:
            with open(pass_file, encoding="utf-8") as f:
                pw = f.read().strip().splitlines()[0].strip() if f else ""
        except OSError:
            pw = ""
        if pw:
            try:
                s.sendall((pw + "\n").encode())
                s.recv(4096)
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

# Kill this CN's other sessions. Targets the management Client ID from the
# status file (column 11, status-version 3) — dynamic-IP safe. The session
# being established is excluded by pool IP (it is not in the status file
# yet, but be defensive against fast status rewrites).
kill_existing_sessions() {
    local target_cn="$1"
    local current_pool="$2"

    if [[ -f "$STATUS_FILE" ]]; then
        while IFS=$'\t' read -r pool cid; do
            [[ "${pool:-}" == "$current_pool" && -n "$current_pool" ]] && continue
            if [[ "${cid:-}" =~ ^[0-9]+$ ]]; then
                mgmt_send "client-kill $cid max-login-takeover"
                log "CN=$target_cn takeover client-kill cid=$cid pool=${pool:-?}"
            fi
        done < <(awk -v cn="$target_cn" '
            BEGIN { FS="\t" }
            $1 == "CLIENT_LIST" && $2 == cn { print $4 "\t" $11 }
        ' "$STATUS_FILE" 2>/dev/null || true)
    fi

    # Fallback for sessions not yet in the status file: kill by marker pool IP
    # is impossible via management, so fall back to the recorded real address.
    while IFS= read -r marker; do
        [[ -f "$marker" ]] || continue
        m_pool="$(awk -F= '$1 == "ifconfig_pool_remote_ip" {print $2}' "$marker" 2>/dev/null || true)"
        [[ -n "$m_pool" && "$m_pool" == "$current_pool" ]] && continue
        m_ip="$(awk -F= '$1 == "trusted_ip" {print $2}' "$marker" 2>/dev/null || true)"
        m_port="$(awk -F= '$1 == "trusted_port" {print $2}' "$marker" 2>/dev/null || true)"
        [[ -n "$m_ip" && -n "$m_port" ]] || continue
        mgmt_send "kill ${m_ip}:${m_port}"
        log "CN=$target_cn takeover fallback kill real=${m_ip}:${m_port}"
    done < <(find "$ACTIVE_DIR" -type f -name "${safe_cn}.*" 2>/dev/null || true)
}

if [[ -z "$cn" ]]; then
    log "no common_name provided; allowing"
    exit 0
fi

safe_cn="$(sanitize "$cn")"

# USERS_DIR must exist and be readable. If it is missing or inaccessible we
# fail-closed: deny the connection rather than risk allowing a disabled user.
# The tree is created by the agent at startup; its absence indicates a
# filesystem or permissions problem that must be fixed.
if [[ ! -d "$USERS_DIR" ]]; then
    log "CN=$cn USERS_DIR missing or not a directory — fail-closed; REJECT"
    exit 1
fi
mkdir -p "$ACTIVE_DIR"
chmod 755 "$ACTIVE_DIR" 2>/dev/null || true

# The disabled marker blocks an already-issued certificate from reconnecting
# after Manager disables the user.
if [[ -f "${USERS_DIR}/${safe_cn}/disabled" ]]; then
    log "CN=$cn is disabled; REJECT"
    exit 1
fi

limit="$DEFAULT_LIMIT"
limit_file="${USERS_DIR}/${safe_cn}/limit"
if [[ -f "$limit_file" ]]; then
    raw="$(tr -dc '0-9' < "$limit_file" || true)"
    [[ -n "$raw" ]] && limit="$raw"
fi

if [[ "$limit" -eq 0 ]]; then
    log "CN=$cn limit=unlimited; LOCAL_ALLOW"
    exit 0
fi

pool_ip="${ifconfig_pool_remote_ip:-}"
pool_ip_s="$(sanitize "${pool_ip:-noip}")"
trusted_ip_s="$(sanitize "${trusted_ip:-unknown}")"
trusted_port_s="$(sanitize "${trusted_port:-unknown}")"
time_s="$(date +%s)"

# Session identity: CN + pool IP (unique per live session, IP-change proof).
# Without a pool IP (rare: hook order edge cases) fall back to the real
# address so two concurrent no-pool sessions cannot share a key.
if [[ -n "$pool_ip" ]]; then
    session_key="${safe_cn}.${pool_ip_s}"
else
    session_key="${safe_cn}.noip.${trusted_ip_s}.${trusted_port_s}"
fi
session_file="${ACTIVE_DIR}/${session_key}"

exec 9>"$LOCK_FILE"
flock -x 9

# ── Reconnect detection (dynamic IP aware) ───────────────────────
# If ANY marker for this CN was written within the grace period, the user is
# reconnecting (their IP may have changed). Remove the OLDEST such marker
# (most likely the dropped session) and proceed to write a fresh marker.
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
# Remove markers older than grace whose (CN, pool IP) is NOT in the status
# file. Matching on the pool IP (status column 4) is immune to the client's
# real IP changing between sessions. Markers without a pool IP fall back to
# real-address matching (legacy markers).
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
        m_pool="$(awk -F= '$1 == "ifconfig_pool_remote_ip" {print $2}' "$marker" 2>/dev/null || true)"
        if [[ -n "$m_pool" ]]; then
            if ! awk -v cn="$cn" -v pool="$m_pool" '
                BEGIN { FS="\t"; found=0 }
                $1 == "CLIENT_LIST" && $2 == cn && $4 == pool { found=1 }
                END { exit(found ? 0 : 1) }
            ' "$STATUS_FILE" 2>/dev/null; then
                rm -f "$marker" 2>/dev/null || true
                log "CN=$cn removed_stale_marker=$(basename "$marker") age=${age}s (pool=$m_pool gone)"
            fi
        else
            m_ip="$(awk -F= '$1 == "trusted_ip" {print $2}' "$marker" 2>/dev/null || true)"
            m_port="$(awk -F= '$1 == "trusted_port" {print $2}' "$marker" 2>/dev/null || true)"
            if ! awk -v cn="$cn" -v real="${m_ip}:${m_port}" '
                BEGIN { FS="\t"; found=0 }
                $1 == "CLIENT_LIST" && $2 == cn && $3 == real { found=1 }
                END { exit(found ? 0 : 1) }
            ' "$STATUS_FILE" 2>/dev/null; then
                rm -f "$marker" 2>/dev/null || true
                log "CN=$cn removed_stale_marker=$(basename "$marker") age=${age}s (legacy real-addr)"
            fi
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
        kill_existing_sessions "$cn" "$pool_ip"
        sleep 0.3
        remaining=0
        if [[ -f "$STATUS_FILE" ]]; then
            remaining="$(awk -v cn="$cn" -v pool="$pool_ip" '
                BEGIN { FS="\t" }
                $1 == "CLIENT_LIST" && $2 == cn && (pool == "" || $4 != pool) { c++ }
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
ifconfig_pool_remote_ip=${pool_ip}
created=$time_s
EOF
chmod 600 "$session_file" 2>/dev/null || true

log "CN=$cn limit=$limit active=$active_files status=$status_count; ALLOW session=$session_key"
exit 0
