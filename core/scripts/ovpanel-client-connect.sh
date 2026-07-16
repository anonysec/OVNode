#!/usr/bin/env bash
# OVManager local max-login enforcement for OpenVPN client-connect.
#
# Local-only policy for one-node-per-user operation:
# - max_logins=1: local takeover. A new device disconnects only the old
#   same-CN session(s), then allows the new session.
# - max_logins=N>1: allow up to N local sessions, reject N+1.
# - max_logins=0: unlimited.
#
# Important: do not use OpenVPN management `kill <common-name>` for takeover.
# That command can kill every matching CN, including the connection currently
# passing through client-connect. We instead kill old sessions by Client ID or
# by their Real Address from the status file/marker registry.

set -euo pipefail

LIMITS_DIR="/etc/openvpn/limits"
ACTIVE_DIR="/etc/openvpn/ovpanel-active"
LOCK_FILE="${ACTIVE_DIR}/.lock"
STATUS_FILE="${OVPANEL_STATUS_FILE:-/var/log/openvpn-status.log}"
MGMT_HOST="${OVPANEL_MGMT_HOST:-127.0.0.1}"
MGMT_PORT="${OVPANEL_MGMT_PORT:-7505}"
DEFAULT_LIMIT=1
LOG_TAG="ovpanel-mlogin"

cn="${common_name:-${1:-}}"

log() { logger -t "$LOG_TAG" "$*" 2>/dev/null || echo "$LOG_TAG: $*" >&2; }
sanitize() { printf '%s' "$1" | sed 's/[^A-Za-z0-9_.-]/_/g'; }

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
    local killed=0

    # Prefer client-kill by Client ID from status-version 3. If Client ID is
    # missing, fall back to killing the exact Real Address (IP:port). Never kill
    # by common-name because it can catch the new in-flight client-connect.
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
            killed=$((killed + 1))
        done < <(awk -v cn="$target_cn" '
            BEGIN { FS="\t" }
            $1 == "CLIENT_LIST" && $2 == cn { print $3 "\t" $11 }
        ' "$STATUS_FILE" 2>/dev/null || true)
    fi

    # If status has not refreshed or is unavailable, markers still contain the
    # old trusted_ip/trusted_port. Kill those exact remotes as a best effort.
    while IFS= read -r marker; do
        [[ -f "$marker" ]] || continue
        m_ip="$(awk -F= '$1 == "trusted_ip" {print $2}' "$marker" 2>/dev/null || true)"
        m_port="$(awk -F= '$1 == "trusted_port" {print $2}' "$marker" 2>/dev/null || true)"
        [[ -n "$m_ip" && -n "$m_port" ]] || continue
        marker_real="${m_ip}:${m_port}"
        [[ "$marker_real" == "$current_real" ]] && continue
        mgmt_send "kill $marker_real"
        log "CN=$target_cn takeover kill marker_real=$marker_real marker=$(basename "$marker")"
        killed=$((killed + 1))
    done < <(find "$ACTIVE_DIR" -type f -name "${safe_cn}.*" 2>/dev/null || true)

    return 0
}

if [[ -z "$cn" ]]; then
    log "no common_name provided; allowing"
    exit 0
fi

safe_cn="$(sanitize "$cn")"
mkdir -p "$LIMITS_DIR" "$ACTIVE_DIR"
chmod 755 "$ACTIVE_DIR" 2>/dev/null || true

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

# Remove very old crash leftovers.
find "$ACTIVE_DIR" -type f -name "${safe_cn}.*" -mmin +1440 -delete 2>/dev/null || true

# Reconcile active markers with OpenVPN status. This prevents stale files from
# blocking reconnects after network/app drops. For max_logins=1 we intentionally
# keep markers until the takeover decision so fast reconnects are handled as
# takeover rather than accidental temporary duplicates.
status_count=0
if [[ -f "$STATUS_FILE" ]]; then
    status_count="$(awk -v cn="$cn" '
        BEGIN { FS="\t" }
        $1 == "CLIENT_LIST" && $2 == cn { c++ }
        END { print c+0 }
    ' "$STATUS_FILE" 2>/dev/null || echo 0)"

    if [[ "$limit" -ne 1 ]]; then
        now_s="$(date +%s)"
        while IFS= read -r marker; do
            [[ -f "$marker" ]] || continue
            created_s="$(awk -F= '$1 == "created" {print $2}' "$marker" 2>/dev/null || echo 0)"
            [[ "$created_s" =~ ^[0-9]+$ ]] || created_s=0
            # Keep recent markers for race protection while status refresh catches up.
            if (( now_s - created_s < 60 )); then
                continue
            fi
            m_ip="$(awk -F= '$1 == "trusted_ip" {print $2}' "$marker" 2>/dev/null || true)"
            m_port="$(awk -F= '$1 == "trusted_port" {print $2}' "$marker" 2>/dev/null || true)"
            if ! awk -v cn="$cn" -v ip="$m_ip" -v port="$m_port" '
                BEGIN { FS="\t"; found=0 }
                $1 == "CLIENT_LIST" && $2 == cn {
                    split($3, a, ":"); p=a[length(a)]; sub(":" p "$", "", $3); if ($3 == ip && p == port) found=1
                }
                END { exit(found ? 0 : 1) }
            ' "$STATUS_FILE" 2>/dev/null; then
                rm -f "$marker" 2>/dev/null || true
                log "CN=$cn removed_stale_marker=$(basename "$marker")"
            fi
        done < <(find "$ACTIVE_DIR" -type f -name "${safe_cn}.*" 2>/dev/null)
    fi
fi

active_files="$(find "$ACTIVE_DIR" -type f -name "${safe_cn}.*" 2>/dev/null | wc -l | tr -d ' ')"
cur="$active_files"
if [[ "$status_count" -gt "$cur" ]]; then cur="$status_count"; fi

if (( cur >= limit )); then
    if [[ "$limit" -eq 1 ]]; then
        log "CN=$cn limit=1 active_files=$active_files status=$status_count; LOCAL_TAKEOVER kill_old_by_id_allow_new"
        kill_existing_sessions "$cn" "$current_real"
        rm -f "${ACTIVE_DIR}/${safe_cn}."* 2>/dev/null || true
        active_files=0
        status_count=0
        cur=0
        # Brief pause lets old client-disconnect hooks start before we write
        # the new marker. Those hooks clean only their exact old IP:port.
        sleep 1
    else
        log "CN=$cn limit=$limit active_files=$active_files status=$status_count; LOCAL_REJECT max_login_reached"
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

log "CN=$cn limit=$limit active_files=$active_files status=$status_count; LOCAL_ALLOW session=$session_key"
exit 0
