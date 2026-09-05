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
#   Verification reads the LIVE management status (not the 5s-cadence status
#   file): a kill that succeeded is visible immediately, so a legitimate
#   reconnect is never rejected because of a stale file row.
# - max_logins=N>1: allow up to N sessions, reject N+1.
# - max_logins=0: unlimited.
# - limit=1 with the management socket down: degrade (replace markers, let
#   ping-restart reap the corpse) instead of rejecting a legit reconnect.
#   Strict cases (limit>1, disabled, unknown) still fail closed.
#
# Reconnection handling:
# - Grace period absorbs a fresh marker ONLY when its (CN, pool IP) is absent
#   from the live status: a dropped session already reaped, or a concurrent
#   hook. A fresh marker that is still live in status counts toward the
#   limit and goes through takeover (newest wins).
# - Stale cleanup removes markers whose (CN, pool IP) is absent from the
#   status file (status-version 3, tab-separated).

set -euo pipefail

# Per-user state lives in one folder per user (see core/openvpn/store.py):
#   users/<cn>/limit     max simultaneous logins (0 = unlimited)
#   users/<cn>/disabled  marker — exists = reject the connection
# Session markers live in sessions/ (one file per live session).
# USERS_DIR/ACTIVE_DIR honor env overrides for hermetic tests; production
# always uses the compiled-in defaults (identical values).
USERS_DIR="${OVNODE_USERS_DIR:-/etc/openvpn/ovnode/users}"
ACTIVE_DIR="${OVNODE_SESSIONS_DIR:-/etc/openvpn/ovnode/sessions}"
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

# mgmt_query sends one management command and PRINTS the raw reply.
# Exit 0 = transport ok (reply received), non-zero = socket/auth failure.
# Reads until an END/SUCCESS/ERROR terminator or a 5s deadline so a
# multi-hundred-line `status` dump is never truncated mid-row.
mgmt_query() {
    local cmd="$1"
    python3 - "$MGMT_HOST" "$MGMT_PORT" "$cmd" "$MGMT_PASS_FILE" <<'PYQUERY'
import socket, sys, time
host, port, cmd, pass_file = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
out = []
try:
    s = socket.create_connection((host, port), timeout=2)
    s.settimeout(2)
    try:
        banner = s.recv(2048).decode(errors="ignore")
    except Exception:
        banner = ""
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
    deadline = time.monotonic() + 5.0
    chunks = []
    while time.monotonic() < deadline:
        try:
            chunk = s.recv(65536)
        except Exception:
            break
        if not chunk:
            break
        chunks.append(chunk.decode(errors="ignore"))
        text = "".join(chunks)
        lines = text.splitlines()
        if any(ln.strip() in ("END", "SUCCESS") or ln.startswith("SUCCESS") or ln.startswith("ERROR") for ln in lines):
            break
    try:
        s.sendall(b"quit\n")
    except Exception:
        pass
    s.close()
    sys.stdout.write("".join(chunks))
except Exception as e:
    sys.stderr.write("mgmt_query failed: %s\n" % e)
    sys.exit(1)
PYQUERY
}

# Kill this CN's other sessions. Targets the management Client ID from the
# status file (column 11, status-version 3) — dynamic-IP safe.
#
# ALL CIDs for the CN are killed, including same-pool-IP rows: during this
# hook the new session cannot be in CLIENT_LIST yet (OpenVPN adds it only
# after client-connect succeeds), so every listed row is a corpse — even
# when the pool IP was recycled from ipp.txt. Skipping same-pool rows used
# to leave exactly that corpse alive and fail the verify below.
kill_existing_sessions() {
    local target_cn="$1"
    local current_file="$2"

    if [[ -f "$STATUS_FILE" ]]; then
        while IFS=$'\t' read -r pool cid; do
            if [[ "${cid:-}" =~ ^[0-9]+$ ]]; then
                if mgmt_query "client-kill $cid max-login-takeover" 2>/dev/null | grep -qi "^SUCCESS"; then
                    log "CN=$target_cn takeover client-kill cid=$cid pool=${pool:-?} OK"
                else
                    log "CN=$target_cn takeover client-kill cid=$cid pool=${pool:-?} no-success (already gone?)"
                fi
            fi
        done < <(awk -v cn="$target_cn" '
            BEGIN { FS="\t" }
            $1 == "CLIENT_LIST" && $2 == cn { print $4 "\t" $11 }
        ' "$STATUS_FILE" 2>/dev/null || true)
    fi

    # Fallback for sessions not yet in the status file: kill by marker pool IP
    # is impossible via management, so fall back to the recorded real address.
    # The marker being written for THIS connection is skipped; every other
    # marker for the CN is a corpse (including same-pool rows from pool-IP
    # recycling — the new session is never in CLIENT_LIST during its own
    # connect hook, so CID kills above already covered the listed ones).
    while IFS= read -r marker; do
        [[ -f "$marker" ]] || continue
        [[ "$marker" == "$current_file" ]] && continue
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
# A fresh marker (< grace) is absorbed as "the dropped session" ONLY when
# its (CN, pool IP) is absent from the live status: the corpse was already
# reaped, or a concurrent hook is in flight. A fresh marker that is still
# live in status is a real session — it counts toward the limit below and
# loses via takeover (newest wins), never via silent absorb.
reconnected=0
oldest_marker=""
oldest_time=999999999

for old_marker in "$ACTIVE_DIR"/${safe_cn}.*; do
    [[ -f "$old_marker" ]] || continue
    created_s="$(awk -F= '$1 == "created" {print $2}' "$old_marker" 2>/dev/null || echo 0)"
    [[ "$created_s" =~ ^[0-9]+$ ]] || created_s=0
    age=$(( time_s - created_s ))
    if (( age < RECONNECT_GRACE )); then
        m_pool="$(awk -F= '$1 == "ifconfig_pool_remote_ip" {print $2}' "$old_marker" 2>/dev/null || true)"
        if [[ -n "$m_pool" ]] && [[ -f "$STATUS_FILE" ]] && awk -v cn="$cn" -v pool="$m_pool" '
            BEGIN { FS="\t"; found=0 }
            $1 == "CLIENT_LIST" && $2 == cn && $4 == pool { found=1 }
            END { exit(found ? 0 : 1) }
        ' "$STATUS_FILE" 2>/dev/null; then
            # Still live — not a dropped session; leave it for counting.
            continue
        fi
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
        if ! mgmt_available; then
            # Degraded takeover: the corpse cannot be killed right now, but
            # rejecting a legitimate reconnect is worse than a transient
            # double session — ping-restart reaps the dead one, and the
            # marker swap below keeps max-login accounting exact.
            # Strict cases (limit>1, disabled, unknown) still fail closed.
            log "CN=$cn limit=1 active=$active_files status=$status_count; management unavailable; DEGRADE (markers replaced, corpse reaped by ping-restart)"
            rm -f "${ACTIVE_DIR}/${safe_cn}."* 2>/dev/null || true
        else
            log "CN=$cn limit=1 active=$active_files status=$status_count; TAKEOVER"
            kill_existing_sessions "$cn" "$session_file"
            # Verify against the LIVE management status, not the status
            # file: a successful kill disappears immediately, while the
            # file lags up to 5s. The old 0.3s-sleep + file re-read
            # rejected legitimate reconnects on every dynamic-IP roam.
            verified=0
            for _ in $(seq 1 14); do
                mgmt_out="$(mgmt_query "status 2" 2>/dev/null || true)"
                if [[ -n "$mgmt_out" ]] && ! grep -qF "CLIENT_LIST,${cn}," <<<"$mgmt_out"; then
                    verified=1
                    break
                fi
                sleep 0.5
            done
            if [[ "$verified" -ne 1 ]]; then
                log "CN=$cn takeover could not verify old session termination; REJECT"
                exit 1
            fi
            rm -f "${ACTIVE_DIR}/${safe_cn}."* 2>/dev/null || true
        fi
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
