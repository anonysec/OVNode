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

# Performance budget (reconnect storm: 100 phones rejoining at once):
# - marker parsing is bash builtins (no awk per file),
# - ONE awk prefilter over the status file per hook (pools/cids/reals),
# - management is ONE python fork per takeover (auth once, pipelined
#   kills, verify polls), zero forks on the allow path,
# - locks are per-CN: different users never serialize behind each other.
# Remaining forks per allow: flock, logger, ≤1 awk. Takeover adds 1 python.

set -euo pipefail
shopt -s nullglob

# Per-user state lives in one folder per user (see core/openvpn/store.py):
#   users/<cn>/limit     max simultaneous logins (0 = unlimited)
#   users/<cn>/disabled  marker — exists = reject the connection
# Session markers live in sessions/ (one file per live session).
# USERS_DIR/ACTIVE_DIR honor env overrides for hermetic tests; production
# always uses the compiled-in defaults (identical values).
USERS_DIR="${OVNODE_USERS_DIR:-/etc/openvpn/ovnode/users}"
ACTIVE_DIR="${OVNODE_SESSIONS_DIR:-/etc/openvpn/ovnode/sessions}"
# Per-CN lock file (assigned after safe_cn exists): every critical section
# below is CN-scoped (own markers, own usage), so a global lock would
# serialize unrelated users behind a reconnect storm for no reason.
LOCK_FILE=""
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

# mgmt_takeover runs kill commands AND the verify poll over ONE management
# connection (auth once) and prints a machine-readable last line:
#   RESULT VERIFIED — no CLIENT_LIST row left for the CN
#   RESULT TIMEOUT  — rows remain after the 7s budget (caller rejects)
#   RESULT DOWN <err> — transport/auth failure (caller degrades or rejects)
# Exit code mirrors the verdict (0/1/2). Kill replies are logged as
#   KILL OK|FAIL <command>
# Usage: mgmt_takeover "$cn" "client-kill 7 take" "kill 1.2.3.4:5000" ...
mgmt_takeover() {
    local cn="$1"; shift
    python3 - "$MGMT_HOST" "$MGMT_PORT" "$MGMT_PASS_FILE" "$cn" "$@" <<'PYTAKEOVER'
import socket, sys, time
host, port, pass_file, cn = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
cmds = sys.argv[5:]

def out(line):
    sys.stdout.write(line + "\n")

def read_until(s, markers, budget):
    chunks = []
    deadline = time.monotonic() + budget
    while time.monotonic() < deadline:
        try:
            chunk = s.recv(65536)
        except Exception:
            break
        if not chunk:
            break
        chunks.append(chunk.decode(errors="ignore"))
        upper = "".join(chunks).upper()
        if any(m in upper for m in markers):
            break
    return "".join(chunks)

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
    for c in cmds:
        try:
            s.sendall((c.rstrip() + "\n").encode())
            reply = read_until(s, ("SUCCESS", "ERROR"), 2.0)
            ok = "SUCCESS" in reply.upper()
            short = " ".join(reply.split())[:120]
            out("KILL %s %s (%s)" % ("OK" if ok else "FAIL", c, short))
        except Exception as e:
            out("KILL FAIL %s (%s)" % (c, e))
    verified = False
    deadline = time.monotonic() + 7.0
    while time.monotonic() < deadline:
        try:
            s.sendall(b"status 2\n")
            text = read_until(s, ("END",), 3.0)
            rows = [ln for ln in text.splitlines() if ln.startswith("CLIENT_LIST,")]
            # Exact CN match (comma-delimited): a CN containing a comma can
            # never match, failing closed toward TIMEOUT instead of a false
            # VERIFIED.
            if not any(r.split(",")[1:2] == [cn] for r in rows):
                verified = True
                break
        except Exception:
            pass
        time.sleep(0.5)
    try:
        s.sendall(b"quit\n")
    except Exception:
        pass
    s.close()
    out("RESULT " + ("VERIFIED" if verified else "TIMEOUT"))
    sys.exit(0 if verified else 1)
except Exception as e:
    out("RESULT DOWN (%s)" % e)
    sys.exit(2)
PYTAKEOVER
}

# read_marker populates m_created/m_pool/m_ip/m_port from a marker file
# with bash builtins (no awk fork per file).
read_marker() {
    m_created=0; m_pool=""; m_ip=""; m_port=""
    [[ -f $1 ]] || return 0
    local k v
    while IFS='=' read -r k v; do
        case "$k" in
            created) [[ $v =~ ^[0-9]+$ ]] && m_created=$v ;;
            ifconfig_pool_remote_ip) m_pool=$v ;;
            trusted_ip) m_ip=$v ;;
            trusted_port) m_port=$v ;;
        esac
    done < "$1" 2>/dev/null || true
}

# status_has_pool/real: presence probes over the prefiltered arrays.
status_has_pool() {
    local want="$1" x
    for x in ${status_pools[@]+"${status_pools[@]}"}; do
        [[ $x == "$want" ]] && return 0
    done
    return 1
}

status_has_real() {
    local want="$1" x
    for x in ${status_reals[@]+"${status_reals[@]}"}; do
        [[ $x == "$want" ]] && return 0
    done
    return 1
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
if [[ -f $limit_file ]]; then
    # NOTE: read exits nonzero on a newline-less file AFTER assigning what
    # it read — so no `|| raw=` clobber here (it once turned limit=2 into
    # limit=1 and allowed a second device).
    raw=""
    IFS= read -r raw < "$limit_file" 2>/dev/null || true
    raw="${raw//[^0-9]/}"
    [[ -n $raw ]] && limit="$raw"
fi

if [[ "$limit" -eq 0 ]]; then
    log "CN=$cn limit=unlimited; LOCAL_ALLOW"
    exit 0
fi

pool_ip="${ifconfig_pool_remote_ip:-}"
pool_ip_s="$(sanitize "${pool_ip:-noip}")"
trusted_ip_s="$(sanitize "${trusted_ip:-unknown}")"
trusted_port_s="$(sanitize "${trusted_port:-unknown}")"
time_s="${EPOCHSECONDS:-$(date +%s)}"

# Session identity: CN + pool IP (unique per live session, IP-change proof).
# Without a pool IP (rare: hook order edge cases) fall back to the real
# address so two concurrent no-pool sessions cannot share a key.
if [[ -n "$pool_ip" ]]; then
    session_key="${safe_cn}.${pool_ip_s}"
else
    session_key="${safe_cn}.noip.${trusted_ip_s}.${trusted_port_s}"
fi
session_file="${ACTIVE_DIR}/${session_key}"

LOCK_FILE="${ACTIVE_DIR}/.lock.${safe_cn}"
exec 9>"$LOCK_FILE"
flock -x 9

# ── One status prefilter for the whole hook ────────────────────────
# pools/cids/reals of THIS cn + row count. Every presence check below is a
# bash builtin over these arrays — the file is read exactly once.
status_pools=(); status_cids=(); status_reals=(); status_count=0
if [[ -f $STATUS_FILE ]]; then
    while IFS=$'\t' read -r _pool _cid _real; do
        [[ -n "${_pool}${_cid}${_real}" ]] || continue
        status_pools+=("$_pool"); status_cids+=("$_cid"); status_reals+=("$_real")
        status_count=$((status_count + 1))
    done < <(awk -v cn="$cn" '
        BEGIN { FS="\t" }
        $1 == "CLIENT_LIST" && $2 == cn { print $4 "\t" $11 "\t" $3 }
    ' "$STATUS_FILE" 2>/dev/null || true)
fi

# Snapshot of this CN's markers (taken under the per-CN lock, so no sibling
# hook can mutate it mid-run; other CNs never touch these files).
cn_markers=("$ACTIVE_DIR"/${safe_cn}.*)

# ── Reconnect detection (dynamic IP aware) ───────────────────────
# A fresh marker (< grace) is absorbed as "the dropped session" ONLY when
# its (CN, pool IP) is absent from the live status: the corpse was already
# reaped, or a concurrent hook is in flight. A fresh marker that is still
# live in status is a real session — it counts toward the limit below and
# loses via takeover (newest wins), never via silent absorb.
reconnected=0
oldest_marker=""
oldest_time=999999999

for old_marker in ${cn_markers[@]+"${cn_markers[@]}"}; do
    [[ -f $old_marker ]] || continue
    read_marker "$old_marker"
    created_s=$m_created
    age=$(( time_s - created_s ))
    if (( age < RECONNECT_GRACE )); then
        if [[ -n $m_pool ]] && status_has_pool "$m_pool"; then
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
if [[ -f $STATUS_FILE ]]; then
    for marker in ${cn_markers[@]+"${cn_markers[@]}"}; do
        [[ -f $marker ]] || continue
        read_marker "$marker"
        created_s=$m_created
        age=$(( time_s - created_s ))
        # Keep recent markers (within grace) — handled above
        if (( age < RECONNECT_GRACE )); then
            continue
        fi
        if [[ -n $m_pool ]]; then
            if ! status_has_pool "$m_pool"; then
                rm -f "$marker" 2>/dev/null || true
                log "CN=$cn removed_stale_marker=$(basename "$marker") age=${age}s (pool=$m_pool gone)"
            fi
        elif ! status_has_real "${m_ip}:${m_port}"; then
            rm -f "$marker" 2>/dev/null || true
            log "CN=$cn removed_stale_marker=$(basename "$marker") age=${age}s (legacy real-addr)"
        fi
    done
fi

# ── Count active sessions ────────────────────────────────────────
active_files=0
for _m in ${cn_markers[@]+"${cn_markers[@]}"}; do
    [[ -f $_m ]] && active_files=$((active_files + 1))
done
cur="$active_files"
if [[ "$status_count" -gt "$cur" ]]; then cur="$status_count"; fi

if (( cur >= limit )); then
    if [[ "$limit" -eq 1 ]]; then
        # One management session for the whole takeover: auth once, run
        # every kill, then poll the LIVE status until the CN is gone.
        # Exit 0 = verified, 1 = rows remain (reject), 2 = mgmt down.
        takeover_cmds=()
        for _cid in ${status_cids[@]+"${status_cids[@]}"}; do
            [[ ${_cid:-} =~ ^[0-9]+$ ]] && takeover_cmds+=("client-kill $_cid max-login-takeover")
        done
        for marker in ${cn_markers[@]+"${cn_markers[@]}"}; do
            [[ -f $marker && $marker != "$session_file" ]] || continue
            read_marker "$marker"
            [[ -n $m_ip && -n $m_port ]] || continue
            [[ $m_ip =~ ^[0-9a-fA-F.:]+$ && $m_port =~ ^[0-9]+$ ]] || continue
            takeover_cmds+=("kill $m_ip:$m_port")
        done
            log "CN=$cn limit=1 active=$active_files status=$status_count; TAKEOVER (${#takeover_cmds[@]} mgmt cmds, one session)"
            # NOTE: the || guards set -e — a bare failing $() would kill
            # the hook with python's code before rc=$? executes.
            rc=0
            takeover_out="$(mgmt_takeover "$cn" ${takeover_cmds[@]+"${takeover_cmds[@]}"} 2>/dev/null)" || rc=$?
        while IFS= read -r _line; do log "CN=$cn mgmt: ${_line}"; done <<<"$takeover_out"
        if (( rc == 0 )); then
            rm -f "${ACTIVE_DIR}/${safe_cn}."* 2>/dev/null || true
        elif (( rc == 1 )); then
            log "CN=$cn takeover could not verify old session termination; REJECT"
            exit 1
        else
            # Degraded takeover: the corpse cannot be killed right now, but
            # rejecting a legitimate reconnect is worse than a transient
            # double session — ping-restart reaps the dead one, and the
            # marker swap below keeps max-login accounting exact.
            # Strict cases (limit>1, disabled, unknown) still fail closed.
            log "CN=$cn limit=1 active=$active_files status=$status_count; management unavailable; DEGRADE (markers replaced, corpse reaped by ping-restart)"
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
