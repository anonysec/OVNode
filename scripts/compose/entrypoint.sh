#!/usr/bin/env bash
# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT
#
# OVNode container entrypoint — supervises the two processes a node needs:
#
#   1. the sync agent (main.py) — answers the panel, generates PKI and
#      server.conf on first boot, patches config on /sync/config
#   2. the OpenVPN daemon — started once the agent has produced server.conf,
#      restarted with backoff if it ever crashes
#
# The container exits when the AGENT exits (Docker's restart policy takes it
# from there). OpenVPN crashing does NOT kill the API — it is restarted in
# place so the panel keeps visibility while the node self-heals.
#
# Environment:
#   OVNODE_SKIP_OPENVPN=1   agent only (debugging / running OpenVPN elsewhere)
#   OVNODE_VPN_SUBNET       NAT subnet (default 10.8.0.0/24)

set -euo pipefail

OPENVPN_ROOT="${OVNODE_OPENVPN_ROOT:-/etc/openvpn}"
SERVER_DIR="${OPENVPN_ROOT}/server"
SERVER_CONF="${SERVER_DIR}/server.conf"
PID_FILE="${SERVER_DIR}/ovnode.pid"
VPN_SUBNET="${OVNODE_VPN_SUBNET:-10.8.0.0/24}"

log() { echo "[entrypoint] $*" >&2; }

# Content hash of server.conf for the supervisor watch. sha256 when
# available, mtime fallback (busybox images without coreutils sha256).
conf_hash_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" 2>/dev/null | awk '{print $1}'
    else
        stat -c %Y "$1" 2>/dev/null || echo ""
    fi
}

# ── network prerequisites (all best-effort: fail loud, not fatal) ─────

setup_tun() {
    if [[ ! -c /dev/net/tun ]]; then
        mkdir -p /dev/net
        if mknod /dev/net/tun c 10 200 2>/dev/null; then
            log "created /dev/net/tun"
        else
            log "WARNING: /dev/net/tun unavailable — bind-mount it or add CAP_MKNOD; OpenVPN cannot start without it"
        fi
    fi
    chmod 660 /dev/net/tun 2>/dev/null || true
}

setup_forwarding() {
    if ! sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1; then
        current="$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo '?')"
        if [[ "$current" != "1" ]]; then
            log "WARNING: could not enable net.ipv4.ip_forward (current: ${current}) — set it on the host or via compose sysctls; clients will not route"
        fi
    fi
    if [[ "${OVNODE_ENABLE_IPV6:-0}" == "1" ]]; then
        sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
    fi
}

setup_nat() {
    # MASQUERADE the VPN subnet out of the default-route interface, and
    # REDIRECT any extra published ports onto the primary OpenVPN port
    # (multi-port). Idempotent: -C before -A.
    local uplink
    uplink="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
    if [[ -z "$uplink" ]]; then
        log "WARNING: no default route found — skipping NAT setup"
        return 0
    fi
    if ! iptables -t nat -C POSTROUTING -s "$VPN_SUBNET" -o "$uplink" -j MASQUERADE 2>/dev/null; then
        iptables -t nat -A POSTROUTING -s "$VPN_SUBNET" -o "$uplink" -j MASQUERADE 2>/dev/null \
            && log "NAT: MASQUERADE ${VPN_SUBNET} via ${uplink}" \
            || log "WARNING: could not add MASQUERADE rule (need CAP_NET_ADMIN) — clients will not reach the internet"
    fi
    if [[ "${OVNODE_ENABLE_IPV6:-0}" == "1" ]] && command -v ip6tables >/dev/null 2>&1; then
        v6subnet="${OVNODE_IPV6_PREFIX:-fd42:42:42:42::/64}"
        if ! ip6tables -t nat -C POSTROUTING -s "$v6subnet" -o "$uplink" -j MASQUERADE 2>/dev/null; then
            ip6tables -t nat -A POSTROUTING -s "$v6subnet" -o "$uplink" -j MASQUERADE 2>/dev/null \
                && log "NAT: MASQUERADE ${v6subnet} via ${uplink} (v6)" \
                || log "WARNING: could not add IPv6 MASQUERADE rule — v6 clients may not reach the internet"
        fi
    fi

    local main_port="${OPENVPN_PORT:-1194}" proto p pr
    proto="$(awk '$1 == "proto" {print $2; exit}' "$SERVER_CONF" 2>/dev/null || true)"
    proto="${proto%%-*}"; proto="${proto:-udp}"
    IFS=',' read -ra extra <<< "${OVNODE_EXTRA_PORTS:-}"
    for p in "${extra[@]}"; do
        p="$(echo "$p" | tr -d '[:space:]')"
        [[ "$p" =~ ^[0-9]+$ ]] || continue
        [[ "$p" == "$main_port" ]] && continue
        # Both protocols, like the native installer: a tcp→udp flip must
        # not leave the other family's redirect missing.
        for pr in tcp udp; do
            if ! iptables -t nat -C PREROUTING -p "$pr" --dport "$p" -j REDIRECT --to-ports "$main_port" 2>/dev/null; then
                iptables -t nat -A PREROUTING -p "$pr" --dport "$p" -j REDIRECT --to-ports "$main_port" 2>/dev/null \
                    && log "NAT: extra port ${p}/${pr} → ${main_port}" \
                    || log "WARNING: could not redirect extra port ${p}/${pr}"
            fi
        done
    done
    # Prune a redirect for the non-current proto left by an older single-proto
    # install (proto flip tcp→udp or back). Best-effort: never fatal.
    for pr in tcp udp; do
        [[ "$pr" == "$proto" ]] && continue
        for p in "${extra[@]}"; do
            p="$(echo "$p" | tr -d '[:space:]')"
            [[ "$p" =~ ^[0-9]+$ ]] || continue
            [[ "$p" == "$main_port" ]] && continue
            iptables -t nat -D PREROUTING -p "$pr" --dport "$p" -j REDIRECT --to-ports "$main_port" 2>/dev/null \
                && log "NAT: pruned stale extra port ${p}/${pr}" || true
        done
    done
}

# ── supervision ───────────────────────────────────────────────────────

AGENT_PID=""
OPENVPN_SUPERVISOR_PID=""

shutdown() {
    local code="${1:-0}"
    trap - TERM INT
    log "shutting down..."
    [[ -n "$OPENVPN_SUPERVISOR_PID" ]] && kill "$OPENVPN_SUPERVISOR_PID" 2>/dev/null || true
    [[ -f "$PID_FILE" ]] && kill "$(cat "$PID_FILE" 2>/dev/null)" 2>/dev/null || true
    [[ -n "$AGENT_PID" ]] && kill "$AGENT_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    exit "$code"
}
trap shutdown TERM INT

supervise_openvpn() {
    # Wait for the agent to generate server.conf on first boot.
    local waited=0
    while [[ ! -s "$SERVER_CONF" ]]; do
        sleep 2
        waited=$((waited + 2))
        if (( waited >= 180 )); then
            log "WARNING: server.conf not generated after ${waited}s — is the agent healthy? OpenVPN not started"
            return 0
        fi
    done

    setup_nat

    # Restart-with-backoff loop: a crashing OpenVPN must not take the sync
    # API down with it. The loop also watches server.conf's CONTENT HASH (not
    # mtime — a touch or atime-only change must not bounce tunnels): the
    # panel rewrites it atomically on POST /sync/config, and port/proto
    # changes need a FULL restart (SIGHUP cannot rebind them), so a changed
    # conf kills the child and the loop re-execs it fresh.
    local backoff=2
    local conf_hash=""
    conf_hash="$(conf_hash_of "$SERVER_CONF")"
    while :; do
        log "starting OpenVPN (conf: ${SERVER_CONF})"
        set +e
        openvpn --cd "$SERVER_DIR" --config "$SERVER_CONF" --writepid "$PID_FILE" &
        local vpn_pid=$!
        local changed=0
        while kill -0 "$vpn_pid" 2>/dev/null; do
            sleep 2
            local now_hash=""
            now_hash="$(conf_hash_of "$SERVER_CONF")"
            if [[ -n "$now_hash" && -n "$conf_hash" && "$now_hash" != "$conf_hash" ]]; then
                log "server.conf content changed — restarting OpenVPN (full rebind)"
                conf_hash="$now_hash"
                kill "$vpn_pid" 2>/dev/null || true
                wait "$vpn_pid" 2>/dev/null || true
                setup_nat
                backoff=2
                changed=1
                break
            fi
            conf_hash="$now_hash"
        done
        if [[ "$changed" == "0" ]]; then
            wait "$vpn_pid" 2>/dev/null
            rc=$?
            log "OpenVPN exited rc=${rc}; restarting in ${backoff}s"
            sleep "$backoff"
            (( backoff < 30 )) && backoff=$((backoff * 2))
        fi
        set -e
    done
}

main() {
    setup_tun
    setup_forwarding

    log "starting OVNode agent"
    python /app/main.py &
    AGENT_PID=$!

    if [[ "${OVNODE_SKIP_OPENVPN:-0}" != "1" ]]; then
        supervise_openvpn &
        OPENVPN_SUPERVISOR_PID=$!
    else
        log "OVNODE_SKIP_OPENVPN=1 — agent only"
    fi

    # Container lives and dies with the agent; Docker's restart policy
    # handles resurrection. Propagate the agent's exit code so failures
    # are visible to Docker / the installer status check.
    set +e
    wait "$AGENT_PID"
    rc=$?
    set -e
    log "agent exited rc=${rc}"
    shutdown "$rc"
}

main "$@"
