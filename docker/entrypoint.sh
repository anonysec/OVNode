#!/usr/bin/env bash
# Copyright (c) 2025 anonysec. All rights reserved.
# Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
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

    local main_port="${OPENVPN_PORT:-1194}" proto p
    proto="$(awk '$1 == "proto" {print $2; exit}' "$SERVER_CONF" 2>/dev/null || true)"
    proto="${proto%%-*}"; proto="${proto:-udp}"
    IFS=',' read -ra extra <<< "${OVNODE_EXTRA_PORTS:-}"
    for p in "${extra[@]}"; do
        p="$(echo "$p" | tr -d '[:space:]')"
        [[ "$p" =~ ^[0-9]+$ ]] || continue
        [[ "$p" == "$main_port" ]] && continue
        if ! iptables -t nat -C PREROUTING -p "$proto" --dport "$p" -j REDIRECT --to-ports "$main_port" 2>/dev/null; then
            iptables -t nat -A PREROUTING -p "$proto" --dport "$p" -j REDIRECT --to-ports "$main_port" 2>/dev/null \
                && log "NAT: extra port ${p}/${proto} → ${main_port}" \
                || log "WARNING: could not redirect extra port ${p}"
        fi
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
    # API down with it. Config reloads use SIGHUP (control.py) and don't
    # pass through here.
    local backoff=2
    while :; do
        log "starting OpenVPN (conf: ${SERVER_CONF})"
        set +e
        openvpn --cd "$SERVER_DIR" --config "$SERVER_CONF" --writepid "$PID_FILE"
        rc=$?
        set -e
        log "OpenVPN exited rc=${rc}; restarting in ${backoff}s"
        sleep "$backoff"
        (( backoff < 30 )) && backoff=$((backoff * 2))
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
