#!/bin/bash
# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT
#
# ovnode — OVNode agent manager (installed as ovnode/ovn).
# Day-to-day operations for an installed node: status, service control,
# VPN restart, logs, backups, TLS. Install/update/uninstall live in
# install.sh — this script delegates to it.
#
#   ovn                  Interactive numbered menu (needs a terminal)
#   ovn status           Report install state (respects --json)
#   ovn update           Update via install.sh (with backup)
#   ovn uninstall        Remove OVNode (data kept unless --purge)
#

set -Eeuo pipefail

# ── Constants ──────────────────────────────────────────────────────────
VERSION="1.1.5"
APP_DIR="${OVN_APP_DIR:-/opt/ovnode}"
DATA_BASE="/var/lib/ovnode"
OPENVPN_ROOT="/etc/openvpn"
DEFAULT_PORT=2083
SYSTEMD_SERVICE="ovnode.service"
INSTALLER="$APP_DIR/install.sh"
# Installed command names.
BIN_DIR="${OVN_BIN_DIR:-/usr/local/bin}"
CLI_NAME="ovnode"
CLI_ALIAS="ovn"

# Exit codes (documented in --help; stable for automation)
EX_OK=0 EX_ERROR=1 EX_USAGE=2 EX_ALREADY=3 EX_NOTINSTALLED=4

# ── Settings (env defaults OVN_*, overridden by CLI flags) ─────────────
ACTION=""
YES="${OVN_YES:-0}"
PURGE="${OVN_PURGE:-0}"
JSON="${OVN_JSON:-0}"
QUIET="${OVN_QUIET:-0}"
FIX=0
PIN=""
LOGS_ARG=""
AUTO_BACKUP_ACTION="" BACKUP_TIME="" BACKUP_KEEP=""
NODE_NAME="${OVN_NAME:-}"

compose_file() { echo "$DATA_BASE/${NODE_NAME:-ovnode}/docker-compose.yml"; }

# Shared helpers (output, prompts, TLS, menus). APP fallback lets this
# script run straight from a checkout (./manager.sh) as well as installed.
if [[ -f "$APP_DIR/lib/common.sh" ]]; then
    # shellcheck disable=SC1091
    . "$APP_DIR/lib/common.sh"
elif [[ -f "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh" ]]; then
    # shellcheck disable=SC1091
    . "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"
else
    echo -e "\n  Error: lib/common.sh not found (looked in $APP_DIR/lib and ./lib)\n" >&2
    exit 1
fi



# die <message> [exit-code]  — single error path, JSON-aware.

trap 'echo -e "\n  ${RD}Interrupted.${NC}" >&2; exit 130' INT TERM
trap 'warn "Command failed near line $LINENO (running: ${BASH_COMMAND:0:80})"' ERR

# Spinners/prompts only for interactive humans; plain logs otherwise.


# run <label> <cmd...> — required step: spinner on a TTY, plain log lines
# in automation. Fails the install with a clear message on error.

# try_run <label> <cmd...> — best-effort step: warns instead of dying.

# Masked input: one * per character on stderr, backspace works; the value
# goes to stdout and is never echoed as plain text.



# Explicit-yes prompt (default NO) for destructive extras like deleting data.

# ── OS / package manager ───────────────────────────────────────────────
OS_ID="" OS_NAME="" PKG_INSTALL="" PKG_UPDATE=""



has_systemd() { command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; }

# ── Help / args ────────────────────────────────────────────────────────


# ── Validation ─────────────────────────────────────────────────────────

# Splits VPN_PORTS ("1194,443,8443") into VPN_PORT (primary listener) and
# EXTRA_PORTS (comma separated, redirected to the primary).






# ── Toolchain ──────────────────────────────────────────────────────────
UV_BIN=""

# Reproducible dependency install: the lockfile pins exact versions.
# Fall back to a fresh resolve only when the lock cannot be honored.

# ── Backups ────────────────────────────────────────────────────────────

# ── TLS ────────────────────────────────────────────────────────────────




# ── Forwarding / NAT / multi-port redirects ────────────────────────────
# IP forwarding is a host sysctl in BOTH modes (a container usually cannot
# write /proc/sys). The iptables rules live in one idempotent script owned
# by a oneshot systemd unit — native mode only; in Docker the entrypoint
# applies the equivalent rules itself via CAP_NET_ADMIN.



# ── Log rotation ───────────────────────────────────────────────────────
# server.conf uses `log-append openvpn.log`, which grows without bound and
# will eventually fill a small VPS disk (killing OpenVPN with it). The
# agent log rotates itself; the OpenVPN log needs logrotate. Native
# installs SIGHUP the daemon (clean reopen, no teardown); Docker keeps
# copytruncate because the daemon's PID namespace is unreachable from a
# host logrotate postrotate.

# ── OpenVPN scaffolding ────────────────────────────────────────────────


# Mandatory post-flight for Docker mode (twice bitten): the container's
# OpenVPN must own 1194/7505. A native daemon holding those ports on the
# shared host network namespace crash-loops the container's OpenVPN
# (mgmt bind EADDRINUSE), while the agent health check stays green.


# ── Firewall ───────────────────────────────────────────────────────────
# Every VPN port is opened for BOTH protocols: the panel can switch the
# node between udp and tcp at runtime, and the extra-port redirects always
# cover both.

# Mirror of open_firewall_ports for uninstall: remove exactly what an
# install would have opened, using the INSTALLED .env values (flags may
# differ from install time). Best-effort — never fail the uninstall.

# ── Systemd unit ───────────────────────────────────────────────────────


# ── Source / environment ───────────────────────────────────────────────



# Download the versioned release file into $1 (an existing directory).
# The .sha256 sidecar is verified when published; a missing sidecar only
# warns (older releases).



# ── Docker ─────────────────────────────────────────────────────────────



# ── JSON result ────────────────────────────────────────────────────────
# emit_result <ok> <action> [key value]... — values are emitted as strings
# except numbers/booleans, detected by shape. One line, stdout only.


# ── Install ────────────────────────────────────────────────────────────

# ── Update ─────────────────────────────────────────────────────────────

# ── Uninstall ──────────────────────────────────────────────────────────
# Update and uninstall live in install.sh — delegate so there is exactly one
# implementation. Machine flags pass through (stdout JSON contract kept).
run_installer() {
    [[ -e "$APP_DIR" ]] || [[ "$1" == "uninstall" ]] || die "Not installed ($APP_DIR missing)" "$EX_NOTINSTALLED"
    [[ -x "$INSTALLER" ]] || die "Installer missing ($INSTALLER)" "$EX_ERROR"
    exec "$INSTALLER" "$@"
}

delegate_update() {
    local args=()
    [[ "$YES" -eq 1 ]] && args+=(-y)
    [[ "$JSON" -eq 1 ]] && args+=(--json)
    [[ "$QUIET" -eq 1 ]] && args+=(--quiet)
    [[ -n "$PIN" ]] && args+=(--version "$PIN")
    run_installer update "${args[@]}"
}

delegate_uninstall() {
    local args=()
    [[ "$YES" -eq 1 ]] && args+=(-y)
    [[ "$JSON" -eq 1 ]] && args+=(--json)
    [[ "$QUIET" -eq 1 ]] && args+=(--quiet)
    [[ "$PURGE" -eq 1 ]] && args+=(--purge)
    run_installer uninstall "${args[@]}"
}

# ── Status ─────────────────────────────────────────────────────────────
do_status() {
    local installed=false mode="none" node="" port="" tls="none"
    local agent="unknown" health="unknown" openvpn="unknown" agent_version=""

    if [[ -f "$APP_DIR/.env" ]]; then
        installed=true
        local env_get; env_get() { grep -E "^$1=" "$APP_DIR/.env" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"' || true; }
        node="$(env_get NODE_NAME)"; : "${node:=ovnode}"
        port="$(env_get SERVICE_PORT)"; : "${port:=$DEFAULT_PORT}"
        tls="$(env_get TLS_METHOD)"; : "${tls:=selfsigned}"
        mode="native"
        [[ -f "$DATA_BASE/$node/docker-compose.yml" ]] && mode="docker"

        agent_version="$(grep -Eo '"[0-9]+\.[0-9]+\.[0-9]+"' "$APP_DIR/core/version.py" 2>/dev/null | head -1 | tr -d '"' || true)"

        if [[ "$mode" == "docker" ]]; then
            if command -v docker >/dev/null 2>&1 \
                && docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "ovnode-$node"; then
                agent="running"
            else
                agent="stopped"
            fi
            openvpn="in-container"
        else
            if has_systemd; then
                agent="$(systemctl is-active "$SYSTEMD_SERVICE" 2>/dev/null || true)"
                openvpn="$(systemctl is-active openvpn-server@server 2>/dev/null || true)"
            fi
        fi

        local scheme="http"
        [[ "$tls" != "none" ]] && scheme="https"
        if wait_health "${scheme}://127.0.0.1:${port}/sync/health" 2; then
            health="ok"
        else
            health="unreachable"
        fi
    fi

    field "Installed" "$installed"
    if [[ "$installed" == "true" ]]; then
        field "Mode"      "$mode"
        field "Node"      "$node"
        field "Version"   "${agent_version:-unknown}"
        field "Agent"     "$agent"
        field "OpenVPN"   "$openvpn"
        field "API port"  "$port"
        field "TLS"       "$tls"
        field "Health"    "$health"
    fi

    emit_result true status \
        installed "$installed" \
        mode "$mode" \
        node "$node" \
        agent_version "${agent_version:-}" \
        agent "$agent" \
        openvpn "$openvpn" \
        service_port "${port:-0}" \
        tls "$tls" \
        health "$health"

    [[ "$installed" == "true" ]] || exit "$EX_NOTINSTALLED"
}

# ── Interactive setup (humans on a TTY) ────────────────────────────────

# Express install: safe defaults, no further questions. TLS is always on.

# Friendly front door: shown only for a bare interactive invocation.


# ── Terminal command (TUI) ─────────────────────────────────────────────
# install_cli() copies this installer to $BIN_DIR as "ovnode" (+ "ovn"), so a
# bare `ovnode` opens the menu. Every action is also a subcommand for scripts:
# status | start | stop | restart | restart-vpn | logs [N|-f] | backup |
# update | tls | uninstall | menu | help.




is_docker_node() { [[ -f "$(compose_file)" ]]; }

# systemd waits up to TimeoutStopSec for a stuck unit; bound the wait so an
# uninstall/update never looks frozen, then force the unit.
STOP_TIMEOUT="${OVN_STOP_TIMEOUT:-20}"


node_service_action() {  # start|stop|restart
    if is_docker_node; then
        command -v docker >/dev/null 2>&1 || die "Docker not found on this host"
        ( cd "$APP_DIR" && docker compose -f "$(compose_file)" "$1" ) || die "docker compose $1 failed"
    else
        systemctl "$1" "$SYSTEMD_SERVICE" || die "systemctl $1 $SYSTEMD_SERVICE failed"
    fi
    step "Node agent $1: done"
}

restart_vpn() {
    if timeout "$STOP_TIMEOUT" systemctl restart openvpn-server@server 2>/dev/null; then
        step "OpenVPN restarted (systemd)"
        return 0
    fi
    local pidfile pid found=0
    for pidfile in "$OPENVPN_ROOT/server/ovnode.pid" /run/openvpn-server/*.pid; do
        [[ -f "$pidfile" ]] || continue
        pid="$(cat "$pidfile" 2>/dev/null || true)"
        if [[ -n "$pid" ]] && kill -HUP "$pid" 2>/dev/null; then found=1; fi
    done
    if [[ "$found" -eq 0 ]]; then
        for pid in $(pgrep -x openvpn 2>/dev/null || true); do
            kill -HUP "$pid" 2>/dev/null && found=1
        done
    fi
    if [[ "$found" -eq 1 ]]; then
        step "OpenVPN reloaded (SIGHUP)"
    else
        warn "No running OpenVPN process found — it starts with the agent"
    fi
}

do_node_logs() {
    local arg="${1:-100}" name
    name="$(node_name_from_env)"
    if is_docker_node; then
        if [[ "$arg" == "-f" ]]; then docker logs -f --tail 100 "ovnode-$name"; else docker logs --tail "$arg" "ovnode-$name"; fi \
            || warn "Could not read container logs"
    elif [[ "$arg" == "-f" ]]; then
        journalctl -u "$SYSTEMD_SERVICE" -n 100 -f || warn "Could not read logs"
    else
        journalctl -u "$SYSTEMD_SERVICE" -n "$arg" --no-pager || warn "Could not read logs"
    fi
}

do_node_backup() {
    backup_dir "$DATA_BASE" "node"
    backup_dir "$OPENVPN_ROOT/server/pki" "node-pki"
    prune_backups "${BACKUP_KEEP:-14}"
}

# Keep only the newest N tarballs this installer writes (/var/backups).
prune_backups() {
    local keep="${1:-14}" i=0 f
    [[ "$keep" =~ ^[0-9]+$ ]] || keep=14
    shopt -s nullglob
    local files=(/var/backups/node-*.tar.gz /var/backups/node-pki-*.tar.gz)
    shopt -u nullglob
    ((${#files[@]} > keep)) || return 0
    while IFS= read -r f; do
        i=$((i + 1))
        if ((i > keep)); then rm -f "$f"; fi
    done < <(ls -1t "${files[@]}" 2>/dev/null)
    return 0
}

# Host-level daily backup: a systemd timer running `ovnode backup`.
auto_backup_units_write() {
    local time="$1" keep="$2"
    local service="/etc/systemd/system/ovnode-backup.service"
    local timer="/etc/systemd/system/ovnode-backup.timer"
    cat > "$service" << EOF
[Unit]
Description=OVNode automatic backup

[Service]
Type=oneshot
ExecStart=${BIN_DIR}/${CLI_NAME} backup --keep ${keep}
EOF
    cat > "$timer" << EOF
[Unit]
Description=Daily OVNode backup

[Timer]
OnCalendar=*-*-* ${time}:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
}

auto_backup_cli() {
    local action="${1:-status}" service timer time keep
    service="/etc/systemd/system/ovnode-backup.service"
    timer="/etc/systemd/system/ovnode-backup.timer"
    time="${BACKUP_TIME:-03:30}"
    keep="${BACKUP_KEEP:-14}"
    case "$action" in
        on)
            [[ "$time" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] || die "Invalid time '$time' (use HH:MM)" "$EX_USAGE"
            [[ "$keep" =~ ^[0-9]+$ ]] && ((keep >= 1 && keep <= 500)) || die "Invalid --keep '$keep' (1-500)" "$EX_USAGE"
            command -v systemctl >/dev/null 2>&1 || die "systemd not found — the auto-backup timer needs it"
            auto_backup_units_write "$time" "$keep"
            systemctl daemon-reload
            systemctl enable --now ovnode-backup.timer >/dev/null 2>&1 \
                || die "Could not enable the backup timer (systemd available?)"
            step "Auto backup enabled: daily at ${time}, keeping ${keep} tarballs"
            ;;
        off)
            systemctl disable --now ovnode-backup.timer >/dev/null 2>&1 || true
            rm -f "$timer" "$service"
            systemctl daemon-reload >/dev/null 2>&1 || true
            step "Auto backup disabled (host timer removed)"
            ;;
        status|"")
            if [[ -f "$timer" ]]; then
                info "Host timer: enabled ($(systemctl is-active ovnode-backup.timer 2>/dev/null || echo unknown))"
                systemctl list-timers ovnode-backup.timer --no-pager 2>/dev/null | sed -n '2p' || true
            else
                info "Host timer: disabled  (enable: ${CLI_NAME} auto-backup on)"
            fi
            ;;
        *)
            die "Usage: $CLI_NAME auto-backup on [--time HH:MM] [--keep N] | off | status" "$EX_USAGE" ;;
    esac
}



node_tls_menu() {
    local envfile="$APP_DIR/.env"
    [[ -f "$envfile" ]] || die "Not installed ($envfile missing)"
    local method keyfile certfile expiry
    method="$(env_get "$envfile" TLS_METHOD)"; : "${method:=selfsigned}"
    keyfile="$(env_get "$envfile" SSL_KEYFILE)"
    certfile="$(env_get "$envfile" SSL_CERTFILE)"
    expiry="$(openssl x509 -enddate -noout -in "$certfile" 2>/dev/null | cut -d= -f2 || true)"
    line ""
    line "${B}TLS certificate — panel ↔ node API${NC}"
    kv "Mode"    "$method"
    kv "Key file"  "${keyfile:-<none>}"
    kv "Cert file" "${certfile:-<none>}"
    [[ -n "$expiry" ]] && kv "Expires" "$expiry"
    line ""
    line "  1) Self-signed (regenerate)"
    line "  2) Let's Encrypt for a domain"
    line "  3) Let's Encrypt for this IP"
    line "  4) Custom key + cert paths"
    line "  0) Back"
    local c; c="$(ask "Select" "0")"
    case "${c:-0}" in
        1) TLS_METHOD="selfsigned" ;;
        2) TLS_METHOD="letsencrypt"; TLS_DOMAIN="$(ask "Domain" "")"
           [[ -n "$TLS_DOMAIN" ]] || { warn "Domain required"; return 0; } ;;
        3) TLS_METHOD="letsencrypt-ip"; TLS_DOMAIN="$(primary_ip)" ;;
        4) TLS_METHOD="custom"; TLS_KEY="$(ask "Key file" "")"; TLS_CERT="$(ask "Cert file" "")"
           [[ -f "$TLS_KEY" && -f "$TLS_CERT" ]] || { warn "Key/cert files not found"; return 0; } ;;
        0|*) return 0 ;;
    esac
    setup_tls || return 0
    env_set "$envfile" TLS_METHOD "$TLS_METHOD"
    env_set "$envfile" SSL_KEYFILE "$TLS_KEY"
    env_set "$envfile" SSL_CERTFILE "$TLS_CERT"
    step "Certificate updated — restarting the node agent"
    node_service_action restart
}

# Boxed menu when whiptail is already installed; colored menu otherwise.

backup_submenu() {
    while true; do
        line ""
        line "${B}Backup${NC}"
        line "  ${WH}1${NC}) Backup now"
        line "  ${WH}2${NC}) Auto-backup status"
        line "  ${WH}3${NC}) Enable daily auto-backup"
        line "  ${WH}4${NC}) Disable auto-backup"
        line "  ${WH}0${NC}) Back"
        line ""
        local c
        c="$(ask "Select" "0")"
        case "${c:-0}" in
            1) check_root; do_node_backup ;;
            2) auto_backup_cli status ;;
            3) check_root; auto_backup_cli on ;;
            4) check_root; auto_backup_cli off ;;
            0|*) return 0 ;;
        esac
    done
}

manager_menu() {
    while true; do
        line ""
        line "  ${B}ovnode — node manager${NC}  ${GY}v${VERSION}${NC}"
        line "  ${WH}1${NC}) Status"
        line "  ${WH}2${NC}) Update node"
        line "  ${WH}3${NC}) Restart agent"
        line "  ${WH}4${NC}) Restart VPN"
        line "  ${WH}5${NC}) Logs"
        line "  ${WH}6${NC}) Backup"
        line "  ${WH}7${NC}) TLS certificate"
        line "  ${WH}8${NC}) Health check (doctor)"
        line "  ${WH}9${NC}) Roll back update"
        line "  ${WH}10${NC}) Uninstall node"
        line "  ${WH}0${NC}) Exit"
        line ""
        local c
        c="$(ask "Select" "0")"
        case "${c:-0}" in
            1) do_status ;;
            2) delegate_update ;;
            3) check_root; node_service_action restart ;;
            4) check_root; restart_vpn ;;
            5) do_node_logs "${LOGS_ARG:-100}" ;;
            6) backup_submenu ;;
            7) check_root; node_tls_menu ;;
            8) do_doctor ;;
            9) check_root; do_rollback ;;
            10) delegate_uninstall ;;
            0|*) return 0 ;;
        esac
    done
}



# ── Preconditions ──────────────────────────────────────────────────────
check_root() { [[ "$EUID" -eq 0 ]] || die "Must run as root."; }


# ── Health check (doctor) ────────────────────────────────────────────
# Read-only by default; --fix restarts a dead agent.
do_doctor() {
    [[ -d "$APP_DIR" ]] || die "Not installed ($APP_DIR missing)" "$EX_NOTINSTALLED"
    local problems=0
    sep
    line "  ${B}Node health${NC}"
    # 1. Agent service.
    local agent="unknown"
    if is_docker_node; then
        agent="docker"
    elif has_systemd; then
        agent="$(systemctl is-active "$SYSTEMD_SERVICE" 2>/dev/null || echo unknown)"
    fi
    if [[ "$agent" == "active" || "$agent" == "docker" ]]; then
        field "Agent" "$agent"
    else
        field "Agent" "$agent"
        warn "Fix: ovn restart"
        problems=$((problems + 1))
        if [[ "$FIX" -eq 1 ]]; then
            info "Restarting the agent…"
            node_service_action restart && problems=$((problems - 1)) || true
        fi
    fi
    # 2. OpenVPN daemon.
    local ovpn="unknown"
    if is_docker_node; then
        ovpn="in-container"
        field "OpenVPN" "$ovpn"
    elif has_systemd; then
        ovpn="$(systemctl is-active openvpn-server@server 2>/dev/null || echo unknown)"
        if [[ "$ovpn" == "active" ]]; then
            field "OpenVPN" "$ovpn"
        else
            field "OpenVPN" "$ovpn"
            warn "Fix: ovn restart-vpn"
            problems=$((problems + 1))
        fi
    fi
    # 3. Disk.
    local disk
    disk="$(df "$DATA_BASE" 2>/dev/null | awk 'NR==2 {print $5}' | tr -d '%' || echo 0)"
    if (( disk < 80 )); then
        field "Disk" "${disk}% used"
    else
        field "Disk" "${disk}% used"
        warn "Fix: ovn backup --keep 7, then remove old tarballs in /var/backups"
        problems=$((problems + 1))
    fi
    # 4. API answers (values from the installed .env).
    local port tls scheme
    port="$(env_get "$APP_DIR/.env" SERVICE_PORT)"; : "${port:=$DEFAULT_PORT}"
    tls="$(env_get "$APP_DIR/.env" TLS_METHOD)"; : "${tls:=selfsigned}"
    scheme="http"; [[ "$tls" != "none" ]] && scheme="https"
    if wait_health "${scheme}://127.0.0.1:${port}/sync/health" 5; then
        field "API" "ok"
    else
        field "API" "unreachable"
        warn "Fix: ovn logs 50, then ovn restart"
        problems=$((problems + 1))
    fi
    # 5. Server certificate expiry.
    local cert days_left
    cert="$(env_get "$APP_DIR/.env" SSL_CERTFILE)"; : "${cert:=/etc/ssl/self-signed/fullchain.pem}"
    if [[ -f "$cert" ]]; then
        days_left=$(( ($(date -d "$(openssl x509 -enddate -noout -in "$cert" 2>/dev/null | cut -d= -f2)" +%s 2>/dev/null || echo 0) - $(date +%s)) / 86400 ))
        field "Certificate" "expires in ${days_left}d"
        if (( days_left <= 30 )); then
            warn "Fix: ovn tls"
            problems=$((problems + 1))
        fi
    else
        field "Certificate" "not found"
        problems=$((problems + 1))
    fi
    # 6. Backup age.
    local newest age
    newest="$(ls -t /var/backups/node-*.tar.gz 2>/dev/null | head -1 || true)"
    if [[ -n "$newest" ]]; then
        age=$(( ($(date +%s) - $(stat -c %Y "$newest" 2>/dev/null || echo 0)) / 86400 ))
        field "Backup" "${age}d old"
        if (( age > 7 )); then
            warn "Fix: ovn backup"
            problems=$((problems + 1))
        fi
    else
        field "Backup" "none yet"
        warn "Fix: ovn backup"
        problems=$((problems + 1))
    fi
    # 7. Interrupted update transaction.
    local update_interrupted=0
    [[ -f "$DATA_BASE/update-maintenance" ]] && update_interrupted=1
    if [[ "$update_interrupted" -eq 0 && -f "$DATA_BASE/update-state.json" ]]; then
        python3 - "$DATA_BASE/update-state.json" <<'PY' >/dev/null 2>&1 || update_interrupted=1
import json, sys
phase = json.load(open(sys.argv[1])).get("phase")
raise SystemExit(0 if phase in {"committed", "failed_over"} else 1)
PY
    fi
    if [[ "$update_interrupted" -eq 1 ]]; then
        field "Update" "recovery required"
        warn "Fix: ovn recover-update"
        problems=$((problems + 1))
        if [[ "$FIX" -eq 1 ]]; then
            info "Recovering the interrupted update…"
            if run_installer recover-update; then
                problems=$((problems - 1))
            else
                warn "Update recovery needs manual attention"
            fi
        fi
    else
        field "Update" "no interrupted transaction"
    fi
    # 8. Code snapshot usable for explicit rollback.
    local snap
    snap="$(latest_snapshot node 2>/dev/null || true)"
    if [[ -n "$snap" ]]; then
        if tar -tzf "$snap" >/dev/null 2>&1; then
            field "Snapshot" "ok"
        else
            field "Snapshot" "corrupt ($snap)"
            warn "Fix: ovn update (creates a fresh snapshot)"
            problems=$((problems + 1))
        fi
    else
        field "Snapshot" "none yet (created on first update)"
    fi
    # 9. VPN PKI expiry (CA + server cert): a lapsed CA silently kills
    # every client, and the API-TLS check above does not cover it.
    local pki_dir="$OPENVPN_ROOT/server/pki"
    for cert_label in "ca:ca.crt" "server:issued/server.crt"; do
        local label="${cert_label%%:*}" file="$pki_dir/${cert_label#*:}"
        if [[ -f "$file" ]]; then
            local pki_days
            pki_days=$(( ($(date -d "$(openssl x509 -enddate -noout -in "$file" 2>/dev/null | cut -d= -f2)" +%s 2>/dev/null || echo 0) - $(date +%s)) / 86400 ))
            if (( pki_days > 30 )); then
                field "PKI $label" "expires in ${pki_days}d"
            else
                field "PKI $label" "expires in ${pki_days}d — plan renewal"
                warn "VPN $label certificate expires in ${pki_days}d"
                problems=$((problems + 1))
            fi
        fi
    done
    # 10. Stale operation lock (update/recover/uninstall coordination).
    if [[ -d "$DATA_BASE/.operation.lock" ]]; then
        local lock_pid
        lock_pid="$(cat "$DATA_BASE/.operation.lock/pid" 2>/dev/null || true)"
        if [[ "$lock_pid" =~ ^[0-9]+$ ]] && kill -0 "$lock_pid" 2>/dev/null; then
            field "Op lock" "held by process $lock_pid"
        else
            field "Op lock" "stale — safe to clear"
            warn "Fix: ovn doctor --fix"
            problems=$((problems + 1))
            if [[ "$FIX" -eq 1 ]]; then
                rm -rf "$DATA_BASE/.operation.lock" \
                    && field "Op lock" "stale lock cleared" && problems=$((problems - 1)) \
                    || warn "Could not clear the operation lock"
            fi
        fi
    fi
    # 11. Host integration files (unit / NAT / logrotate present).
    if ! is_docker_node && has_systemd; then
        if [[ -f "/etc/systemd/system/$SYSTEMD_SERVICE" ]]; then
            field "Unit" "present"
        else
            field "Unit" "missing"
            warn "Fix: ovn doctor --fix"
            problems=$((problems + 1))
            if [[ "$FIX" -eq 1 ]]; then
                if run_installer repair-unit; then
                    problems=$((problems - 1))
                else
                    warn "Unit repair failed"
                fi
            fi
        fi
    fi
    sep
    if (( problems == 0 )); then
        step "Healthy — nothing to fix"
    else
        warn "$problems problem(s) found"
    fi
    return 0
}

# Roll back to the newest pre-update code snapshot (update failover).
do_rollback() {
    [[ -d "$APP_DIR" ]] || die "Not installed ($APP_DIR missing)" "$EX_NOTINSTALLED"
    # An interrupted transaction owns recovery: rollback must not fight it.
    if [[ -f "$DATA_BASE/update-maintenance" ]]; then
        die "An update transaction is interrupted — run: ovn recover-update" "$EX_ERROR"
    fi
    local snap
    snap="$(latest_snapshot node)"
    [[ -n "$snap" ]] || die "No code snapshot in /var/backups — nothing to roll back to" "$EX_ERROR"
    check_root
    info "Rolling back to: $snap"
    [[ "$YES" -eq 1 ]] || confirm "Restore the pre-update tree and restart?" || exit "$EX_OK"
    local port tls scheme
    port="$(env_get "$APP_DIR/.env" SERVICE_PORT)"; : "${port:=$DEFAULT_PORT}"
    tls="$(env_get "$APP_DIR/.env" TLS_METHOD)"; : "${tls:=selfsigned}"
    scheme="http"; [[ "$tls" != "none" ]] && scheme="https"
    systemctl_bounded stop "$SYSTEMD_SERVICE" >/dev/null 2>&1 || true
    tar -xzf "$snap" -C "$(dirname "$APP_DIR")" >/dev/null 2>&1 \
        || die "Rollback extract failed — snapshot kept at $snap" "$EX_ERROR"
    run "Restarting node agent" systemctl_bounded restart "$SYSTEMD_SERVICE"
    if wait_health "${scheme}://127.0.0.1:${port}/sync/health" 45; then
        step "Rolled back and healthy"
    else
        die "Rollback did not restore health — snapshot at $snap, data backups in /var/backups." "$EX_ERROR"
    fi
}


# ── Help / args ────────────────────────────────────────────────────────
show_help() {
    cat << 'EOF' >&2
  ovnode — OVNode node manager (alias: ovn)

  Usage:
    ovn                         Interactive numbered menu
    ovn status [--json]         Report install state
    ovn update                  Update via install.sh (with backup)
    ovn start|stop|restart      Control the node agent service
    ovn restart-vpn             Restart/reload OpenVPN
    ovn logs [N|-f]             Last N log lines (default 100), or follow
    ovn backup [--keep N]       Save state + PKI backups now
    ovn auto-backup on|off|status   Host timer: daily backup at 03:30
    ovn tls                     Show/replace the cert
    ovn doctor [--fix]          Health check (agent, VPN, disk, cert, backups)
    ovn rollback                Restore the newest pre-update code snapshot
    ovn recover-update          Recover an interrupted update transaction
    ovn uninstall [--purge]     Remove OVNode (data kept unless --purge)
    ovn help                    This help

  Flags (every flag has an OVN_* env equivalent; CLI wins):
    --yes | -y          Never prompt, accept defaults    [OVN_YES=1]
    --json | -j         Machine output on stdout         [OVN_JSON=1]
    --quiet | -q        Suppress progress logs           [OVN_QUIET=1]
    --purge             With uninstall: remove data too  [OVN_PURGE=1]
    --keep N            backup: keep newest N tarballs
    -v | --version      update: install this release instead
    --fix               doctor: apply safe automatic fixes
    --help | -h         This help

  Update and uninstall are implemented in install.sh — this script
  delegates to $APP_DIR/install.sh so there is exactly one copy.
EOF
    exit "$EX_OK"
}

parse_args() {
    local need2='[[ $# -ge 2 ]] || die "$1 needs a value" "$EX_USAGE"'
    while [[ $# -gt 0 ]]; do
        case "$1" in
            status)       ACTION="status"; shift ;;
            update)       ACTION="update"; shift ;;
            uninstall|--uninstall) ACTION="uninstall"; shift ;;
            help|--help|-h) show_help ;;
            start)        ACTION="start"; shift ;;
            stop)         ACTION="stop"; shift ;;
            restart)      ACTION="restart"; shift ;;
            restart-vpn)  ACTION="restart-vpn"; shift ;;
            backup)       ACTION="backup"; shift ;;
            auto-backup)  ACTION="auto-backup"; shift
                          if [[ $# -ge 1 && "$1" != -* ]]; then AUTO_BACKUP_ACTION="$1"; shift; fi ;;
            --keep)       eval "$need2"; BACKUP_KEEP="$2"; shift 2 ;;
            tls)          ACTION="tls"; shift ;;
            doctor)       ACTION="doctor"; shift ;;
            rollback)     ACTION="rollback"; shift ;;
            recover-update) ACTION="recover-update"; shift ;;
            logs)         ACTION="logs"
                          if [[ $# -ge 2 && ( "$2" == "-f" || "$2" =~ ^[0-9]+$ ) ]]; then
                              LOGS_ARG="$2"; shift 2
                          else
                              shift
                          fi ;;
            --yes|-y)     YES=1; shift ;;
            --purge)      PURGE=1; shift ;;
            --json|-j)    JSON=1; YES=1; shift ;;
            --fix)        FIX=1; shift ;;
            -v|--version) eval "$need2"; PIN="$2"; shift 2 ;;
            *)            die "Unknown option: $1 (ovn help for usage)" "$EX_USAGE" ;;
        esac
    done
}

# ── Main ───────────────────────────────────────────────────────────────
main() {
    parse_args "$@"
    if [[ -z "$ACTION" ]]; then
        if is_tty; then
            manager_menu
            exit "$EX_OK"
        fi
        die "No terminal — run 'ovn help' for the command list." "$EX_USAGE"
    fi
    case "$ACTION" in
        status)    do_status; exit "$EX_OK" ;;
        update)    delegate_update; exit "$EX_OK" ;;
        start|stop|restart) check_root; node_service_action "$ACTION"; exit "$EX_OK" ;;
        restart-vpn) check_root; restart_vpn; exit "$EX_OK" ;;
        logs) do_node_logs "$LOGS_ARG"; exit "$EX_OK" ;;
        backup) check_root; do_node_backup; exit "$EX_OK" ;;
        auto-backup) check_root; auto_backup_cli "$AUTO_BACKUP_ACTION"; exit "$EX_OK" ;;
        tls) check_root; node_tls_menu; exit "$EX_OK" ;;
        doctor) do_doctor; exit "$EX_OK" ;;
        rollback) do_rollback; exit "$EX_OK" ;;
        recover-update) run_installer recover-update; exit "$EX_OK" ;;
        uninstall) delegate_uninstall; exit "$EX_OK" ;;
    esac
}

main "$@"
