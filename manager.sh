#!/bin/bash
# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT
#
# ovnode — OVNode agent manager (installed as ovnode/ovn).
# Day-to-day operations for an installed node: status, service control,
# VPN restart, logs, backups, TLS. Install/update/uninstall live in
# install.sh — this script delegates to it. Run `ovn help` for the list.

set -Eeuo pipefail

# ── Constants ──────────────────────────────────────────────────────────
VERSION="1.0.0"
APP_DIR="${OVN_APP_DIR:-/opt/ovnode}"
DATA_BASE="/var/lib/ovnode"
OPENVPN_ROOT="/etc/openvpn"
DEFAULT_PORT=2083
SYSTEMD_SERVICE="ovnode.service"
INSTALLER="$APP_DIR/install.sh"
BIN_DIR="${OVN_BIN_DIR:-/usr/local/bin}"
CLI_NAME="ovnode"
CLI_ALIAS="ovn"
# OVN_COMPLETION_DIR override exists for hermetic tests, like OVN_APP_DIR.
COMPLETION_DIR="${OVN_COMPLETION_DIR:-/etc/bash_completion.d}"

# Exit codes (documented in --help; stable for automation)
EX_OK=0 EX_ERROR=1 EX_USAGE=2 EX_ALREADY=3 EX_NOTINSTALLED=4

# ── Settings (env defaults OVN_*, overridden by CLI flags) ─────────────
ACTION=""
YES="${OVN_YES:-0}"
PURGE="${OVN_PURGE:-0}"
QUIET="${OVN_QUIET:-0}"
FIX=0
SHOW_ALL=0
PIN=""
LOGS_ARG=""
AUTO_BACKUP_ACTION="" BACKUP_TIME="" BACKUP_KEEP=""
RESTORE_NAME=""
NODE_NAME="${OVN_NAME:-}"

# Shared helpers (output, prompts, TLS, menus), all defined in
# scripts/lib/{common,render}.sh and never copied here.
#
# The copy BESIDE this script wins: sibling files are by definition the same
# version as each other. The installed copy is the fallback for a script run
# from outside its tree.
#
# Preferring the installed copy fails in the case that actually happens — a
# newer manager.sh against an older installed lib calls helpers that lib has
# never heard of and dies with "<name>: command not found".
_SELF_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
for _lib in common.sh render.sh; do
    if [[ -f "$_SELF_DIR/scripts/lib/$_lib" ]]; then
        _libdir="$_SELF_DIR/scripts/lib"
    elif [[ -f "$APP_DIR/scripts/lib/$_lib" ]]; then
        _libdir="$APP_DIR/scripts/lib"
    else
        echo -e "\n  Error: scripts/lib/$_lib not found (looked in $_SELF_DIR/scripts/lib and $APP_DIR/scripts/lib)\n" >&2
        exit 1
    fi
    # shellcheck disable=SC1091
    . "$_libdir/$_lib"
done
unset _lib _libdir

trap 'echo -e "\n  ${RD}Interrupted.${NC}" >&2; exit 130' INT TERM
trap 'render_warn "Command failed near line $LINENO (running: ${BASH_COMMAND:0:80})"' ERR

# ── OS / package manager ───────────────────────────────────────────────
OS_ID="" OS_NAME="" PKG_INSTALL="" PKG_UPDATE=""

# ── Toolchain ──────────────────────────────────────────────────────────
UV_BIN=""

# ── Update / uninstall ─────────────────────────────────────────────────
# Both are implemented in install.sh and delegated, so there is one copy.
run_installer() {
    [[ -e "$APP_DIR" ]] || [[ "$1" == "uninstall" ]] || die "Not installed ($APP_DIR missing)" "$EX_NOTINSTALLED"
    [[ -x "$INSTALLER" ]] || die "Installer missing ($INSTALLER)" "$EX_ERROR"
    exec "$INSTALLER" "$@"
}

delegate_update() {
    local args=()
    [[ "$YES" -eq 1 ]] && args+=(-y)
    [[ "$QUIET" -eq 1 ]] && args+=(--quiet)
    [[ -n "$PIN" ]] && args+=(--version "$PIN")
    run_installer update "${args[@]}"
}

delegate_uninstall() {
    local args=()
    [[ "$YES" -eq 1 ]] && args+=(-y)
    [[ "$QUIET" -eq 1 ]] && args+=(--quiet)
    [[ "$PURGE" -eq 1 ]] && args+=(--purge)
    run_installer uninstall "${args[@]}"
}

# ── Status ─────────────────────────────────────────────────────────────
do_status() {
    local installed=false mode="none" node="" port="" tls="none"
    local agent="unknown" health="unknown" openvpn="unknown" agent_version=""

    if [[ -f "$APP_DIR/.env" ]]; then
        # Readable, not merely present: swallowing the permission error left a
        # healthy node reporting "Agent inactive / Health unreachable / Version
        # unknown" and exiting 0.
        [[ -r "$APP_DIR/.env" ]] || die "Cannot read $APP_DIR/.env — run with sudo." "$EX_ERROR"
        installed=true
        node="$(env_get "$APP_DIR/.env" NODE_NAME)"; : "${node:=ovnode}"
        port="$(env_get "$APP_DIR/.env" SERVICE_PORT)"; : "${port:=$DEFAULT_PORT}"
        tls="$(env_get "$APP_DIR/.env" TLS_METHOD)"; : "${tls:=selfsigned}"
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

    if [[ "$installed" == "true" ]]; then
        render_kv "Agent"     "$agent"
        render_kv "Health"    "$health"
        render_kv "Version"   "${agent_version:-unknown}"
        render_kv "OpenVPN"   "$openvpn"
        if [[ "$SHOW_ALL" -eq 1 ]]; then
            render_kv "Node"      "$node"
            render_kv "Mode"      "$mode"
            render_kv "API port"  "$port"
            render_kv "TLS"       "$tls"
            # The two rows a task-ordered success card offloads here. Labels copied
            # from install.sh's shared summary card so the card and --all cannot drift.
            render_kv "Data"        "$DATA_BASE/$node"
            render_kv "OpenVPN cfg" "$OPENVPN_ROOT/server"
        fi
    else
        render_kv "Installed" "no"
    fi

    [[ "$installed" == "true" ]] || exit "$EX_NOTINSTALLED"
}

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
    render_ok "Node agent $1: done"
}

restart_vpn() {
    if timeout "$STOP_TIMEOUT" systemctl restart openvpn-server@server 2>/dev/null; then
        render_ok "OpenVPN restarted (systemd)"
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
        render_ok "OpenVPN reloaded (SIGHUP)"
    else
        render_warn "No running OpenVPN process found — it starts with the agent"
    fi
}

do_node_logs() {
    local arg="${1:-100}" name
    name="$(node_name_from_env)"
    if is_docker_node; then
        if [[ "$arg" == "-f" ]]; then docker logs -f --tail 100 "ovnode-$name"; else docker logs --tail "$arg" "ovnode-$name"; fi \
            || render_warn "Could not read container logs"
    elif [[ "$arg" == "-f" ]]; then
        journalctl -u "$SYSTEMD_SERVICE" -n 100 -f || render_warn "Could not read logs"
    else
        journalctl -u "$SYSTEMD_SERVICE" -n "$arg" --no-pager || render_warn "Could not read logs"
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

# ── Restore ────────────────────────────────────────────────────────────
# What `ovn backup` saves is what `ovn restore` puts back: $DATA_BASE (node
# state) and the OpenVPN PKI, one tarball each. Code snapshots
# (node-*-code-*) are a different thing and are never listed here —
# `ovn rollback` owns those.

data_backup_files() {  # every restorable tarball, one path per line
    shopt -s nullglob
    local files=(/var/backups/node-*.tar.gz)
    shopt -u nullglob
    local f
    for f in "${files[@]}"; do
        case "$(basename "$f")" in
            *-code-*) continue ;;
            *) printf '%s\n' "$f" ;;
        esac
    done
}

list_data_backups() {
    local files=() f
    while IFS= read -r f; do
        [[ -n "$f" ]] && files+=("$f")
    done < <(data_backup_files)
    if (( ${#files[@]} == 0 )); then
        render_line "No data backups in /var/backups — create one with: ${CLI_ALIAS} backup"
        return 0
    fi
    render_line ""
    render_line "${B}Data backups${NC} in /var/backups"
    for f in "${files[@]}"; do
        printf '  %-44s %s  %s\n' "$(basename "$f")" \
            "$(date -r "$f" '+%Y-%m-%d %H:%M')" "$(du -h "$f" 2>/dev/null | cut -f1)" >&2
    done
    render_line ""
    render_line "  Restore one with: ${CLI_ALIAS} restore <name>"
}

# Where an archive is unpacked. Its name decides, so the PKI backup cannot
# land on the node state by a wrong guess.
restore_target_dir() {
    case "$(basename "$1")" in
        node-pki-*) printf '%s' "$(dirname "$OPENVPN_ROOT/server/pki")" ;;
        *)          printf '%s' "$(dirname "$DATA_BASE")" ;;
    esac
}

# Restore one data backup over the current state. Never unattended: the
# confirmation defaults to NO, and the current state is copied to a fresh
# backup first, so a restore that goes wrong is undone by restoring that copy.
do_restore() {
    local name="$1"
    if [[ -z "$name" ]]; then
        list_data_backups
        return 0
    fi
    check_root
    case "$name" in
        */*|.*) die "Invalid backup name: $name" "$EX_USAGE" ;;
    esac
    local src="/var/backups/$name"
    [[ -f "$src" ]] || die "No such backup: $name — '${CLI_ALIAS} restore' lists them" "$EX_USAGE"
    tar -tzf "$src" >/dev/null 2>&1 || die "Not a readable backup archive: $src" "$EX_ERROR"

    local port tls scheme
    port="$(env_get "$APP_DIR/.env" SERVICE_PORT)"; : "${port:=$DEFAULT_PORT}"
    tls="$(env_get "$APP_DIR/.env" TLS_METHOD)"; : "${tls:=selfsigned}"
    scheme="http"; [[ "$tls" != "none" ]] && scheme="https"

    render_line "Restoring: $name"
    confirm "Replace the current node data with this backup?" n || die "Cancelled."

    # Safety copy first, through the same helper `ovn backup` uses.
    local before after f safety=()
    before="$(data_backup_files)"
    backup_dir "$DATA_BASE" "node-pre-restore"
    backup_dir "$OPENVPN_ROOT/server/pki" "node-pki-pre-restore"
    after="$(data_backup_files)"
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        if ! grep -qxF "$f" <<< "$before"; then safety+=("$f"); fi
    done <<< "$after"
    (( ${#safety[@]} )) || die "Could not back up the current state — refusing to restore without a safety copy" "$EX_ERROR"
    for f in "${safety[@]}"; do render_line "Safety copy: $(basename "$f")"; done

    # Point of no return: nothing may write while the tree is replaced.
    if is_docker_node; then
        node_service_action stop
    else
        systemctl_bounded stop "$SYSTEMD_SERVICE" >/dev/null 2>&1 || true
        systemctl_bounded stop openvpn-server@server >/dev/null 2>&1 || true
    fi
    tar -xzf "$src" -C "$(restore_target_dir "$src")" \
        || die "Restore failed — $name was not fully unpacked; the safety copies above hold the previous state" "$EX_ERROR"
    node_service_action restart
    if ! is_docker_node; then restart_vpn; fi

    render_kv "Restored" "$name"
    for f in "${safety[@]}"; do render_kv "Safety copy" "$(basename "$f")"; done
    if wait_health "${scheme}://127.0.0.1:${port}/sync/health" 45; then
        render_ok "Restore finished and the node is healthy"
    else
        die "Restore finished but the node is not answering health — check: ${CLI_ALIAS} logs 50" "$EX_ERROR"
    fi
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
            render_ok "Auto backup enabled: daily at ${time}, keeping ${keep} tarballs"
            ;;
        off)
            systemctl disable --now ovnode-backup.timer >/dev/null 2>&1 || true
            rm -f "$timer" "$service"
            systemctl daemon-reload >/dev/null 2>&1 || true
            render_ok "Auto backup disabled (host timer removed)"
            ;;
        status|"")
            if [[ -f "$timer" ]]; then
                render_line "Host timer: enabled ($(systemctl is-active ovnode-backup.timer 2>/dev/null || echo unknown))"
                systemctl list-timers ovnode-backup.timer --no-pager 2>/dev/null | sed -n '2p' || true
            else
                render_line "Host timer: disabled  (enable: ${CLI_NAME} auto-backup on)"
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
    render_line ""
    render_line "${B}TLS certificate — panel ↔ node API${NC}"
    render_kv "Mode"    "$method"
    render_kv "Key file"  "${keyfile:-<none>}"
    render_kv "Cert file" "${certfile:-<none>}"
    [[ -n "$expiry" ]] && render_kv "Expires" "$expiry"
    render_line ""
    render_line "  1) Self-signed (regenerate)"
    render_line "  2) Let's Encrypt for a domain"
    render_line "  3) Let's Encrypt for this IP"
    render_line "  4) Custom key + cert paths"
    render_line "  0) Back"
    local c; c="$(ask "Select" "0")"
    case "${c:-0}" in
        1) TLS_METHOD="selfsigned"; TLS_REGENERATE=1 ;;
        2) TLS_METHOD="letsencrypt"; TLS_DOMAIN="$(ask "Domain" "")"
           [[ -n "$TLS_DOMAIN" ]] || { render_warn "Domain required"; return 0; } ;;
        3) TLS_METHOD="letsencrypt-ip"; TLS_DOMAIN="$(primary_ip)" ;;
        4) TLS_METHOD="custom"; TLS_KEY="$(ask "Key file" "")"; TLS_CERT="$(ask "Cert file" "")"
           [[ -f "$TLS_KEY" && -f "$TLS_CERT" ]] || { render_warn "Key/cert files not found"; return 0; } ;;
        0|*) return 0 ;;
    esac
    setup_tls || return 0
    env_set "$envfile" TLS_METHOD "$TLS_METHOD"
    env_set "$envfile" SSL_KEYFILE "$TLS_KEY"
    env_set "$envfile" SSL_CERTFILE "$TLS_CERT"
    render_ok "Certificate updated — restarting the node agent"
    node_service_action restart
}

backup_submenu() {
    while true; do
        render_line ""
        render_line "${B}Backup${NC}"
        render_line "  ${WH}1${NC}) Backup now"
        render_line "  ${WH}2${NC}) Restore from backup"
        render_line "  ${WH}3${NC}) Auto-backup status"
        render_line "  ${WH}4${NC}) Enable daily auto-backup"
        render_line "  ${WH}5${NC}) Disable auto-backup"
        render_line "  ${WH}0${NC}) Back"
        render_line ""
        local c
        c="$(ask "Select" "0")"
        case "${c:-0}" in
            1) check_root; do_node_backup ;;
            2) list_data_backups; do_restore "$(ask "Restore which backup" "")" ;;
            3) auto_backup_cli status ;;
            4) check_root; auto_backup_cli on ;;
            5) check_root; auto_backup_cli off ;;
            0|*) return 0 ;;
        esac
    done
}

manager_menu() {
    while true; do
        # Clear between menus, but never when output is piped.
        if is_tty; then command clear >/dev/null 2>&1 || true; fi
        render_line ""
        render_line "  ${B}ovnode — node manager${NC}  ${GY}v${VERSION}${NC}"
        render_line "  ${WH}1${NC}) Status"
        render_line "  ${WH}2${NC}) Update node"
        render_line "  ${WH}3${NC}) Restart agent"
        render_line "  ${WH}4${NC}) Restart VPN"
        render_line "  ${WH}5${NC}) Logs"
        render_line "  ${WH}6${NC}) Backup"
        render_line "  ${WH}7${NC}) TLS certificate"
        render_line "  ${WH}8${NC}) Health check (doctor)"
        render_line "  ${WH}9${NC}) Roll back update"
        render_line "  ${WH}10${NC}) Uninstall node"
        render_line "  ${WH}0${NC}) Exit"
        render_line ""
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

# ── Health check (doctor) ────────────────────────────────────────────
# Read-only by default; --fix restarts a dead agent.
do_doctor() {
    [[ -d "$APP_DIR" ]] || die "Not installed ($APP_DIR missing)" "$EX_NOTINSTALLED"
    # Up front, so the report is not half-printed before the error: step 4 below
    # reads .env, and everything before it would look like a result.
    if [[ -f "$APP_DIR/.env" && ! -r "$APP_DIR/.env" ]]; then
        die "Cannot read $APP_DIR/.env — run with sudo." "$EX_ERROR"
    fi
    local problems=0
    render_rule
    render_line "  ${B}Node health${NC}"
    # 1. Agent service.
    local agent="unknown"
    if is_docker_node; then
        agent="docker"
    elif has_systemd; then
        agent="$(systemctl is-active "$SYSTEMD_SERVICE" 2>/dev/null || echo unknown)"
    fi
    if [[ "$agent" == "active" || "$agent" == "docker" ]]; then
        render_kv "Agent" "$agent"
    else
        render_kv "Agent" "$agent"
        render_warn "Fix: ovn restart"
        problems=$((problems + 1))
        if [[ "$FIX" -eq 1 ]]; then
            render_line "Restarting the agent…"
            node_service_action restart && problems=$((problems - 1)) || true
        fi
    fi
    # 2. OpenVPN daemon.
    local ovpn="unknown"
    if is_docker_node; then
        ovpn="in-container"
        render_kv "OpenVPN" "$ovpn"
    elif has_systemd; then
        ovpn="$(systemctl is-active openvpn-server@server 2>/dev/null || echo unknown)"
        if [[ "$ovpn" == "active" ]]; then
            render_kv "OpenVPN" "$ovpn"
        else
            render_kv "OpenVPN" "$ovpn"
            render_warn "Fix: ovn restart-vpn"
            problems=$((problems + 1))
        fi
    fi
    # 3. Disk.
    local disk
    disk="$(df "$DATA_BASE" 2>/dev/null | awk 'NR==2 {print $5}' | tr -d '%' || echo 0)"
    if (( disk < 80 )); then
        render_kv "Disk" "${disk}% used"
    else
        render_kv "Disk" "${disk}% used"
        render_warn "Fix: ovn backup --keep 7, then remove old tarballs in /var/backups"
        problems=$((problems + 1))
    fi
    # 4. API answers (values from the installed .env).
    local port tls scheme
    port="$(env_get "$APP_DIR/.env" SERVICE_PORT)"; : "${port:=$DEFAULT_PORT}"
    tls="$(env_get "$APP_DIR/.env" TLS_METHOD)"; : "${tls:=selfsigned}"
    scheme="http"; [[ "$tls" != "none" ]] && scheme="https"
    if wait_health "${scheme}://127.0.0.1:${port}/sync/health" 5; then
        render_kv "API" "ok"
    else
        render_kv "API" "unreachable"
        render_warn "Fix: ovn logs 50, then ovn restart"
        problems=$((problems + 1))
    fi
    # 5. Server certificate expiry.
    local cert days_left
    cert="$(env_get "$APP_DIR/.env" SSL_CERTFILE)"; : "${cert:=/etc/ssl/self-signed/fullchain.pem}"
    if [[ -f "$cert" ]]; then
        days_left=$(( ($(date -d "$(openssl x509 -enddate -noout -in "$cert" 2>/dev/null | cut -d= -f2)" +%s 2>/dev/null || echo 0) - $(date +%s)) / 86400 ))
        render_kv "Certificate" "expires in ${days_left}d"
        if (( days_left <= 30 )); then
            render_warn "Fix: ovn tls"
            problems=$((problems + 1))
        fi
    else
        render_kv "Certificate" "not found"
        problems=$((problems + 1))
    fi
    # 6. Backup age.
    local newest age
    newest="$(ls -t /var/backups/node-*.tar.gz 2>/dev/null | head -1 || true)"
    if [[ -n "$newest" ]]; then
        age=$(( ($(date +%s) - $(stat -c %Y "$newest" 2>/dev/null || echo 0)) / 86400 ))
        render_kv "Backup" "${age}d old"
        if (( age > 7 )); then
            render_warn "Fix: ovn backup"
            problems=$((problems + 1))
        fi
    else
        render_kv "Backup" "none yet"
        render_warn "Fix: ovn backup"
        problems=$((problems + 1))
    fi
    # 7. Interrupted update transaction.
    local update_interrupted=0 node_dir="$DATA_BASE/$(node_name_from_env)"
    [[ -f "$node_dir/update-maintenance" ]] && update_interrupted=1
    if [[ "$update_interrupted" -eq 0 && -f "$DATA_BASE/update-state.json" ]]; then
        python3 - "$DATA_BASE/update-state.json" <<'PY' >/dev/null 2>&1 || update_interrupted=1
import json, sys
phase = json.load(open(sys.argv[1])).get("phase")
raise SystemExit(0 if phase in {"committed", "failed_over"} else 1)
PY
    fi
    if [[ "$update_interrupted" -eq 1 ]]; then
        render_kv "Update" "recovery required"
        render_warn "Fix: ovn recover-update"
        problems=$((problems + 1))
        if [[ "$FIX" -eq 1 ]]; then
            render_line "Recovering the interrupted update…"
            if run_installer recover-update; then
                problems=$((problems - 1))
            else
                render_warn "Update recovery needs manual attention"
            fi
        fi
    else
        render_kv "Update" "no interrupted transaction"
    fi
    # 8. Code snapshot usable for explicit rollback.
    local snap
    snap="$(latest_snapshot node 2>/dev/null || true)"
    if [[ -n "$snap" ]]; then
        if tar -tzf "$snap" >/dev/null 2>&1; then
            render_kv "Snapshot" "ok"
        else
            render_kv "Snapshot" "corrupt ($snap)"
            render_warn "Fix: ovn update (creates a fresh snapshot)"
            problems=$((problems + 1))
        fi
    else
        render_kv "Snapshot" "none yet (created on first update)"
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
                render_kv "PKI $label" "expires in ${pki_days}d"
            else
                render_kv "PKI $label" "expires in ${pki_days}d — plan renewal"
                render_warn "VPN $label certificate expires in ${pki_days}d"
                problems=$((problems + 1))
            fi
        fi
    done
    # 10. Stale operation lock (update/recover/uninstall coordination).
    if [[ -d "$DATA_BASE/.operation.lock" ]]; then
        local lock_pid
        lock_pid="$(cat "$DATA_BASE/.operation.lock/pid" 2>/dev/null || true)"
        if [[ "$lock_pid" =~ ^[0-9]+$ ]] && kill -0 "$lock_pid" 2>/dev/null; then
            render_kv "Op lock" "held by process $lock_pid"
        else
            render_kv "Op lock" "stale — safe to clear"
            render_warn "Fix: ovn doctor --fix"
            problems=$((problems + 1))
            if [[ "$FIX" -eq 1 ]]; then
                rm -rf "$DATA_BASE/.operation.lock" \
                    && render_kv "Op lock" "stale lock cleared" && problems=$((problems - 1)) \
                    || render_warn "Could not clear the operation lock"
            fi
        fi
    fi
    # 11. Host integration files (unit / NAT / logrotate present).
    if ! is_docker_node && has_systemd; then
        if [[ -f "/etc/systemd/system/$SYSTEMD_SERVICE" ]]; then
            render_kv "Unit" "present"
        else
            render_kv "Unit" "missing"
            render_warn "Fix: ovn doctor --fix"
            problems=$((problems + 1))
            if [[ "$FIX" -eq 1 ]]; then
                if run_installer repair-unit; then
                    problems=$((problems - 1))
                else
                    render_warn "Unit repair failed"
                fi
            fi
        fi
    fi
    render_rule
    if (( problems == 0 )); then
        render_ok "Healthy — nothing to fix"
    else
        render_warn "$problems problem(s) found"
    fi
    return 0
}

# Roll back to the newest pre-update code snapshot (update failover).
do_rollback() {
    [[ -d "$APP_DIR" ]] || die "Not installed ($APP_DIR missing)" "$EX_NOTINSTALLED"
    # An interrupted transaction owns recovery: rollback must not fight it.
    if [[ -f "$DATA_BASE/$(node_name_from_env)/update-maintenance" ]]; then
        die "An update transaction is interrupted — run: ovn recover-update" "$EX_ERROR"
    fi
    local snap
    snap="$(latest_snapshot node)"
    [[ -n "$snap" ]] || die "No code snapshot in /var/backups — nothing to roll back to" "$EX_ERROR"
    check_root
    render_line "Rolling back to: $snap"
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
        render_ok "Rolled back and healthy"
    else
        die "Rollback did not restore health — snapshot at $snap, data backups in /var/backups." "$EX_ERROR"
    fi
}

# Node registration values, re-readable at any time — the installer shows them
# once on the Ready card, and this is how they come back after --quiet or a
# closed terminal. Read from the same .env the agent loads, so they cannot drift.
do_credentials() {
    # Installed-check first, so the root gate stays about the secret.
    [[ -f "$APP_DIR/.env" ]] || die "OVNode is not installed." "$EX_NOTINSTALLED"
    check_root

    local node port tls key scheme tls_flag host bundle
    node="$(env_get "$APP_DIR/.env" NODE_NAME)"
    [[ -n "$node" ]] || node="ovnode"
    port="$(env_get "$APP_DIR/.env" SERVICE_PORT)"
    [[ -n "$port" ]] || port="$DEFAULT_PORT"
    tls="$(env_get "$APP_DIR/.env" TLS_METHOD)"
    [[ -n "$tls" ]] || tls="selfsigned"
    key="$(env_get "$APP_DIR/.env" API_KEY)"
    [[ -n "$key" ]] || die "No API key found in $APP_DIR/.env" "$EX_ERROR"

    scheme="http"
    if [[ "$tls" != "none" ]]; then scheme="https"; fi
    tls_flag=0
    if [[ "$tls" != "none" ]]; then tls_flag=1; fi
    host="$(primary_ip)"
    # Same shape as the installer's Ready card, or the panel cannot register it.
    bundle="ovnode://${node}@${host}:${port}?key=${key}&tls=${tls_flag}"

    render_kv "Node"    "$node"
    render_kv "Service" "${scheme}://${host}:${port}"
    render_kv "API key" "$key"
    render_kv "Bundle"  "$bundle"
}

# ── Completion ─────────────────────────────────────────────────────────
# ~20 subcommands is more than anyone remembers, so Tab beats reading --help.
generate_completion() {
    cat <<'EOF'
_ovn_completions() {
    local cur
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    local cmds="status credentials update start stop restart restart-vpn logs backup restore auto-backup tls doctor rollback recover-update uninstall completion help"
    local flags="--yes -y --help -h --quiet -q --purge --keep -v --version --fix -a --all"
    if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "$flags" -- "$cur") )
    else
        COMPREPLY=( $(compgen -W "$cmds" -- "$cur") )
    fi
    return 0
}
EOF
    echo "complete -F _ovn_completions ${CLI_ALIAS}"
    echo "complete -F _ovn_completions ${CLI_NAME}"
}

# Not gated on EUID: what matters is whether the file can be written, and saying
# so beats a generic "must run as root" when it is really a permission problem.
do_completion() {
    local file="$COMPLETION_DIR/ovn"
    mkdir -p "$COMPLETION_DIR" 2>/dev/null \
        || die "Could not create $COMPLETION_DIR — run as root." "$EX_ERROR"
    generate_completion > "$file" 2>/dev/null \
        || die "Could not write $file — run as root." "$EX_ERROR"
    chmod 644 "$file" 2>/dev/null || true
    render_ok "Bash completion installed to $file"
    render_line "Activate it in this session:  source $file"
    render_line "New terminals load it automatically."
}

# ── Help / args ────────────────────────────────────────────────────────
show_help() {
    cat << 'EOF' >&2
  ovnode — OVNode node manager (alias: ovn)

  Usage:
    ovn                         Interactive numbered menu
    ovn status                  Agent, health, version and VPN state
    ovn status --all            Also show node, mode, port and TLS
    ovn credentials             Node name, API key and bundle for the panel
    ovn update                  Update via install.sh (with backup)
    ovn start|stop|restart      Control the node agent service
    ovn restart-vpn             Restart/reload OpenVPN
    ovn logs [N|-f]             Last N log lines (default 100), or follow
    ovn backup [--keep N]       Save state + PKI backups now
    ovn auto-backup on|off|status   Host timer: daily backup at 03:30
    ovn restore [name]          List data backups, or restore one by name
    ovn tls                     Show/replace the cert
    ovn doctor [--fix]          Health check (agent, VPN, disk, cert, backups)
    ovn rollback                Restore the newest pre-update code snapshot
    ovn recover-update          Recover an interrupted update transaction
    ovn completion              Install bash completion for ovn
    ovn uninstall [--purge]     Remove OVNode (data kept unless --purge)
    ovn help                    This help

  Flags (an OVN_* variable, where shown, sets the same thing; CLI wins):
    --yes | -y          Never prompt, accept defaults    [OVN_YES=1]
    --quiet | -q        Suppress progress logs           [OVN_QUIET=1]
    --purge             With uninstall: remove data too  [OVN_PURGE=1]
    --keep N            backup: keep newest N tarballs  (flag only)
    -v | --version      update: install this release instead  (flag only)
    --fix               doctor: apply safe automatic fixes
    -a, --all            status: include node, mode, port and TLS
    --help | -h         This help

  The installer's own version is reported by: ovnode/install.sh version-script

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
            credentials)  ACTION="credentials"; shift ;;
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
            restore)      ACTION="restore"; shift
                          if [[ $# -ge 1 && "$1" != -* ]]; then RESTORE_NAME="$1"; shift; fi ;;
            tls)          ACTION="tls"; shift ;;
            doctor)       ACTION="doctor"; shift ;;
            rollback)     ACTION="rollback"; shift ;;
            recover-update) ACTION="recover-update"; shift ;;
            completion)   ACTION="completion"; shift ;;
            logs)         ACTION="logs"
                          if [[ $# -ge 2 && ( "$2" == "-f" || "$2" =~ ^[0-9]+$ ) ]]; then
                              LOGS_ARG="$2"; shift 2
                          else
                              shift
                          fi ;;
            --yes|-y)     YES=1; shift ;;
            --purge)      PURGE=1; shift ;;
            --fix)        FIX=1; shift ;;
            -a|--all)     SHOW_ALL=1; shift ;;
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
        credentials) do_credentials; exit "$EX_OK" ;;
        update)    delegate_update; exit "$EX_OK" ;;
        start|stop|restart) check_root; node_service_action "$ACTION"; exit "$EX_OK" ;;
        restart-vpn) check_root; restart_vpn; exit "$EX_OK" ;;
        logs) do_node_logs "$LOGS_ARG"; exit "$EX_OK" ;;
        backup) check_root; do_node_backup; exit "$EX_OK" ;;
        restore) do_restore "$RESTORE_NAME"; exit "$EX_OK" ;;
        auto-backup) check_root; auto_backup_cli "$AUTO_BACKUP_ACTION"; exit "$EX_OK" ;;
        tls) check_root; node_tls_menu; exit "$EX_OK" ;;
        doctor) do_doctor; exit "$EX_OK" ;;
        rollback) do_rollback; exit "$EX_OK" ;;
        recover-update) run_installer recover-update; exit "$EX_OK" ;;
        completion) do_completion; exit "$EX_OK" ;;
        uninstall) delegate_uninstall; exit "$EX_OK" ;;
    esac
}

main "$@"
