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
VERSION="1.0.43"
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
# tls's subcommand. Empty means the bare form: report the certificate, then
# list what can replace it, without asking anything.
TLS_ACTION="" TLS_DOMAIN="" TLS_KEY="" TLS_CERT="" TLS_REGENERATE=0
# auth's action. Empty means the bare form: show the credential, then list what
# can be done about it.
AUTH_ACTION=""
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
for _lib in common.sh render.sh doctor.sh; do
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

    # A previous update that died mid-flight leaves the install needing recovery
    # and refuses to start. `update` is the command an operator reaches for when
    # something looks wrong, so it is the one that should fix it — which is what
    # lets `recover-update` leave the short help while keeping the same code
    # path underneath.
    if [[ -f "$DATA_BASE/update-state.json" ]] && node_update_needs_recovery; then
        render_note "Finishing an interrupted update first…"
        run_installer recover-update "${args[@]}" || {
            render_fail "update" "the interrupted update could not be recovered — nothing was changed"
            return "$EX_ERROR"
        }
    fi
    run_installer update "${args[@]}"
}

# True when the recorded phase is one that means "an update stopped here".
# Read with grep rather than python3: this runs on the failure path, where the
# least can be assumed about the box, and a missing python3 is exactly the kind
# of state that gets an install stuck.
node_update_needs_recovery() {
    grep -q '"phase": *"recovery_required"\|"phase": *"rollback_failed"\|"phase": *"candidate_failed"' \
        "$DATA_BASE/update-state.json" 2>/dev/null
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
        [[ -f "$(node_data_dir)/docker-compose.yml" ]] && mode="docker"

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
            render_kv "Data"        "$(node_data_dir)"
            render_kv "OpenVPN cfg" "$OPENVPN_ROOT/server"
        fi
    else
        # A failure line, not a row. "Installed: no" reads as one more fact on a
        # working node, and the exit code is what a script checks anyway — this
        # is for the person, and a person should not have to notice a missing
        # subject in a table of values.
        render_fail "not installed" "$APP_DIR/.env missing"
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

# Autostart is a systemd-only concept: a compose container is restarted by the
# daemon whenever docker starts, so there is nothing to enable and pretending
# otherwise would leave the operator believing a box comes back after a reboot
# when it does not.
node_autostart() {  # enable|disable
    is_docker_node && die "A container node starts with docker — nothing to enable." "$EX_USAGE"
    systemctl "$1" "$SYSTEMD_SERVICE" || die "systemctl $1 $SYSTEMD_SERVICE failed"
    case "$1" in
        enable)  render_ok "node agent starts on boot" ;;
        disable) render_ok "node agent will not start on boot" ;;
    esac
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
    render_line ""
    if (( ${#files[@]} == 0 )); then
        render_line "${B}Data backups${NC} in /var/backups"
        render_line "    none — create one with: ${CLI_ALIAS} backup"
        return 0
    fi
    render_line "${B}Data backups${NC} in /var/backups"
    # render_kv_w at a width computed from the filenames. This listing hand-
    # rolled its own 2-space indent and its own 44-wide column, which put it out
    # of line with every render_kv row on every other screen; and at the shared
    # fixed width of 14, a 40-character filename dropped its date a column right
    # of every other row's. The column has to fit the labels actually present.
    local name when size width=$RENDER_LABEL_W
    for f in "${files[@]}"; do
        name="$(basename "$f")"
        (( ${#name} > width )) && width=${#name}
    done
    for f in "${files[@]}"; do
        name="$(basename "$f")"
        when="$(date -r "$f" '+%Y-%m-%d %H:%M')"
        size="$(du -h "$f" 2>/dev/null | cut -f1)"
        render_kv_w "$width" "$name" "$when  $size"
    done
    render_blank
    render_line "    restore one with: ${CLI_ALIAS} restore <name>"
}

# Where an archive is unpacked. Its name decides, so the PKI backup cannot
# land on the node state by a wrong guess.
restore_target_dir() {
    case "$(basename "$1")" in
        node-pki-*) printf '%s' "$(dirname "$OPENVPN_ROOT/server/pki")" ;;
        *)          printf '%s' "$(dirname "$DATA_BASE")" ;;
    esac
}

# Restore one data backup over the current state. Never automatic: the
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

    render_kv "Restoring" "$name"
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
    for f in "${safety[@]}"; do render_kv "Safety copy" "$(basename "$f")"; done

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
            # render_kv, not a "Label: value" line built by hand, and the last
            # row says the command that changes it — using the current spelling.
            # The old text told you to run `auto-backup on`, a name that is
            # retired and no longer in the short help.
            if [[ -f "$timer" ]]; then
                render_kv "Auto backup" "enabled"
                render_kv "Timer" "$(systemctl is-active ovnode-backup.timer 2>/dev/null || echo unknown)"
                render_kv "Next" "$(systemctl list-timers ovnode-backup.timer --no-pager 2>/dev/null | sed -n '2p' | awk '{print $1, $2, $3}')"
            else
                render_kv "Auto backup" "disabled"
                render_kv "Enable" "${CLI_ALIAS} backup schedule on"
            fi
            ;;
        *)
            die "Usage: $CLI_NAME backup schedule on [--time HH:MM] [--keep N] | off | status" "$EX_USAGE" ;;
    esac
}

node_tls() {
    local envfile="$APP_DIR/.env"
    local method="selfsigned" keyfile="" certfile="" expiry=""
    # Bare, it reports and lists. The numbered menu it used to open is the one
    # thing a script cannot answer, and the two questions it asked — what am I
    # running, how do I change it — are both answered here without a prompt.
    #
    # The option list is the point of this command, so it is printed whatever
    # the read does. An operator who came to find out what `ovn tls` can do must
    # not be met with an error from the thing it was about to offer.
    if [[ -z "$TLS_ACTION" ]]; then
        if [[ -f "$envfile" ]]; then
            method="$(env_get "$envfile" TLS_METHOD)"; : "${method:=selfsigned}"
            keyfile="$(env_get "$envfile" SSL_KEYFILE)"
            certfile="$(env_get "$envfile" SSL_CERTFILE)"
            expiry="$(openssl x509 -enddate -noout -in "$certfile" 2>/dev/null | cut -d= -f2 || true)"
        else
            render_warn "not installed — the paths below are where the installer would put them"
        fi
        render_line ""
        render_line "${B}TLS certificate — panel ↔ node API${NC}"
        render_kv "Mode"      "$method"
        render_kv "Key file"  "${keyfile:-<none>}"
        render_kv "Cert file" "${certfile:-<none>}"
        [[ -n "$expiry" ]] && render_kv "Expires" "$expiry"
        render_line ""
        render_kv "Selfsigned" "ovn tls selfsigned"
        render_kv "Encrypt"    "ovn tls le IP|DOMAIN"
        render_kv "Custom"     "ovn tls custom CERT KEY"
        render_line "  the paths come from .env — this writes the certificate, never the file"
        return 0
    fi

    # Past the listing, a missing install is fatal — there is nothing to
    # operate on and quietly returning success would be worse than an error.
    [[ -f "$envfile" ]] || die "Not installed ($envfile missing)" "$EX_NOTINSTALLED"

    case "$TLS_ACTION" in
        selfsigned)
            # Explicit regeneration, always. An intact pair is kept by the
            # generator, and the panel pinned this certificate to the node, so
            # replacing it silently is how a working node stops validating.
            TLS_METHOD="selfsigned"; TLS_REGENERATE=1 ;;
        le)
            [[ -n "$TLS_DOMAIN" ]] || die "ovn tls le needs an ip or a domain" "$EX_USAGE"
            # One free-text field for both kinds: a bare IP gets the short-lived
            # IP certificate and a name gets the ordinary one, decided here
            # rather than by asking the operator to know which they want.
            if is_ip_literal "$TLS_DOMAIN"; then TLS_METHOD="letsencrypt-ip"
            else TLS_METHOD="letsencrypt"; fi ;;
        custom)
            [[ -n "$TLS_KEY" && -n "$TLS_CERT" ]] || die "ovn tls custom needs CERT and KEY" "$EX_USAGE"
            [[ -f "$TLS_KEY" && -f "$TLS_CERT" ]] || die "Key or certificate file not found: $TLS_KEY $TLS_CERT" "$EX_ERROR"
            TLS_METHOD="custom" ;;
        *) die "ovn tls: unknown option '$TLS_ACTION'  (see: ovn tls)" "$EX_USAGE" ;;
    esac
    setup_tls || return "$EX_ERROR"
    node_tls_install_to_declared "$TLS_KEY" "$TLS_CERT"
    render_ok "Certificate updated — restarting the node agent"
    node_service_action restart
}

# Put the issued pair where the agent will look for it.
#
# .env declared the paths at install and is not edited since: it is a
# declaration, and the job here is to fulfil it rather than to record where the
# files happened to land. setup_tls writes wherever the chosen method wants,
# which is not necessarily either of those.
node_tls_install_to_declared() {
    local want_key="$1" want_cert="$2" envfile="$APP_DIR/.env"
    local decl_key decl_cert
    decl_key="$(env_get "$envfile" SSL_KEYFILE)"
    decl_cert="$(env_get "$envfile" SSL_CERTFILE)"
    [[ -n "$decl_key" && -n "$decl_cert" ]] || return 0   # TLS is off; nothing to serve
    [[ "$decl_key" == "$want_key" ]] && return 0
    mkdir -p "$(dirname "$decl_key")" "$(dirname "$decl_cert")" \
        || die "Could not create the certificate directory" "$EX_ERROR"
    cp -f "$want_key" "$decl_key" || die "Could not install the key at $decl_key" "$EX_ERROR"
    cp -f "$want_cert" "$decl_cert" || die "Could not install the certificate at $decl_cert" "$EX_ERROR"
    secure_tls_files "$decl_key" "$decl_cert"
}




# Roll back to the newest pre-update code snapshot (update failover).
do_rollback() {
    [[ -d "$APP_DIR" ]] || die "Not installed ($APP_DIR missing)" "$EX_NOTINSTALLED"
    # An interrupted transaction owns recovery: rollback must not fight it.
    if [[ -f "$(node_data_dir)/update-maintenance" ]]; then
        die "An update transaction is interrupted — run: ovn recover-update" "$EX_ERROR"
    fi
    local snap
    snap="$(latest_snapshot node)"
    [[ -n "$snap" ]] || die "No code snapshot in /var/backups — nothing to roll back to" "$EX_ERROR"
    check_root
    render_kv "Snapshot" "$snap"
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
# `ovn auth`. The node has one credential and two states — before the panel
# has it, and after — and the right action differs between them, so the state
# comes first and the action follows from it. Same shape as the panel's
# `ovm auth`, so the rule is learned once for both tools.
do_auth() {
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

    case "$AUTH_ACTION" in
        key)
            render_kv "Node"     "$node"
            render_kv "Service"  "${scheme}://${host}:${port}"
            # Bold, and one line of prose under it, because this is the one value
            # on screen that gets copied out of it. Printed at the same weight as
            # every other row it was read past, and the key is not recoverable
            # from the panel — losing it means re-enrolling the node.
            render_key "API key" "$key"
            render_url "Bundle"  "$bundle"
            render_line "  paste the bundle into the panel to register this node"
            return 0 ;;
        rotate) auth_rotate; return $? ;;
    esac

    render_kv "Owner"     "$node"
    render_kv "Service"   "${scheme}://${host}:${port}"
    render_kv "API key"   "set — see: ovn auth key"
    render_blank
    render_kv "Key"    "ovn auth key — print the key and the registration bundle"
    render_kv "Rotate" "ovn auth rotate — generate a new key"
}

# Generate a replacement key, print it, and tell the operator the one line to
# change. It does not edit .env.
#
# .env is written once by the installer and belongs to the operator afterwards —
# the same rule that retired env_set. A command that quietly rewrote the file
# would reopen exactly the split-brain that rule exists to prevent, and the
# operator would have no way to see that the file their backups carry had
# changed under them. So the key is generated, shown, and left for them.
auth_rotate() {
    local envfile="$APP_DIR/.env" new
    # Same generator and length the installer uses, so a rotated key is
    # indistinguishable from an installed one — anything that validates length
    # or shape keeps working.
    new="$(openssl rand -hex 32)" || die "Could not generate a key" "$EX_ERROR"
    [[ ${#new} -ge 16 ]] || die "Could not generate a key" "$EX_ERROR"

    render_ok "new API key"
    render_key "API key" "$new"
    render_line "  change one line in $envfile:"
    render_line "    API_KEY=$new"
    render_line "  then: ovn restart, and give the panel the same key"
    render_line "  the old key stops working the moment the agent restarts"
}

# `ovn config` — every effective setting and where it comes from. Read-only.
#
# The question it answers is the one a hand-edited .env raises: is the agent
# using this file, or something else? Everything the agent needs at boot lives
# here and nowhere else, so the honest answer is "all of it, and here is the
# file" — which is worth saying once, in a place an operator can look.
do_config() {
    local envfile="$APP_DIR/.env"
    [[ -f "$envfile" ]] || die "OVNode is not installed." "$EX_NOTINSTALLED"
    check_root
    render_line ""
    render_line "${B}settings${NC}"
    render_blank
    local key value
    while IFS='=' read -r key value; do
        [[ -n "$key" && "$key" != \#* ]] || continue
        case "$key" in
            API_KEY)
                # Never printed. `ovn credentials` is where it is shown, once,
                # on purpose — a value that appears in two places is a value
                # that ends up in a screenshot.
                render_kv "$key" "set — see: ovn credentials" ;;
            TLS_METHOD|SSL_KEYFILE|SSL_CERTFILE)
                render_kv "$key" "$value  — read by ovn tls" ;;
            *)
                render_kv "$key" "$value" ;;
        esac
    done < "$envfile"
    render_blank
    render_line "  .env is written once by the installer and never by this tool"
    render_line "  edit it freely; changes take effect on: ovn restart"
}

# ── Completion ─────────────────────────────────────────────────────────
# ~20 subcommands is more than anyone remembers, so Tab beats reading --help.
generate_completion() {
    cat <<'EOF'
_ovn_completions() {
    local cur
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    local cmds="status credentials config update enable disable restart restart-vpn logs backup restore auto-backup tls doctor rollback recover-update uninstall completion help start stop"
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
    # Twelve verbs, one screen, and the same shape as the panel's so the two
    # read as one product. Everything else is one flag away.
    cat << 'EOF' >&2
  ovnode — node manager  (alias: ovn)

  USAGE
    ovn status              Agent, health, version, service address  (--all for paths)
    ovn logs [N|-f]         Last N lines, or follow live
    ovn doctor [--fix]      Health checks; --fix applies the safe ones
    ovn restart             Restart the node agent
    ovn restart core        Restart the OpenVPN server
    ovn enable | disable    Automatic start on or off

    ovn auth                Owner credential — lists the options
    ovn auth key            API key and the panel registration bundle
    ovn auth rotate         Generate a new API key
    ovn tls                 Certificate — lists the options

    ovn backup [--keep N]   Write a state + PKI backup now
    ovn backup schedule     on | off | status — the host timer
    ovn restore [NAME]      List backups, or restore one

    ovn update              Staged update; recovers an interrupted one first
    ovn rollback            Restore the pre-update code snapshot
    ovn uninstall           Remove the node (--purge for data too)

  full reference: ovn help --all
EOF
    exit "$EX_OK"
}

# The full reference. "One flag away" only works if the flag is there.
show_help_full() {
    cat << 'EOF' >&2
  ovnode — node manager  (alias: ovn)

  COMMANDS
    ovn status              Agent, health, version, service address
    ovn status --all        Adds node name, mode, port and TLS paths
    ovn logs [N|-f]         Last N lines (default 100), or follow live
    ovn doctor [--all]      Health checks; --all lists every one
    ovn doctor --fix        Same checks, plus safe automatic repairs
    ovn restart             Restart the node agent
    ovn restart core        Restart the OpenVPN server process
    ovn enable | disable    Turn automatic start on or off

    ovn auth                Credential state, and what to do about it
    ovn auth key            API key and the panel registration bundle
    ovn auth rotate         Generate a new API key, printed not stored
    ovn tls                 Certificate: method, key, cert, expiry
    ovn tls selfsigned      New self-signed certificate
    ovn tls le IP|DOMAIN    Let's Encrypt — ip or domain, detected
    ovn tls custom CERT KEY Use your own pair

    ovn backup [--keep N]   Write a verified state + PKI backup now
    ovn backup schedule     on | off | status — the host timer
    ovn restore [NAME]      List data backups, or restore one by name
    ovn update              Staged update with automatic failover
    ovn rollback            Restore the newest pre-update code snapshot
    ovn uninstall [--purge] Remove the node (data kept unless --purge)
    ovn completion          Install bash completion, print the source line
    ovn config              Every effective setting and where it comes from

  RETIRED NAMES — still work, no longer in the short help
    ovn credentials         → ovn auth key
    ovn restart-vpn         → ovn restart core
    ovn auto-backup         → ovn backup schedule
    ovn recover-update      → ovn update (it recovers first)
    ovn start | stop        → ovn restart

  OPTIONS
    -y, --yes           Never prompt
    -a, --all           status and doctor: include everything
    --fix               doctor: apply safe automatic fixes
    --keep N            backup: how many backups to keep
    --purge             uninstall: also delete data and PKI
    -v, --version V     update: pin a release, e.g. -v v1.0.15
    -q, --quiet         Suppress progress logs        [OVN_QUIET=1]
    -h, --help          This help

  ENVIRONMENT
    OVN_YES=1           same as -y
    OVN_PURGE=1         same as --purge
    OVN_QUIET=1         same as -q
    CI=true             implies -y

  .env
    Written once by the installer and never by this tool. It owns the boot
    settings outright — NODE_NAME, DATA_DIR, SERVICE_PORT, API_KEY, OPENVPN_PORT,
    TLS_METHOD, SSL_KEYFILE, SSL_CERTFILE — because the agent cannot open its
    state without DATA_DIR and cannot bind without the ports. Edit it freely;
    changes take effect on restart.

    `ovn auth rotate` prints a new key and the line to change rather than
    writing it, for the same reason. Nothing edits this file after install.

    The API key lives here, not in the panel. It is printed by the installer and
    by `ovn auth key`; neither can be recovered elsewhere, so losing .env means
    re-enrolling the node.

  Update and uninstall are implemented in install.sh — this script delegates to
  $APP_DIR/install.sh so there is exactly one copy of each.
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
            help|--help|-h)
                          # "One flag away" only works if the flag is there.
                          # The spaces matter: `ovn help --all` puts --all last,
                          # so a bare suffix match never fires.
                          [[ " $* " == *" --all "* ]] && show_help_full
                          show_help ;;
            start)        ACTION="start"; shift ;;
            stop)         ACTION="stop"; shift ;;
            restart)      ACTION="restart"; shift
                          # `restart core` is the OpenVPN server process, named
                          # here rather than as a second verb so the two restarts
                          # sit next to each other and cannot drift apart.
                          if [[ "${1:-}" == "core" ]]; then ACTION="restart-core"; shift; fi ;;
            enable|disable) ACTION="$1"; shift ;;
            auto-backup)  ACTION="auto-backup"; shift
                          if [[ $# -ge 1 && "$1" != -* ]]; then AUTO_BACKUP_ACTION="$1"; shift; fi ;;
            --keep)       eval "$need2"; BACKUP_KEEP="$2"; shift 2 ;;
            --time)       eval "$need2"; BACKUP_TIME="$2"; shift 2 ;;
            restore)      ACTION="restore"; shift
                          if [[ $# -ge 1 && "$1" != -* ]]; then RESTORE_NAME="$1"; shift; fi ;;
            doctor)       ACTION="doctor"; shift ;;
            rollback)     ACTION="rollback"; shift ;;
            completion)   ACTION="completion"; shift ;;
            logs)         ACTION="logs"
                          if [[ $# -ge 2 && ( "$2" == "-f" || "$2" =~ ^[0-9]+$ ) ]]; then
                              LOGS_ARG="$2"; shift 2
                          else
                              shift
                          fi ;;
            backup)       ACTION="backup"; shift
                          if [[ "${1:-}" == "schedule" ]]; then
                              # One shift, not `shift 2`: the arm already consumed
                              # "backup", so only "schedule" is left. `shift 2` on
                              # one argument is an error under the ERR trap, which
                              # is what made this print a trap warning and nothing
                              # else.
                              ACTION="auto-backup"; AUTO_BACKUP_ACTION="status"
                              shift
                              # Then the action, if there is one. Without this the
                              # word after "schedule" fell through to the next
                              # arm: `backup schedule on` said "Unknown option:
                              # on", and `backup schedule status` ran the full
                              # status screen instead.
                              if [[ $# -ge 1 && "$1" != -* ]]; then
                                  AUTO_BACKUP_ACTION="$1"; shift
                              fi
                          fi ;;
            auth)         ACTION="auth"; shift
                          AUTH_ACTION=""
                          if [[ $# -ge 1 && "$1" != -* ]]; then
                              case "$1" in
                                  key)    AUTH_ACTION="key"; shift ;;
                                  rotate) AUTH_ACTION="rotate"; shift ;;
                                  *) die "ovn auth: unknown option '$1'  (see: ovn auth)" "$EX_USAGE" ;;
                              esac
                          fi ;;
            # ── the two grouped commands ──
            # Bare, each prints what it can do; a subcommand acts. Same rule as
            # the panel's tls/auth/url, so the shape is learned once for both.
            tls)          ACTION="tls"; shift
                          TLS_ACTION=""
                          if [[ $# -ge 1 && "$1" != -* ]]; then
                              case "$1" in
                                  selfsigned) TLS_ACTION="selfsigned"; shift ;;
                                  le)         eval "$need2"; TLS_ACTION="le"; TLS_DOMAIN="$2"; shift 2 ;;
                                  custom)     eval "$need2"; eval "$need2"
                                              TLS_ACTION="custom"; TLS_CERT="$2"; TLS_KEY="$3"; shift 3 ;;
                                  *) die "ovn tls: unknown option '$1'  (see: ovn tls)" "$EX_USAGE" ;;
                              esac
                          fi ;;
            config)       ACTION="config"; shift ;;

            # ── retired names ──
            # Still dispatched, out of the short help, and mapped in
            # `ovn help --all`. Nothing warns, because a deprecation line on
            # every nightly backup job is noise rather than notice.
            #
            # One block, one arm per old name. They used to be scattered through
            # the case, which is how `credentials` ended up defined twice with
            # the first one winning and `ovn backup schedule` becoming dead
            # code — both shipped, both invisible to the tests.
            restart-vpn)  ACTION="restart-core"; shift ;;
            credentials)  ACTION="auth"; AUTH_ACTION="key"; shift ;;
            recover-update) ACTION="recover-update"; shift ;;

            --yes|-y)     YES=1; shift ;;
            --purge)      PURGE=1; shift ;;
            --fix)        FIX=1; shift ;;
            -q|--quiet)   QUIET=1; shift ;;
            -a|--all)     SHOW_ALL=1; shift ;;
            -v|--version) eval "$need2"; PIN="$2"; shift 2 ;;
            *)            die "Unknown option: $1 (ovn help for usage)" "$EX_USAGE" ;;
        esac
    done
}

# ── Main ───────────────────────────────────────────────────────────────
main() {
    parse_args "$@"
    # Bare, it lists. There is no menu.
    #
    # The menu was a second hand-maintained list of this tool's own commands,
    # and it drifted twice: it had ten items against thirteen verbs, and one arm
    # still called a function that had been deleted. Every new command had to be
    # wired into it and nothing failed when someone forgot.
    #
    # The list is the same text as `ovn help`, so there is one place a verb is
    # written down rather than two, and `ovm` behaves this way too.
    [[ -z "$ACTION" ]] && { show_help; exit "$EX_OK"; }
    local rc=0
    case "$ACTION" in
        status)    do_status; exit "$EX_OK" ;;
        auth)      do_auth; exit $? ;;
        config)    do_config; exit "$EX_OK" ;;
        update|recover-update) delegate_update; exit "$EX_OK" ;;
        start|stop|restart) check_root; node_service_action "$ACTION"; exit "$EX_OK" ;;
        enable|disable) check_root; node_autostart "$ACTION"; exit "$EX_OK" ;;
        restart-core) check_root; restart_vpn; exit "$EX_OK" ;;
        logs) do_node_logs "$LOGS_ARG"; exit "$EX_OK" ;;
        backup) check_root; do_node_backup; exit "$EX_OK" ;;
        restore) do_restore "$RESTORE_NAME"; exit "$EX_OK" ;;
        auto-backup) check_root; auto_backup_cli "$AUTO_BACKUP_ACTION"; exit "$EX_OK" ;;
        tls) check_root; node_tls; exit $? ;;
        doctor) do_doctor || rc=$?; exit "$rc" ;;
        rollback) do_rollback; exit "$EX_OK" ;;
        completion) do_completion; exit "$EX_OK" ;;
        uninstall) delegate_uninstall; exit "$EX_OK" ;;
    esac
}

main "$@"
