#!/usr/bin/env bash
# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT
#
# OVNode shared shell library — sourced by install.sh and manager.sh, and the
# only copy of every function below (tests/test_no_duplicate_functions.py).

# ── Colour / TTY ───────────────────────────────────────────────────────
# Every renderer writes to fd 2, so the gate tests fd 2. NO_COLOR removes the
# colour; TERM=dumb removes the motion too, because a dumb terminal honours
# neither. render.sh reads these globals — it does not define them.
NC=$'\033[0m'; B=$'\033[1m'; D=$'\033[2m'
WH=$'\033[97m'; GR=$'\033[32m'; RD=$'\033[31m'
YL=$'\033[33m'; CY=$'\033[36m'; GY=$'\033[90m'
OR=$'\033[38;5;208m'
[[ -t 2 && -z "${NO_COLOR:-}" && "${TERM:-dumb}" != "dumb" ]] \
    || { NC=''; B=''; D=''; WH=''; GR=''; RD=''; YL=''; CY=''; GY=''; OR=''; }
: "${QUIET:=0}"

# die <message> [exit-code]  — single error path.
#
# Deliberately not a render helper: this is the exit path, not decoration, and
# it must keep working when the terminal is unusable and when render.sh failed
# to source. QUIET does not silence it — an error nobody sees is a silent
# failure.
die() {
    local msg="$1" code="${2:-$EX_ERROR}"
    printf '\n  %bError:%b %s\n\n' "$RD" "$NC" "$msg" >&2
    exit "$code"
}

# is_tty asks for a terminal on BOTH ends: this is the prompt predicate, and a
# prompt nobody can answer is worse than no prompt. The renderer asks only about
# stderr, because `curl … | bash -s` has a pipe on stdin and a terminal an
# operator is watching — the wrong answer here would degrade the most common
# install path.
is_tty() { [[ -t 0 && -t 2 ]]; }

# Spinners/prompts only for interactive humans.
fancy()  { is_tty && [[ "$QUIET" -eq 0 ]]; }

# run <label> <cmd...> — required step. A failure is fatal: continuing would
# leave a half-installed node the operator believes is whole.
run() {
    local label="$1"; shift
    render_begin "$label"
    render_watch
    if "$@" >/dev/null 2>&1; then
        render_done ""
        return 0
    fi
    render_fail "$label" "command failed"
    die "Step failed: $label"
}

# try_run <label> <cmd...> — best-effort step: warns instead of dying.
try_run() {
    local label="$1"; shift
    render_begin "$label"
    render_watch
    if "$@" >/dev/null 2>&1; then
        render_done ""
        return 0
    fi
    render_fail "$label" "continuing"
    render_warn "$label failed — continuing"
    return 1
}

# Masked input: one * per char on stderr, backspace works; value goes to stdout.
_masked_read() {
    local buf="" ch
    while IFS= read -rsn1 ch; do
        case "$ch" in
            ""|$'\n'|$'\r') break ;;
            $'\x7f'|$'\b')
                if [[ -n "$buf" ]]; then buf="${buf%?}"; printf '\b \b' >&2; fi ;;
            *) buf+="$ch"; printf '*' >&2 ;;
        esac
    done
    printf '\n' >&2
    printf '%s' "$buf"
}

ask() {
    local label="$1" default="$2" hidden="${3:-}" val=""
    if is_tty && [[ "$YES" -eq 0 ]]; then
        render_ask "$label" "$default"
        if [[ "$hidden" == "h" ]]; then
            val="$(_masked_read)"
        else
            read -r val
        fi
    fi
    echo "${val:-$default}"
}

# confirm <question> [default] — default is y, which is what an unattended run
# gets. A destructive caller must pass n: with no terminal nobody can answer, and
# answering yes on their behalf would replace live data from a cron or CI run.
confirm() {
    local default="${2:-y}" c=""
    [[ "$YES" -eq 1 ]] && return 0
    if ! is_tty; then
        [[ "$default" == "y" ]]
        return
    fi
    if [[ "$default" == "y" ]]; then
        render_ask "$1" "Y/n"
        read -r c
        [[ ! "$c" =~ ^[Nn]$ ]]
    else
        render_ask "$1" "y/N"
        read -r c
        [[ "$c" =~ ^[Yy]$ ]]
    fi
}

# Explicit-yes prompt (default NO) for destructive extras like deleting data.
confirm_no() {
    [[ "$YES" -eq 1 ]] && return 1
    is_tty || return 1
    render_ask "$1" "y/N"
    local c=""
    read -r c
    [[ "$c" =~ ^[Yy]$ ]]
}

# confirm_word <question> <word> — the destructive default. `uninstall` asks for
# the word "purge" before it deletes a node's PKI and key material, and Enter
# keeps them. A plain y/N made the destructive answer one stray keystroke from
# the default.
confirm_word() {
    local question="$1" word="$2" reply=""
    [[ "$YES" -eq 1 ]] && return 0
    is_tty || return 1
    render_ask "$question" "press enter to keep it"
    read -r reply
    [[ "$reply" == "$word" ]]
}

is_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )); }

backup_dir() {
    local src="$1" label="$2"
    [[ -d "$src" ]] || return 0
    mkdir -p /var/backups
    local stamp; stamp="$(date +%Y%m%d-%H%M%S)"
    local base; base="$(basename "$src")"
    local file="/var/backups/${label}-${base}-${stamp}.tar.gz"
    # Contains the PKI (CA private key) and, in Docker mode, the compose file
    # with the API key: root-only from the start, not the caller's umask.
    local old_umask; old_umask="$(umask)"
    umask 077
    if tar -czf "$file" -C "$(dirname "$src")" "$base" 2>/dev/null; then
        umask "$old_umask"
        chmod 600 "$file" 2>/dev/null || true
        render_ok "Backup saved: $file"
    else
        umask "$old_umask"
        render_warn "Backup failed for $src — continuing anyway"
    fi
}

wait_health() {
    local url="$1" tries="${2:-30}" i
    for i in $(seq 1 "$tries"); do
        curl -fsSk -o /dev/null --max-time 3 "$url" 2>/dev/null && return 0
        sleep 1
    done
    return 1
}

# wait_health_live — wait_health, but the running step counts the attempts.
#
# The old wait was a minute of complete silence on first boot, which is
# indistinguishable from a hang: first boot generates the PKI, so it is the
# slowest and the most normal part of a node install. Each poll updates the step
# line, so the operator sees it is trying and how long it has been trying.
wait_health_live() {  # wait_health_live <url> <tries>
    local url="$1" tries="${2:-30}" i code="" ms=0
    for (( i = 1; i <= tries; i++ )); do
        code="$(curl -fsSk -o /dev/null -w '%{http_code}' --max-time 3 "$url" 2>/dev/null || true)"
        if [[ "$code" == "200" ]]; then
            render_note "200 in ${ms}ms"
            return 0
        fi
        render_note "waiting · attempt ${i}/${tries}"
        sleep 1
        ms=$(( ms + 1000 ))
    done
    return 1
}

env_get() {  # env_get FILE KEY → value
    [[ -f "$1" ]] || return 0
    # A file we can see but cannot read is not "no value": returning empty made
    # callers fall back to defaults that look like real data, so a healthy node
    # reported itself broken and exited 0 — worse than an error, because it
    # invites someone to repair a working box.
    [[ -r "$1" ]] || die "Cannot read $1 — run with sudo." "$EX_ERROR"
    awk -F= -v k="$2" '$1 == k { sub(/^[^=]*=/, ""); print; exit }' "$1" | tr -d '\r'
}

node_name_from_env() {
    local name; name="$(env_get "$APP_DIR/.env" NODE_NAME)"
    printf '%s' "${name:-ovnode}"
}

systemctl_bounded() {  # systemctl_bounded stop|restart <unit>
    local action="$1" unit="$2"
    # Not loaded (Docker install, or NAT unit absent): nothing to do.
    if [[ "$(systemctl show -p LoadState --value "$unit" 2>/dev/null)" != "loaded" ]]; then
        return 0
    fi
    if timeout "$STOP_TIMEOUT" systemctl "$action" "$unit" 2>/dev/null; then
        return 0
    fi
    render_warn "systemctl $action $unit did not finish in ${STOP_TIMEOUT}s — forcing it"
    systemctl kill -s SIGKILL "$unit" >/dev/null 2>&1 || true
    sleep 1
    if [[ "$action" == "restart" ]]; then
        timeout "$STOP_TIMEOUT" systemctl start "$unit" 2>/dev/null || true
    fi
    return 0
}

# Menu. The drawing and the keystrokes belong to render.sh; this is the wrapper
# for callers that want a tag back.
#
# The old version preferred whiptail when it happened to be installed, so the
# same menu rendered two completely different ways on two different boxes. One
# renderer, so the pointer, the number and the arrow always agree.
tui_select() { render_menu "$@"; }

_existing_tls_pair_usable() {  # <key> <cert> → 0 when an intact, unexpired pair is already there
    local key="$1" cert="$2" key_pub cert_pub
    [[ -s "$key" && -s "$cert" ]] || return 1
    openssl x509 -noout -checkend 0 -in "$cert" >/dev/null 2>&1 || return 1
    key_pub="$(openssl pkey -pubout -in "$key" 2>/dev/null | openssl sha256)" || return 1
    cert_pub="$(openssl x509 -pubkey -noout -in "$cert" 2>/dev/null | openssl sha256)" || return 1
    [[ -n "$key_pub" && "$key_pub" == "$cert_pub" ]]
}

generate_selfsigned() {
    local key="/etc/ssl/self-signed/privkey.pem"
    local cert="/etc/ssl/self-signed/fullchain.pem"
    mkdir -p /etc/ssl/self-signed
    # /etc/ssl/self-signed is a shared convention: OVManager keeps its panel
    # certificate in these same two files. Regenerating replaces the panel's
    # identity, and the chmod 600 below drops the group read its non-root service
    # account needs, so an intact pair is reused untouched — permissions included.
    # `ovn tls` option 1 is the explicit way to ask for a new one.
    if [[ "${TLS_REGENERATE:-0}" != "1" ]] && _existing_tls_pair_usable "$key" "$cert"; then
        TLS_KEY="$key"
        TLS_CERT="$cert"
        render_ok "self-signed certificate already present — reusing it"
        return 0
    fi
    local cn; cn="$(primary_ip)"
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "$key" \
        -out "$cert" \
        -subj "/C=US/ST=Local/L=Local/O=OVNode/CN=${cn:-ovnode}" >/dev/null 2>&1
    # The sync API TLS key is a secret: owner-only (the agent runs as root).
    chmod 600 "$key"
    chmod 644 "$cert"
    TLS_KEY="$key"
    TLS_CERT="$cert"
    render_ok "self-signed certificate generated"
}

ensure_acme() {
    if [[ ! -x "$HOME/.acme.sh/acme.sh" ]]; then
        run "Installing acme.sh" bash -c 'curl -s https://get.acme.sh | sh'
    fi
}

issue_letsencrypt() {
    local domain="$1" is_ip="$2"
    ensure_acme
    local email="acme-$(openssl rand -hex 4)@example.com"
    local outdir="/etc/letsencrypt/$domain"
    mkdir -p "$outdir"

    if [[ -f "$outdir/fullchain.pem" ]]; then
        local expiry days_left=0
        expiry="$(openssl x509 -enddate -noout -in "$outdir/fullchain.pem" 2>/dev/null | cut -d= -f2)"
        days_left=$(( ($(date -d "$expiry" +%s 2>/dev/null || echo 0) - $(date +%s)) / 86400 ))
        if (( days_left > 7 )); then
            render_ok "existing certificate valid for ${days_left} more days"
            TLS_KEY="$outdir/privkey.pem"; TLS_CERT="$outdir/fullchain.pem"
            return 0
        fi
        render_warn "certificate expires soon (${days_left}d) — renewing"
    fi

    local extra_args=()
    if [[ "$is_ip" == "1" ]]; then extra_args=(--certificate-profile shortlived --days 6); fi

    "$HOME/.acme.sh/acme.sh" --issue -d "$domain" --standalone "${extra_args[@]}" \
        --accountemail "$email" >/dev/null 2>&1 \
        || die "Failed to issue Let's Encrypt certificate for $domain (is port 80 free and the domain pointed here?)"

    "$HOME/.acme.sh/acme.sh" --install-cert -d "$domain" \
        --key-file "$outdir/privkey.pem" \
        --fullchain-file "$outdir/fullchain.pem" \
        --reloadcmd "systemctl restart $SYSTEMD_SERVICE >/dev/null 2>&1 || true" >/dev/null 2>&1 \
        || die "Failed to install certificate to $outdir"
    TLS_KEY="$outdir/privkey.pem"; TLS_CERT="$outdir/fullchain.pem"
    render_ok "certificate installed to $outdir"
}

setup_tls() {
    case "$TLS_METHOD" in
        none) ;;
        selfsigned)     generate_selfsigned ;;
        letsencrypt)    issue_letsencrypt "$TLS_DOMAIN" "0" ;;
        letsencrypt-ip) issue_letsencrypt "$TLS_DOMAIN" "1" ;;
        custom)
            local out="/etc/letsencrypt/${TLS_DOMAIN:-node}"
            mkdir -p "$out"
            cp "$TLS_KEY" "$out/privkey.pem"
            cp "$TLS_CERT" "$out/fullchain.pem"
            TLS_KEY="$out/privkey.pem"; TLS_CERT="$out/fullchain.pem"
            render_ok "custom certificate installed to $out"
            ;;
    esac
}

# ── Misc helpers ───────────────────────────────────────────────────────
primary_ip() { hostname -I 2>/dev/null | awk '{print $1}'; }

# This box's public address, as Let's Encrypt would see it: a public resolver
# first (the address the internet routes to), then the local interfaces filtered
# to globally routable ranges. An address behind NAT is still the right answer
# here — the certificate names what the world dials.
public_ip() {
    local ip
    for ip in $(curl -fsS --max-time 3 https://api.ipify.org 2>/dev/null) \
              $(curl -fsS --max-time 3 https://ifconfig.me/ip 2>/dev/null); do
        [[ "$ip" =~ ^[0-9a-fA-F:.]+$ ]] && { printf '%s' "$ip"; return 0; }
    done
    for ip in $(hostname -I 2>/dev/null); do
        case "$ip" in
            *:*) continue ;;                       # IPv6 is not offered for LE here
            127.*|10.*|192.168.*|169.254.*) continue ;;
            172.1[6-9].*|172.2[0-9].*|172.3[01].*) continue ;;   # 172.16/12 is private
            *) printf '%s' "$ip"; return 0 ;;
        esac
    done
    return 1
}

# Every routable address on this host, for a box with more than one: the prompt
# names them so an operator with several can pick the one the certificate
# should carry instead of guessing.
public_ips() {
    local ip out=""
    for ip in $(hostname -I 2>/dev/null); do
        case "$ip" in
            *:*) continue ;;
            127.*|10.*|192.168.*|169.254.*) continue ;;
            172.1[6-9].*|172.2[0-9].*|172.3[01].*) continue ;;
            *) out+="$ip " ;;
        esac
    done
    printf '%s' "${out% }"
}

# Is this a bare IP rather than a hostname? Decides whether a Let's Encrypt
# request is the short-lived IP kind or the ordinary domain one, so one free-text
# prompt can serve both.
is_ip_literal() {
    [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || [[ "$1" == *:* ]]
}

# Resolve and report, so a certificate attempt is not spent discovering a
# misconfigured record. Prints the address on success, empty otherwise.
resolve_host() {
    local host="$1"
    getent hosts "$host" 2>/dev/null | awk '{ print $1; exit }' || true
}

# Code-tree snapshots for update failover: keep the newest $keep.
snapshot_code() {  # snapshot_code <dir> <label> [keep=2] → prints the file
    local dir="$1" label="$2" keep="${3:-2}"
    [[ -d "$dir" ]] || die "Not installed ($dir missing)" "$EX_ERROR"
    mkdir -p /var/backups
    local stamp base file
    stamp="$(date +%Y%m%d-%H%M%S)"
    base="$(basename "$dir")"
    file="/var/backups/${label}-code-${base}-${stamp}.tar.gz"
    tar -czf "$file" -C "$(dirname "$dir")" "$base" 2>/dev/null \
        || die "Could not snapshot $dir" "$EX_ERROR"
    render_ok "snapshot  $file"
    # Read the list line by line: `rm -f $old` word-splits on whitespace and
    # globs the result, so a label containing a space deletes the wrong set.
    local old=() line
    while IFS= read -r line; do
        [[ -n "$line" ]] && old+=("$line")
    done < <(ls -t /var/backups/"${label}"-code-*.tar.gz 2>/dev/null | tail -n +$((keep + 1)) || true)
    if (( ${#old[@]} )); then
        rm -f -- "${old[@]}"
    fi
    printf '%s' "$file"
}

latest_snapshot() {  # latest_snapshot <label> → prints newest code snapshot or empty
    ls -t /var/backups/"$1"-code-*.tar.gz 2>/dev/null | head -1 || true
}

# ── Host / install-mode probes ─────────────────────────────────────────
check_root() { [[ "$EUID" -eq 0 ]] || die "Must run as root."; }
has_systemd() { command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; }
compose_file() { echo "$DATA_BASE/${NODE_NAME:-ovnode}/docker-compose.yml"; }
is_docker_node() { [[ -f "$(compose_file)" ]]; }
