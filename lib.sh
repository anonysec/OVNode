#!/usr/bin/env bash
# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT
#
# OVNode shared shell library — the only copy of every helper below.
# Sourced by install.sh and ovnode.sh, and embedded in the binary so the scripts
# on a box always match the binary beside them. The two halves below used to be
# two files that called each other: render.sh asked common.sh for `ask`, and
# common.sh asked render.sh to print. One file, one dependency direction.

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
    if "$@" >/dev/null 2>&1; then
        render_ok "$label"
        return 0
    fi
    render_fail "$label" "command failed"
    die "Step failed: $label"
}

# try_run <label> <cmd...> — best-effort step: warns instead of dying.
try_run() {
    local label="$1"; shift
    if "$@" >/dev/null 2>&1; then
        render_ok "$label"
        return 0
    fi
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

# confirm <question> [default] — default is y, which is what a run with no
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

# backup_dir() and the code snapshots below share one root. OVN_BACKUP_ROOT
# exists for the test suite and for an off-box backup target; unset, every
# tarball lands where it always has — /var/backups.
backup_dir() {
    local src="$1" label="$2"
    [[ -d "$src" ]] || return 0
    local root="${OVN_BACKUP_ROOT:-/var/backups}"
    mkdir -p "$root"
    local stamp; stamp="$(date +%Y%m%d-%H%M%S)"
    local base; base="$(basename "$src")"
    local file="$root/${label}-${base}-${stamp}.tar.gz"
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

# The one answer to "where does this node keep its data".
#
# It used to be written as ${DATA_BASE}/${NODE_NAME} in seventeen places, and
# that nesting was a layout for several nodes per host that nothing ever
# implemented — there is one NODE_NAME, one service, one agent. A node's data
# therefore belongs at the base, and the path belongs in one function so a layout
# question is answered once rather than seventeen times.
#
# .env declares it, the same way it declares the certificate paths: an install
# that already names a directory keeps it, and a fresh one gets the base. That
# is also what makes the one-time migration in install.sh possible without this
# file having to know it happened.
node_data_dir() {
    local declared
    declared="$(env_get "$APP_DIR/.env" DATA_DIR)"
    printf '%s' "${declared:-$DATA_BASE}"
}

# The pre-flatten location, when it holds anything. An install from before the
# change has its data one level down and says so here, which is how the
# migration finds it without a flag file.
node_legacy_data_dir() { printf '%s/%s' "$DATA_BASE" "$(node_name_from_env)"; }

# The flat layout's destination is always the base, and deliberately not
# node_data_dir(). While the old declaration is still in .env that helper returns
# the *old* path, so asking it where to migrate to answers "nowhere" and the
# migration silently does nothing — which is exactly what it did the first time
# this ran. The base is not a guess: it is what the flat layout means.
migrate_flat_data_dir() {
    local legacy node_data
    legacy="$(node_legacy_data_dir)"
    node_data="$DATA_BASE"
    [[ "$legacy" != "$node_data" ]] || return 0
    [[ -d "$legacy" ]] || return 0

    local entry name clash=""
    for entry in "$legacy"/* "$legacy"/.[!.]*; do
        [[ -e "$entry" ]] || continue
        name="$(basename "$entry")"
        [[ -e "$node_data/$name" ]] && clash+=" $name"
    done
    if [[ -n "$clash" ]]; then
        render_fail "flat data migration" "already present in $node_data:$clash — refusing to merge"
        return 1
    fi

    mkdir -p "$node_data" || { render_fail "flat data migration" "could not create $node_data"; return 1; }
    for entry in "$legacy"/* "$legacy"/.[!.]*; do
        [[ -e "$entry" ]] || continue
        cp -a "$entry" "$node_data/$(basename "$entry")" || {
            render_fail "flat data migration" "could not copy $(basename "$entry")"
            return 1
        }
    done
    # Only now is the copy known complete, so the old directory can go.
    rmdir "$legacy" 2>/dev/null || rm -rf "$legacy"

    # And the declaration has to follow, or the agent comes back reading a
    # directory that is no longer there. This is the installer editing .env,
    # which is its job — install.sh already rewrites it during an update to
    # strip retired keys. The operator CLI never touches it.
    if [[ -f "$APP_DIR/.env" ]]; then
        local tmp; tmp="$(mktemp "${APP_DIR}/.env.XXXXXX")" || {
            render_fail "flat data migration" "could not stage $APP_DIR/.env"
            return 1
        }
        if awk -v k=DATA_DIR -v v="$node_data" '
            BEGIN { k = k; v = v; done = 0 }
            index($0, k "=") == 1 { if (!done) { print k "=" v; done = 1 } ; next }
            { print }
            END { if (!done) print k "=" v }
        ' "$APP_DIR/.env" > "$tmp" 2>/dev/null; then
            chmod --reference="$APP_DIR/.env" "$tmp" 2>/dev/null || chmod 600 "$tmp"
            chown --reference="$APP_DIR/.env" "$tmp" 2>/dev/null || true
            mv -f "$tmp" "$APP_DIR/.env" || { rm -f "$tmp"; render_fail "flat data migration" "could not replace .env"; return 1; }
        else
            rm -f "$tmp"
            render_fail "flat data migration" "could not rewrite DATA_DIR in .env"
            return 1
        fi
    fi

    render_ok "moved node data to $node_data"
    render_kv "From" "$legacy"
    render_kv "To"   "$node_data"
    render_line "    DATA_DIR in $APP_DIR/.env now points there; the old directory is gone"
    return 0
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

# Where this node's own key and certificate live.
#
# It used to be /etc/ssl/self-signed, which is a *shared* convention: OVManager
# keeps its panel certificate in exactly those two files on the same host. The
# node then wrote over the panel's identity and chmod 600'd the key, which
# drops the group read the panel's non-root service account needs — so the panel
# stopped starting, and nothing in either project's doctor said why.
#
# Reusing an intact pair mitigated that only while the pair stayed intact. Once
# it was not — a mismatched key, an unreadable file, anything — the fallback
# regenerated into the shared path and did the damage again, which is how the
# panel on this host spent a day in a restart loop.
#
# So the node writes to its own directory. An install that already declares
# SSL_KEYFILE/SSL_CERTFILE keeps using them, which is what the .env is for.
node_tls_paths() {
    local key cert
    key="$(env_get "$APP_DIR/.env" SSL_KEYFILE)"
    cert="$(env_get "$APP_DIR/.env" SSL_CERTFILE)"
    printf '%s\n%s\n' "${key:-/etc/ovnode/tls/privkey.pem}" "${cert:-/etc/ovnode/tls/fullchain.pem}"
}

generate_selfsigned() {
    local key cert
    { read -r key; read -r cert; } < <(node_tls_paths)
    mkdir -p "$(dirname "$key")" "$(dirname "$cert")"
    # Reuse an intact pair, permissions included. `ovnode tls selfsigned` is the
    # explicit way to ask for a new one, and only that sets TLS_REGENERATE.
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
    # The sync API TLS key is a secret, so it is owner-only — but only ever at a
    # path this node owns. The 600 used to be applied to whatever sat in the
    # shared directory, which is what took the panel down.
    chmod 600 "$key"
    chmod 644 "$cert"
    TLS_KEY="$key"
    TLS_CERT="$cert"
    render_ok "self-signed certificate generated at $cert"
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
    local root="${OVN_BACKUP_ROOT:-/var/backups}"
    mkdir -p "$root"
    local stamp base file
    stamp="$(date +%Y%m%d-%H%M%S)"
    base="$(basename "$dir")"
    file="$root/${label}-code-${base}-${stamp}.tar.gz"
    tar -czf "$file" -C "$(dirname "$dir")" "$base" 2>/dev/null \
        || die "Could not snapshot $dir" "$EX_ERROR"
    render_ok "snapshot  $file"
    # Read the list line by line: `rm -f $old` word-splits on whitespace and
    # globs the result, so a label containing a space deletes the wrong set.
    local old=() line
    while IFS= read -r line; do
        [[ -n "$line" ]] && old+=("$line")
    done < <(ls -t "$root/${label}"-code-*.tar.gz 2>/dev/null | tail -n +$((keep + 1)) || true)
    if (( ${#old[@]} )); then
        rm -f -- "${old[@]}"
    fi
    printf '%s' "$file"
}

latest_snapshot() {  # latest_snapshot <label> → prints newest code snapshot or empty
    ls -t "${OVN_BACKUP_ROOT:-/var/backups}/$1"-code-*.tar.gz 2>/dev/null | head -1 || true
}

# ── Host / install-mode probes ─────────────────────────────────────────
check_root() { [[ "$EUID" -eq 0 ]] || die "Must run as root."; }
has_systemd() { command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; }
compose_file() { echo "$(node_data_dir)/docker-compose.yml"; }
is_docker_node() { [[ -f "$(compose_file)" ]]; }

# ── Capability detection ───────────────────────────────────────────────
# One decision, made once, read everywhere. Resolved at source time so the
# helpers below are branch-free.
#
# The colour gate tests fd 2, not fd 1: every helper here writes to fd 2, and
# `install.sh 2>install.log` from a terminal used to pass [[ -t 1 ]] and write
# escape codes into the log.
if [[ -t 2 && -z "${NO_COLOR:-}" && "${TERM:-dumb}" != "dumb" ]]; then
    RENDER_COLOR=1
else
    RENDER_COLOR=0
fi

# Braille is the only widely-available frame set that reads as continuous
# rotation without shifting the line. Nothing rotates any more — the set is
# kept because the ASCII/Unicode split also decides the glyph vocabulary.
if [[ "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" == *[Uu][Tt][Ff]* ]]; then
    RENDER_SPINNER_UNICODE=1
else
    RENDER_SPINNER_UNICODE=0
fi

# ── Primitives ──────────────────────────────────────────────────────────

# Every glyph in one place, ASCII and Unicode pairs. Callers never type a
# character directly, so LANG=C output stays coherent.
if [[ "$RENDER_SPINNER_UNICODE" -eq 1 ]]; then
    RENDER_POINTER='▸'
    RENDER_OK='✓'
    RENDER_BAD='✗'
    RENDER_RULE='──────────────────────────────────────────────'
else
    RENDER_POINTER='>'
    RENDER_OK='ok'
    RENDER_BAD='XX'
    RENDER_RULE='----------------------------------------------'
fi

_render_paint() {  # _render_paint <colour> <text> — no-op when colour is off
    if [[ "$RENDER_COLOR" -eq 1 ]]; then printf '%b%s%b' "$1" "$2" "${NC:-}"; else printf '%s' "$2"; fi
}

_render_out() { printf '  %b\n' "$*" >&2; }

# ── Banner / screen ─────────────────────────────────────────────────────

render_banner() {  # render_banner <name> <version>
    local name="$1" version="$2"
    _render_out "$(_render_paint "$B" "$name")  $version  $(_render_paint "$GY" "· anonysec")"
    render_rule
}

render_rule() { _render_out "$(_render_paint "$GY" "$RENDER_RULE")"; }

# Wipe between wizard steps. TTY only: `clear` in a pipe writes form feeds into
# the log and destroys the record of what was chosen.
render_screen() {
    [[ -t 2 ]] || return 0
    # `clear 2>/dev/null`, not `command clear >/dev/null 2>&1`. `clear` clears
    # by *printing* escape codes, so redirecting its stdout to /dev/null threw
    # the codes away and the screen was never cleared — the exact opposite of
    # what that redirection looks like it is doing.
    clear 2>/dev/null || printf '\033[H\033[2J\033[3J' >&2 || true
    return 0
}

# ── Menu ───────────────────────────────────────────────────────────────
#
# Numbers only. Typing a number needs no arrow keys, no separate fd and no
# read timeout, so a pasted line, a closed terminal or a tmux that lost the
# pane cannot leave a half-drawn frame on screen.
#
# render_menu <title> <tag> <label> [<tag> <label> ...] → prints the tag.

render_menu() {
    shift    # title is the caller's; the banner already said what this is
    local -a tags=() labels=()
    while [[ $# -ge 2 ]]; do tags+=("$1"); labels+=("$2"); shift 2; done
    local count=${#tags[@]}
    [[ "$count" -gt 0 ]] || return 1

    local i=0
    while (( i < count )); do
        printf '  %b%d%b  %s\n' "$B" "$(( i + 1 ))" "$NC" "${labels[$i]}" >&2
        i=$(( i + 1 ))
    done

    local n
    n="$(ask "choice" "1")"
    [[ "$n" =~ ^[0-9]+$ ]] || n=1
    # Wrap into range rather than crash on 0 or a stray large number. The
    # modulo is done in bash's own arithmetic, where a negative operand keeps
    # its sign: $(( (0 - 1) % 3 )) is -1, and indexing with -1 is the last
    # element rather than the first. Adding the count first keeps it positive.
    printf '%s' "${tags[$(( ((10#$n - 1) + count) % count ))]}"
    return 0
}

# ── Steps ───────────────────────────────────────────────────────────────
#
# A step is two lines: what is about to happen, then what came of it.
#
#   ..    release
#   ok    checksum ok
#
# There is no block, no counter and no repaint. The earlier renderer drew a
# numbered block and rewrote it in place as each step finished; that looked
# better in a terminal and was useless everywhere else — a piped install log
# ended up as a column of escape sequences with the useful lines buried. The
# numbering also cost a second, competing way of saying where you are.

RENDER_STEP_LABEL=""

# render_begin <label> — announce a step.
render_begin() {
    RENDER_STEP_LABEL="$1"
    printf '  %b..%b    %s\n' "$GY" "$NC" "$1" >&2
    return 0
}

# render_stage <title> — the numbered stage header the installer uses. A bar,
# not a step: it separates the phases of a long install the way the panel's
# installer does, and the number tells an operator how much is left.
render_stage() {
    printf '\n  ============================== %s ==============================\n' "$1" >&2
    return 0
}

# render_done <detail> — close the step. An empty detail still says the step
# finished, so the log never has a line that promises something and forgets it.
render_done() {
    RENDER_STEP_LABEL=""
    printf '  %b%s%b  %s\n' "$GR" "$RENDER_OK" "$NC" "${1:-}" >&2
    return 0
}

# render_end — close the step without a result line. Used where a step failed
# and the failure is reported by the caller.
render_end() {
    RENDER_STEP_LABEL=""
    return 0
}

# render_note <detail> — a line under the open step.
render_note() {
    printf '  %b..%b    %s\n' "$GY" "$NC" "$1" >&2
    return 0
}

# ── Plain lines ─────────────────────────────────────────────────────────
# Everything that is not a numbered step. One place, so there is exactly one
# answer to "how is ordinary output indented and coloured".

render_line() { _render_out "$*"; }
render_blank() { printf '\n' >&2; }

# render_ok <text> — a completed thing that is not one of the numbered steps.
# The green check is the same glyph the steps use, so "done" looks the same
# everywhere in the installer.
render_ok() {
    printf '  %b%s%b  %s\n' "$GR" "$RENDER_OK" "$NC" "$1" >&2
}

# render_warn <text> — a caveat. Yellow, no glyph: a mid-run warning marker on
# its own line is the thing operators learn to skip, so the colour carries it
# and the text carries the meaning.
render_warn() {
    printf '  %b%s%b\n' "$YL" "$1" "$NC" >&2
}

# Card rows share one label width, so every value starts in the same column.
# 14 is the longest label either card uses ("install name" is 12, "setup key"
# and "not written" are shorter) — wide enough for the node card's labels, and
# not so wide that a short value sits in the middle of the screen.
RENDER_LABEL_W=14

# render_kv <label> <value> — a label/value row.
render_kv() {
    printf '   %b%-*s%b %s\n' "$GY" "$RENDER_LABEL_W" "$1" "$NC" "$2" >&2
}

# render_kv_w <width> <label> <value> — a row in a column this caller computed.
#
# A fixed width only works when every label is shorter than it. At 14, a
# 44-character backup filename printed whole and dropped its date a column right
# of every other row's, so a table of timestamps lined up with nothing. Pass the
# width the set actually needs and the values line up.
render_kv_w() {
    printf '   %b%-*s%b %s\n' "$GY" "$1" "$2" "$NC" "$3" >&2
}

# render_key — a secret. The only thing in the installer that gets bold white,
# because it is the only thing that must not be skimmed past.
render_key() {
    printf '   %b%-*s%b %b%s%b\n' "$GY" "$RENDER_LABEL_W" "$1" "$NC" "$B" "$2" "$NC" >&2
}

# render_url — bold for the same reason as render_key: it gets copied.
render_url() { render_kv "$1" "$(_render_paint "$B" "$2")"; }

# ── Card ───────────────────────────────────────────────────────────────
#
# The finish card fades in line by line, and the secret is passed in second so
# it is on screen before the lines that explain it: an operator who interrupts
# at the second line has the one thing they must not lose.
#
# render_card <title> <secret-label> <secret> <row>... — rows are "label|value".
# The uninstall line is added by render_card_undo, not here, so a caller that
# has no uninstall command does not print a broken one.

render_card() {
    local title="$1" secret_label="$2" secret="$3"; shift 3
    render_blank
    _render_out "$(_render_paint "$B" "$title")"
    render_rule
    [[ -n "$secret_label" ]] && render_key "$secret_label" "$secret"
    local row
    for row in "$@"; do
        [[ "$row" == *"|"* ]] || continue
        render_kv "${row%%|*}" "${row#*|}"
    done
    render_blank
    return 0
}

# render_card_undo <url> — the removal command, spelled out in full. An operator
# who wants it later is reading a log or a terminal scrollback, not the source.
render_card_undo() {
    render_blank
    _render_out "$(printf '%buninstall:%b %s' "$GY" "$NC" "$1")"
    render_blank
}

# ── Failure ────────────────────────────────────────────────────────────
#
# One line, then one way out. The gap between what was promised and what
# happened is the thing an operator actually needs, and it fits in a line — the
# rest of the old error prose was the same information at four times the length.

render_fail() {  # render_fail <label> <cause>
    RENDER_STEP_LABEL=""
    printf '  %b%s%b %b%s%b  %s\n' "$RD" "$RENDER_BAD" "$NC" "$B" "$1" "$NC" "$2" >&2
    return 0
}

render_next() {  # render_next <how to look> <how to remove>
    printf '  %bnext%b  %s · uninstall: %s\n' "$GY" "$NC" "$1" "$2" >&2
}

# ── Ask ─────────────────────────────────────────────────────────────────
# Styled to match the menu: the default is bold, the label is dim, and the
# colon sits after the bracket so the answer's position never moves.

render_ask() {  # render_ask <label> <default>
    printf '  %b%s%b %b[%s]%b: ' "$GY" "$1" "$NC" "$B" "$2" "$NC" >&2
}

render_ask_note() { _render_out "$(_render_paint "$GY" "$1")"; }
