#!/usr/bin/env bash
# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT
#
# OVNode shared shell library — sourced by install.sh and manager.sh, and the
# only copy of every function below (tests/test_no_duplicate_functions.py).

# ── Output ─────────────────────────────────────────────────────────────
# All human-readable output goes to stderr, so stdout stays clean for callers.
NC=$'\033[0m'; B=$'\033[1m'
WH=$'\033[97m'; GR=$'\033[32m'; RD=$'\033[31m'
YL=$'\033[33m'; CY=$'\033[36m'; GY=$'\033[90m'
[[ -t 2 ]] || { NC=''; B=''; WH=''; GR=''; RD=''; YL=''; CY=''; GY=''; }
: "${QUIET:=0}"

line()  { [[ "$QUIET" -eq 1 ]] || echo -e "  $1" >&2; }

step()  { line "${GR}  ✓${NC} $1"; }

info()  { line "${CY}  →${NC} $1"; }

warn()  { line "${YL}  ⚠${NC} $1"; }

field() { [[ "$QUIET" -eq 1 ]] || printf "  ${GY}%-18s${NC} %s\n" "$1" "$2" >&2; }

sep()   { line "${GY}$(printf '%.0s─' {1..56})${NC}"; }

# die <message> [exit-code]  — single error path.
die() {
    local msg="$1" code="${2:-$EX_ERROR}"
    echo -e "\n  ${RD}Error:${NC} $msg\n" >&2
    exit "$code"
}

is_tty() { [[ -t 0 && -t 2 ]]; }

# Spinners/prompts only for interactive humans.
fancy()  { is_tty && [[ "$QUIET" -eq 0 ]]; }

spinner() {
    local msg="$1" pid=$2 chars='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏' i=0 rc=0
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r  ${CY}%s${NC} %-46s" "${chars:$((i%9)):1}" "$msg" >&2
        sleep 0.1; i=$(( i + 1 ))
    done
    wait "$pid" 2>/dev/null || rc=$?
    printf "\r\033[K" >&2
    if [[ $rc -eq 0 ]]; then step "$msg"; else line "${RD}  ✗${NC} $msg"; fi
    return $rc
}

# run <label> <cmd...> — required step: spinner on a TTY, plain logs otherwise.
run() {
    local label="$1"; shift
    if fancy; then
        ( "$@" ) >/dev/null 2>&1 &
        spinner "$label" $! || die "Step failed: $label"
    else
        "$@" >/dev/null 2>&1 || die "Step failed: $label"
        step "$label"
    fi
}

# try_run <label> <cmd...> — best-effort step: warns instead of dying.
try_run() {
    local label="$1"; shift
    if fancy; then
        ( "$@" ) >/dev/null 2>&1 &
        spinner "$label" $! || { warn "$label — failed (continuing)"; return 1; }
    else
        if "$@" >/dev/null 2>&1; then step "$label"; else
            warn "$label — failed (continuing)"; return 1
        fi
    fi
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
        printf "  ${WH}%-24s${NC} ${GY}[%s]${NC} : " "$label" "$default" >&2
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
        printf "  %s [${GR}Y${NC}/n] : " "$1" >&2
        read -r c
        [[ ! "$c" =~ ^[Nn]$ ]]
    else
        printf "  %s [y/${GR}N${NC}] : " "$1" >&2
        read -r c
        [[ "$c" =~ ^[Yy]$ ]]
    fi
}

# Explicit-yes prompt (default NO) for destructive extras like deleting data.
confirm_no() {
    [[ "$YES" -eq 1 ]] && return 1
    is_tty || return 1
    printf "  %s [y/${GR}N${NC}] : " "$1" >&2
    local c=""
    read -r c
    [[ "$c" =~ ^[Yy]$ ]]
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
        step "Backup saved: $file"
    else
        umask "$old_umask"
        warn "Backup failed for $src — continuing anyway"
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

env_get() {  # env_get FILE KEY → value
    [[ -f "$1" ]] || return 0
    # A file we can see but cannot read is not "no value": returning empty made
    # callers fall back to defaults that look like real data, so a healthy node
    # reported itself broken and exited 0 — worse than an error, because it
    # invites someone to repair a working box.
    [[ -r "$1" ]] || die "Cannot read $1 — run with sudo." "$EX_ERROR"
    awk -F= -v k="$2" '$1 == k { sub(/^[^=]*=/, ""); print; exit }' "$1" | tr -d '\r'
}

env_set() {  # env_set FILE KEY VALUE — rewrite one line, atomically
    local file="$1" key="$2" value="$3" tmp
    if [[ ! -f "$file" ]]; then
        printf '%s=%s\n' "$key" "$value" >> "$file"
        return 0
    fi
    tmp="$(mktemp "${file}.XXXXXX")" || die "Could not create a temp file next to $file"
    ENV_K="$key" ENV_V="$value" awk '
        BEGIN { k = ENVIRON["ENV_K"]; v = ENVIRON["ENV_V"]; done = 0 }
        index($0, k "=") == 1 { if (!done) { print k "=" v; done = 1 } ; next }
        { print }
        END { if (!done) print k "=" v }
    ' "$file" > "$tmp" || { rm -f "$tmp"; die "Could not update $file"; }
    chmod --reference="$file" "$tmp" 2>/dev/null || chmod 600 "$tmp"
    chown --reference="$file" "$tmp" 2>/dev/null || true
    mv -f "$tmp" "$file"
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
    warn "systemctl $action $unit did not finish in ${STOP_TIMEOUT}s — forcing it"
    systemctl kill -s SIGKILL "$unit" >/dev/null 2>&1 || true
    sleep 1
    if [[ "$action" == "restart" ]]; then
        timeout "$STOP_TIMEOUT" systemctl start "$unit" 2>/dev/null || true
    fi
    return 0
}

# Boxed menu when whiptail is already installed; colored menu otherwise.
tui_select() {  # tui_select "Title" tag label [tag label ...] → prints the tag
    local title="$1"; shift
    local tags=() labels=() tag i=0
    while [[ $# -ge 2 ]]; do tags+=("$1"); labels+=("$2"); shift 2; done
    if command -v whiptail >/dev/null 2>&1 && is_tty; then
        local args=() out
        for tag in "${tags[@]}"; do args+=("$tag" "${labels[$i]}"); i=$((i + 1)); done
        out="$(whiptail --title "$title" --menu "Choose an action" 24 78 12 "${args[@]}" 3>&1 1>&2 2>&3)" && {
            printf '%s' "$out"
            return 0
        }
        return 0
    fi
    line "${B}${title}${NC}"; line ""
    i=0
    for tag in "${tags[@]}"; do
        i=$((i + 1))
        printf '  %b%d%b)  %s\n' "$WH" "$i" "$NC" "${labels[$((i - 1))]}" >&2
    done
    line ""
    local choice; choice="$(ask "Select" "1")"
    [[ "$choice" =~ ^[0-9]+$ ]] || { printf '%s' "${tags[0]}"; return 0; }
    printf '%s' "${tags[$(((choice - 1) % ${#tags[@]}))]}"
}

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
        step "Self-signed certificate already present — reusing it"
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
    step "Self-signed certificate generated"
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
            step "Existing certificate valid for ${days_left} more days"
            TLS_KEY="$outdir/privkey.pem"; TLS_CERT="$outdir/fullchain.pem"
            return 0
        fi
        warn "Certificate expires soon (${days_left}d) — renewing..."
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
    step "Certificate installed to $outdir"
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
            step "Custom certificate installed to $out"
            ;;
    esac
}

# ── Misc helpers (kv is manager-only) ──────────────────────────────────
kv() { [[ "$QUIET" -eq 1 ]] || printf "  ${GY}%-18s${NC} %s\n" "$1" "$2" >&2; }
primary_ip() { hostname -I 2>/dev/null | awk '{print $1}'; }

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
    step "Snapshot  $file"
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
