#!/usr/bin/env bash
# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT
#
# The node health check, collected then rendered.
#
# It used to print a row as it walked each check, so thirteen passing checks
# spent sixteen lines saying the word "ok" and a single failure sat at position
# five, buried under eight rows that were fine. That is the screen nobody reads,
# which is the worst property a diagnostic can have.
#
# Now every check reports into a buffer and nothing is printed until the last one
# has run. Two things fall out of that:
#
#   * Failures can go first. They are the reason the command was typed.
#   * A check that dies mid-way no longer leaves a half-printed report that reads
#     like a result. Either the whole picture is there or none of it is.
#
# --fix is therefore a second phase rather than something interleaved: the
# report describes what is true when it is printed, not what was true before the
# first restart.

# doctor_add <name> <ok|bad> <detail> [fix]
#
# Buffered, never printed. The four fields are separated by $'\x1f' because a
# check detail can contain spaces, colons and dashes, and a delimiter chosen for
# legibility would eventually appear inside a value.
doctor_add() {
    DOCTOR_NAME+=("$1")
    DOCTOR_OK+=("$2")
    DOCTOR_DETAIL+=("$3")
    DOCTOR_FIX+=("${4:-}")
}

doctor_reset() {
    DOCTOR_NAME=(); DOCTOR_OK=(); DOCTOR_DETAIL=(); DOCTOR_FIX=()
}

# Run one check, and if --fix was asked for, try the repair and re-run just that
# check to find out whether the repair worked.
#
# Re-checking only the repaired check is the point: re-running the whole suite
# would double every wait_health probe, and a diagnostic that takes twice as
# long is one people stop running.
# Run one check and buffer the result. Always returns zero.
#
# A failure is a finding, not an error. `manager.sh` runs under an ERR trap that
# aborts on any non-zero command, and that trap is inherited into command
# substitutions — so a check whose last statement is a failing test both killed
# its own subshell before the detail was flushed and tripped the trap in the
# caller. `trap - ERR` inside the substitution is what keeps the two apart.
doctor_check() {  # doctor_check <name> <fix-command> <fix-function> <check-function>
    local name="$1" fix_cmd="$2" fix_fn="$3" check_fn="$4"
    local detail
    if detail="$( { trap - ERR; "$check_fn"; } 2>/dev/null )"; then
        doctor_add "$name" ok "$detail"
        return 0
    fi
    # The check failed but its detail is what the reader needs, and the non-zero
    # return above discarded it. Run it again, ignoring the status, to get it.
    detail="$( { trap - ERR; "$check_fn"; } 2>/dev/null || true)"
    if [[ "$FIX" -eq 1 && -n "$fix_fn" ]]; then
        render_line "  fixing ${name}…"
        if "$fix_fn" >/dev/null 2>&1 && detail="$( { trap - ERR; "$check_fn"; } 2>/dev/null )"; then
            doctor_add "$name" ok "$detail — fixed"
            return 0
        fi
        detail="$( { trap - ERR; "$check_fn"; } 2>/dev/null || true)"
    fi
    doctor_add "$name" bad "$detail" "$fix_cmd"
    return 0
}

# ── The checks ────────────────────────────────────────────────────────
# Each returns the detail string on success and fails (non-zero) on a problem,
# so doctor_check can tell the two apart without a second return channel.

chk_agent() {
    local a
    if is_docker_node; then printf 'docker'; return 0; fi
    if has_systemd; then a="$(systemctl is-active "$SYSTEMD_SERVICE" 2>/dev/null || echo unknown)"
    else printf 'no systemd'; return 0; fi
    printf '%s' "$a"
    [[ "$a" == "active" ]]
}

chk_vpn() {
    local a
    if is_docker_node; then printf 'in-container'; return 0; fi
    if has_systemd; then a="$(systemctl is-active openvpn-server@server 2>/dev/null || echo unknown)"
    else printf 'no systemd'; return 0; fi
    printf '%s' "$a"
    [[ "$a" == "active" ]]
}

chk_disk() {
    local d
    # ${d:-0} rather than `|| echo 0`: a failed substitution yields an empty
    # string, not a non-zero status, so `(( d < 80 ))` would read as a pass on a
    # box where the disk could not be measured at all.
    d="$(df "$DATA_BASE" 2>/dev/null | awk 'NR==2 {print $5}' | tr -d '%')"
    [[ -n "$d" ]] || { printf 'could not measure %s' "$DATA_BASE"; return 1; }
    printf '%s%% used on %s' "$d" "$DATA_BASE"
    (( d < 80 ))
}

chk_api() {
    local port tls scheme
    port="$(env_get "$APP_DIR/.env" SERVICE_PORT)"; : "${port:=$DEFAULT_PORT}"
    tls="$(env_get "$APP_DIR/.env" TLS_METHOD)"; : "${tls:=selfsigned}"
    scheme="http"; [[ "$tls" != "none" ]] && scheme="https"
    if wait_health "${scheme}://127.0.0.1:${port}/sync/health" 5; then
        printf 'ok'
    else
        printf 'unreachable'
        return 1
    fi
}

chk_cert() {
    local cert days
    cert="$(env_get "$APP_DIR/.env" SSL_CERTFILE)"; : "${cert:=/etc/ssl/self-signed/fullchain.pem}"
    [[ -f "$cert" ]] || { printf 'not found at %s' "$cert"; return 1; }
    days=$(( ($(date -d "$(openssl x509 -enddate -noout -in "$cert" 2>/dev/null | cut -d= -f2)" +%s 2>/dev/null || echo 0) - $(date +%s)) / 86400 ))
    printf 'expires in %sd' "$days"
    (( days > 30 ))
}

chk_backup() {
    local newest age
    newest="$(ls -t /var/backups/node-*.tar.gz 2>/dev/null | head -1 || true)"
    [[ -n "$newest" ]] || { printf 'none yet'; return 1; }
    age=$(( ($(date +%s) - $(stat -c %Y "$newest" 2>/dev/null || echo 0)) / 86400 ))
    printf '%sd old' "$age"
    (( age <= 7 ))
}

chk_update() {
    local node_dir="$DATA_BASE/$(node_name_from_env)"
    if [[ -f "$node_dir/update-maintenance" ]]; then printf 'recovery required'; return 1; fi
    if [[ -f "$DATA_BASE/update-state.json" ]]; then
        # No python3: this may be the reason recovery is needed.
        if ! grep -q '"phase": *"\(committed\|failed_over\)"' "$DATA_BASE/update-state.json" 2>/dev/null; then
            printf 'recovery required'; return 1
        fi
    fi
    printf 'no interrupted transaction'
}

chk_snapshot() {
    local snap
    snap="$(latest_snapshot node 2>/dev/null || true)"
    [[ -n "$snap" ]] || { printf 'none yet (created on first update)'; return 0; }
    if tar -tzf "$snap" >/dev/null 2>&1; then printf 'ok'; return 0; fi
    printf 'corrupt (%s)' "$snap"
    return 1
}

# PKI expiry: a lapsed CA silently kills every client, and the API-TLS check
# above does not cover it. Reported as one check covering both certificates,
# because "renew the CA" and "renew the server cert" are the same visit.
chk_pki() {
    local dir="$OPENVPN_ROOT/server/pki" worst=0 days label file out=""
    for cert_label in "ca:ca.crt" "server:issued/server.crt"; do
        label="${cert_label%%:*}"; file="$dir/${cert_label#*:}"
        [[ -f "$file" ]] || continue
        days=$(( ($(date -d "$(openssl x509 -enddate -noout -in "$file" 2>/dev/null | cut -d= -f2)" +%s 2>/dev/null || echo 0) - $(date +%s)) / 86400 ))
        out+="${label} ${days}d, "
        (( days <= 30 )) && worst=1
    done
    [[ -n "$out" ]] || { printf 'no PKI found'; return 0; }
    printf '%s' "${out%, }"
    return $worst
}

chk_lock() {
    local pid_file="$DATA_BASE/.operation.lock/pid" pid
    [[ -d "$DATA_BASE/.operation.lock" ]] || { printf 'none'; return 0; }
    pid="$(cat "$pid_file" 2>/dev/null || true)"
    if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
        printf 'held by process %s' "$pid"
    else
        printf 'stale — safe to clear'
        return 1
    fi
}

chk_unit() {
    if is_docker_node; then printf 'n/a (container)'; return 0; fi
    if ! has_systemd; then printf 'no systemd'; return 0; fi
    if [[ -f "/etc/systemd/system/$SYSTEMD_SERVICE" ]]; then
        printf 'present'
        return 0
    fi
    printf 'missing'
    return 1
}

# ── The repairs ───────────────────────────────────────────────────────

fix_agent()   { node_service_action restart; }
fix_vpn()     { restart_vpn; }
fix_lock()    { rm -rf "$DATA_BASE/.operation.lock"; }
fix_unit()    { run_installer repair-unit; }

# ── The render ────────────────────────────────────────────────────────

doctor_render() {
    local i failed=0 passed=0
    for i in "${!DOCTOR_NAME[@]}"; do
        [[ "${DOCTOR_OK[$i]}" == "ok" ]] && passed=$((passed + 1)) || failed=$((failed + 1))
    done

    if (( failed == 0 )); then
        render_ok "no problems — ${passed} checks passed"
        render_line "    detail: ovn doctor --all"
        return 0
    fi

    # Not render_fail: that is the installer's one-line-failure shape, with a
    # cause and a "next" line for how to look. This is a heading.
    render_line "  ${RD}${RENDER_BAD}${NC} ${failed} problem$( ((failed == 1)) || printf 's')"
    render_blank
    # One label column for the whole block, so a long name pushes the column
    # rather than its own value. At a fixed width, "OpenVPN server" printed
    # whole and dropped its detail a column right of every other check's.
    local width=$RENDER_LABEL_W name
    for name in "${DOCTOR_NAME[@]}"; do
        (( ${#name} > width )) && width=${#name}
    done
    for i in "${!DOCTOR_NAME[@]}"; do
        [[ "${DOCTOR_OK[$i]}" == "ok" ]] && continue
        # printf, not render_kv: the column is computed per block, and render_kv
        # is fixed at RENDER_LABEL_W. A longer name has to push the column or
        # its own detail lands a column right of every other check's.
        printf '   %-*s %s\n' "$width" "${DOCTOR_NAME[$i]}" "${DOCTOR_DETAIL[$i]}" >&2
        [[ -n "${DOCTOR_FIX[$i]}" ]] \
            && printf '   %-*s %s\n' "$width" "fix" "${DOCTOR_FIX[$i]}" >&2
    done

    if [[ "$SHOW_ALL" -eq 1 || "$passed" -eq 0 ]]; then
        render_blank
        render_line "  all checks"
        for i in "${!DOCTOR_NAME[@]}"; do
            local mark="ok"; [[ "${DOCTOR_OK[$i]}" == "ok" ]] || mark="FAIL"
            printf '  %-*s  %s  %s\n' "$width" "${DOCTOR_NAME[$i]}" "$mark" "${DOCTOR_DETAIL[$i]}" >&2
        done
    else
        render_blank
        render_line "    ${passed} other checks passed — detail: ovn doctor --all"
    fi
    return 1
}

# ── Entry point ───────────────────────────────────────────────────────

do_doctor() {
    [[ -d "$APP_DIR" ]] || die "Not installed ($APP_DIR missing)" "$EX_NOTINSTALLED"
    # Up front, so the report is not half-printed before the error. Nothing is
    # printed until every check has run now, but .env is read by four of them
    # and failing here names the real cause instead of four symptoms.
    if [[ -f "$APP_DIR/.env" && ! -r "$APP_DIR/.env" ]]; then
        die "Cannot read $APP_DIR/.env — run with sudo." "$EX_ERROR"
    fi

    doctor_reset
    doctor_check "Agent"       "ovn restart"          fix_agent chk_agent
    doctor_check "OpenVPN"     "ovn restart core"     fix_vpn   chk_vpn
    doctor_check "Disk"        "ovn backup --keep 7, then remove old tarballs in /var/backups" "" chk_disk
    doctor_check "API"         "ovn logs 50, then ovn restart" "" chk_api
    doctor_check "Certificate" "ovn tls"              ""        chk_cert
    doctor_check "Backup"      "ovn backup"           ""        chk_backup
    doctor_check "Update"      "ovn update"           ""        chk_update
    doctor_check "Snapshot"    "ovn update (creates a fresh snapshot)" "" chk_snapshot
    doctor_check "PKI"         "renew the CA and server certificate" "" chk_pki
    doctor_check "Op lock"     "ovn doctor --fix"     fix_lock  chk_lock
    doctor_check "Unit"        "ovn doctor --fix"     fix_unit  chk_unit

    render_rule
    # Non-zero when something is wrong, so `ovn doctor` is usable in a
    # monitoring check. It was always zero, which meant a script could not tell
    # a healthy box from a broken one without reading the text.
    #
    # `|| rc=1` rather than letting the return propagate: the ERR trap would
    # print "Command failed near line ..." on top of a report that is not a
    # failure of the command, it is the report.
    local rc=0
    doctor_render || rc=1
    return "$rc"
}
