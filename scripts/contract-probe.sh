#!/usr/bin/env bash
# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT
#
# Contract probe: check that a running node answers every route the OVManager
# panel calls, with the response keys the panel reads.
#
# The panel is the client; this script is the panel's expectations written
# down. Each route is checked twice: the status code, and the presence of the
# data keys the panel dereferences. A node that answers 200 with the wrong
# shape fails here, not in the panel's dashboard.
#
#   scripts/contract-probe.sh [--url https://host:2083] [--key KEY]
#
# The key comes from the node's .env (or --key). The writes use a
# throwaway id, so the probe leaves nothing behind.
set -uo pipefail

URL="https://127.0.0.1:2083"
KEY="${OVNODE_API_KEY:-}"
PROBE_ID="contract-probe"
PANEL_ID="${OVNODE_PANEL_ID:-}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --url)  URL="$2"; shift 2 ;;
        --key)  KEY="$2"; shift 2 ;;
        --panel-id) PANEL_ID="$2"; shift 2 ;;
        --help|-h)
            sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

if [[ -z "$KEY" && -r /opt/ovnode/.env ]]; then
    KEY="$(grep -E '^API_KEY=' /opt/ovnode/.env | head -1 | cut -d= -f2-)"
fi

CURL=(curl -sk --max-time 10)
if [[ -n "$KEY" ]]; then CURL+=(-H "key: ${KEY}"); fi
# The panel sends its identity, and the node leases itself to one panel. A
# probe without an identity is refused with 409 as soon as the node has ever
# been paired, which is the correct behaviour — not something to work around.
if [[ -n "$PANEL_ID" ]]; then CURL+=(-H "X-Panel-ID: ${PANEL_ID}"); fi

pass=0
fail=0

# check <label> <expected-status> <method> <path> <body|-> [data-key ...]
#
# The data-key arguments are keys of the response's `data` object. A key of
# "raw" means the body is not an envelope and is checked literally.
check() {
    local label="$1" want="$2" method="$3" path="$4" body="$5"
    shift 5
    local -a args=(-o - -w $'\n%{http_code}' -X "$method")
    [[ "$body" != "-" ]] && args+=(--data-binary "$body" -H "Content-Type: application/json")
    local raw status
    raw="$("${CURL[@]}" "${args[@]}" "${URL}${path}" 2>/dev/null)"
    status="${raw##*$'\n'}"
    local response="${raw%$'\n'*}"

    local problems=()
    [[ "$status" == "$want" ]] || problems+=("status ${status}, want ${want}")

    if [[ "$want" == "200" ]]; then
        for key in "$@"; do
            [[ "$key" == "-" ]] && continue
            if [[ "$key" == "raw" ]]; then
                # The .ovpn download is a raw body: the panel requires it to
                # start with "client" or to carry a <ca> block.
                if ! grep -qE '^(client|<ca>)' <<<"$response"; then
                    problems+=("body is not a client profile")
                fi
                continue
            fi
            # A fixed-string hunt, not a JSON parse: the probe must not need
            # jq, and a key present in the data object is present for the
            # panel too.
            if ! grep -qF "\"${key}\"" <<<"$response"; then
                problems+=("data ${key} missing")
            fi
        done
    fi

    if [[ ${#problems[@]} -eq 0 ]]; then
        printf '  ok   %-24s %-46s %s\n' "$label" "$method $path" ""
        pass=$((pass + 1))
    else
        printf '  FAIL %-24s %-46s %s\n' "$label" "$method $path" "${problems[*]}"
        fail=$((fail + 1))
    fi
}

echo "Contract probe against ${URL}"

# Unauthenticated: the health probe answers without a key.
check "health" 200 GET /sync/health -

# Authenticated routes. The listed keys are the ones the panel dereferences.
# The list mirrors the panel's own contract table
# (OVManager internal/node/contract.go), which is the authority: a key the
# panel never reads is not worth a node field, and a key the panel reads but
# the node omits is a silent zero in the panel's dashboard.
check "status" 200 GET /sync/status - version cpu_usage memory_usage cert_expiry
check "usage" 200 GET /sync/usage - totals
check "sessions" 200 GET "/sync/sessions?hours=8" - \
    live_sessions stale_markers live_count stale_marker_count \
    auth_errors auth_errors_by_cn rejects policy_rejects warn_rejects \
    events last_error
check "logs" 200 GET "/sync/logs?level=WARNING&limit=10" - \
    records last_error errors_1h
check "config" 200 GET /sync/config - port proto tunnel_address

# Item-level keys: the panel reads these inside a list entry, so a list that
# is present but empty cannot be checked here. The log records are asked for
# at INFO because a healthy node has no warnings to show, and an empty list
# would then hide the keys the panel needs.
check "session item keys" 200 GET "/sync/sessions?hours=8" - common_name cn ts action severity reason ongoing
check "log item keys" 200 GET "/sync/logs?level=INFO&limit=10" - level time message where

# Writes use an id that does not exist yet: the node must answer inside the
# envelope, not hang or fail with a 500 on a missing user.
check "create user" 200 POST /sync/user \
    "{\"id\":\"${PROBE_ID}\",\"name\":\"${PROBE_ID}\",\"max_logins\":1}" -
check "change status" 200 PUT /sync/user \
    "{\"id\":\"${PROBE_ID}\",\"status\":\"activate\"}" -
check "set limit" 200 PUT /sync/user/limit \
    "{\"id\":\"${PROBE_ID}\",\"max_logins\":1}" -
check "bulk limits" 200 POST /sync/users \
    "{\"users\":[{\"id\":\"${PROBE_ID}\",\"max_logins\":1}]}" applied failed
# The download comes BEFORE the delete: the profile is the user's, and a
# deleted user has none.
check "download ovpn" 200 GET "/sync/download/ovpn/${PROBE_ID}" - raw
check "disconnect" 200 POST "/sync/user/${PROBE_ID}/disconnect" - \
    removed_markers killed_sessions
check "reset usage" 200 POST "/sync/user/${PROBE_ID}/reset-usage" - -
check "delete user" 200 DELETE "/sync/user/${PROBE_ID}" - -

echo
echo "passed ${pass}, failed ${fail}"
[[ $fail -eq 0 ]]
