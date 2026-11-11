#!/usr/bin/env bash
# shellcheck disable=SC2329
# Real-host smoke test for a fresh OVNode install. Run as root.
set -uo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "This smoke test must run as root." >&2
    exit 2
fi

PORT="${PORT:-2083}"
AppDir="${AppDir:-/opt/ovnode}"
KEY="$(grep '^ApiKey=' "${AppDir}/.env" 2>/dev/null | head -n 1 | cut -d= -f2-)"
BASE="https://127.0.0.1:${PORT}"

if [[ -t 1 ]]; then
    GREEN=$'\033[32m'
    RED=$'\033[31m'
    RESET=$'\033[0m'
else
    GREEN=''
    RED=''
    RESET=''
fi

failures=0

check() {
    local name="$1"
    shift
    if "$@"; then
        printf '%sPASS %s%s\n' "${GREEN}" "${name}" "${RESET}"
    else
        printf '%sFAIL %s%s\n' "${RED}" "${name}" "${RESET}"
        failures=$((failures + 1))
    fi
}

for cmd in curl jq openssl iptables; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        echo "Missing required command: ${cmd}" >&2
        exit 2
    fi
done

API() {
    curl -sk --max-time 20 -H "key: ${KEY}" "$@"
}

check_health() {
    local body
    body="$(curl -sk --max-time 20 "${BASE}/sync/health")"
    jq -e '.success == true' <<<"${body}" >/dev/null 2>&1
}

check_status() {
    local body
    body="$(API "${BASE}/sync/status")"
    jq -e '.success == true and .data.openvpn_running == true and (.data.crl_days_remaining | type == "number")' <<<"${body}" >/dev/null 2>&1
}

check_wrong_key_401() {
    local code
    code="$(curl -sk --max-time 20 -o /dev/null -w '%{http_code}' -H 'key: definitely-wrong' "${BASE}/sync/status")"
    [[ "${code}" == "401" ]]
}

check_create_user() {
    local body
    body="$(API -X POST -H 'Content-Type: application/json' -d '{"id":"smoke1053","name":"smoke","max_logins":1}' "${BASE}/sync/user")"
    jq -e '.success == true' <<<"${body}" >/dev/null 2>&1
}

check_download_ovpn() {
    local body
    body="$(API "${BASE}/sync/download/ovpn/smoke1053")"
    grep -q '<ca>' <<<"${body}" && grep -q '<key>' <<<"${body}"
}

check_revocation() {
    API -X DELETE "${BASE}/sync/user/smoke1053" >/dev/null 2>&1 || true
    API -X POST -H 'Content-Type: application/json' -d '{"id":"smoke1053","name":"smoke","max_logins":1}' "${BASE}/sync/user" >/dev/null 2>&1 || true
    API -X DELETE "${BASE}/sync/user/smoke1053" >/dev/null 2>&1 || true

    if grep -q '^V.*/CN=smoke1053' /etc/openvpn/server/pki/index.txt; then
        return 1
    fi

    local count
    count="$(openssl crl -in /etc/openvpn/server/pki/crl.pem -noout -text 2>/dev/null | grep -c 'Serial Number' || true)"
    [[ "${count}" -ge 2 ]]
}

check_config_noop() {
    local cfg port proto before after
    cfg="$(API "${BASE}/sync/config")"
    port="$(jq -r '.data.port' <<<"${cfg}")"
    proto="$(jq -r '.data.proto' <<<"${cfg}")"

    before="$(journalctl -u ovnode-openvpn -u openvpn-server@server --since '-1min' 2>/dev/null | grep -ci 'SIGHUP' || true)"

    API -X POST -H 'Content-Type: application/json' \
        -d "{\"ovpn_port\":${port},\"protocol\":\"${proto}\",\"set_new_setting\":true}" \
        "${BASE}/sync/config" >/dev/null 2>&1 || true
    API -X POST -H 'Content-Type: application/json' \
        -d "{\"ovpn_port\":${port},\"protocol\":\"${proto}\",\"set_new_setting\":true}" \
        "${BASE}/sync/config" >/dev/null 2>&1 || true

    after="$(journalctl -u ovnode-openvpn -u openvpn-server@server --since '-1min' 2>/dev/null | grep -ci 'SIGHUP' || true)"

    [[ "${after}" -le "${before}" ]]
}

check_reserved_port() {
    local body
    body="$(API -X POST -H 'Content-Type: application/json' -d '{"ovpn_port":22,"protocol":"udp","set_new_setting":true}' "${BASE}/sync/config")"
    jq -e '.success == false' <<<"${body}" >/dev/null 2>&1
}

check_nat() {
    local cfg port proto body
    cfg="$(API "${BASE}/sync/config")"
    port="$(jq -r '.data.port' <<<"${cfg}")"
    proto="$(jq -r '.data.proto' <<<"${cfg}")"

    body="$(API -X POST -H 'Content-Type: application/json' \
        -d "{\"ovpn_port\":${port},\"protocol\":\"${proto}\",\"extra_ports\":\"8443\",\"set_new_setting\":true}" \
        "${BASE}/sync/config")"
    jq -e '.success == true' <<<"${body}" >/dev/null 2>&1 || return 1

    if ! iptables -t nat -S PREROUTING 2>/dev/null | grep 'ovnode-redirect' | grep -q '8443'; then
        return 1
    fi

    body="$(API -X POST -H 'Content-Type: application/json' \
        -d "{\"ovpn_port\":${port},\"protocol\":\"${proto}\",\"extra_ports\":\"\",\"set_new_setting\":true}" \
        "${BASE}/sync/config")"
    jq -e '.success == true' <<<"${body}" >/dev/null 2>&1 || return 1

    if iptables -t nat -S PREROUTING 2>/dev/null | grep 'ovnode-redirect' | grep -q '8443'; then
        return 1
    fi
    return 0
}

check_permissions() {
    [[ "$(stat -c '%a' /etc/openvpn/server/tls.key 2>/dev/null)" == "600" ]] &&
        [[ "$(stat -c '%a' /etc/openvpn/server/pki/private 2>/dev/null)" == "700" ]]
}

check_rate_lock() {
    local code last=''
    for _ in {1..12}; do
        code="$(curl -sk --max-time 20 -o /dev/null -w '%{http_code}' -H 'key: definitely-wrong' "${BASE}/sync/status")"
        last="${code}"
    done
    [[ "${last}" == "429" ]]
}

check "health endpoint" check_health
check "status endpoint" check_status
check "wrong key is 401" check_wrong_key_401
check "create user" check_create_user
check "download ovpn" check_download_ovpn
check "revocation re-issue" check_revocation
check "config no-op" check_config_noop
check "reserved port rejected" check_reserved_port
check "NAT redirect" check_nat
check "secret permissions" check_permissions
check "rate limit lockout" check_rate_lock

echo "Note: the smoke-test IP is now blocked for about 5 minutes; a correct request from this IP will also return 429 until then."

if (( failures > 0 )); then
    echo "${failures} check(s) failed."
    exit 1
fi

echo "All smoke checks passed."
exit 0
