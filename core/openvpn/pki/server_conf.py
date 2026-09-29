# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""server.conf generation/hardening and the shared client template."""

import os
import secrets

from core.logger import logger
from core.openvpn import dns as dns_policy
from core.openvpn import ipv6 as ipv6_policy
from core.openvpn import pki as _pki


def ensure_mgmt_password() -> str:
    """Create the mgmt password file (0600) if missing; return its path."""
    try:
        if os.path.exists(_pki.MGMT_PASS_FILE):
            os.chmod(_pki.MGMT_PASS_FILE, 0o600)
            with open(_pki.MGMT_PASS_FILE, encoding="utf-8") as f:
                if f.read().strip():
                    return _pki.MGMT_PASS_FILE
        os.makedirs(os.path.dirname(_pki.MGMT_PASS_FILE), exist_ok=True)
        pw = secrets.token_hex(32)
        with open(_pki.MGMT_PASS_FILE, "w", encoding="utf-8") as f:
            f.write(pw + "\n")
        os.chmod(_pki.MGMT_PASS_FILE, 0o600)
        logger.info("Management password created at %s", _pki.MGMT_PASS_FILE)
    except Exception as e:
        logger.error("Could not ensure mgmt password file: %s", e)
    return _pki.MGMT_PASS_FILE


def mgmt_line() -> str:
    """Canonical management directive with password file."""
    try:
        port = _pki._management_port()
    except Exception:
        port = 7505
    return f"management 127.0.0.1 {port} {_pki.MGMT_PASS_FILE}"


# ── server.conf ──────────────────────────────────────────────────────

_SERVER_CONF_HARDENING = None  # built lazily (needs runtime user/group)


def _hardening_directives() -> list[str]:
    """Directives appended to EXISTING configs to bring them up to date.

    Never removes or overwrites admin choices — only adds what is missing.
    """
    _pki.ensure_mgmt_password()
    return [
        "tls-version-min 1.2",
        "remote-cert-tls client",
        _pki.mgmt_line(),
        f"writepid {_pki.PID_FILE}",
        "script-security 2",
        "status-version 3",
    ]


def _fresh_proto() -> str:
    """Fresh-install transport: udp when requested, else tcp.

    Only consulted when generating a NEW server.conf / client template —
    existing files are never rewritten (change_config() owns later flips).
    """
    try:
        choice = str(_pki._env("proto", "tcp")).strip().lower()
    except Exception:
        choice = "tcp"
    return "udp" if choice.startswith("udp") else "tcp"


def _fresh_server_conf() -> str:
    """Modern hardened server.conf template for new installs."""
    _pki.ensure_mgmt_password()
    port = _pki._openvpn_port()
    proto = _pki._fresh_proto()
    # Panel-managed DNS state wins over installer defaults, so a node whose
    # server.conf gets regenerated keeps the operator's chosen resolvers.
    dns_lines = [
        f'push "dhcp-option DNS {server}"' for server in dns_policy.effective(_pki._vpn_dns())
    ]
    user, group = _pki._runtime_user(), _pki._runtime_group()
    lines = [
        f"port {port}",
        f"proto {proto}",
        "dev tun",
        "topology subnet",
        f"server {_pki._vpn_network()} {_pki._vpn_netmask()}",
        # Flush the persisted pool every 10 min: ipp.txt otherwise grows
        # forever (every CN ever seen), slowing pool allocation on restart.
        f"ifconfig-pool-persist {os.path.join(_pki._OPENVPN_ROOT, 'server', 'ipp.txt')} 600",
        'push "redirect-gateway def1 bypass-dhcp"',
        *dns_lines,
        'push "block-outside-dns"',
    ]
    # Panel-managed IPv6 state wins over the installer/env default, exactly
    # like the DNS push lines above.
    ipv6_enabled, ipv6_prefix = ipv6_policy.effective()
    if ipv6_enabled:
        lines += ipv6_policy.block_lines(ipv6_prefix)
    lines += [
        # 10s ping, 60s dead-time: dynamic-IP corpses are reaped fast enough
        # for the connect-hook takeover to matter. Existing installs keep
        # their value — the tune-up pass never rewrites keepalive.
        "keepalive 10 60",
        f"ca {_pki.CA_CERT}",
        f"cert {_pki.SERVER_CERT}",
        f"key {os.path.join(_pki.PKI_DIR, 'private', 'server.key')}",
        # ECDHE negotiates the key exchange; no static DH file needed.
        "dh none",
        f"tls-crypt {_pki.TLS_KEY}",
        # Fresh installs require TLS 1.3 (2.6+). Existing installs keep
        # their value — the tune-up pass never rewrites tls-version lines.
        "tls-version-min 1.3",
        "remote-cert-tls client",
        "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305",
        "data-ciphers-fallback AES-256-GCM",
        "auth SHA256",
        # No `cipher` / `ncp-ciphers`: deprecated since 2.5/2.6, only
        # data-ciphers negotiates.
        # PPPoE/LTE-safe MTU + roomy socket buffers for single-flow speed.
        "mssfix 1360",
        "tun-mtu 1500",
        "sndbuf 393216",
        "rcvbuf 393216",
        # Compression stays off explicitly (post-VORACLE default).
        "allow-compression no",
        f"user {user}",
        f"group {group}",
        "persist-key",
        "persist-tun",
        "script-security 2",
        f"client-connect {os.path.join(_pki.SCRIPTS_DIR, 'ovnode-client-connect.sh')}",
        f"client-disconnect {os.path.join(_pki.SCRIPTS_DIR, 'ovnode-client-disconnect.sh')}",
        f"client-config-dir {os.path.join(_pki._OPENVPN_ROOT, 'ccd')}",
        f"crl-verify {_pki.CRL_FILE}",
        f"status {os.path.join(_pki._OPENVPN_ROOT, 'server', 'status.log')} 5",
        "status-version 3",
        _pki.mgmt_line(),
        f"writepid {_pki.PID_FILE}",
        f"log-append {os.path.join(_pki._OPENVPN_ROOT, 'server', 'openvpn.log')}",
        # verb 2 on fresh installs: verb 3 logs every handshake at scale.
        # Existing installs keep their level — the tune-up never rewrites it.
        "verb 2",
        "mute 20",
        f"explicit-exit-notify {1 if proto == 'udp' else 0}",
        "duplicate-cn",
        f"max-clients {_pki._max_clients()}",
        f"cd {os.path.join(_pki._OPENVPN_ROOT, 'server')}",
    ]
    if proto == "udp":
        # fast-io is UDP-only (the daemon warns on TCP); fresh installs only.
        lines.append("fast-io")
    return "\n".join(lines) + "\n"


def _ensure_server_conf() -> bool:
    """Write a fresh hardened server.conf, or tune an existing one up.

    Single writer for server.conf directives (fresh + tune-up): PKI/TLS
    hardening AND the multi-login hook directives. Previously a second
    patcher in multilogin.py re-scanned the same file, making restarts
    order-dependent. Returns True when the file changed.
    """
    if not os.path.exists(_pki.SERVER_CONF):
        # Atomic: a crash mid-write must not leave a truncated server.conf,
        # which is the only copy and the file OpenVPN refuses to start on.
        _pki.write_text_atomic(_pki.SERVER_CONF, _pki._fresh_server_conf())
        logger.info("Created hardened server.conf")
        return True

    # Existing config → idempotent, non-destructive hardening pass.
    try:
        with open(_pki.SERVER_CONF, encoding="utf-8") as f:
            content = f.read()
        lines = content.splitlines()
        # Multi-login hooks (single writer — replaces multilogin._patch_server_conf):
        # repoint stale script paths in place, then ensure the hook directives
        # and duplicate-cn exist. The connect script enforces max_logins.
        connect_dst = os.path.join(_pki.SCRIPTS_DIR, "ovnode-client-connect.sh")
        disconnect_dst = os.path.join(_pki.SCRIPTS_DIR, "ovnode-client-disconnect.sh")
        hook_targets = {"client-connect": connect_dst, "client-disconnect": disconnect_dst}
        repointed_hooks = False
        for i, ln in enumerate(lines):
            parts = ln.strip().split()
            if (
                len(parts) == 2
                and parts[0] in hook_targets
                and "ovnode-client-" in parts[1]
                and parts[1] != hook_targets[parts[0]]
            ):
                lines[i] = f"{parts[0]} {hook_targets[parts[0]]}"
                repointed_hooks = True
        existing = {ln.strip() for ln in lines}
        to_add = [d for d in _pki._hardening_directives() if d not in existing]
        for d in (
            f"client-connect {connect_dst}",
            f"client-disconnect {disconnect_dst}",
            "duplicate-cn",
        ):
            if d not in existing:
                to_add.append(d)
        # crl-verify must always be present (revocation enforcement).
        crl = f"crl-verify {_pki.CRL_FILE}"
        if crl not in existing:
            to_add.append(crl)
        # A status log with the machine-readable layout is required by the
        # connect script and traffic parser.
        if not any(ln.strip().startswith("status ") for ln in lines):
            to_add.append(f"status {os.path.join(_pki._OPENVPN_ROOT, 'server', 'status.log')} 5")
        # If an existing `dh <path>` references a file that no longer exists
        # (e.g. the PKI was re-initialized), replace it with `dh none` so the
        # config keeps loading (ECDHE needs no static DH). Files that exist
        # are left untouched. An outdated status-version (1/2) is upgraded in
        # place: the enforcement hooks parse the tab-separated version 3.
        replaced_dh = False
        replaced_status = False
        removed_mgmt_client = False
        upgraded_mgmt = False
        canonical_mgmt = _pki.mgmt_line()
        out_lines = []
        for ln in lines:
            parts = ln.split()
            stripped = ln.strip()
            # Drop legacy management-client-* lines: valid only for unix sockets,
            # fatal for TCP (the current management) — see OpenVPN error
            # "management-client-(user|group) can only be used on unix domain sockets".
            if stripped.startswith("management-client-"):
                removed_mgmt_client = True
                continue
            # Upgrade legacy passwordless `management 127.0.0.1 <port>` to the
            # password-protected form. Exact canonical line is kept as-is.
            if stripped.startswith("management ") and stripped != canonical_mgmt:
                out_lines.append(canonical_mgmt)
                upgraded_mgmt = True
                to_add = [d for d in to_add if d != canonical_mgmt]
                continue
            if stripped.startswith("status-version") and stripped != "status-version 3":
                out_lines.append("status-version 3")
                replaced_status = True
                to_add = [d for d in to_add if d != "status-version 3"]
                continue
            if (
                len(parts) >= 2
                and parts[0] == "dh"
                and parts[1] != "none"
                and not os.path.exists(parts[1])
            ):
                out_lines.append("dh none")
                replaced_dh = True
                logger.warning("Replaced missing dh file %s with 'dh none'", parts[1])
            else:
                out_lines.append(ln)
        changed = (
            replaced_dh
            or replaced_status
            or removed_mgmt_client
            or upgraded_mgmt
            or repointed_hooks
            or bool(to_add)
        )
        if to_add:
            if out_lines and out_lines[-1].strip() != "":
                out_lines.append("")
            out_lines.append("# ovnode hardening")
            out_lines.extend(to_add)
        if changed:
            _pki.write_text_atomic(_pki.SERVER_CONF, "\n".join(out_lines) + "\n")
            logger.info("Hardened existing server.conf (added: %s)", to_add)
        return changed
    except OSError as e:
        logger.error("Could not harden server.conf: %s", e)
        return False


# ── client template ──────────────────────────────────────────────────


def _ensure_client_template() -> None:
    """Write client-common.txt if missing (tunnel address filled by panel)."""
    if os.path.exists(_pki.CLIENT_TEMPLATE):
        return
    port = _pki._openvpn_port()
    proto = _pki._fresh_proto()
    tunnel_addr = os.getenv("TUNNEL_ADDRESS", "").strip()
    if not tunnel_addr:
        # Never ship the "UPDATE_VIA_PANEL" placeholder to a client: fall
        # back to this node's own public address so the profile is usable
        # immediately; the panel overwrites it whenever it pushes config.
        tunnel_addr = _pki._node_public_ip()
    content = f"""client
dev tun
proto {proto}
{_pki._remote_lines(tunnel_addr, port)}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
tls-version-min 1.3
auth SHA256
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
data-ciphers-fallback AES-256-GCM
verb 2
"""
    with open(_pki.CLIENT_TEMPLATE, "w", encoding="utf-8") as f:
        f.write(content)
    logger.info("Created client-common.txt")
