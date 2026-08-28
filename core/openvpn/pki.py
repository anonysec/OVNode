# Copyright (c) 2025 anonysec. All rights reserved.
# Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.

"""
PKI + OpenVPN configuration initialization for OVNode.

Responsibilities (all idempotent, safe to call on every startup):

* Fresh installs get a modern ECDSA (secp384r1) PKI — no slow RSA DH params
  (OpenVPN uses ECDHE, so a static ``dh`` file is unnecessary).
* A hardened ``server.conf`` is generated for new installs and *tuned up* for
  existing ones (missing hardening directives are appended, admin edits are
  never clobbered).
* ``client-common.txt`` is generated if missing (the tunnel address is filled
  in by the panel via ``/sync/config``).
* The client config builder appends the ``tls-crypt`` key inline so generated
  ``.ovpn`` files actually match the server's ``tls-crypt`` directive.
"""

import os
import subprocess

from core.logger import logger
from core.openvpn.easyrsa import run_easyrsa as _easyrsa

_OPENVPN_ROOT = os.getenv("OVNODE_OPENVPN_ROOT", "/etc/openvpn")
EASYRSA_DIR = os.path.join(_OPENVPN_ROOT, "server", "easy-rsa")
PKI_DIR = os.path.join(_OPENVPN_ROOT, "server", "pki")
SERVER_CONF = os.path.join(_OPENVPN_ROOT, "server", "server.conf")
CLIENT_TEMPLATE = os.path.join(_OPENVPN_ROOT, "server", "client-common.txt")
TLS_KEY = os.path.join(_OPENVPN_ROOT, "server", "tls.key")
CA_CERT = os.path.join(PKI_DIR, "ca.crt")
SERVER_CERT = os.path.join(PKI_DIR, "issued", "server.crt")
DH_PEM = os.path.join(PKI_DIR, "dh.pem")
CRL_FILE = os.path.join(PKI_DIR, "crl.pem")
SCRIPTS_DIR = os.path.join(_OPENVPN_ROOT, "scripts")
PID_FILE = os.path.join(_OPENVPN_ROOT, "server", "ovnode.pid")

REQUIRED_DIRS = [
    os.path.join(_OPENVPN_ROOT, "server"),
    os.path.join(_OPENVPN_ROOT, "clients"),
    os.path.join(_OPENVPN_ROOT, "ccd"),
    os.path.join(_OPENVPN_ROOT, "limits"),
    os.path.join(_OPENVPN_ROOT, "disabled"),
    os.path.join(_OPENVPN_ROOT, "ovnode-active"),
    os.path.join(_OPENVPN_ROOT, "scripts"),
]


def _env(name: str, default: str) -> str:
    """Read an OVNODE_* env var with a default (config.py is the source)."""
    try:
        from core.config import settings

        return str(getattr(settings, f"ovnode_{name}", default) or default)
    except Exception:
        return os.getenv(f"OVNODE_{name.upper()}", default)


def _runtime_user() -> str:
    return _env("runtime_user", "nobody")


def _runtime_group() -> str:
    return _env("runtime_group", "nogroup")


def _management_port() -> int:
    try:
        return int(_env("management_port", "7505"))
    except ValueError:
        return 7505


def _vpn_network() -> str:
    return _env("vpn_network", "10.8.0.0")


def _vpn_netmask() -> str:
    return _env("vpn_netmask", "255.255.255.0")


def _vpn_dns() -> tuple[str, str]:
    return _env("vpn_dns1", "1.1.1.1"), _env("vpn_dns2", "8.8.8.8")


def _max_clients() -> int:
    try:
        return max(1, int(_env("max_clients", "100")))
    except ValueError:
        return 100


def _ipv6_enabled() -> bool:
    return _env("enable_ipv6", "0").lower() in ("1", "true", "yes", "on")


def _ipv6_prefix() -> str:
    return _env("ipv6_prefix", "fd42:42:42:42::/64")


def _openvpn_port() -> int:
    try:
        return int(os.getenv("OPENVPN_PORT", "1194"))
    except ValueError:
        return 1194


def _extra_vpn_ports() -> list[int]:
    """Extra ports the node is reachable on (iptables REDIRECT → primary)."""
    from core.config import parse_extra_ports

    return parse_extra_ports(os.getenv("OVNODE_EXTRA_PORTS", ""), _openvpn_port())


def _remote_lines(tunnel_addr: str, primary_port: int) -> str:
    """One `remote` line per reachable port — clients fail over in order."""
    ports = [primary_port, *_extra_vpn_ports()]
    return "\n".join(f"remote {tunnel_addr} {p}" for p in ports)


def _openvpn_bin() -> str:
    """Locate the openvpn binary (PATH or common locations)."""
    import shutil

    found = shutil.which("openvpn")
    if found:
        return found
    for candidate in ("/usr/sbin/openvpn", "/usr/local/sbin/openvpn", "/sbin/openvpn"):
        if os.path.exists(candidate):
            return candidate
    return "openvpn"  # let subprocess raise a clear error if truly absent


# ── easy-rsa bootstrap ───────────────────────────────────────────────


def _setup_easyrsa() -> None:
    """Copy easy-rsa into place and write a modern vars file (fresh only)."""
    if os.path.exists(EASYRSA_DIR) and os.path.exists(os.path.join(EASYRSA_DIR, "easyrsa")):
        _write_easyrsa_vars()
        return
    os.makedirs(EASYRSA_DIR, exist_ok=True)
    src = "/usr/share/easy-rsa"
    if not os.path.exists(src):
        r = subprocess.run(["dpkg", "-L", "easy-rsa"], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            if line.startswith("/usr/share/easy-rsa/"):
                src = "/usr/share/easy-rsa"
                break
    if os.path.exists(src):
        subprocess.run(["cp", "-r", f"{src}/.", EASYRSA_DIR], check=True)
        os.chmod(os.path.join(EASYRSA_DIR, "easyrsa"), 0o755)
    _write_easyrsa_vars()


def _write_easyrsa_vars() -> None:
    """Write easy-rsa defaults when a vars file does not exist yet.

    Fresh PKI uses ECDSA (secp384r1): faster handshakes, smaller certs, and
    no static DH file needed. Existing installs keep their own vars file, so
    an existing RSA PKI is never disrupted.
    """
    vars_path = os.path.join(EASYRSA_DIR, "vars")
    if os.path.exists(vars_path):
        return
    try:
        with open(vars_path, "w", encoding="utf-8") as f:
            f.write(
                "# Generated by OVNode — ECDSA defaults (safe to edit)\n"
                'set_var EASYRSA_ALGO "ec"\n'
                'set_var EASYRSA_CURVE "secp384r1"\n'
                'set_var EASYRSA_BATCH "1"\n'
                'set_var EASYRSA_NO_PASS "1"\n'
                'set_var EASYRSA_CA_EXPIRE "3650"\n'
                'set_var EASYRSA_CERT_EXPIRE "1825"\n'
                'set_var EASYRSA_CRL_DAYS "365"\n'
                'set_var EASYRSA_REQ_CN "OVNode CA"\n'
            )
        logger.info("Wrote easy-rsa vars file (%s)", vars_path)
    except OSError as e:
        logger.error("Could not write easy-rsa vars: %s", e)


def _ensure_dir_tree() -> None:
    """Create all PKI subdirectories + index files needed by easy-rsa."""
    subdirs = [
        "private",
        "issued",
        "reqs",
        "certs_by_serial",
        "index.txt.attrs",
        "inline/private",
        "revoked/certs_by_serial",
        "revoked/private",
        "revoked/reqs",
        "revoked/issued",
    ]
    for subdir in subdirs:
        os.makedirs(os.path.join(PKI_DIR, subdir), exist_ok=True)
    for fname in [
        "index.txt",
        "index.txt.attr",
        "serial",
        "serial.old",
        "crlnumber",
        "crlnumber.old",
    ]:
        path = os.path.join(PKI_DIR, fname)
        if not os.path.exists(path):
            with open(path, "w") as f:
                if fname in ("serial", "crlnumber"):
                    f.write("1000\n")


def _gen_tls_key() -> None:
    """Generate the tls-crypt pre-shared key (idempotent)."""
    if os.path.exists(TLS_KEY):
        os.chmod(TLS_KEY, 0o600)
        return
    subprocess.run(
        [_openvpn_bin(), "--genkey", "secret", TLS_KEY],
        check=True,
        capture_output=True,
        timeout=60,
    )
    os.chmod(TLS_KEY, 0o600)
    logger.info("TLS-crypt key generated: %s", TLS_KEY)


# ── CRL ──────────────────────────────────────────────────────────────


def _ensure_crl() -> bool:
    """Generate the CRL when missing; keep it world-readable for OpenVPN."""
    if os.path.exists(CRL_FILE):
        try:
            os.chmod(CRL_FILE, 0o644)
        except OSError:
            pass
        return True
    if not _easyrsa("gen-crl"):
        logger.error("CRL generation failed — revoked certs may remain usable.")
        return False
    if not os.path.exists(CRL_FILE):
        logger.error("EasyRSA reported CRL success but %s was not created.", CRL_FILE)
        return False
    try:
        os.chmod(CRL_FILE, 0o644)
    except OSError:
        pass
    logger.info("Certificate revocation list ready at %s", CRL_FILE)
    return True


# ── server.conf ──────────────────────────────────────────────────────

_SERVER_CONF_HARDENING = None  # built lazily (needs runtime user/group)


def _hardening_directives() -> list[str]:
    """Directives appended to EXISTING configs to bring them up to date.

    Never removes or overwrites admin choices — only adds what is missing.
    """
    return [
        "tls-version-min 1.2",
        "remote-cert-tls client",
        f"management 127.0.0.1 {_management_port()}",
        f"management-client-user {_runtime_user()}",
        f"management-client-group {_runtime_group()}",
        f"writepid {PID_FILE}",
        "script-security 2",
        "status-version 3",
    ]


def _fresh_server_conf() -> str:
    """Modern hardened server.conf template for new installs."""
    port = _openvpn_port()
    dns1, dns2 = _vpn_dns()
    user, group = _runtime_user(), _runtime_group()
    lines = [
        f"port {port}",
        "proto tcp",
        "dev tun",
        "topology subnet",
        f"server {_vpn_network()} {_vpn_netmask()}",
        f"ifconfig-pool-persist {os.path.join(_OPENVPN_ROOT, 'server', 'ipp.txt')}",
        'push "redirect-gateway def1 bypass-dhcp"',
        f'push "dhcp-option DNS {dns1}"',
        f'push "dhcp-option DNS {dns2}"',
    ]
    if _ipv6_enabled():
        lines += [
            "tun-ipv6",
            f"server-ipv6 {_ipv6_prefix()}",
            'push "route-ipv6 2000::/3"',
        ]
    lines += [
        "keepalive 10 120",
        f"ca {CA_CERT}",
        f"cert {SERVER_CERT}",
        f"key {os.path.join(PKI_DIR, 'private', 'server.key')}",
        # ECDHE negotiates the key exchange; no static DH file needed.
        "dh none",
        f"tls-crypt {TLS_KEY}",
        "tls-version-min 1.2",
        "remote-cert-tls client",
        "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305",
        "data-ciphers-fallback AES-256-GCM",
        "auth SHA256",
        "cipher AES-256-GCM",
        "ncp-ciphers AES-256-GCM:AES-128-GCM",
        f"user {user}",
        f"group {group}",
        "persist-key",
        "persist-tun",
        "script-security 2",
        f"client-connect {os.path.join(SCRIPTS_DIR, 'ovnode-client-connect.sh')}",
        f"client-disconnect {os.path.join(SCRIPTS_DIR, 'ovnode-client-disconnect.sh')}",
        f"client-config-dir {os.path.join(_OPENVPN_ROOT, 'ccd')}",
        f"crl-verify {CRL_FILE}",
        f"status {os.path.join(_OPENVPN_ROOT, 'server', 'status.log')} 5",
        "status-version 3",
        f"management 127.0.0.1 {_management_port()}",
        f"management-client-user {user}",
        f"management-client-group {group}",
        f"writepid {PID_FILE}",
        f"log-append {os.path.join(_OPENVPN_ROOT, 'server', 'openvpn.log')}",
        "verb 3",
        "mute 20",
        "explicit-exit-notify 0",
        "duplicate-cn",
        f"max-clients {_max_clients()}",
        f"cd {os.path.join(_OPENVPN_ROOT, 'server')}",
    ]
    return "\n".join(lines) + "\n"


def _ensure_server_conf() -> None:
    """Write a fresh hardened server.conf, or tune an existing one up."""
    if not os.path.exists(SERVER_CONF):
        os.makedirs(os.path.dirname(SERVER_CONF), exist_ok=True)
        with open(SERVER_CONF, "w", encoding="utf-8") as f:
            f.write(_fresh_server_conf())
        logger.info("Created hardened server.conf")
        return

    # Existing config → idempotent, non-destructive hardening pass.
    try:
        with open(SERVER_CONF, encoding="utf-8") as f:
            content = f.read()
        lines = content.splitlines()
        existing = {ln.strip() for ln in lines}
        to_add = [d for d in _hardening_directives() if d not in existing]
        # crl-verify must always be present (revocation enforcement).
        crl = f"crl-verify {CRL_FILE}"
        if crl not in existing:
            to_add.append(crl)
        # A status log with the machine-readable layout is required by the
        # connect script and traffic parser.
        if not any(ln.strip().startswith("status ") for ln in lines):
            to_add.append(f"status {os.path.join(_OPENVPN_ROOT, 'server', 'status.log')} 5")
        # If an existing `dh <path>` references a file that no longer exists
        # (e.g. the PKI was re-initialized), replace it with `dh none` so the
        # config keeps loading (ECDHE needs no static DH). Files that exist
        # are left untouched. An outdated status-version (1/2) is upgraded in
        # place: the enforcement hooks parse the tab-separated version 3.
        replaced_dh = False
        replaced_status = False
        out_lines = []
        for ln in lines:
            parts = ln.split()
            stripped = ln.strip()
            if stripped.startswith("status-version") and stripped != "status-version 3":
                out_lines.append("status-version 3")
                replaced_status = True
                to_add = [d for d in to_add if d != "status-version 3"]
                continue
            if len(parts) >= 2 and parts[0] == "dh" and not os.path.exists(parts[1]):
                out_lines.append("dh none")
                replaced_dh = True
                logger.warning("Replaced missing dh file %s with 'dh none'", parts[1])
            else:
                out_lines.append(ln)
        changed = replaced_dh or replaced_status or bool(to_add)
        if to_add:
            if out_lines and out_lines[-1].strip() != "":
                out_lines.append("")
            out_lines.append("# ovnode hardening")
            out_lines.extend(to_add)
        if changed:
            with open(SERVER_CONF, "w", encoding="utf-8") as f:
                f.write("\n".join(out_lines) + "\n")
            logger.info("Hardened existing server.conf (added: %s)", to_add)
    except OSError as e:
        logger.error("Could not harden server.conf: %s", e)


# ── client template ──────────────────────────────────────────────────


def _ensure_client_template() -> None:
    """Write client-common.txt if missing (tunnel address filled by panel)."""
    if os.path.exists(CLIENT_TEMPLATE):
        return
    port = _openvpn_port()
    tunnel_addr = os.getenv("TUNNEL_ADDRESS", "UPDATE_VIA_PANEL")
    content = f"""client
dev tun
proto tcp
{_remote_lines(tunnel_addr, port)}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
tls-version-min 1.2
auth SHA256
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
data-ciphers-fallback AES-256-GCM
cipher AES-256-GCM
verb 3
"""
    with open(CLIENT_TEMPLATE, "w", encoding="utf-8") as f:
        f.write(content)
    logger.info("Created client-common.txt")


# ── tls-crypt key embedding for .ovpn files ─────────────────────────


def read_tls_crypt_key() -> str | None:
    """Return the tls-crypt pre-shared key, or None if unavailable."""
    try:
        with open(TLS_KEY, encoding="utf-8") as f:
            key = f.read().strip()
        return key or None
    except OSError as e:
        logger.error("Could not read tls-crypt key %s: %s", TLS_KEY, e)
        return None


def tls_crypt_block() -> str:
    """The <tls-crypt>…</tls-crypt> block clients need in their .ovpn.

    Generated .ovpn files MUST contain this — server.conf requires tls-crypt,
    so without it the client handshake fails at "TLS key negotiation failed".
    """
    key = read_tls_crypt_key()
    if not key:
        return ""
    return f"\n<tls-crypt>\n{key}\n</tls-crypt>\n"


# ── entrypoint ───────────────────────────────────────────────────────


def init_pki() -> None:
    """Initialize PKI + OpenVPN config. Safe to call on every startup."""
    for d in REQUIRED_DIRS:
        os.makedirs(d, exist_ok=True)

    _setup_easyrsa()

    if os.path.exists(CA_CERT) and os.path.exists(SERVER_CERT):
        logger.info("PKI already exists — skipping CA initialization.")
        _gen_tls_key()
        if not _ensure_crl():
            raise RuntimeError("Certificate revocation list is unavailable")
        _ensure_server_conf()
        _ensure_client_template()
        return

    # If pki dir exists as a Docker mount point it can't be rmdir'd from
    # inside the container — easyrsa --pki-dir handles the rest.
    os.makedirs(PKI_DIR, exist_ok=True)
    logger.info("PKI not found — initializing new ECDSA Certificate Authority at %s", PKI_DIR)
    _ensure_dir_tree()

    if not _easyrsa("build-ca", "nopass"):
        raise RuntimeError("CA creation failed")
    if not _easyrsa("build-server-full", "server", "nopass"):
        raise RuntimeError("Server certificate creation failed")
    if not _ensure_crl():
        raise RuntimeError("PKI initialization cannot continue without a CRL")

    _gen_tls_key()
    _ensure_server_conf()
    _ensure_client_template()
    logger.info("PKI initialization complete (ECDSA, no static DH).")
