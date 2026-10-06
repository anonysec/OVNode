# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""
PKI + OpenVPN configuration initialization for OVNode (all idempotent).

* Fresh installs get an ECDSA (prime256v1) PKI — OpenVPN uses ECDHE, so no
  static ``dh`` file is needed.
* ``server.conf`` is generated for new installs and *tuned up* for existing
  ones: missing hardening directives are appended, admin edits never clobbered.
* ``client-common.txt`` is generated if missing; the panel fills in the tunnel
  address via ``/sync/config``.

Split by concern, still importable as ``backend.openvpn.pki.X``:

* :mod:`backend.openvpn.pki.paths` — path constants (leaf, no internal imports).
* :mod:`backend.openvpn.pki.settings` — OVNODE_* settings accessors.
* :mod:`backend.openvpn.pki.node` — node address, openvpn binary, remote lines.
* :mod:`backend.openvpn.pki.easyrsa` — easy-rsa invocation, lock, PKI tree.
* :mod:`backend.openvpn.pki.certs` — CRL lifecycle, renewal, tls-crypt key.
* :mod:`backend.openvpn.pki.server_conf` — server.conf and client template.
* :mod:`backend.openvpn.pki.bootstrap` — the ``init_pki()`` entrypoint.

Submodules read paths, hooks and helpers they do not own back through this
package (``_pki.SERVER_CONF``) at call time, so
``monkeypatch.setattr(backend.openvpn.pki, "SERVER_CONF", …)`` reaches the code
that uses the name.
"""

import os
import secrets
import shutil
import socket
import subprocess
from datetime import UTC

from backend.logger import logger
from backend.openvpn import dns as dns_policy
from backend.openvpn import ipv6 as ipv6_policy
from backend.openvpn.atomic import write_text_atomic
from backend.openvpn.pki.bootstrap import _init_pki_locked, init_pki
from backend.openvpn.pki.certs import (
    _CRL_RENEW_THRESHOLD_DAYS,
    _MONTHS,
    _crl_days_remaining,
    _days_until_openssl_date,
    _ensure_crl,
    crl_is_current,
    read_tls_crypt_key,
    renew_server_certificate,
    tls_crypt_block,
)
from backend.openvpn.pki.easyrsa import (
    _easyrsa,
    _ensure_dir_tree,
    _gen_tls_key,
    _setup_easyrsa,
    _write_easyrsa_vars,
    run_easyrsa,
)
from backend.openvpn.pki.node import _node_public_ip, _openvpn_bin, _remote_lines
from backend.openvpn.pki.paths import (
    _OPENVPN_ROOT,
    CA_CERT,
    CLIENT_TEMPLATE,
    CRL_FILE,
    DH_PEM,
    EASYRSA_DIR,
    MGMT_PASS_FILE,
    PID_FILE,
    PKI_DIR,
    REQUIRED_DIRS,
    SERVER_CERT,
    SERVER_CONF,
    TLS_KEY,
)
from backend.openvpn.pki.server_conf import (
    _SERVER_CONF_HARDENING,
    _ensure_client_template,
    _ensure_server_conf,
    _fresh_proto,
    _fresh_server_conf,
    _hardening_directives,
    ensure_mgmt_password,
    mgmt_line,
)
from backend.openvpn.pki.settings import (
    _env,
    _extra_vpn_ports,
    _ipv6_enabled,
    _ipv6_prefix,
    _management_port,
    _max_clients,
    _openvpn_port,
    _runtime_group,
    _runtime_user,
    _vpn_dns,
    _vpn_netmask,
    _vpn_network,
)
from backend.openvpn.store import SCRIPTS_DIR
from backend.openvpn.store import ensure_layout as _ensure_store_layout

__all__ = [
    "CA_CERT",
    "CLIENT_TEMPLATE",
    "CRL_FILE",
    "DH_PEM",
    "EASYRSA_DIR",
    "MGMT_PASS_FILE",
    "PID_FILE",
    "PKI_DIR",
    "REQUIRED_DIRS",
    "SCRIPTS_DIR",
    "SERVER_CERT",
    "SERVER_CONF",
    "TLS_KEY",
    "UTC",
    "_CRL_RENEW_THRESHOLD_DAYS",
    "_MONTHS",
    "_OPENVPN_ROOT",
    "_SERVER_CONF_HARDENING",
    "_crl_days_remaining",
    "_days_until_openssl_date",
    "_easyrsa",
    "_ensure_client_template",
    "_ensure_crl",
    "_ensure_dir_tree",
    "_ensure_server_conf",
    "_ensure_store_layout",
    "_env",
    "_extra_vpn_ports",
    "_fresh_proto",
    "_fresh_server_conf",
    "_gen_tls_key",
    "_hardening_directives",
    "_init_pki_locked",
    "_ipv6_enabled",
    "_ipv6_prefix",
    "_management_port",
    "_max_clients",
    "_node_public_ip",
    "_openvpn_bin",
    "_openvpn_port",
    "_remote_lines",
    "_runtime_group",
    "_runtime_user",
    "_setup_easyrsa",
    "_vpn_dns",
    "_vpn_netmask",
    "_vpn_network",
    "_write_easyrsa_vars",
    "crl_is_current",
    "dns_policy",
    "ensure_mgmt_password",
    "init_pki",
    "ipv6_policy",
    "logger",
    "mgmt_line",
    "os",
    "read_tls_crypt_key",
    "renew_server_certificate",
    "run_easyrsa",
    "secrets",
    "shutil",
    "socket",
    "subprocess",
    "tls_crypt_block",
    "write_text_atomic",
]
