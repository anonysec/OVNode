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

Split by concern, still importable as ``core.openvpn.pki.X``:

* :mod:`core.openvpn.pki.paths` — path constants (leaf, no internal imports).
* :mod:`core.openvpn.pki.settings` — OVNODE_* settings accessors.
* :mod:`core.openvpn.pki.node` — node address, openvpn binary, remote lines.
* :mod:`core.openvpn.pki.easyrsa` — easy-rsa invocation, lock, PKI tree.
* :mod:`core.openvpn.pki.certs` — CRL lifecycle, renewal, tls-crypt key.
* :mod:`core.openvpn.pki.server_conf` — server.conf and client template.
* :mod:`core.openvpn.pki.bootstrap` — the ``init_pki()`` entrypoint.

Submodules read paths, hooks and helpers they do not own back through this
package (``_pki.SERVER_CONF``) at call time, so
``monkeypatch.setattr(core.openvpn.pki, "SERVER_CONF", …)`` reaches the code
that uses the name.
"""

import os
import secrets
import shutil
import socket
import subprocess
from datetime import UTC

from core.logger import logger
from core.openvpn import dns as dns_policy
from core.openvpn import ipv6 as ipv6_policy
from core.openvpn.atomic import write_text_atomic
from core.openvpn.pki.bootstrap import _init_pki_locked, init_pki
from core.openvpn.pki.certs import (
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
from core.openvpn.pki.easyrsa import (
    _easyrsa,
    _ensure_dir_tree,
    _gen_tls_key,
    _setup_easyrsa,
    _write_easyrsa_vars,
    run_easyrsa,
)
from core.openvpn.pki.node import _node_public_ip, _openvpn_bin, _remote_lines
from core.openvpn.pki.paths import (
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
from core.openvpn.pki.server_conf import (
    _SERVER_CONF_HARDENING,
    _ensure_client_template,
    _ensure_server_conf,
    _fresh_proto,
    _fresh_server_conf,
    _hardening_directives,
    ensure_mgmt_password,
    mgmt_line,
)
from core.openvpn.pki.settings import (
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
from core.openvpn.store import SCRIPTS_DIR
from core.openvpn.store import ensure_layout as _ensure_store_layout

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
