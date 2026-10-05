# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""PKI + OpenVPN configuration initialization for OVNode (all idempotent).

* Fresh installs get an ECDSA (prime256v1) PKI — OpenVPN uses ECDHE, so no
  static ``dh`` file is needed.
* ``server.conf`` is generated for new installs and *tuned up* for existing
  ones: missing hardening directives are appended, admin edits never clobbered.
* ``client-common.txt`` is generated if missing; the panel fills in the tunnel
  address via ``/sync/config``.

Split by concern:

* :mod:`core.openvpn.pki.paths` — path constants (leaf, no internal imports).
* :mod:`core.openvpn.pki.node` — node address, ports, OVNODE_* settings.
* :mod:`core.openvpn.pki.easyrsa` — easy-rsa invocation, lock, PKI tree.
* :mod:`core.openvpn.pki.certs` — CRL lifecycle, renewal, tls-crypt key.
* :mod:`core.openvpn.pki.server_conf` — server.conf and client template.
* :mod:`core.openvpn.pki.bootstrap` — the ``init_pki()`` entrypoint.

Only the names external callers import are re-exported here; everything else
lives in its defining submodule.
"""

from core.openvpn.pki.bootstrap import init_pki
from core.openvpn.pki.certs import (
    _days_until_openssl_date,
    _ensure_crl,
    crl_is_current,
    renew_server_certificate,
    tls_crypt_block,
)
from core.openvpn.pki.easyrsa import _write_easyrsa_vars, run_easyrsa
from core.openvpn.pki.node import _node_public_ip, _vpn_dns
from core.openvpn.pki.paths import (
    CA_CERT,
    CLIENT_TEMPLATE,
    CRL_FILE,
    PKI_DIR,
    SERVER_CERT,
    SERVER_CONF,
    TLS_KEY,
)
from core.openvpn.pki.server_conf import (
    _ensure_client_template,
    _ensure_server_conf,
    _fresh_server_conf,
)

__all__ = [
    "CA_CERT",
    "CLIENT_TEMPLATE",
    "CRL_FILE",
    "PKI_DIR",
    "SERVER_CERT",
    "SERVER_CONF",
    "TLS_KEY",
    "_days_until_openssl_date",
    "_ensure_client_template",
    "_ensure_crl",
    "_ensure_server_conf",
    "_fresh_server_conf",
    "_node_public_ip",
    "_vpn_dns",
    "_write_easyrsa_vars",
    "crl_is_current",
    "init_pki",
    "renew_server_certificate",
    "run_easyrsa",
    "tls_crypt_block",
]
