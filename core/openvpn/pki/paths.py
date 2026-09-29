# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Every path the PKI writes to.

Leaf module: it imports nothing else from this package, so the other
submodules can depend on it without a circular import.
"""

import os

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
PID_FILE = os.path.join(_OPENVPN_ROOT, "server", "ovnode.pid")
# Management-interface password file (0600). Localhost is shared in
# host-network mode, so the mgmt socket must require auth, not just bind.
MGMT_PASS_FILE = os.path.join(_OPENVPN_ROOT, "server", "mgmt-pass")

REQUIRED_DIRS = [
    os.path.join(_OPENVPN_ROOT, "server"),
    os.path.join(_OPENVPN_ROOT, "ccd"),
]
