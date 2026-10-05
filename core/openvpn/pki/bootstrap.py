# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""The idempotent PKI + OpenVPN config entrypoint."""

import os

from core.logger import logger
from core.openvpn.pki import certs as _certs_mod
from core.openvpn.pki import easyrsa as _easyrsa_mod
from core.openvpn.pki import paths as _paths
from core.openvpn.pki import server_conf as _server_conf
from core.openvpn.store import ensure_layout as _ensure_store_layout

# ── entrypoint ───────────────────────────────────────────────────────


def init_pki() -> None:
    """Initialize PKI + OpenVPN config. Safe to call on every startup.

    The whole check-then-create sequence runs under a dedicated init lock:
    two agent processes sharing one PKI (e.g. a stray manual start next to
    the service) would otherwise both see "no CA" and race build-ca.
    """
    import fcntl

    os.makedirs(_paths.PKI_DIR, exist_ok=True)
    lock_path = os.path.join(_paths.PKI_DIR, ".pki-init.lock")
    try:
        lock_fh = open(lock_path, "a")
    except OSError as e:
        logger.warning("PKI init lock unavailable (%s) — initializing unguarded", e)
        _init_pki_locked()
        return
    try:
        fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
        _init_pki_locked()
    finally:
        try:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        lock_fh.close()


def _init_pki_locked() -> None:
    """The actual init sequence; callers hold the PKI init lock."""
    for d in _paths.REQUIRED_DIRS:
        os.makedirs(d, exist_ok=True)
    # Store layout first: it also migrates any legacy on-disk layout, and
    # everything below (template, hooks config) points into the new tree.
    _ensure_store_layout()

    _easyrsa_mod._setup_easyrsa()

    if os.path.exists(_paths.CA_CERT) and os.path.exists(_paths.SERVER_CERT):
        logger.info("PKI already exists — skipping CA initialization.")
        _easyrsa_mod._gen_tls_key()
        if not _certs_mod._ensure_crl():
            raise RuntimeError("Certificate revocation list is unavailable")
        _server_conf._ensure_server_conf()
        _server_conf._ensure_client_template()
        return

    # If pki dir exists as a Docker mount point it can't be rmdir'd from
    # inside the container — easyrsa --pki-dir handles the rest.
    os.makedirs(_paths.PKI_DIR, exist_ok=True)
    logger.info(
        "PKI not found — initializing new ECDSA Certificate Authority at %s", _paths.PKI_DIR
    )
    _easyrsa_mod._ensure_dir_tree()

    if not _easyrsa_mod._easyrsa("build-ca", "nopass"):
        raise RuntimeError("CA creation failed")
    if not _easyrsa_mod._easyrsa("build-server-full", "server", "nopass"):
        raise RuntimeError("Server certificate creation failed")
    if not _certs_mod._ensure_crl():
        raise RuntimeError("PKI initialization cannot continue without a CRL")

    _easyrsa_mod._gen_tls_key()
    _server_conf._ensure_server_conf()
    _server_conf._ensure_client_template()
    logger.info("PKI initialization complete (ECDSA, no static DH).")
