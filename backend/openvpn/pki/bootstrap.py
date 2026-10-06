# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""The idempotent PKI + OpenVPN config entrypoint."""

import os

from backend.logger import logger
from backend.openvpn import pki as _pki

# ── entrypoint ───────────────────────────────────────────────────────


def init_pki() -> None:
    """Initialize PKI + OpenVPN config. Safe to call on every startup.

    The whole check-then-create sequence runs under a dedicated init lock:
    two agent processes sharing one PKI (e.g. a stray manual start next to
    the service) would otherwise both see "no CA" and race build-ca.
    """
    import fcntl

    os.makedirs(_pki.PKI_DIR, exist_ok=True)
    lock_path = os.path.join(_pki.PKI_DIR, ".pki-init.lock")
    try:
        lock_fh = open(lock_path, "a")
    except OSError as e:
        logger.warning("PKI init lock unavailable (%s) — initializing unguarded", e)
        _pki._init_pki_locked()
        return
    try:
        fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
        _pki._init_pki_locked()
    finally:
        try:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        lock_fh.close()


def _init_pki_locked() -> None:
    """The actual init sequence; callers hold the PKI init lock."""
    for d in _pki.REQUIRED_DIRS:
        os.makedirs(d, exist_ok=True)
    # Store layout first: it also migrates any legacy on-disk layout, and
    # everything below (template, hooks config) points into the new tree.
    _pki._ensure_store_layout()

    _pki._setup_easyrsa()

    if os.path.exists(_pki.CA_CERT) and os.path.exists(_pki.SERVER_CERT):
        logger.info("PKI already exists — skipping CA initialization.")
        _pki._gen_tls_key()
        if not _pki._ensure_crl():
            raise RuntimeError("Certificate revocation list is unavailable")
        _pki._ensure_server_conf()
        _pki._ensure_client_template()
        return

    # If pki dir exists as a Docker mount point it can't be rmdir'd from
    # inside the container — easyrsa --pki-dir handles the rest.
    os.makedirs(_pki.PKI_DIR, exist_ok=True)
    logger.info("PKI not found — initializing new ECDSA Certificate Authority at %s", _pki.PKI_DIR)
    _pki._ensure_dir_tree()

    if not _pki._easyrsa("build-ca", "nopass"):
        raise RuntimeError("CA creation failed")
    if not _pki._easyrsa("build-server-full", "server", "nopass"):
        raise RuntimeError("Server certificate creation failed")
    if not _pki._ensure_crl():
        raise RuntimeError("PKI initialization cannot continue without a CRL")

    _pki._gen_tls_key()
    _pki._ensure_server_conf()
    _pki._ensure_client_template()
    logger.info("PKI initialization complete (ECDSA, no static DH).")
