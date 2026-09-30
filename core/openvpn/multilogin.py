# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Idempotent setup for the multi-login (per-config connection limit) feature.

Wires the server so ovmanager's per-user ``max_logins`` is enforced on connect:
installs the ``client-connect`` / ``client-disconnect`` scripts, and ensures
``server.conf`` enables ``duplicate-cn``, the hooks and a ``status`` log (the
connect script counts live sessions from it). Over-limit connections are
REJECTED. Safe to run on every app start; it restarts OpenVPN only when
something changed.
"""

import os

from core.logger import logger
from core.openvpn import store

SCRIPTS_SRC_DIR = os.path.join(os.path.dirname(__file__), "..", "scripts")

CONNECT_DST = os.path.join(store.SCRIPTS_DIR, "ovnode-client-connect.sh")
DISCONNECT_DST = os.path.join(store.SCRIPTS_DIR, "ovnode-client-disconnect.sh")


# server.conf has a SINGLE writer: pki._ensure_server_conf covers both PKI
# hardening and these multi-login directives (hooks, duplicate-cn, mgmt).
# This module owns scripts + env + restart only — it must never patch the
# conf file itself (two writers made restarts order-dependent).


def _write_mlogin_env() -> None:
    """Remove the legacy node→panel callback env file if present.

    Older builds wrote ovnode-mlogin.env (panel URL + API key) so the connect
    hook could query the panel for a global session count, which coupled every
    node to the panel's address. Enforcement is strictly per-node now;
    cross-node policy belongs to the panel.
    """
    legacy = os.path.join(store.SCRIPTS_DIR, "ovnode-mlogin.env")
    try:
        os.remove(legacy)
        logger.info("multilogin: removed legacy panel-callback env %s", legacy)
    except FileNotFoundError:
        pass
    except OSError as e:
        logger.warning("multilogin: could not remove %s: %s", legacy, e)


def _install_scripts() -> bool:
    """Copy the enforcement scripts into place. Returns True if anything changed."""
    changed = False
    os.makedirs(store.SCRIPTS_DIR, exist_ok=True)
    store.fix_runtime_permissions()

    for fname, dst in (
        ("ovnode-client-connect.sh", CONNECT_DST),
        ("ovnode-client-disconnect.sh", DISCONNECT_DST),
    ):
        src = os.path.join(SCRIPTS_SRC_DIR, fname)
        if not os.path.exists(src):
            logger.error("multilogin: source script missing: %s", src)
            continue
        with open(src, encoding="utf-8") as f:
            new = f.read()
        old = None
        if os.path.exists(dst):
            with open(dst, encoding="utf-8") as f:
                old = f.read()
        if new != old:
            # Atomic install: OpenVPN executes these on every connect, so a
            # truncated destination (plain copyfile) could run mid-write.
            tmp = dst + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(new)
            os.chmod(tmp, 0o755)
            os.replace(tmp, dst)
            changed = True
        os.chmod(dst, 0o755)
    return changed


def _restart_openvpn() -> None:
    from core.openvpn.control import restart_openvpn

    if not restart_openvpn():
        logger.error("multilogin: failed to restart OpenVPN")


def ensure_multilogin_setup() -> None:
    """Idempotently set up multi-login enforcement. Safe to call on every start."""
    from core.openvpn.pki import _ensure_server_conf

    try:
        scripts_changed = _install_scripts()
        # Single-writer conf pass (pki covers hooks + hardening).
        conf_changed = bool(_ensure_server_conf())
        _write_mlogin_env()
        # server.conf may have been created/edited after _install_scripts() read it.
        store.fix_runtime_permissions()
        if conf_changed:
            # Reload only for server.conf: hook scripts are read from disk per
            # connection, so a script update must not bounce active users.
            _restart_openvpn()
        if scripts_changed or conf_changed:
            logger.info(
                "multilogin: setup applied (scripts=%s, conf=%s)", scripts_changed, conf_changed
            )
    except Exception as e:
        logger.error("multilogin: setup error: %s", e)
