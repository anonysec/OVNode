# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Idempotent setup for the multi-login (per-config connection limit) feature.

This wires the OpenVPN server so that ovmanager's per-user ``max_logins`` is
actually enforced on connect:

* installs the ``client-connect`` / ``client-disconnect`` enforcement scripts,
* ensures ``server.conf`` enables ``duplicate-cn``, the script hooks, and a
  ``status`` log (the connect script counts live sessions from it),
* enforcement policy: REJECT the new connection when the limit is reached.

The connect script uses a small active-session registry plus the OpenVPN status
log. The registry prevents race conditions where two devices connect before the
status log refreshes; the status log is a safety fallback.

It is safe to run repeatedly (on every app start). It only restarts OpenVPN
when it actually changed something.
"""

import os
import shutil

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
    hook could query the panel for a global session count. That coupled every
    node to the panel's address — moving the panel would have required
    reconfiguring all nodes. Enforcement is now strictly per-node; cross-node
    policy belongs to the panel, which already polls /sync/sessions and can
    disconnect via /sync/user/{uid}/disconnect on any node.
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
        new = open(src).read()
        old = open(dst).read() if os.path.exists(dst) else None
        if new != old:
            shutil.copyfile(src, dst)
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
            # OpenVPN must reload only when server.conf changed. Hook script
            # contents are executed from disk for each new connection, so script
            # updates do not need an OpenVPN restart and should not disconnect
            # active VPN users.
            _restart_openvpn()
        if scripts_changed or conf_changed:
            logger.info(
                "multilogin: setup applied (scripts=%s, conf=%s)", scripts_changed, conf_changed
            )
    except Exception as e:
        logger.error("multilogin: setup error: %s", e)
