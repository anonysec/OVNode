# Copyright (c) 2025 anonysec. All rights reserved.
# Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.

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

_OPENVPN_ROOT = os.getenv("OVNODE_OPENVPN_ROOT", "/etc/openvpn")
SERVER_CONF = os.path.join(_OPENVPN_ROOT, "server", "server.conf")
CRL_FILE = os.path.join(_OPENVPN_ROOT, "server", "pki", "crl.pem")
SCRIPTS_SRC_DIR = os.path.join(os.path.dirname(__file__), "..", "scripts")

CONNECT_DST = os.path.join(store.SCRIPTS_DIR, "ovnode-client-connect.sh")
DISCONNECT_DST = os.path.join(store.SCRIPTS_DIR, "ovnode-client-disconnect.sh")

# Path the connect script reads to count live sessions. Must match the
# `status` directive in server.conf and OVNODE_STATUS_FILE in the script.
STATUS_FILE = os.getenv("OVNODE_STATUS_FILE", os.path.join(_OPENVPN_ROOT, "server", "status.log"))


# Directives we need in server.conf for an exact N-device per-cert limit.
# The management interface is required by the connect script for takeover
# (limit=1) and by the agent for disconnects.
def _required_directives() -> list[str]:
    mgmt_port = os.getenv("OVNODE_MANAGEMENT_PORT", "7505")
    return [
        "duplicate-cn",
        "script-security 2",
        f"client-connect {CONNECT_DST}",
        f"client-disconnect {DISCONNECT_DST}",
        f"crl-verify {CRL_FILE}",
        f"management 127.0.0.1 {mgmt_port}",
        f"writepid {os.path.join(_OPENVPN_ROOT, 'server', 'ovnode.pid')}",
    ]


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


def _patch_server_conf() -> bool:
    """Ensure required directives exist in server.conf. Returns True if changed."""
    if not os.path.exists(SERVER_CONF):
        logger.warning("multilogin: %s not found; skipping conf patch", SERVER_CONF)
        return False

    with open(SERVER_CONF) as f:
        content = f.read()

    lines = content.splitlines()

    # Repoint hook directives that reference an old scripts location (the
    # hooks moved into the ovnode/ tree). Rewriting in place preserves the
    # admin's line ordering.
    repointed = False
    _hook_targets = {"client-connect": CONNECT_DST, "client-disconnect": DISCONNECT_DST}
    for i, ln in enumerate(lines):
        parts = ln.strip().split()
        if (
            len(parts) == 2
            and parts[0] in _hook_targets
            and "ovnode-client-" in parts[1]
            and parts[1] != _hook_targets[parts[0]]
        ):
            lines[i] = f"{parts[0]} {_hook_targets[parts[0]]}"
            repointed = True

    existing = {ln.strip() for ln in lines}
    to_add = [d for d in _required_directives() if d not in existing]

    # The connect script and the traffic parser count sessions from the status
    # log, so a `status` directive must be present. Only add one if no status
    # line exists at all (don't fight an existing custom path/interval).
    has_status = any(ln.strip().startswith("status ") for ln in lines)
    if not has_status:
        to_add.append(f"status {STATUS_FILE} 5")

    # The connect script counts sessions and resolves Client IDs from the
    # status log with tab-separated awk, which requires the machine-readable
    # status-version 3 layout. Version 1 has no CLIENT_LIST rows at all and
    # version 2 is comma-separated — either would silently break both the
    # connection limit and takeover kills. Ensure version 3, upgrading an
    # existing version 1/2 directive in place.
    replaced_status_version = False
    for i, ln in enumerate(lines):
        stripped = ln.strip()
        if stripped.startswith("status-version") and stripped != "status-version 3":
            lines[i] = "status-version 3"
            replaced_status_version = True
    has_status_version = any(ln.strip().startswith("status-version") for ln in lines)
    if not has_status_version:
        to_add.append("status-version 3")

    if not to_add and not replaced_status_version and not repointed:
        return False

    if to_add:
        if lines and lines[-1].strip() != "":
            lines.append("")
        lines.append("# ovmanager multi-login (per-config connection limit) enforcement")
        lines.extend(to_add)

    with open(SERVER_CONF, "w") as f:
        f.write("\n".join(lines) + "\n")

    logger.info("multilogin: added directives to server.conf: %s", to_add)
    return True


def _restart_openvpn() -> None:
    from core.openvpn.control import restart_openvpn

    if not restart_openvpn():
        logger.error("multilogin: failed to restart OpenVPN")


def ensure_multilogin_setup() -> None:
    """Idempotently set up multi-login enforcement. Safe to call on every start."""
    try:
        scripts_changed = _install_scripts()
        conf_changed = _patch_server_conf()
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
