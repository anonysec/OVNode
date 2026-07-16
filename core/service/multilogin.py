"""Idempotent setup for the multi-login (per-config connection limit) feature.

This wires the OpenVPN server so that ov-panel's per-user ``max_logins`` is
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
import subprocess
from pathlib import Path

from core.logger import logger

SERVER_CONF = "/etc/openvpn/server/server.conf"
SCRIPTS_DST_DIR = "/etc/openvpn/scripts"
LIMITS_DIR = "/etc/openvpn/limits"
ACTIVE_DIR = "/etc/openvpn/ovpanel-active"
LOCK_FILE = os.path.join(ACTIVE_DIR, ".lock")
SCRIPTS_SRC_DIR = os.path.join(os.path.dirname(__file__), "..", "scripts")

CONNECT_DST = os.path.join(SCRIPTS_DST_DIR, "ovpanel-client-connect.sh")
DISCONNECT_DST = os.path.join(SCRIPTS_DST_DIR, "ovpanel-client-disconnect.sh")

# Path the connect script reads to count live sessions. Must match the
# `status` directive in server.conf and OVPANEL_STATUS_FILE in the script.
STATUS_FILE = "/var/log/openvpn-status.log"

# Directives we need in server.conf for an exact N-device per-cert limit.
REQUIRED_DIRECTIVES = [
    "duplicate-cn",
    "script-security 2",
    f"client-connect {CONNECT_DST}",
    f"client-disconnect {DISCONNECT_DST}",
]


def _openvpn_runtime_user_group() -> tuple[str, str]:
    """Return the user/group OpenVPN drops privileges to.

    Hook scripts run as this user, not root. The active-session registry and
    lock file must therefore be writable by this account; otherwise OpenVPN
    returns AUTH_FAILED even for the first valid client.
    """
    user = "nobody"
    group = "nogroup"
    try:
        if os.path.exists(SERVER_CONF):
            for line in Path(SERVER_CONF).read_text(encoding="utf-8").splitlines():
                parts = line.strip().split()
                if len(parts) >= 2 and parts[0] == "user":
                    user = parts[1]
                elif len(parts) >= 2 and parts[0] == "group":
                    group = parts[1]
    except Exception as e:
        logger.warning("multilogin: failed to read OpenVPN runtime user/group: %s", e)
    return user, group


def _fix_runtime_permissions() -> None:
    """Make the registry writable by the OpenVPN hook runtime user."""
    os.makedirs(LIMITS_DIR, exist_ok=True)
    os.makedirs(ACTIVE_DIR, exist_ok=True)
    Path(LOCK_FILE).touch(exist_ok=True)

    user, group = _openvpn_runtime_user_group()
    try:
        shutil.chown(ACTIVE_DIR, user=user, group=group)
        shutil.chown(LOCK_FILE, user=user, group=group)
    except Exception as e:
        logger.warning(
            "multilogin: failed to chown registry to %s:%s: %s", user, group, e
        )
    try:
        os.chmod(ACTIVE_DIR, 0o755)
        os.chmod(LOCK_FILE, 0o664)
    except Exception as e:
        logger.warning("multilogin: failed to chmod registry/lock: %s", e)


def _install_scripts() -> bool:
    """Copy the enforcement scripts into place. Returns True if anything changed."""
    changed = False
    os.makedirs(SCRIPTS_DST_DIR, exist_ok=True)
    _fix_runtime_permissions()

    for fname, dst in (
        ("ovpanel-client-connect.sh", CONNECT_DST),
        ("ovpanel-client-disconnect.sh", DISCONNECT_DST),
    ):
        src = os.path.join(SCRIPTS_SRC_DIR, fname)
        if not os.path.exists(src):
            logger.error("multilogin: source script missing: %s", src)
            continue
        new = open(src, "r").read()
        old = open(dst, "r").read() if os.path.exists(dst) else None
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

    with open(SERVER_CONF, "r") as f:
        content = f.read()

    lines = content.splitlines()
    existing = {ln.strip() for ln in lines}
    to_add = [d for d in REQUIRED_DIRECTIVES if d not in existing]

    # The connect script and the traffic parser count sessions from the status
    # log, so a `status` directive must be present. Only add one if no status
    # line exists at all (don't fight an existing custom path/interval).
    has_status = any(ln.strip().startswith("status ") for ln in lines)
    if not has_status:
        to_add.append(f"status {STATUS_FILE} 5")

    # The parser expects the machine-readable `CLIENT_LIST,...` layout, which is
    # produced by status-version 2/3. The default (version 1) uses a different
    # format with no CLIENT_LIST prefix, which would silently break both the
    # connection limit and traffic accounting. Ensure version 3 is set.
    has_status_version = any(
        ln.strip().startswith("status-version") for ln in lines
    )
    if not has_status_version:
        to_add.append("status-version 2")

    if not to_add:
        return False

    if lines and lines[-1].strip() != "":
        lines.append("")
    lines.append("# ov-panel multi-login (per-config connection limit) enforcement")
    lines.extend(to_add)

    with open(SERVER_CONF, "w") as f:
        f.write("\n".join(lines) + "\n")

    logger.info("multilogin: added directives to server.conf: %s", to_add)
    return True


def _restart_openvpn() -> None:
    try:
        subprocess.run(
            ["/usr/bin/systemctl", "restart", "openvpn-server@server"],
            check=True,
            timeout=30,
        )
        logger.info("multilogin: OpenVPN restarted")
    except Exception as e:
        logger.error("multilogin: failed to restart OpenVPN: %s", e)


def ensure_multilogin_setup() -> None:
    """Idempotently set up multi-login enforcement. Safe to call on every start."""
    try:
        scripts_changed = _install_scripts()
        conf_changed = _patch_server_conf()
        # server.conf may have been created/edited after _install_scripts() read it.
        _fix_runtime_permissions()
        if conf_changed:
            # OpenVPN must reload only when server.conf changed. Hook script
            # contents are executed from disk for each new connection, so script
            # updates do not need an OpenVPN restart and should not disconnect
            # active VPN users.
            _restart_openvpn()
        if scripts_changed or conf_changed:
            logger.info("multilogin: setup applied (scripts=%s, conf=%s)",
                        scripts_changed, conf_changed)
    except Exception as e:
        logger.error("multilogin: setup error: %s", e)
