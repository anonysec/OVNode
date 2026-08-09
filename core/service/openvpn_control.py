"""OpenVPN service management for OVNode.

Single shared module for restarting OpenVPN after config changes.
"""

import glob
import logging
import os
import signal
import subprocess

logger = logging.getLogger("ovnode.openvpn")

_OPENVPN_ROOT = os.getenv("OVNODE_OPENVPN_ROOT", "/etc/openvpn")
SERVER_CONF = os.path.join(_OPENVPN_ROOT, "server", "server.conf")


def _openvpn_runtime_user_group() -> tuple[str, str]:
    """Return the user/group OpenVPN drops privileges to."""
    user = "nobody"
    group = "nogroup"
    try:
        if os.path.exists(SERVER_CONF):
            for line in open(SERVER_CONF, encoding="utf-8"):
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
    from pathlib import Path

    from core.service.multilogin import ACTIVE_DIR, LIMITS_DIR, LOCK_FILE

    os.makedirs(LIMITS_DIR, exist_ok=True)
    os.makedirs(ACTIVE_DIR, exist_ok=True)
    Path(LOCK_FILE).touch(exist_ok=True)

    user, group = _openvpn_runtime_user_group()
    try:
        import shutil

        shutil.chown(ACTIVE_DIR, user=user, group=group)
        shutil.chown(LOCK_FILE, user=user, group=group)
    except Exception as e:
        logger.warning("Failed to chown runtime dirs: %s", e)


def restart_openvpn() -> bool:
    """Restart the OpenVPN service.

    Tries systemctl first (for non-Docker installs), then falls back to
    sending SIGHUP to the OpenVPN master process (for Docker containers
    where systemd is not available).

    Returns True on success, False on failure.
    """
    _fix_runtime_permissions()

    logger.info("Restarting OpenVPN service...")

    # Try systemctl first (works on bare-metal / systemd installs)
    try:
        subprocess.run(
            ["/usr/bin/systemctl", "restart", "openvpn-server@server"],
            check=True,
            timeout=30,
        )
        logger.info("OpenVPN service restarted successfully via systemctl.")
        return True
    except FileNotFoundError:
        logger.info("systemctl not found (likely Docker); falling back to SIGHUP.")
    except subprocess.TimeoutExpired:
        logger.error("Timeout while restarting OpenVPN service via systemctl")
    except Exception as e:
        logger.warning("systemctl restart failed (%s); falling back to SIGHUP.", e)

    # Fallback: send SIGHUP to the OpenVPN master process
    try:
        pids = glob.glob("/run/openvpn-server/*.pid")
        if not pids:
            # Try finding openvpn process directly
            result = subprocess.run(
                ["pgrep", "-x", "openvpn"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            pids = result.stdout.strip().split() if result.stdout.strip() else []
        for pid_file in pids:
            try:
                if pid_file.isdigit():
                    pid = int(pid_file)
                else:
                    with open(pid_file) as f:
                        pid = int(f.read().strip())
                os.kill(pid, signal.SIGHUP)
                logger.info("Sent SIGHUP to OpenVPN PID %s.", pid)
            except (ValueError, FileNotFoundError, ProcessLookupError) as e:
                logger.warning("Could not signal PID from %s: %s", pid_file, e)
        if not pids:
            logger.warning("No OpenVPN process found to restart; config will apply on next start.")
        return True
    except Exception as e:
        logger.error("Error restarting OpenVPN via SIGHUP: %s", e)
        return False
