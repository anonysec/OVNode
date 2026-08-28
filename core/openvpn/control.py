# Copyright (c) 2025 anonysec. All rights reserved.
# Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.

"""OpenVPN service management for OVNode.

Single shared module for checking and restarting OpenVPN after config changes.

Restart strategy (in order):
1. systemd   → ``systemctl restart openvpn-server@server``
2. OpenRC    → ``rc-service openvpn restart``
3. PID file  → SIGHUP to the PID written by ``writepid`` (works in Docker)
4. pgrep     → SIGHUP to the matching openvpn master process

SIGHUP makes OpenVPN reload server.conf without a full process teardown.
"""

import glob
import logging
import os
import signal
import subprocess

logger = logging.getLogger("ovnode.openvpn")

_OPENVPN_ROOT = os.getenv("OVNODE_OPENVPN_ROOT", "/etc/openvpn")
SERVER_CONF = os.path.join(_OPENVPN_ROOT, "server", "server.conf")
PID_FILE = os.path.join(_OPENVPN_ROOT, "server", "ovnode.pid")


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
        logger.warning("Failed to read OpenVPN runtime user/group: %s", e)
    return user, group


def _fix_runtime_permissions() -> None:
    """Make the mlogin registry writable by the OpenVPN hook runtime user."""
    from pathlib import Path

    from core.openvpn.multilogin import ACTIVE_DIR, LIMITS_DIR, LOCK_FILE

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


def openvpn_is_running() -> bool:
    """True when an OpenVPN master process for this node is alive."""
    pids = _openvpn_pids()
    if pids:
        for pid in pids:
            try:
                os.kill(pid, 0)
                return True
            except ProcessLookupError:
                continue
    return False


def _openvpn_pids() -> list[int]:
    """Collect candidate PIDs: pidfile first, then /run + pgrep."""
    pids: list[int] = []
    pid_paths = [PID_FILE] if os.path.exists(PID_FILE) else []
    pid_paths += glob.glob("/run/openvpn-server/*.pid")
    for path in pid_paths:
        try:
            with open(path, encoding="utf-8") as f:
                pids.append(int(f.read().strip()))
        except (OSError, ValueError):
            continue
    if not pids:
        try:
            out = subprocess.run(
                ["pgrep", "-x", "openvpn"], capture_output=True, text=True, timeout=5
            )
            pids = [int(p) for p in out.stdout.split() if p.strip().isdigit()]
        except Exception:
            pids = []
    return pids


def _sighup_fallback() -> bool:
    """Reload via SIGHUP to the OpenVPN master process (Docker-friendly)."""
    pids = _openvpn_pids()
    signaled = 0
    for pid in pids:
        try:
            os.kill(pid, signal.SIGHUP)
            signaled += 1
            logger.info("Sent SIGHUP to OpenVPN PID %s.", pid)
        except ProcessLookupError:
            continue
        except OSError as e:
            logger.warning("Could not signal PID %s: %s", pid, e)
    if signaled == 0:
        logger.warning("No OpenVPN process found — config will apply on next start.")
        return True  # nothing to restart yet is not a hard failure
    return True


def restart_openvpn() -> bool:
    """Restart/reload the OpenVPN server. Returns True on success."""
    _fix_runtime_permissions()
    logger.info("Restarting OpenVPN service...")

    # 1) systemd
    try:
        subprocess.run(
            ["/usr/bin/systemctl", "restart", "openvpn-server@server"],
            check=True,
            timeout=30,
        )
        logger.info("OpenVPN restarted via systemctl.")
        return True
    except FileNotFoundError:
        logger.info("systemctl not found (Docker?); trying next method.")
    except subprocess.TimeoutExpired:
        logger.error("Timeout restarting OpenVPN via systemctl")
    except Exception as e:
        logger.warning("systemctl restart failed (%s); trying next method.", e)

    # 2) OpenRC
    if os.path.exists("/sbin/rc-service"):
        try:
            subprocess.run(
                ["/sbin/rc-service", "openvpn", "restart"],
                check=True,
                timeout=30,
            )
            logger.info("OpenVPN restarted via rc-service.")
            return True
        except Exception as e:
            logger.warning("rc-service restart failed (%s); trying SIGHUP.", e)

    # 3) SIGHUP fallback
    return _sighup_fallback()
