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
import re
import shutil
import signal
import subprocess
import tempfile

from core.openvpn import store

logger = logging.getLogger("ovnode.openvpn")

_OPENVPN_ROOT = os.getenv("OVNODE_OPENVPN_ROOT", "/etc/openvpn")
SERVER_CONF = os.path.join(_OPENVPN_ROOT, "server", "server.conf")
PID_FILE = os.path.join(_OPENVPN_ROOT, "server", "ovnode.pid")


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
    """Reload via SIGHUP to the OpenVPN master process (Docker-friendly).

    Returns False when no process was found so callers can distinguish
    "nothing running" from a successful reload.
    """
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
        return False
    return True


def restart_openvpn() -> bool:
    """Restart/reload the OpenVPN server. Returns True on success."""
    store.fix_runtime_permissions()
    logger.info("Restarting OpenVPN service...")

    # 1) systemd (resolve binary instead of hardcoding /usr/bin path)
    systemctl = shutil.which("systemctl")
    if systemctl:
        try:
            subprocess.run(
                [systemctl, "restart", "openvpn-server@server"],
                check=True,
                timeout=30,
            )
            logger.info("OpenVPN restarted via systemctl.")
            return True
        except subprocess.TimeoutExpired:
            logger.error("Timeout restarting OpenVPN via systemctl")
        except Exception as e:
            logger.warning("systemctl restart failed (%s); trying next method.", e)
    else:
        logger.info("systemctl not found (Docker?); trying next method.")

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


# ── panel-driven settings (POST /sync/config) ────────────────────────


def _atomic_write(path: str, content: str) -> None:
    """Write file atomically via temp+rename, keeping a .bak of the previous."""
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        try:
            if os.path.exists(path):
                shutil.copy2(path, path + ".bak")
        except OSError as e:
            logger.warning("Could not backup %s: %s", path, e)
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass


def change_config(request) -> bool:
    """Apply tunnel address / protocol / port pushed by the panel.

    Rewrites server.conf (port/proto) and rebuilds the client template's
    full `remote` block — one line per reachable port (primary +
    OVNODE_EXTRA_PORTS) so clients fail over between ports when an ISP
    blocks one. Cached .ovpn profiles are invalidated when the template
    actually changed.
    """
    from core.config import parse_extra_ports

    openvpn_root = os.getenv("OVNODE_OPENVPN_ROOT", "/etc/openvpn")
    setting_file = os.path.join(openvpn_root, "server", "server.conf")
    template_file = os.path.join(openvpn_root, "server", "client-common.txt")
    # Normalize protocol to tcp/udp (ignore any tcp-server/udp6 style variants).
    proto = "tcp" if str(request.protocol).lower().startswith("tcp") else "udp"
    # Validate the port before touching any file.
    try:
        ovpn_port = int(request.ovpn_port)
        if not (1 <= ovpn_port <= 65535):
            raise ValueError(f"ovpn_port out of range: {ovpn_port}")
    except (TypeError, ValueError) as e:
        logger.error("Invalid OpenVPN port %r: %s", request.ovpn_port, e)
        return False
    try:
        # Read current proto/port so we can detect whether anything changed.
        with open(setting_file) as file:
            config = file.read()

        old_proto_match = re.search(r"^proto\s+(\S+)", config, flags=re.MULTILINE)
        old_port_match = re.search(r"^port\s+(\d+)", config, flags=re.MULTILINE)
        old_proto = old_proto_match.group(1) if old_proto_match else ""
        old_port = old_port_match.group(1) if old_port_match else ""
        changed = (not old_proto.startswith(proto)) or (old_port != str(ovpn_port))

        config = re.sub(r"^port\s+\d+", f"port {ovpn_port}", config, flags=re.MULTILINE)
        # Match the full proto token (\S+) so variants like "tcp-server" are
        # fully replaced instead of leaving a dangling "-server".
        config = re.sub(r"^proto\s+\S+", f"proto {proto}", config, flags=re.MULTILINE)
        # explicit-exit-notify is a UDP-only nicety: 1 for UDP, 0 for TCP.
        config = re.sub(
            r"^explicit-exit-notify\s+\d+",
            f"explicit-exit-notify {1 if proto == 'udp' else 0}",
            config,
            flags=re.MULTILINE,
        )

        _atomic_write(setting_file, config)

        # Update the client template
        with open(template_file) as file:
            template = file.read()
        original_template = template
        tunnel_addr = request.tunnel_address.strip() if request.tunnel_address else ""
        # Validate tunnel_address contains only safe characters (IP or hostname).
        # Reject regex metacharacters that could alter the replacement.
        _TUNNEL_RE = re.compile(r"^[A-Za-z0-9._:-]+$")
        if tunnel_addr and not _TUNNEL_RE.match(tunnel_addr):
            raise ValueError(f"Invalid tunnel_address: {tunnel_addr!r}")

        # Rebuild the full `remote` block. Without a new tunnel address,
        # keep the one from the first existing remote line.
        extra_ports = parse_extra_ports(os.getenv("OVNODE_EXTRA_PORTS", ""), ovpn_port)
        remote_re = re.compile(r"^remote\s+(\S+)\s+\d+\s*$")
        lines = template.splitlines()
        if not tunnel_addr:
            tunnel_addr = next(
                (m.group(1) for ln in lines if (m := remote_re.match(ln))),
                "UPDATE_VIA_PANEL",
            )
        remote_block = [f"remote {tunnel_addr} {p}" for p in (ovpn_port, *extra_ports)]

        rebuilt: list[str] = []
        inserted = False
        for ln in lines:
            if remote_re.match(ln):
                if not inserted:
                    rebuilt.extend(remote_block)
                    inserted = True
                continue
            rebuilt.append(ln)
        if not inserted:
            # Template had no remote line at all — insert after `client`.
            idx = next((i for i, ln in enumerate(rebuilt) if ln.strip() == "client"), -1)
            rebuilt[idx + 1 : idx + 1] = remote_block
        template = "\n".join(rebuilt) + "\n"

        template = re.sub(r"^proto\s+\S+", f"proto {proto}", template, flags=re.MULTILINE)
        _atomic_write(template_file, template)

        # If the protocol/port/remotes actually changed, the already-generated
        # client profiles are stale (they embed the old values) — remove them
        # so they regenerate from the updated template on the next download.
        if changed or template != original_template:
            _invalidate_cached_ovpn()

        if not restart_openvpn():
            # The config is already persisted on disk; a restart failure only
            # means it activates on the next OpenVPN start. Don't report the
            # change as failed — the write succeeded.
            logger.warning(
                "OpenVPN restart failed; new settings are saved and will "
                "activate on the next OpenVPN (re)start"
            )

        # CRITICAL for multi-login: re-apply scripts and server.conf directives
        try:
            from core.openvpn.multilogin import ensure_multilogin_setup

            ensure_multilogin_setup()
        except Exception as e:
            logger.error("Failed to re-apply multi-login after config change: %s", e)

        logger.info(
            "OpenVPN port changed to %s, protocol to %s, and tunnel address to %s",
            ovpn_port,
            proto,
            request.tunnel_address,
        )
        return True
    except Exception as e:
        logger.error("Error changing OpenVPN settings: %s", e)
        return False


def _invalidate_cached_ovpn() -> None:
    """Delete cached client profiles so they regenerate with the new settings."""
    for path in glob.glob(os.path.join(store.USERS_DIR, "*", "client.ovpn")):
        try:
            os.remove(path)
            logger.info("Removed stale client profile: %s", path)
        except Exception as e:
            logger.error("Could not remove %s: %s", path, e)
