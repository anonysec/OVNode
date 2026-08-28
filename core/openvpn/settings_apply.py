# Copyright (c) 2025 anonysec. All rights reserved.
# Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.

import glob
import os
import re

from core.api.schemas import SetSettingsModel
from core.config import parse_extra_ports
from core.logger import logger
from core.openvpn.users import CLIENTS_DIR


def change_config(request: SetSettingsModel) -> bool:
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
        config = re.sub(
            r"^proto\s+\S+",
            f"proto {proto}",
            config,
            flags=re.MULTILINE,
        )
        # explicit-exit-notify is a UDP-only nicety: 1 for UDP, 0 for TCP.
        config = re.sub(
            r"^explicit-exit-notify\s+\d+",
            f"explicit-exit-notify {1 if proto == 'udp' else 0}",
            config,
            flags=re.MULTILINE,
        )

        with open(setting_file, "w") as file:
            file.write(config)

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

        # Rebuild the full `remote` block: one line per reachable port
        # (primary + OVNODE_EXTRA_PORTS), so clients fail over between ports
        # when an ISP blocks one. Without a new tunnel address, keep the one
        # from the first existing remote line.
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

        template = re.sub(
            r"^proto\s+\S+",
            f"proto {proto}",
            template,
            flags=re.MULTILINE,
        )
        with open(template_file, "w") as file:
            file.write(template)

        # If the protocol/port/remotes actually changed, the already-generated
        # client *.ovpn files are now stale (they embed the old values).
        # Remove them so they regenerate from the updated template on the
        # next download.
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

        change_msg = (
            f"OpenVPN port changed to {ovpn_port}, "
            f"protocol to {proto}, "
            f"and tunnel address to {request.tunnel_address}"
        )
        logger.info(change_msg)
        return True
    except Exception as e:
        logger.error("Error changing OpenVPN settings: %s", e)
        return False


def _invalidate_cached_ovpn() -> None:
    """Delete cached .ovpn files (in CLIENTS_DIR) so they regenerate with the new settings."""
    try:
        for path in glob.glob(os.path.join(CLIENTS_DIR, "*.ovpn")):
            try:
                os.remove(path)
                logger.info("Removed stale client config: %s", path)
            except Exception as e:
                logger.error("Could not remove %s: %s", path, e)
    except Exception as e:
        logger.error("Error invalidating cached ovpn files: %s", e)


def restart_openvpn() -> bool:
    """Restart the OpenVPN service (delegates to shared module)."""
    from core.openvpn.control import restart_openvpn as _restart

    if not _restart():
        logger.error("Failed to restart OpenVPN from setting/core.py")
        return False
    return True
