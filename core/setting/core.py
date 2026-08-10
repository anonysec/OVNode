import glob
import os
import re

from core.logger import logger
from core.schema.all_schemas import SetSettingsModel
from core.service.user_management import CLIENTS_DIR


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
        tunnel_addr = request.tunnel_address.strip() if request.tunnel_address else ""
        # Validate tunnel_address contains only safe characters (IP or hostname).
        # Reject regex metacharacters that could alter the replacement.
        _TUNNEL_RE = re.compile(r"^[A-Za-z0-9._:-]+$")
        if tunnel_addr and not _TUNNEL_RE.match(tunnel_addr):
            raise ValueError(f"Invalid tunnel_address: {tunnel_addr!r}")
        if tunnel_addr:
            template = re.sub(
                r"^remote\s+\S+\s+\d+",
                f"remote {tunnel_addr} {ovpn_port}",
                template,
                flags=re.MULTILINE,
            )
        else:
            template = re.sub(
                r"^remote\s+(\S+)\s+\d+",
                rf"remote \1 {ovpn_port}",
                template,
                flags=re.MULTILINE,
            )

        template = re.sub(
            r"^proto\s+\S+",
            f"proto {proto}",
            template,
            flags=re.MULTILINE,
        )
        with open(template_file, "w") as file:
            file.write(template)

        # If the protocol/port actually changed, the already-generated client
        # *.ovpn files in /root are now stale (they embed the old proto/port).
        # Remove them so they are regenerated from the updated template on the
        # next download.
        if changed:
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
            from core.service.multilogin import ensure_multilogin_setup

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


def restart_openvpn() -> None:
    """Restart the OpenVPN service (delegates to shared module)."""
    from core.service.openvpn_control import restart_openvpn

    if not restart_openvpn():
        logger.error("Failed to restart OpenVPN from setting/core.py")
