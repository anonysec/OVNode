import glob
import os
import re

from core.logger import logger
from core.schema.all_schemas import SetSettingsModel
from core.service.user_managment import CLIENTS_DIR


def change_config(request: SetSettingsModel) -> bool:
    setting_file = "/etc/openvpn/server/server.conf"
    template_file = "/etc/openvpn/server/client-common.txt"
    # Normalize protocol to tcp/udp (ignore any tcp-server/udp6 style variants).
    proto = "tcp" if str(request.protocol).lower().startswith("tcp") else "udp"
    try:
        # Read current proto/port so we can detect whether anything changed.
        with open(setting_file) as file:
            config = file.read()

        old_proto_match = re.search(r"^proto\s+(\S+)", config, flags=re.MULTILINE)
        old_port_match = re.search(r"^port\s+(\d+)", config, flags=re.MULTILINE)
        old_proto = old_proto_match.group(1) if old_proto_match else ""
        old_port = old_port_match.group(1) if old_port_match else ""
        changed = (not old_proto.startswith(proto)) or (old_port != str(request.ovpn_port))

        config = re.sub(r"^port\s+\d+", f"port {request.ovpn_port}", config, flags=re.MULTILINE)
        # Match the full proto token (\S+) so variants like "tcp-server" are
        # fully replaced instead of leaving a dangling "-server".
        config = re.sub(
            r"^proto\s+\S+",
            f"proto {proto}",
            config,
            flags=re.MULTILINE,
        )

        with open(setting_file, "w") as file:
            file.write(config)

        # Update the client template
        with open(template_file) as file:
            template = file.read()
        if request.tunnel_address and request.tunnel_address.strip() != "":
            # Update both address and port
            template = re.sub(
                r"^remote\s+\S+\s+\d+",
                f"remote {request.tunnel_address} {request.ovpn_port}",
                template,
                flags=re.MULTILINE,
            )
        else:
            template = re.sub(
                r"^remote\s+(\S+)\s+\d+",
                rf"remote \1 {request.ovpn_port}",
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

        restart_openvpn()

        # CRITICAL for multi-login: re-apply scripts and server.conf directives
        try:
            from core.service.multilogin import ensure_multilogin_setup

            ensure_multilogin_setup()
        except Exception as e:
            logger.error(f"Failed to re-apply multi-login after config change: {e}")

        change_msg = (
            f"OpenVPN port changed to {request.ovpn_port}, "
            f"protocol to {proto}, "
            f"and tunnel address to {request.tunnel_address}"
        )
        logger.info(change_msg)
        return True
    except Exception as e:
        logger.error(f"Error changing OpenVPN settings: {e}")
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
    """Restart the OpenVPN service.

    Tries systemctl first (for non-Docker installs), then falls back to
    sending SIGHUP to the OpenVPN master process (for Docker containers
    where systemd is not available).
    """
    import subprocess
    import signal

    logger.info("Restarting OpenVPN service...")

    # Try systemctl first (works on bare-metal / systemd installs)
    try:
        subprocess.run(
            ["/usr/bin/systemctl", "restart", "openvpn-server@server"],
            check=True,
            timeout=30,
        )
        logger.info("OpenVPN service restarted successfully via systemctl.")
        return
    except FileNotFoundError:
        logger.info("systemctl not found (likely Docker); falling back to SIGHUP.")
    except subprocess.TimeoutExpired:
        logger.error("Timeout while restarting OpenVPN service via systemctl")
    except Exception as e:
        logger.warning(f"systemctl restart failed ({e}); falling back to SIGHUP.")

    # Fallback: send SIGHUP to the OpenVPN master process
    try:
        pids = glob.glob("/run/openvpn-server/*.pid")
        if not pids:
            # Try finding openvpn process directly
            result = subprocess.run(
                ["pgrep", "-f", "openvpn"],
                capture_output=True, text=True, timeout=5,
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
                logger.info(f"Sent SIGHUP to OpenVPN PID {pid}.")
            except (ValueError, FileNotFoundError, ProcessLookupError) as e:
                logger.warning(f"Could not signal PID from {pid_file}: {e}")
        if not pids:
            logger.warning("No OpenVPN process found to restart; config will apply on next start.")
    except Exception as e:
        logger.error(f"Error restarting OpenVPN via SIGHUP: {e}")
