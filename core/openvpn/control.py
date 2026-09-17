# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

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

from core.openvpn import dns as dns_policy
from core.openvpn import ipv6 as ipv6_policy
from core.openvpn import ports as ports_policy
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


def read_config() -> dict:
    """Return the live VPN endpoint settings (GET /sync/config).

    Lets the panel detect drift after a manual server.conf edit: port/proto
    from server.conf, tunnel address from the first `remote` line of the
    client template, extra ports from the environment (same source
    change_config() uses to build the template).
    """
    import os as _os

    openvpn_root = _os.getenv("OVNODE_OPENVPN_ROOT", "/etc/openvpn")
    setting_file = _os.path.join(openvpn_root, "server", "server.conf")
    template_file = _os.path.join(openvpn_root, "server", "client-common.txt")
    port: int | None = None
    proto: str | None = None
    tunnel_address: str | None = None
    try:
        with open(setting_file, encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped.startswith("port ") and port is None:
                    try:
                        port = int(stripped.split()[1])
                    except (IndexError, ValueError):
                        pass
                elif stripped.startswith("proto ") and proto is None:
                    proto = stripped.split()[1] if len(stripped.split()) > 1 else None
                if port is not None and proto is not None:
                    break
    except OSError:
        pass
    try:
        with open(template_file, encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3 and parts[0] == "remote":
                    tunnel_address = parts[1]
                    break
    except OSError:
        pass
    return {"port": port, "proto": proto, "tunnel_address": tunnel_address}


def _atomic_write(path: str, content: str) -> None:
    """Write file atomically via temp+rename, keeping a .bak of the previous."""
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
            f.flush()
            # mkstemp creates 0600; both files this helper writes (server.conf,
            # client-common.txt) are non-secret and must stay readable by the
            # dropped-privilege OpenVPN user after a SIGHUP reload.
            os.fchmod(f.fileno(), 0o644)
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


def _rollback_changed_files(setting_file: str, template_file: str, tmpl_changed: bool) -> bool:
    """Restore files from the ``.bak`` copies kept by :func:`_atomic_write`.

    Called when a required restart failed: putting the previous config back
    lets the retry restart bring the daemon up on known-good settings instead
    of leaving it down with a config it refused. Returns True when at least
    one ``.bak`` existed, i.e. a rollback actually happened.
    """
    found = False
    candidates = [setting_file]
    if tmpl_changed:
        candidates.append(template_file)
    for path in candidates:
        backup = path + ".bak"
        if not os.path.exists(backup):
            continue
        found = True
        try:
            shutil.copy2(backup, path)
            logger.warning("Rolled back %s from %s", path, backup)
        except OSError as e:
            logger.error("Could not roll back %s from %s: %s", path, backup, e)
    return found


def change_config(request) -> bool:
    """Apply tunnel address / protocol / port pushed by the panel.

    Rewrites server.conf (port/proto, panel-managed DNS push lines and
    IPv6 block) and rebuilds the client template's full `remote` block — one line per
    reachable port (primary + panel-managed extras, falling back to
    OVNODE_EXTRA_PORTS on nodes with no ports state) so clients fail over
    between ports when an ISP blocks one. Cached .ovpn profiles are
    invalidated when the template actually changed.

    Restart policy (tunnels are user traffic — never bounce them idly):
    - nothing changed (same bytes) → return True, no write, no signal.
    - port/proto values changed → full restart (rebind required).
    - conf normalization only (e.g. `tcp-server` → `tcp`, DNS rewrite) →
      SIGHUP reload.
    - template-only change (tunnel address) → no daemon signal at all;
      the template is only read when generating .ovpn profiles.
    - extra-ports change (template + NAT redirects, no rebind) → SIGHUP.
    """
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

    # Validate panel-provided DNS servers before touching any file. Omitted
    # fields (old panels never send them) leave the node's values unchanged.
    dns1 = getattr(request, "dns1", None)
    dns2 = getattr(request, "dns2", None)
    dns_provided = dns1 is not None or dns2 is not None
    valid_dns1 = dns_policy.validate(dns1)
    valid_dns2 = dns_policy.validate(dns2)
    for label, value, normalized in (("dns1", dns1, valid_dns1), ("dns2", dns2, valid_dns2)):
        if value is not None and normalized is None:
            logger.error("Invalid DNS address for %s: %r", label, value)
            return False

    # Validate the panel-managed IPv6 prefix before touching any file. Omitted
    # fields (old panels never send them) leave the node's setting unchanged.
    ipv6_enabled = getattr(request, "enable_ipv6", None)
    ipv6_prefix = getattr(request, "ipv6_prefix", None)
    valid_ipv6_prefix = ipv6_policy.validate_prefix(ipv6_prefix)
    if ipv6_prefix is not None and valid_ipv6_prefix is None:
        logger.error("Invalid IPv6 prefix: %r", ipv6_prefix)
        return False

    # Validate the panel-managed extra ports before touching any file. Omitted
    # (old panels never send them) leaves the node's list unchanged; an empty
    # string clears it.
    extra_ports_raw = getattr(request, "extra_ports", None)
    valid_extra_ports: list[int] | None = None
    if extra_ports_raw is not None:
        valid_extra_ports = ports_policy.validate(extra_ports_raw, ovpn_port)
        if valid_extra_ports is None:
            logger.error("Invalid extra VPN ports: %r", extra_ports_raw)
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

        new_config = re.sub(r"^port\s+\d+", f"port {ovpn_port}", config, flags=re.MULTILINE)
        # Match the full proto token (\S+) so variants like "tcp-server" are
        # fully replaced instead of leaving a dangling "-server".
        new_config = re.sub(r"^proto\s+\S+", f"proto {proto}", new_config, flags=re.MULTILINE)
        # explicit-exit-notify is a UDP-only nicety: 1 for UDP, 0 for TCP.
        new_config = re.sub(
            r"^explicit-exit-notify\s+\d+",
            f"explicit-exit-notify {1 if proto == 'udp' else 0}",
            new_config,
            flags=re.MULTILINE,
        )
        # Panel DNS servers: collapse the old push lines into the desired
        # list (one line per server, no duplicates) and persist the state
        # file only after server.conf was written.
        dns_desired: list[str] | None = None
        if dns_provided:
            dns_desired = dns_policy.resolve_desired(config, valid_dns1, valid_dns2)
            new_config, _ = dns_policy.rewrite_push_lines(new_config, dns_desired)
        # Panel-managed IPv6: collapse the generated directives into the
        # desired block and persist the state file only after server.conf was
        # written. A prefix sent without an explicit flag keeps the current
        # enabled state (and vice versa), so partial pushes never flip the
        # other field. Enabling/disabling only rewrites the file — never a
        # rebind, so the SIGHUP path below applies.
        ipv6_desired: tuple[bool, str] | None = None
        if ipv6_enabled is not None or valid_ipv6_prefix is not None:
            current_enabled, current_prefix = ipv6_policy.effective(config)
            desired_enabled = current_enabled if ipv6_enabled is None else bool(ipv6_enabled)
            desired_prefix = current_prefix if valid_ipv6_prefix is None else valid_ipv6_prefix
            ipv6_desired = (desired_enabled, desired_prefix)
            new_config, _ = ipv6_policy.rewrite_block(new_config, desired_enabled, desired_prefix)
        conf_changed = new_config != config
        if conf_changed:
            _atomic_write(setting_file, new_config)
        if dns_desired is not None:
            dns_policy.write_state(dns_desired)
        if ipv6_desired is not None:
            ipv6_policy.write_state(*ipv6_desired)

        # Panel-managed extra ports: persist the desired list, rebuild the
        # client template remote block and re-apply the NAT redirects on
        # native installs (Docker applies them inside the container). The
        # module invalidates cached profiles when the template changed; an
        # unchanged list is a total no-op.
        extras_changed = False
        if valid_extra_ports is not None:
            before_extras = ports_policy.effective(ovpn_port)
            applied, ports_msg = ports_policy.set_extra_ports(ovpn_port, extra_ports_raw)
            if not applied:
                logger.error("Extra VPN ports rejected: %s", ports_msg)
                return False
            extras_changed = ports_policy.effective(ovpn_port) != before_extras
            logger.info("Extra VPN ports: %s", ports_msg)

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
        if not tunnel_addr:
            tunnel_addr = ports_policy.remote_address(template) or "UPDATE_VIA_PANEL"
        template, _ = ports_policy.rewrite_remote_lines(
            template, tunnel_addr, ovpn_port, ports_policy.effective(ovpn_port)
        )

        template = re.sub(r"^proto\s+\S+", f"proto {proto}", template, flags=re.MULTILINE)
        tmpl_changed = template != original_template
        if tmpl_changed:
            _atomic_write(template_file, template)

        # No-op push (panel re-sent identical settings): touch nothing so the
        # entrypoint mtime watcher and multilogin stay quiet — zero restarts.
        if not conf_changed and not tmpl_changed and not extras_changed:
            logger.info("OpenVPN settings already match; no write, no restart.")
            return True

        # If the protocol/port/remotes actually changed, the already-generated
        # client profiles are stale (they embed the old values) — remove them
        # so they regenerate from the updated template on the next download.
        if changed or tmpl_changed:
            _invalidate_cached_ovpn()

        restart_failed = False
        if changed:
            # Port/proto rebind requires a full restart.
            if not restart_openvpn():
                restart_failed = True
                # Restore the previous config (when one exists) and retry:
                # the daemon would otherwise stay down with a config it
                # refused. Callers must see failure either way.
                if _rollback_changed_files(setting_file, template_file, tmpl_changed):
                    if restart_openvpn():
                        logger.warning(
                            "OpenVPN restart failed; rolled back to the previous "
                            "config and the rollback restart succeeded."
                        )
                    else:
                        logger.error(
                            "OpenVPN restart failed; rolled back to the previous "
                            "config but the rollback restart also failed — OpenVPN "
                            "may be down."
                        )
                else:
                    logger.error(
                        "OpenVPN restart failed and no previous config exists to "
                        "roll back to (first write); the new config stays and will "
                        "activate on the next OpenVPN (re)start."
                    )
        elif conf_changed or extras_changed:
            # Normalization only (no rebind): reload without teardown.
            _sighup_fallback()

        # CRITICAL for multi-login: re-apply scripts and server.conf directives
        try:
            from core.openvpn.multilogin import ensure_multilogin_setup

            ensure_multilogin_setup()
        except Exception as e:
            logger.error("Failed to re-apply multi-login after config change: %s", e)

        if restart_failed:
            return False

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
