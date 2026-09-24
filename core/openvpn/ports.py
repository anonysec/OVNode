# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Panel-managed extra VPN ports.

The node listens only on its primary port; extra ports reach the same daemon
through iptables REDIRECT rules and are advertised to clients as additional
``remote`` lines so an ISP blocking one port can be bypassed.

The panel owns the desired list; the node mirrors it in a small state file and
in the ``remote`` block of ``client-common.txt``. The state file makes the
operator's choice survive template regeneration and lets an explicitly cleared
list stay cleared even when the installer set ``OVNODE_EXTRA_PORTS``. Writes
are atomic (mkstemp + os.replace), matching :mod:`core.openvpn.dns` and
``store.write_state``.

Native installs also keep ``/etc/default/ovnode-nat`` in sync and re-run the
installer's ``ovnode-nat.sh apply`` best-effort. Docker nodes apply the
equivalent rules inside the container, so NAT is skipped there.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile

from core.logger import logger
from core.updater import is_docker

# Installer-owned NAT files (native installs only — Docker applies the same
# rules inside the container from env at (re)start).
NAT_CONF = "/etc/default/ovnode-nat"
NAT_SCRIPT = "/usr/local/sbin/ovnode-nat.sh"

_REMOTE_RE = re.compile(r"^remote\s+(\S+)\s+\d+\s*$")

_NAT_KEYS = ("VPN_PRIMARY_PORT", "VPN_EXTRA_PORTS")


def state_path() -> str:
    """Location of the desired-extra-ports state file (root read at call time)."""
    root = os.getenv("OVNODE_OPENVPN_ROOT", "/etc/openvpn")
    return os.path.join(root, "ovnode", "ports")


def template_path() -> str:
    """Location of the client template shared with OpenVPN (read at call time)."""
    root = os.getenv("OVNODE_OPENVPN_ROOT", "/etc/openvpn")
    return os.path.join(root, "server", "client-common.txt")


def validate(raw: object, primary: int) -> list[int] | None:
    """Normalized extra ports for a panel push, or None when invalid.

    ``None`` means "not provided" (the caller keeps the current state).
    An empty/whitespace/separator-only string means "clear" (``[]``).
    Every token must be a port in 1-65535; duplicates, blank tokens and the
    primary port itself are dropped. Comma and semicolon separators are
    accepted (same tolerance as ``core.config.parse_extra_ports``).
    """
    if raw is None:
        return None
    ports: list[int] = []
    for token in str(raw).replace(";", ",").split(","):
        token = token.strip()
        if not token:
            continue
        try:
            port = int(token)
        except ValueError:
            logger.warning("ports: rejected non-numeric extra VPN port %r", raw)
            return None
        if not (1 <= port <= 65535):
            logger.warning("ports: rejected extra VPN port %r (out of range 1-65535)", token)
            return None
        if port == primary or port in ports:
            continue
        ports.append(port)
    return ports


def _parse_state(value: str) -> list[int]:
    """Tolerant state-file parser (drops junk instead of rejecting pins)."""
    ports: list[int] = []
    for token in value.replace(";", ",").split(","):
        token = token.strip()
        try:
            port = int(token)
        except ValueError:
            continue
        if 1 <= port <= 65535 and port not in ports:
            ports.append(port)
    return ports


def read_state() -> list[int] | None:
    """Extra ports pinned by the panel, or None when no state file exists.

    ``[]`` deliberately means "the panel explicitly cleared the extras" so
    :func:`effective` never resurrects the installer's ``OVNODE_EXTRA_PORTS``.
    """
    try:
        with open(state_path(), encoding="utf-8") as f:
            for line in f:
                if "=" not in line:
                    continue
                key, _, value = line.strip().partition("=")
                if key == "ports":
                    return _parse_state(value)
    except OSError:
        pass
    return None


def _sync_env(ports: list[int]) -> None:
    """Mirror the pinned list into ``OVNODE_EXTRA_PORTS``.

    The state file stays authoritative and survives restarts; keeping the
    process env in step lets legacy env readers (``pki._ensure_client_template``)
    build a regenerated template with the panel's ports instead of the
    installer defaults.
    """
    os.environ["OVNODE_EXTRA_PORTS"] = ",".join(str(port) for port in ports)


def write_state(ports: list[int]) -> bool:
    """Atomically persist the desired extra ports. Returns True when changed."""
    path = state_path()
    content = "ports=" + ",".join(str(port) for port in ports) + "\n"
    _sync_env(ports)
    try:
        with open(path, encoding="utf-8") as f:
            if f.read() == content:
                return False
    except OSError:
        pass
    directory = os.path.dirname(path)
    try:
        os.makedirs(directory, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".ports-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(content)
            os.chmod(tmp, 0o644)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise
    except OSError as e:
        logger.error("ports: could not write state file %s: %s", path, e)
        return False
    return True


def effective(primary: int) -> list[int]:
    """Extra ports a fresh ``remote`` block should list.

    State-pinned values win (an explicitly cleared list stays empty); with no
    state file the installer's ``OVNODE_EXTRA_PORTS`` is the fallback. The
    primary port and duplicates are always filtered out.
    """
    state = read_state()
    if state is None:
        from core.config import parse_extra_ports

        source = parse_extra_ports(os.getenv("OVNODE_EXTRA_PORTS", ""), primary)
    else:
        source = state
    result: list[int] = []
    for port in source:
        if port != primary and port not in result:
            result.append(port)
    return result


def remote_address(template: str) -> str | None:
    """Tunnel address from the first ``remote`` line (None when absent)."""
    for line in template.splitlines():
        match = _REMOTE_RE.match(line)
        if match:
            return match.group(1)
    return None


def rewrite_remote_lines(
    template: str, tunnel_addr: str, primary: int, extras: list[int]
) -> tuple[str, bool]:
    """Rewrite the ``remote`` block to exactly primary + extras.

    One line per port, primary first; existing lines collapse into the first
    one's position so repeated pushes never duplicate them. When the template
    has none, the block is inserted after ``client`` (matching the fresh
    template); with no anchor it is appended. Returns (new_template, changed).
    """
    remote_block = [f"remote {tunnel_addr} {port}" for port in (primary, *extras)]
    out: list[str] = []
    inserted = False
    for line in template.splitlines():
        if _REMOTE_RE.match(line):
            if not inserted:
                out.extend(remote_block)
                inserted = True
            continue
        out.append(line)
    if not inserted:
        idx = next((i for i, line in enumerate(out) if line.strip() == "client"), -1)
        out[idx + 1 : idx + 1] = remote_block
    new_template = "\n".join(out)
    if template.endswith("\n"):
        new_template += "\n"
    return new_template, new_template != template


def _atomic_write(path: str, content: str) -> None:
    """Write a non-secret file atomically via temp+rename."""
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".ports-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
            os.fchmod(f.fileno(), 0o644)
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass


def rewrite_nat_conf(content: str, primary: int, extras: list[int]) -> str:
    """Replace/insert the managed NAT keys, preserving every other line."""
    desired = {
        "VPN_PRIMARY_PORT": str(primary),
        "VPN_EXTRA_PORTS": ",".join(str(port) for port in extras),
    }
    out: list[str] = []
    seen: set[str] = set()
    for line in content.splitlines():
        key = line.strip().partition("=")[0].strip() if "=" in line else ""
        if key in desired:
            out.append(f"{key}={desired.pop(key)}")
            seen.add(key)
        elif key in seen:
            continue
        else:
            out.append(line)
    for key in _NAT_KEYS:
        if key in desired:
            out.append(f"{key}={desired[key]}")
    return "\n".join(out) + "\n"


def _apply_nat(primary: int, extras: list[int]) -> str:
    """Keep the installer NAT conf in sync and re-apply its rules.

    Best-effort: Docker (rules live inside the container) and hosts without
    the installer's NAT files are reported in the message instead of failing —
    the state file and client template are already updated.
    """
    if is_docker():
        return "NAT redirects skipped (Docker applies them inside the container)."
    if not (os.path.isfile(NAT_CONF) and os.access(NAT_SCRIPT, os.X_OK)):
        return (
            "NAT redirects skipped (native NAT files not present — "
            "run ovnode-nat.sh apply manually if this host uses them)."
        )
    try:
        with open(NAT_CONF, encoding="utf-8") as f:
            content = f.read()
    except OSError:
        content = ""
    try:
        _atomic_write(NAT_CONF, rewrite_nat_conf(content, primary, extras))
    except OSError as e:
        logger.error("ports: could not write NAT conf %s: %s", NAT_CONF, e)
        return "NAT redirects not applied (NAT conf could not be written)."
    try:
        result = subprocess.run([NAT_SCRIPT, "apply"], capture_output=True, text=True, timeout=30)
    except Exception as e:
        logger.warning("ports: could not run %s apply: %s", NAT_SCRIPT, e)
        return "NAT redirects not applied (script failed — they apply on the next node restart)."
    if result.returncode != 0:
        logger.warning(
            "ports: %s apply exited %s: %s",
            NAT_SCRIPT,
            result.returncode,
            (result.stderr or "").strip(),
        )
        return "NAT redirects not applied (script failed — they apply on the next node restart)."
    return "NAT redirects applied."


def _invalidate_cached_profiles() -> None:
    """Delete cached .ovpn files, exactly like change_config() does."""
    from core.openvpn.control import _invalidate_cached_ovpn

    _invalidate_cached_ovpn()


def set_extra_ports(primary: int, raw: object) -> tuple[bool, str]:
    """Apply a panel extra-ports push and report what happened.

    Updates the state file, rebuilds the client template's ``remote`` block
    (invalidating cached profiles when it changed) and — on native installs
    where the installer's NAT files exist — rewrites ``/etc/default/ovnode-nat``
    and runs ``ovnode-nat.sh apply`` best-effort. An unchanged list is a total
    no-op: no write, no NAT run, no signal. Returns ``(ok, message)``.
    """
    extras = validate(raw, primary)
    if extras is None:
        return (
            False,
            "Invalid extra ports — send comma-separated ports 1-65535, "
            "different from the primary VPN port.",
        )

    state_changed = write_state(extras)

    template_changed = False
    try:
        path = template_path()
        with open(path, encoding="utf-8") as f:
            template = f.read()
        address = remote_address(template)
        if not address or address == "UPDATE_VIA_PANEL":
            from core.openvpn.pki import _node_public_ip

            address = _node_public_ip()
        new_template, template_changed = rewrite_remote_lines(template, address, primary, extras)
        if template_changed:
            _atomic_write(path, new_template)
    except OSError as e:
        logger.warning("ports: could not update the client template: %s", e)

    if not state_changed and not template_changed:
        listed = ",".join(str(port) for port in extras) or "none"
        return True, f"Extra ports already match ({listed}) — nothing changed."

    if template_changed:
        _invalidate_cached_profiles()
    listed = ",".join(str(port) for port in extras) or "none"
    return True, f"Extra ports set to {listed}. {_apply_nat(primary, extras)}"
