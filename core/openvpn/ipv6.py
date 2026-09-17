# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Panel-managed IPv6 setting for the VPN server.

The panel owns whether the node pushes an IPv6 pool; the node mirrors it in a
small state file (``ovnode/ipv6``) and in the three directives
:mod:`core.openvpn.pki` generates for a fresh server.conf (``tun-ipv6``,
``server-ipv6 <prefix>`` and the ``route-ipv6`` push). The state file makes
the operator's choice survive server.conf regeneration instead of silently
reverting to the installer/env default — same pattern as
:mod:`core.openvpn.dns` for the pushed DNS servers.

Writes are atomic (mkstemp + os.replace), matching ``store.write_state``.
"""

from __future__ import annotations

import ipaddress
import os
import re
import tempfile

from core.logger import logger

DEFAULT_PREFIX = "fd42:42:42:42::/64"

_STATE_KEYS = ("enabled", "prefix")

# The canonical lines _fresh_server_conf() emits. `tun-ipv6` and the route
# push match exactly; `server-ipv6` matches any prefix so a panel push with a
# new prefix replaces the old line instead of duplicating it.
_TUN_IPV6_RE = re.compile(r"^\s*tun-ipv6\s*$")
_SERVER_IPV6_RE = re.compile(r"^\s*server-ipv6\s+\S+\s*$")
_ROUTE_IPV6_RE = re.compile(r'^\s*push\s+"?route-ipv6\s+2000::/3"?\s*$')


def state_path() -> str:
    """Location of the desired-IPv6 state file (root read at call time)."""
    root = os.getenv("OVNODE_OPENVPN_ROOT", "/etc/openvpn")
    return os.path.join(root, "ovnode", "ipv6")


def validate_prefix(value: object) -> str | None:
    """Normalized IPv6 network (explicit prefix length required), or None."""
    if value is None:
        return None
    candidate = str(value).strip()
    if not candidate or "/" not in candidate:
        logger.warning("ipv6: rejected invalid prefix %r", value)
        return None
    try:
        network = ipaddress.ip_network(candidate, strict=False)
    except ValueError as e:
        logger.warning("ipv6: rejected invalid prefix %r (%s)", value, e)
        return None
    if network.version != 6:
        logger.warning("ipv6: rejected non-IPv6 prefix %r", value)
        return None
    return str(network)


def _defaults() -> tuple[bool, str]:
    """Installer/env defaults, used for un-pinned state values."""
    try:
        from core.openvpn.pki import _ipv6_enabled, _ipv6_prefix

        return _ipv6_enabled(), validate_prefix(_ipv6_prefix()) or DEFAULT_PREFIX
    except Exception:
        return False, DEFAULT_PREFIX


def read_state() -> dict[str, str]:
    """enabled/prefix from the state file ({} when unset or unreadable)."""
    state: dict[str, str] = {}
    try:
        with open(state_path(), encoding="utf-8") as f:
            for line in f:
                if "=" not in line:
                    continue
                key, _, value = line.strip().partition("=")
                if key in _STATE_KEYS and value.strip():
                    state[key] = value.strip()
    except OSError:
        pass
    return state


def write_state(enabled: bool, prefix: str) -> bool:
    """Atomically persist the desired IPv6 setting. Returns True when changed."""
    desired = {"enabled": "1" if enabled else "0", "prefix": prefix}
    path = state_path()
    if read_state() == desired and os.path.exists(path):
        return False
    directory = os.path.dirname(path)
    try:
        os.makedirs(directory, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".ipv6-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                for key in _STATE_KEYS:
                    f.write(f"{key}={desired[key]}\n")
            os.chmod(tmp, 0o644)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise
    except OSError as e:
        logger.error("ipv6: could not write state file %s: %s", path, e)
        return False
    return True


def _conf_block(config: str) -> tuple[bool | None, str | None]:
    """(enabled, prefix) as currently present in a server.conf, or (None, None)."""
    enabled: bool | None = None
    prefix: str | None = None
    for line in config.splitlines():
        if _TUN_IPV6_RE.match(line) or _ROUTE_IPV6_RE.match(line):
            enabled = True
        elif _SERVER_IPV6_RE.match(line):
            enabled = True
            parts = line.split()
            prefix = parts[1] if len(parts) > 1 else None
    return enabled, prefix


def effective(config: str = "") -> tuple[bool, str]:
    """Current desired (enabled, prefix).

    State-pinned values win per field, then what ``config`` already carries
    (panel-managed lines survive nodes that predate the state file), then the
    installer defaults (env/settings). An unreadable stored value is skipped.
    """
    state = read_state()
    conf_enabled, conf_prefix = _conf_block(config)
    default_enabled, default_prefix = _defaults()
    raw_enabled = state.get("enabled")
    if raw_enabled is not None:
        enabled = raw_enabled.strip().lower() in ("1", "true", "yes", "on")
    elif conf_enabled is not None:
        enabled = conf_enabled
    else:
        enabled = default_enabled
    prefix = validate_prefix(state.get("prefix")) or validate_prefix(conf_prefix) or default_prefix
    return enabled, prefix


def block_lines(prefix: str) -> list[str]:
    """The three directives a fresh server.conf emits when IPv6 is on."""
    return ["tun-ipv6", f"server-ipv6 {prefix}", 'push "route-ipv6 2000::/3"']


def _is_block_line(line: str) -> bool:
    return bool(
        _TUN_IPV6_RE.match(line) or _SERVER_IPV6_RE.match(line) or _ROUTE_IPV6_RE.match(line)
    )


def rewrite_block(config: str, enabled: bool, prefix: str) -> tuple[str, bool]:
    """Rewrite the IPv6 directives to exactly one block (or none).

    Existing ``tun-ipv6`` / ``server-ipv6`` / ``route-ipv6`` lines collapse
    into the first one's position, so a repeated push never duplicates them.
    When the config has none, the block is inserted after
    ``push "block-outside-dns"`` (or after the redirect-gateway push, or after
    ``server``); with no anchor at all it is appended. Returns
    ``(new_config, changed)``.
    """
    desired = block_lines(prefix) if enabled else []
    out: list[str] = []
    inserted = False
    found = False
    for line in config.splitlines():
        if _is_block_line(line):
            found = True
            if not inserted and desired:
                out.extend(desired)
                inserted = True
            continue
        out.append(line)
    if not found and desired:
        anchor = None
        for i, line in enumerate(out):
            if line.strip().startswith('push "block-outside-dns"'):
                anchor = i
                break
        if anchor is None:
            for i, line in enumerate(out):
                if line.strip().startswith('push "redirect-gateway'):
                    anchor = i
                    break
        if anchor is None:
            for i, line in enumerate(out):
                if line.strip().startswith("server "):
                    anchor = i
                    break
        if anchor is None:
            out.extend(desired)
        else:
            out[anchor + 1 : anchor + 1] = desired
    new_config = "\n".join(out)
    if config.endswith("\n"):
        new_config += "\n"
    return new_config, new_config != config
