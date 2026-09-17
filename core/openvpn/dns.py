# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Panel-managed DNS servers for pushed client configs.

The panel owns the desired DNS list; the node mirrors it in a small state
file and in the ``push "dhcp-option DNS ..."`` lines of server.conf. The
state file makes the operator's choice survive server.conf regeneration
(:mod:`core.openvpn.pki`) instead of silently reverting to the installer
defaults. Writes are atomic (mkstemp + os.replace), matching
``store.write_state``.
"""

from __future__ import annotations

import ipaddress
import os
import re
import tempfile

from core.logger import logger

# Fresh server.conf emits push "dhcp-option DNS <ip>"; the unquoted form is
# accepted too (hand-edited configs). `DNS6` never matches (DNS + \s+).
_PUSH_DNS_RE = re.compile(r'^\s*push\s+"?dhcp-option\s+DNS\s+([^"\s]+)"?\s*$', re.IGNORECASE)

_STATE_KEYS = ("dns1", "dns2")


def state_path() -> str:
    """Location of the desired-DNS state file (root read at call time)."""
    root = os.getenv("OVNODE_OPENVPN_ROOT", "/etc/openvpn")
    return os.path.join(root, "ovnode", "dns")


def _default_dns() -> tuple[str, str]:
    """Installer defaults (env/settings), used for un-pinned state values."""
    try:
        from core.openvpn.pki import _vpn_dns

        return _vpn_dns()
    except Exception:
        return "1.1.1.1", "8.8.8.8"


def validate(value: object) -> str | None:
    """Normalized IP address, or None when missing/invalid."""
    if value is None:
        return None
    candidate = str(value).strip()
    if not candidate:
        return None
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        logger.warning("dns: rejected invalid DNS address %r", value)
        return None


def read_state() -> dict[str, str]:
    """dns1/dns2 from the state file ({} when unset or unreadable)."""
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


def write_state(servers: list[str]) -> bool:
    """Atomically persist the desired DNS list. Returns True when changed."""
    first = servers[0] if len(servers) > 0 else None
    second = servers[1] if len(servers) > 1 else None
    desired = {key: value for key, value in zip(_STATE_KEYS, (first, second), strict=True) if value}
    path = state_path()
    if desired and read_state() == desired and os.path.exists(path):
        return False
    directory = os.path.dirname(path)
    try:
        os.makedirs(directory, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".dns-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                for key in _STATE_KEYS:
                    if desired.get(key):
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
        logger.error("dns: could not write state file %s: %s", path, e)
        return False
    return True


def effective(defaults: tuple[str, str]) -> list[str]:
    """Desired DNS list for a freshly generated server.conf.

    State-pinned values win per field; the rest fall back to the installer
    defaults (env/settings).
    """
    state = read_state()
    values = [state.get("dns1") or defaults[0], state.get("dns2") or defaults[1]]
    return [value for value in values if value]


def pushed_servers(config: str) -> list[str]:
    """DNS addresses currently present in server.conf push lines (in order)."""
    servers: list[str] = []
    for line in config.splitlines():
        match = _PUSH_DNS_RE.match(line)
        if match:
            servers.append(match.group(1))
    return servers


def resolve_desired(config: str, dns1: str | None, dns2: str | None) -> list[str]:
    """Merge panel values over the current state, then conf, then defaults.

    Omitted (None) fields keep their current value, so a DNS1-only push
    never clobbers DNS2.
    """
    state = read_state()
    from_conf = pushed_servers(config)
    defaults = _default_dns()
    current = [
        state.get("dns1") or (from_conf[0] if from_conf else defaults[0]),
        state.get("dns2") or (from_conf[1] if len(from_conf) > 1 else defaults[1]),
    ]
    if dns1 is not None:
        current[0] = dns1
    if dns2 is not None:
        current[1] = dns2
    return [value for value in current if value]


def rewrite_push_lines(config: str, servers: list[str]) -> tuple[str, bool]:
    """Rewrite the DNS push lines to exactly ``servers`` (deduplicated).

    Existing lines collapse into the first one's position, so repeats are
    removed instead of accumulating. When the config has none, the block is
    inserted after the redirect-gateway push (or after ``server``); with
    neither anchor it is appended. Returns (new_config, changed).
    """
    desired = [f'push "dhcp-option DNS {server}"' for server in servers]
    out: list[str] = []
    inserted = False
    found = False
    for line in config.splitlines():
        if _PUSH_DNS_RE.match(line):
            found = True
            if not inserted:
                out.extend(desired)
                inserted = True
            continue
        out.append(line)
    if not found and desired:
        anchor = None
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
