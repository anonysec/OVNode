# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""OVNODE_* settings the PKI reads at call time (config.py is the source)."""

import os

from backend.openvpn import pki as _pki


def _env(name: str, default: str) -> str:
    """Read an OVNODE_* env var with a default (config.py is the source)."""
    try:
        from backend.config import settings

        return str(getattr(settings, f"ovnode_{name}", default) or default)
    except Exception:
        return os.getenv(f"OVNODE_{name.upper()}", default)


def _runtime_user() -> str:
    return _pki._env("runtime_user", "nobody")


def _runtime_group() -> str:
    return _pki._env("runtime_group", "nogroup")


def _management_port() -> int:
    try:
        return int(_pki._env("management_port", "7505"))
    except ValueError:
        return 7505


def _vpn_network() -> str:
    return _pki._env("vpn_network", "10.8.0.0")


def _vpn_netmask() -> str:
    return _pki._env("vpn_netmask", "255.255.255.0")


def _vpn_dns() -> tuple[str, str]:
    return _pki._env("vpn_dns1", "1.1.1.1"), _pki._env("vpn_dns2", "8.8.8.8")


def _max_clients() -> int:
    try:
        return max(1, int(_pki._env("max_clients", "250")))
    except ValueError:
        return 250


def _ipv6_enabled() -> bool:
    return _pki._env("enable_ipv6", "0").lower() in ("1", "true", "yes", "on")


def _ipv6_prefix() -> str:
    return _pki._env("ipv6_prefix", "fd42:42:42:42::/64")


def _openvpn_port() -> int:
    try:
        return int(os.getenv("OPENVPN_PORT", "1194"))
    except ValueError:
        return 1194


def _extra_vpn_ports() -> list[int]:
    """Extra ports the node is reachable on (iptables REDIRECT → primary)."""
    from backend.config import parse_extra_ports

    return parse_extra_ports(os.getenv("OVNODE_EXTRA_PORTS", ""), _pki._openvpn_port())
