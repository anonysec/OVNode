# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

import logging
import os

from pydantic import Field
from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)


def parse_extra_ports(raw: str, primary_port: int) -> list[int]:
    """Parse a comma-separated port list; validated, de-duplicated, primary excluded."""
    ports: list[int] = []
    for token in (raw or "").replace(";", ",").split(","):
        token = token.strip()
        if not token:
            continue
        try:
            port = int(token)
        except ValueError:
            logger.warning("Ignoring invalid extra VPN port %r (not a number)", token)
            continue
        if port == primary_port or port in ports:
            continue
        if 1 <= port <= 65535:
            ports.append(port)
        else:
            logger.warning("Ignoring extra VPN port %r (out of range 1-65535)", token)
    return ports


class Settings(BaseSettings):
    service_port: int = Field(default=2083, ge=1, le=65535)
    api_key: str
    debug: str = "WARNING"
    doc: bool = False
    # Built-in TLS — when both are set, uvicorn serves HTTPS directly.
    # Certs live under /etc/letsencrypt/<domain>/ or /etc/ssl/self-signed/.
    ssl_certfile: str | None = None
    ssl_keyfile: str | None = None
    # Installer metadata (ignored by the app, used by install.sh for state)
    node_name: str = "node-1"
    data_dir: str = ""
    openvpn_port: int = Field(default=1194, ge=1, le=65535)
    tls_method: str = "none"
    # OpenVPN server tuning (OVNODE_* env vars; see .env.example)
    ovnode_runtime_user: str = "nobody"
    ovnode_runtime_group: str = "nogroup"
    ovnode_management_port: int = Field(default=7505, ge=1, le=65535)
    ovnode_vpn_network: str = "10.8.0.0"
    ovnode_vpn_netmask: str = "255.255.255.0"
    ovnode_vpn_dns1: str = "1.1.1.1"
    ovnode_vpn_dns2: str = "8.8.8.8"
    ovnode_max_clients: int = 100
    ovnode_enable_ipv6: bool = False
    ovnode_ipv6_prefix: str = "fd42:42:42:42::/64"
    # Extra VPN ports (comma-separated, e.g. "443,8443"). The node stays a
    # single OpenVPN instance listening on OPENVPN_PORT; the installer adds
    # iptables REDIRECT rules so the extra ports reach the same daemon, and
    # generated .ovpn profiles list one `remote` line per port so clients
    # fail over automatically when an ISP blocks a port.
    ovnode_extra_ports: str = ""

    @property
    def extra_vpn_ports(self) -> list[int]:
        """Parsed, validated, de-duplicated extra ports (primary excluded)."""
        return parse_extra_ports(self.ovnode_extra_ports, self.openvpn_port)

    model_config = {"env_file": os.path.join(os.path.dirname(__file__), "../.env")}

    def __init__(self, **data):
        super().__init__(**data)
        normalized = self.api_key.strip()
        if len(normalized) < 16:
            raise ValueError(
                "API_KEY must be at least 16 characters for security. "
                "Generate one with: openssl rand -hex 32"
            )
        placeholders = {
            "change_me_to_a_long_random_string_at_least_16_chars",
            "changeme",
            "default",
        }
        if normalized.lower() in placeholders or "change_me" in normalized.lower():
            raise ValueError(
                "API_KEY is still a placeholder; generate a random secret before starting OVNode"
            )
        self.api_key = normalized


settings = Settings()
