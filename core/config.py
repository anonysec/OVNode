# Copyright (c) 2025 anonysec. All rights reserved.
# Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.

import os

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    service_port: int = 2083
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
    openvpn_port: int = 1194
    tls_method: str = "none"
    # OVManager panel base URL (e.g. https://panel.example.com:8443).
    # When set, the client-connect hook performs the GLOBAL (cross-node)
    # max-login check against the panel's /mlogin/status/{username} endpoint,
    # authenticating with this node's name + API key (X-Node-Name / key headers).
    panel_url: str = ""
    # When the panel is unreachable during the global check: fail-open (default,
    # allow the connection) or fail-closed (reject).
    ovnode_global_fail_closed: bool = False
    # OpenVPN server tuning (OVNODE_* env vars; see .env.example)
    ovnode_runtime_user: str = "nobody"
    ovnode_runtime_group: str = "nogroup"
    ovnode_management_port: int = 7505
    ovnode_vpn_network: str = "10.8.0.0"
    ovnode_vpn_netmask: str = "255.255.255.0"
    ovnode_vpn_dns1: str = "1.1.1.1"
    ovnode_vpn_dns2: str = "8.8.8.8"
    ovnode_max_clients: int = 100
    ovnode_enable_ipv6: bool = False
    ovnode_ipv6_prefix: str = "fd42:42:42:42::/64"

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
