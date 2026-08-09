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
