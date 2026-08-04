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
        if len(self.api_key) < 16:
            raise ValueError(
                "API_KEY must be at least 16 characters for security. "
                "Generate one with: openssl rand -hex 32"
            )


settings = Settings()
