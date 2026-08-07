import os

from pydantic_settings import BaseSettings


def _validate_api_key(v: str) -> str:
    """Enforce minimum entropy on API key at startup."""
    # Must be at least 16 chars
    if len(v) < 16:
        raise ValueError(
            "API_KEY must be at least 16 characters for security. "
            "Generate one with: openssl rand -hex 32"
        )
    # Reject common placeholders
    placeholders = {
        "changeme",
        "secret",
        "changeme123",
        "supersecret",
        "dev",
        "test",
        "your-secret",
        "change_me_to_a_long_random_string_at_least_16_chars",
    }
    if v.lower().strip() in placeholders:
        raise ValueError("API_KEY cannot be a default/placeholder value")
    # Reject low-entropy secrets (e.g. all same char, or dictionary word)
    if len(set(v)) < 8:
        raise ValueError(
            "API_KEY has low character diversity; "
            "use a cryptographically random key"
        )
    return v


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
        _validate_api_key(self.api_key)


settings = Settings()
