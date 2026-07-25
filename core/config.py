import os

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    service_port: int = 2083
    api_key: str
    debug: str = "WARNING"
    doc: bool = False
    # Built-in TLS — when both are set, uvicorn serves HTTPS directly.
    # Certs live under /etc/letsencrypt/<domain>/ or /etc/ssl/self-signed/.
    ssl_certfile: str = ""
    ssl_keyfile: str = ""

    class Config:
        env_file = os.path.join(os.path.dirname(__file__), "../.env")


settings = Settings()
