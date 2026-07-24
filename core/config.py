import os

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    service_port: int = 2083
    api_key: str
    debug: str = "WARNING"
    doc: bool = False
    # When True, the panel must connect to this node over HTTPS (TLS).
    # The node itself still serves HTTP; TLS termination is expected at a
    # reverse proxy (nginx/caddy) in front of the node container.
    require_tls: bool = False

    class Config:
        env_file = os.path.join(os.path.dirname(__file__), "../.env")


settings = Settings()
