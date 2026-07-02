import os
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    service_port: int = 2083
    api_key: str
    debug: str = "WARNING"
    doc: bool = False

    class Config:
        env_file = os.path.join(os.path.dirname(__file__), "../.env")


settings = Settings()
