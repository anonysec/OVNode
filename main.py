import logging
from core.logger import logger

logger.info("Starting OV-Node...")

def main():
    from core.app import api
    from uvicorn import Config, Server
    
    from core.config import settings
    ssl_kwargs = {}
    if settings.ssl_certfile and settings.ssl_keyfile:
        ssl_kwargs = {"ssl_certfile": settings.ssl_certfile, "ssl_keyfile": settings.ssl_keyfile}

    config = Config(app=api, host="0.0.0.0", port=settings.service_port, reload=False, workers=1, **ssl_kwargs)
    server = Server(config=config)
    server.run()

if __name__ == "__main__":
    main()
