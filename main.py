import logging
from core.logging_utils import install_log, node, TraceCtx
from core.config import settings

# Get the node-specific logger
node_log = node()


def main():
    node_log.info("Starting OV-Node...")
    # reload=True is a development-only feature (extra watcher process + constant
    # filesystem polling). Disabled to keep the node lightweight.
    from core.app import api
    from uvicorn import Config, Server
    
    ssl_kwargs = {}
    if settings.ssl_certfile and settings.ssl_keyfile:
        ssl_kwargs = {"ssl_certfile": settings.ssl_certfile, "ssl_keyfile": settings.ssl_keyfile}

    config = Config(app=api, host="0.0.0.0", port=settings.service_port, reload=False, workers=1, **ssl_kwargs)
    server = Server(config=config)
    
    with TraceCtx("uvicorn.run"):
        server.run()


if __name__ == "__main__":
    main()