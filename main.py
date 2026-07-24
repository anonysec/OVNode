import logging
from core.logging_utils import install_log, node, TraceCtx

# Get the node-specific logger
node_log = node()


def main():
    node_log.info("Starting OV-Node...")
    # reload=True is a development-only feature (extra watcher process + constant
    # filesystem polling). Disabled to keep the node lightweight.
    from core.app import api
    from uvicorn import Config, Server
    
    config = Config(app=api, host="0.0.0.0", port=2096, reload=False, workers=1)
    server = Server(config=config)
    
    with TraceCtx("uvicorn.run"):
        server.run()


if __name__ == "__main__":
    main()