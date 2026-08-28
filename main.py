# Copyright (c) 2025 anonysec. All rights reserved.
# Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.

import signal

from core.logger import logger

logger.info("Starting OV-Node...")


def _handle_shutdown(signum, frame):
    """Log a clean shutdown reason on SIGTERM/SIGINT."""
    logger.info("OV-Node received %s — shutting down cleanly.", signal.Signals(signum).name)
    raise SystemExit(0)


signal.signal(signal.SIGTERM, _handle_shutdown)
signal.signal(signal.SIGINT, _handle_shutdown)


def main():
    import os

    from uvicorn import Config, Server

    from core.app import api
    from core.config import settings

    ssl_kwargs = {}
    if settings.ssl_certfile and settings.ssl_keyfile:
        if not os.path.isfile(settings.ssl_certfile):
            raise SystemExit(f"SSL cert file not found: {settings.ssl_certfile}")
        if not os.path.isfile(settings.ssl_keyfile):
            raise SystemExit(f"SSL key file not found: {settings.ssl_keyfile}")
        ssl_kwargs = {"ssl_certfile": settings.ssl_certfile, "ssl_keyfile": settings.ssl_keyfile}

    config = Config(
        app=api,
        host="0.0.0.0",
        port=settings.service_port,
        reload=False,
        workers=1,
        # Unified logging: uvicorn's loggers propagate to the root config in
        # core/logger.py (rotating file + journald + /sync/logs ring buffer).
        log_config=None,
        # Per-request access logging is pure overhead for a machine-to-machine
        # API polled every few seconds by the panel; keep it for DEBUG only.
        access_log=settings.debug.upper() == "DEBUG",
        server_header=False,
        **ssl_kwargs,
    )
    server = Server(config=config)
    server.run()


if __name__ == "__main__":
    main()
