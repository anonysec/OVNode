# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

import signal

from backend.logger import logger

logger.info("Starting OV-Node...")


def _handle_shutdown(signum, frame):
    logger.info("OV-Node received %s — shutting down cleanly.", signal.Signals(signum).name)
    raise SystemExit(0)


signal.signal(signal.SIGTERM, _handle_shutdown)
signal.signal(signal.SIGINT, _handle_shutdown)


def _tls_material() -> tuple[str, str]:
    """Cert + key for the API listener.

    TLS is not optional: the panel pins the node CA, so a plaintext listener
    is a hole. The operator's SSL_CERTFILE/SSL_KEYFILE win; the node PKI's
    server pair (pki/issued/server.crt + pki/private/server.key, signed by
    pki/ca.crt) is the default. A missing or unreadable file kills startup —
    there is no plaintext fallback.
    """
    import os

    from backend.config import settings
    from backend.openvpn.pki import paths

    cert = settings.ssl_certfile or paths.SERVER_CERT
    key = settings.ssl_keyfile or paths.SERVER_KEY
    for label, path in (("cert", cert), ("key", key)):
        if not os.path.isfile(path) or not os.access(path, os.R_OK):
            raise SystemExit(
                f"TLS {label} missing or unreadable: {path} — refusing to start without TLS"
            )
    return cert, key


def main():
    from uvicorn import Config, Server

    from backend.app import api
    from backend.config import settings

    ssl_certfile, ssl_keyfile = _tls_material()

    config = Config(
        app=api,
        host="0.0.0.0",
        port=settings.service_port,
        reload=False,
        workers=1,
        # uvicorn's loggers propagate to the root config in backend/logger.py.
        log_config=None,
        # Access logs stay DEBUG-only: the panel polls this API every few seconds.
        access_log=settings.debug.upper() == "DEBUG",
        server_header=False,
        ssl_certfile=ssl_certfile,
        ssl_keyfile=ssl_keyfile,
    )
    server = Server(config=config)
    server.run()


if __name__ == "__main__":
    main()
