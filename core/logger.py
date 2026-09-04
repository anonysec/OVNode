# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""OVNode logging.

One configuration, three sinks:

* rotating file  — ``data/app.log`` (5 MB × 3), full detail with module:line
* stderr         — captured by journald/Docker, same records
* ring buffer    — last 500 records in memory, powering ``GET /sync/logs``
                   and the error counters in ``GET /sync/status`` so a node
                   can be diagnosed from the panel side without SSH.

Uvicorn is started with ``log_config=None`` so its loggers propagate here —
every line of the process shares one format and one rotation policy.
"""

import logging
import os
import time
from collections import deque
from logging.handlers import RotatingFileHandler

from core.config import settings

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(os.path.dirname(BASE_DIR), "data", "app.log")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
}

_RING_SIZE = 500
_ring: deque[dict] = deque(maxlen=_RING_SIZE)


class _RingBufferHandler(logging.Handler):
    """Keep the last N records in memory for /sync/logs and error stats."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            _ring.append(
                {
                    "ts": record.created,
                    "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(record.created)),
                    "level": record.levelname,
                    "levelno": record.levelno,
                    "logger": record.name,
                    "where": f"{record.module}:{record.lineno}",
                    "message": self.format(record),
                }
            )
        except Exception:  # never let diagnostics break the caller
            pass


def _build_handlers() -> list[logging.Handler]:
    detail = logging.Formatter(
        "{asctime} {levelname:<7} {name} {module}:{lineno} — {message}",
        style="{",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler = RotatingFileHandler(
        LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    file_handler.setFormatter(detail)

    stream_handler = logging.StreamHandler()  # stderr → journald / docker logs
    stream_handler.setFormatter(detail)

    ring_handler = _RingBufferHandler()
    ring_handler.setFormatter(logging.Formatter("{message}", style="{"))
    return [file_handler, stream_handler, ring_handler]


# Attach explicitly (not via basicConfig, which silently no-ops when any
# other library configured the root logger first).
_root = logging.getLogger()
if not any(isinstance(h, _RingBufferHandler) for h in _root.handlers):
    for _h in _build_handlers():
        _root.addHandler(_h)
_root.setLevel(_LEVELS.get(settings.debug.upper(), logging.WARNING))

# Single named logger used throughout the node
logger = logging.getLogger("ovnode")
# The node's own records are always kept (root level only gates third-party
# noise): INFO like "user created" is exactly what /sync/logs is for.
logger.setLevel(min(logging.INFO, _LEVELS.get(settings.debug.upper(), logging.WARNING)))


# ── diagnostics API (consumed by core/api/routes.py) ─────────────────


def recent_logs(min_level: str = "WARNING", limit: int = 200) -> list[dict]:
    """Newest-last records at or above ``min_level`` (max ``limit``)."""
    threshold = _LEVELS.get(str(min_level).upper(), logging.WARNING)
    limit = max(1, min(int(limit), _RING_SIZE))
    matched = [r for r in list(_ring) if r["levelno"] >= threshold]
    return matched[-limit:]


def log_stats() -> dict:
    """Error/warning counters for /sync/status (last hour, ring-bounded)."""
    cutoff = time.time() - 3600
    warnings = errors = 0
    last_error: str | None = None
    for r in list(_ring):
        if r["ts"] < cutoff:
            continue
        if r["levelno"] >= logging.ERROR:
            errors += 1
            last_error = f"{r['time']} {r['message']}"
        elif r["levelno"] >= logging.WARNING:
            warnings += 1
    return {"errors_1h": errors, "warnings_1h": warnings, "last_error": last_error}
