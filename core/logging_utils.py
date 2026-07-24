"""Robust logging utilities for installer operations and node management."""
import logging
import os
from datetime import datetime
from pathlib import Path

from core.config import settings

# ============================================================
# File & Console Handlers
# ============================================================

def _get_log_dir() -> Path:
    """Return the directory where log files should live."""
    # If running inside the container, logs go next to config.
    if os.getenv("CONTAINER_ENV"):
        return Path(__file__).parent.parent / "data"
    # Local dev: put under the project root.
    return Path(__file__).parent.parent.parent / "logs"

def _file_formatter():
    return logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)-32s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

def _console_formatter():
    return logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(message)s",
        datefmt="%H:%M:%S",
    )

def _common_handlers():
    log_dir = _get_log_dir()
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "installer_node.log"

    # File handler: structured, persistent, includes timestamp and logger name
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(_file_formatter())

    # Console handler: concise, human-friendly
    ch = logging.StreamHandler()
    ch.setLevel(
        logging.WARNING
        if os.getenv("LOG_LEVEL", "").upper() == "WARNING"
        else logging.INFO
    )
    ch.setFormatter(_console_formatter())

    return [fh, ch]

# root logger configured for the whole app
def _root_logger():
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    if not root.handlers:
        for h in _common_handlers():
            root.addHandler(h)
    return root

# named loggers
_INSTALLER_LOGGER = logging.getLogger("ovnode.installer")
_INSTALLER_LOGGER.setLevel(logging.DEBUG)
if not _INSTALLER_LOGGER.handlers:
    handlers = _common_handlers()
    _INSTALLER_LOGGER.addHandler(handlers[0])
    _INSTALLER_LOGGER.addHandler(handlers[1])

_NODE_LOGGER = logging.getLogger("ovnode.node")
_NODE_LOGGER.setLevel(logging.DEBUG)
if not _NODE_LOGGER.handlers:
    handlers = _common_handlers()
    _NODE_LOGGER.addHandler(handlers[0])
    _NODE_LOGGER.addHandler(handlers[1])

def installer():
    return _INSTALLER_LOGGER

def node():
    return _NODE_LOGGER

# convenience helpers

class TraceCtx:
    """Context manager that logs function entry/exit and elapsed time."""
    def __init__(self, label, logger_=None):
        self.label = label
        self.logger = logger_ or logging.getLogger()

    def __enter__(self):
        self._start = datetime.utcnow()
        self.logger.debug(">>> ENTER %s", self.label)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        elapsed = (datetime.utcnow() - self._start).total_seconds()
        if exc_type:
            self.logger.error(
                "!!! EXIT %s — %s: %s (%.2fs)",
                self.label, exc_type.__name__, exc_val, elapsed,
            )
        else:
            self.logger.debug("=== EXIT %s (%.2fs)", self.label, elapsed)
        return False

def traced(logger_=None):
    def decorator(fn):
        from functools import wraps
        @wraps(fn)
        def _wrapper(*args, **kwargs):
            label = f"{logger_.name}.{fn.__name__}" if logger_ else f"{fn.__module__}.{fn.__name__}"
            with TraceCtx(label, logger_):
                return fn(*args, **kwargs)
        return _wrapper
    return decorator

# structured / audit helpers

def event(msg, **extra):
    _INSTALLER_LOGGER.info(msg, extra=extra)

def audit(action, target, status, details="", uid=None, **kwargs):
    payload = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "action": action,
        "target": target,
        "status": status,
        "details": details,
        "uid": uid,
        **kwargs,
    }
    _NODE_LOGGER.info("AUDIT | %s", str(payload))

def install_log(func):
    """Decorator that logs function entry/exit."""
    from functools import wraps
    @wraps(func)
    def _wrapper(*args, **kwargs):
        with TraceCtx(f"{_INSTALLER_LOGGER.name}.{func.__name__}"):
            return func(*args, **kwargs)
    return _wrapper
