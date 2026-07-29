"""OVNode logging setup.

One file. One logger. stdlib logging. No abstractions.
"""

import logging
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(os.path.dirname(BASE_DIR), "data", "app.log")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

_LEVELS = {"DEBUG": logging.DEBUG, "INFO": logging.INFO, "WARNING": logging.WARNING, "ERROR": logging.ERROR}

from core.config import settings

logging.basicConfig(
    filename=LOG_FILE, encoding="utf-8", filemode="a",
    format="{asctime} - {levelname} - {message}", style="{",
    datefmt="%Y-%m-%d %H:%M", level=_LEVELS.get(settings.debug.upper(), logging.WARNING),
)

# Single named logger used throughout the node
logger = logging.getLogger("ovnode")
