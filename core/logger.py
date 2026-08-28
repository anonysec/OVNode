# Copyright (c) 2025 anonysec. All rights reserved.
# Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.

"""OVNode logging setup.

One file. One logger. stdlib logging. No abstractions.
Rotates at 5 MB (3 backups) so small VPS disks never fill up.
"""

import logging
import os
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

_handler = RotatingFileHandler(
    LOG_FILE,
    maxBytes=5 * 1024 * 1024,
    backupCount=3,
    encoding="utf-8",
)

logging.basicConfig(
    handlers=[_handler],
    format="{asctime} - {levelname} - {message}",
    style="{",
    datefmt="%Y-%m-%d %H:%M",
    level=_LEVELS.get(settings.debug.upper(), logging.WARNING),
)

# Single named logger used throughout the node
logger = logging.getLogger("ovnode")
