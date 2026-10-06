# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Panel-triggered node software update (POST /sync/update).

The command is the fixed ``bash <app_dir>/install.sh update`` — nothing
caller-controlled reaches a shell — launched detached so the HTTP request
returns immediately. Docker nodes refuse: the container image is owned by
the host.
"""

from __future__ import annotations

import os
import subprocess

from backend.logger import logger
from backend.version import __version__

DEFAULT_APP_DIR = "/opt/ovnode"
INSTALL_SCRIPT = "install.sh"


def app_dir() -> str:
    """Node install directory (OVNODE_APP_DIR overrides the default)."""
    return os.getenv("OVNODE_APP_DIR", DEFAULT_APP_DIR)


def install_script_path() -> str:
    return os.path.join(app_dir(), INSTALL_SCRIPT)


def is_docker() -> bool:
    return os.path.exists("/.dockerenv")


def trigger_update() -> dict:
    """Start ``install.sh update`` detached; return the API envelope body.

    Refusals (Docker, missing installer) are business failures inside the
    envelope, not HTTP errors.
    """
    if is_docker():
        return {
            "success": False,
            "msg": "This node runs in Docker — update the container from the host "
            "(docker compose pull && docker compose up -d).",
            "data": None,
        }
    script = install_script_path()
    if not os.path.isfile(script):
        return {
            "success": False,
            "msg": f"install.sh was not found at {script} — run the node update from the host.",
            "data": None,
        }
    argv = ["bash", script, "update"]
    try:
        # Fixed argv, no shell: nothing the caller controls reaches a command.
        subprocess.Popen(
            argv,
            cwd=os.path.dirname(script),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as e:
        logger.error("Could not launch the node updater: %s", e)
        return {"success": False, "msg": f"Could not start the updater: {e}", "data": None}
    logger.info("Node update started detached: %s", " ".join(argv))
    return {
        "success": True,
        "msg": "Update started in the background — the node restarts when it finishes.",
        "data": {"version": __version__},
    }
