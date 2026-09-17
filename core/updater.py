# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Panel-triggered node software update (POST /sync/update).

The panel can only ask the node to run its own installer in update mode.
Nothing caller-controlled ever reaches a shell: the command is the fixed
``bash <app_dir>/install.sh update --json``, launched detached so the HTTP
request returns immediately (the update restarts the agent when it lands).
Docker nodes refuse — the container image is owned by the host.
"""

from __future__ import annotations

import os
import subprocess

from core.logger import logger
from core.version import __version__

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

    Always returns the ``{success, msg, data}`` contract shape: refusals
    (Docker, missing installer) are business failures the panel surfaces,
    not HTTP errors.
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
    argv = ["bash", script, "update", "--json"]
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
