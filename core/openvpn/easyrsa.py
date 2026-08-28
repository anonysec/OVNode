# Copyright (c) 2025 anonysec. All rights reserved.
# Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.

"""Shared easyrsa utilities for OVNode.

Provides a single `run_easyrsa()` helper used by both PKI initialization
(pki.py) and per-user cert management (users.py).
"""

import logging
import os
import subprocess

logger = logging.getLogger("easyrsa")

# Must match the paths used by pki.py
_OPENVPN_ROOT = os.getenv("OVNODE_OPENVPN_ROOT", "/etc/openvpn")
EASYRSA_DIR = os.path.join(_OPENVPN_ROOT, "server", "easy-rsa")
PKI_DIR = os.path.join(_OPENVPN_ROOT, "server", "pki")


def run_easyrsa(*args: str, timeout: int = 120, pki_dir: str | None = None) -> bool:
    """Run easyrsa with batch mode. Returns True on success.

    Args:
        *args: easyrsa subcommands and arguments (e.g. "build-client-full", "cn", "nopass")
        timeout: max seconds before the process is killed
        pki_dir: override the default PKI directory
    """
    easyrsa_bin = os.path.join(EASYRSA_DIR, "easyrsa")
    if not os.path.exists(easyrsa_bin):
        logger.error("easyrsa not found at %s", easyrsa_bin)
        return False
    try:
        target_pki = pki_dir or PKI_DIR
        cmd = [easyrsa_bin, f"--pki-dir={target_pki}"] + list(args)
        env = {**os.environ, "EASYRSA_BATCH": "1"}
        subprocess.run(
            cmd,
            cwd=EASYRSA_DIR,
            env=env,
            check=True,
            capture_output=True,
            timeout=timeout,
        )
        return True
    except subprocess.CalledProcessError as e:
        logger.error(
            "easyrsa %s failed (rc=%d): %s",
            " ".join(args),
            e.returncode,
            e.stderr[-500:].decode() if e.stderr else str(e),
        )
        return False
    except subprocess.TimeoutExpired:
        logger.error("easyrsa %s timed out after %ds", " ".join(args), timeout)
        return False
    except Exception as e:
        logger.error("easyrsa %s error: %s", " ".join(args), e)
        return False
