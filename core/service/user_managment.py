import glob
import json
import os
import re as _re_uuid
import subprocess

from core.logging_utils import TraceCtx, node
from core.pki_setup import EASYRSA_DIR, PKI_DIR
from core.schema.all_schemas import UsersUsage

# Get the node-specific logger
node_logger = node()

# Inline UUID<->CN conversion (shared/ module is outside Docker build context)
_UUID_RE = _re_uuid.compile(
    r"^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$"
)
_CN_RE = _re_uuid.compile(r"^[a-fA-F0-9]{32}$")

# Where per-client simultaneous-login limits are stored.
# Kept separate from the CCD dir because CCD files are wiped on
# deactivate/reactivate, while the limit should survive that.
LIMITS_DIR = "/etc/openvpn/limits"

# Where generated .ovpn config files are cached. Kept out of /root so the
# node does not pollute the home directory of the invoking user.
CLIENTS_DIR = "/etc/openvpn/clients"

# Mapping file: uid (UUID) -> display name (for panel use)
UID_MAP_FILE = os.path.join(CLIENTS_DIR, "uid_map.json")


def _load_uid_map() -> dict:
    if not os.path.exists(UID_MAP_FILE):
        return {}
    try:
        with open(UID_MAP_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_uid_map(mapping: dict) -> None:
    try:
        os.makedirs(CLIENTS_DIR, exist_ok=True)
        with open(UID_MAP_FILE, "w") as f:
            json.dump(mapping, f)
    except Exception as e:
        node_logger.error("Failed to save uid map: %s", e)


def _cn_from_uid(uid: str) -> str:
    if _UUID_RE.match(uid):
        return uid.replace("-", "")
    return uid


def _get_name(uid: str) -> str | None:
    mapping = _load_uid_map()
    return mapping.get(uid)


def _set_name(uid: str, name: str) -> None:
    mapping = _load_uid_map()
    mapping[uid] = name
    _save_uid_map(mapping)


def _remove_name(uid: str) -> None:
    mapping = _load_uid_map()
    if uid in mapping:
        del mapping[uid]
        _save_uid_map(mapping)


def _client_paths(uid: str) -> dict:
    cn = _cn_from_uid(uid)
    return {
        "name": cn,
        "ovpn": os.path.join(CLIENTS_DIR, f"{cn}.ovpn"),
        "crt": f"{PKI_DIR}/issued/{cn}.crt",
        "inline": f"{PKI_DIR}/inline/private/{cn}.inline",
        "template": "/etc/openvpn/server/client-common.txt",
        "ccd": f"/etc/openvpn/ccd/{cn}",
        "limit": os.path.join(LIMITS_DIR, cn),
    }


def set_user_limit(uid: str, max_logins: int) -> bool:
    paths = _client_paths(uid)
    try:
        if max_logins is None:
            return True
        max_logins = int(max_logins)
        if max_logins < 0:
            max_logins = 0
        os.makedirs(LIMITS_DIR, exist_ok=True)
        with open(paths["limit"], "w") as f:
            f.write(str(max_logins))
        node_logger.info(
            "Set login limit for uid='%s' (cn='%s') to %s",
            uid,
            paths["name"],
            max_logins,
        )
        return True
    except Exception as e:
        node_logger.error("Error setting login limit for uid='%s': %s", uid, e)
        return False


def remove_user_limit(uid: str) -> None:
    paths = _client_paths(uid)
    try:
        if os.path.exists(paths["limit"]):
            os.remove(paths["limit"])
    except Exception as e:
        node_logger.error("Error removing login limit for uid='%s': %s", uid, e)


def _generate_ovpn_from_existing_cert(uid: str) -> bool:
    paths = _client_paths(uid)
    try:
        template = paths["template"]
        # Prefer inline file, fall back to cert file, fail if neither exists
        cert_src = None
        if os.path.exists(paths["inline"]):
            cert_src = paths["inline"]
        elif os.path.exists(paths["crt"]):
            cert_src = paths["crt"]
        else:
            node_logger.warning("No inline or cert file for uid='%s', cannot generate OVPN", uid)
            return False
        if not os.path.exists(template):
            node_logger.warning("client-common.txt template missing for uid='%s'", uid)
            return False
        os.makedirs(CLIENTS_DIR, exist_ok=True)
        with open(paths["ovpn"], "w") as out:
            subprocess.run(
                ["grep", "-vh", "^#", template, cert_src],
                stdout=out,
                check=True,
                timeout=30,
            )
        os.chmod(paths["ovpn"], 0o600)
        node_logger.info("Regenerated OVPN file for uid='%s' (cn='%s')", uid, paths["name"])
        return True
    except Exception as e:
        node_logger.error("Failed to regenerate OVPN for uid='%s': %s", uid, e)
        return False


def _easyrsa(*args, timeout=120):
    """Run easyrsa with batch mode. Returns True on success."""
    easyrsa_bin = os.path.join(EASYRSA_DIR, "easyrsa")
    if not os.path.exists(easyrsa_bin):
        node_logger.error("easyrsa not found at %s", easyrsa_bin)
        return False
    try:
        env = {**os.environ, "EASYRSA_BATCH": "1"}
        subprocess.run(
            [easyrsa_bin] + list(args),
            cwd=EASYRSA_DIR,
            env=env,
            check=True,
            capture_output=True,
            timeout=timeout,
        )
        return True
    except subprocess.CalledProcessError as e:
        node_logger.error(
            "easyrsa %s failed: %s",
            " ".join(args),
            e.stderr[-500:] if e.stderr else str(e),
        )
        return False
    except Exception as e:
        node_logger.error("easyrsa %s error: %s", " ".join(args), e)
        return False


def create_user_on_server(uid: str, name: str, max_logins: int = 1) -> bool:
    """Create a new OpenVPN client using direct easyrsa commands.

    The OpenVPN CN is derived deterministically from the UID (UUID without dashes).
    No interactive installer script required — PKI must already be initialized
    by the startup lifespan handler.
    """
    with TraceCtx("create_user_on_server"):
        if name:
            _set_name(uid, name)

        paths = _client_paths(uid)
        cn = paths["name"]
        if cn is None:
            node_logger.error("create_user_on_server: failed to get CN for uid %s", uid)
            return False

        try:
            _cn_from_uid(cn)  # validate
        except ValueError as e:
            node_logger.error("Invalid CN for uid=%s: %s", uid, e)
            return False

        # Already generated -> refresh template and return
        if os.path.exists(paths["ovpn"]):
            if os.path.exists(paths["inline"]):
                _generate_ovpn_from_existing_cert(uid)
            os.makedirs("/etc/openvpn/ccd", exist_ok=True)
            open(paths["ccd"], "a").close()
            set_user_limit(uid, max_logins if max_logins is not None else 1)
            return True

        # Certificate exists but cached .ovpn missing — regenerate
        if os.path.exists(paths["crt"]) or os.path.exists(paths["inline"]):
            if _generate_ovpn_from_existing_cert(uid):
                os.makedirs("/etc/openvpn/ccd", exist_ok=True)
                open(paths["ccd"], "a").close()
                set_user_limit(uid, max_logins if max_logins is not None else 1)
                return True
            node_logger.error("Client '%s' (uid=%s) exists but OVPN regeneration failed", cn, uid)
            return False

        # Ensure PKI exists before creating client
        if not os.path.exists(os.path.join(PKI_DIR, "ca.crt")):
            node_logger.error("PKI not initialized — run init_pki() first (container startup).")
            return False

        # Generate client cert with easyrsa
        if not _easyrsa("build-client-full", cn, "nopass"):
            node_logger.error("Failed to generate client certificate for '%s' (uid=%s)", cn, uid)
            return False

        node_logger.info("Client certificate generated for cn='%s' (uid=%s)", cn, uid)

        # Generate OVPN file from template + inline cert
        if os.path.exists(paths["inline"]):
            _generate_ovpn_from_existing_cert(uid)

        os.makedirs("/etc/openvpn/ccd", exist_ok=True)
        open(paths["ccd"], "a").close()
        set_user_limit(uid, max_logins if max_logins is not None else 1)

        return os.path.exists(paths["ovpn"])


def delete_user_on_server(uid: str) -> bool | str:
    """Delete/revoke a client using direct easyrsa commands."""
    cn = _cn_from_uid(uid)
    if not cn:
        node_logger.error("delete_user_on_server: failed to get CN for uid %s", uid)
        return False

    try:
        _cn_from_uid(cn)  # validate
    except ValueError as e:
        node_logger.error("Invalid CN for uid=%s: %s", uid, e)
        return False

    paths = _client_paths(uid)

    # Check if user actually exists
    if not os.path.exists(paths["crt"]) and not os.path.exists(paths["ovpn"]):
        node_logger.warning("User '%s' (uid=%s) not found on node", cn, uid)
        return "not_found"

    # Revoke with easyrsa
    if os.path.exists(paths["crt"]):
        _easyrsa("revoke", cn)
        _easyrsa("gen-crl")

    # Remove local files
    for key in ["ovpn", "crt", "inline", "ccd", "limit"]:
        fpath = paths.get(key)
        if fpath and os.path.exists(fpath):
            try:
                os.remove(fpath)
            except Exception as e:
                node_logger.warning("Could not remove %s: %s", fpath, e)

    _remove_name(uid)
    node_logger.info("Revoked and cleaned up user '%s' (uid=%s)", cn, uid)
    return True


def change_user_status(uid: str, status: str) -> bool:
    paths = _client_paths(uid)

    if status == "deactivate":
        if os.path.exists(paths["ccd"]):
            try:
                os.remove(paths["ccd"])
                node_logger.info(
                    "Soft-disabled user (removed CCD): uid='%s' cn='%s'",
                    uid,
                    paths["name"],
                )
            except Exception as e:
                node_logger.error("Error removing CCD for uid='%s': %s", uid, e)
                return False
        return True

    elif status == "activate":
        try:
            os.makedirs("/etc/openvpn/ccd", exist_ok=True)
            with open(paths["ccd"], "w") as f:
                f.write("")
            node_logger.info(
                "Soft-enabled user (created CCD): uid='%s' cn='%s'",
                uid,
                paths["name"],
            )
            return True
        except Exception as e:
            node_logger.error("Error creating CCD for uid='%s': %s", uid, e)
            return False

    return False


def restart_openvpn_service() -> bool:
    try:
        subprocess.run(
            ["/usr/bin/systemctl", "restart", "openvpn-server@server"],
            check=True,
            timeout=30,
        )
        node_logger.info("OpenVPN service restarted successfully.")
        return True
    except FileNotFoundError:
        node_logger.info("systemctl not found (likely Docker); falling back to SIGHUP.")
    except subprocess.TimeoutExpired:
        node_logger.error("Timeout while restarting OpenVPN service via systemctl")
    except Exception as e:
        node_logger.warning("systemctl restart failed (%s); falling back to SIGHUP.", e)

    try:
        import signal

        pids = glob.glob("/run/openvpn-server/*.pid")
        if not pids:
            result = subprocess.run(
                ["pgrep", "-f", "openvpn"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            pids = result.stdout.strip().split() if result.stdout.strip() else []
        for pid_file in pids:
            try:
                real_path = os.path.realpath(pid_file)
                if not real_path.startswith("/run/openvpn-server/"):
                    node_logger.warning("Skipping PID file outside expected dir: %s", pid_file)
                    continue
                if not os.path.isfile(real_path):
                    continue
                pid = int(open(real_path).read().strip())
                os.kill(pid, signal.SIGHUP)
                node_logger.info("Sent SIGHUP to OpenVPN PID %s.", pid)
            except (ValueError, FileNotFoundError, ProcessLookupError) as e:
                node_logger.warning("Could not signal PID from %s: %s", pid_file, e)
        if not pids:
            node_logger.warning("No OpenVPN process found to restart.")
    except Exception as e:
        node_logger.error("Error restarting OpenVPN via SIGHUP: %s", e)
        return False
    return True


async def download_ovpn_file(uid: str) -> str | None:
    paths = _client_paths(uid)
    file_path = paths["ovpn"]

    # Use existing name from uid_map or the uid itself as fallback
    existing_name = _get_name(uid) or uid

    if os.path.exists(paths["inline"]):
        if _generate_ovpn_from_existing_cert(uid):
            return file_path

    if os.path.exists(file_path):
        return file_path

    if create_user_on_server(uid, existing_name):
        return file_path if os.path.exists(file_path) else None

    return None


def get_users_usage() -> UsersUsage | None:
    users = {}
    sessions: dict = {}
    file_path = "/var/log/openvpn-status.log"
    if not os.path.exists(file_path):
        node_logger.warning("OpenVPN status log not found: %s", file_path)
        return None
    try:
        with open(file_path) as f:
            lines = f.readlines()
    except Exception as e:
        node_logger.error("Failed to read OpenVPN status log: %s", e)
        return None

    for line in lines:
        line = line.strip()
        if not (line.startswith("CLIENT_LIST,") or line.startswith("CLIENT_LIST\t")):
            continue
        if line.startswith("CLIENT_LIST,Common Name") or line.startswith(
            "CLIENT_LIST\tCommon Name"
        ):
            continue

        parts = line.split("\t") if "\t" in line else line.split(",")
        if len(parts) < 7:
            node_logger.warning("Skipping malformed OpenVPN CLIENT_LIST line: %s", line)
            continue

        username = parts[1]
        real_address = parts[2]
        try:
            bytes_received = int(parts[5] or 0)
            bytes_sent = int(parts[6] or 0)
        except (TypeError, ValueError):
            node_logger.warning("Skipping CLIENT_LIST line with invalid byte counters: %s", line)
            continue

        total_bytes = bytes_received + bytes_sent
        users[username] = users.get(username, 0) + total_bytes
        sessions.setdefault(username, {})[real_address] = total_bytes

    if users:
        return UsersUsage(users=users, sessions=sessions)
    else:
        return None
