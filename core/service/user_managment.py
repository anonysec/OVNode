import pexpect
import re
import os
import subprocess

from core.logger import logger
from core.schema.all_schemas import UsersUsage


script_path = "/root/openvpn-install.sh"

# Where per-client simultaneous-login limits are stored.
# Kept separate from the CCD dir because CCD files are wiped on
# deactivate/reactivate, while the limit should survive that.
LIMITS_DIR = "/etc/openvpn/limits"


def set_user_limit(name: str, max_logins: int) -> bool:
    """Persist the max simultaneous logins for a client.

    max_logins: 1 = single login (default), 0 = unlimited.
    The connect-time enforcement script reads this file.
    """
    try:
        if max_logins is None:
            return True
        max_logins = int(max_logins)
        if max_logins < 0:
            max_logins = 0
        os.makedirs(LIMITS_DIR, exist_ok=True)
        with open(os.path.join(LIMITS_DIR, name), "w") as f:
            f.write(str(max_logins))
        logger.info("Set login limit for '%s' to %s", name, max_logins)
        return True
    except Exception as e:
        logger.error("Error setting login limit for '%s': %s", name, e)
        return False


def remove_user_limit(name: str) -> None:
    """Remove the stored limit file for a client (used on delete)."""
    try:
        path = os.path.join(LIMITS_DIR, name)
        if os.path.exists(path):
            os.remove(path)
    except Exception as e:
        logger.error("Error removing login limit for '%s': %s", name, e)


def _client_paths(name: str) -> dict:
    return {
        "ovpn": f"/root/{name}.ovpn",
        "crt": f"/etc/openvpn/server/easy-rsa/pki/issued/{name}.crt",
        "inline": f"/etc/openvpn/server/easy-rsa/pki/inline/private/{name}.inline",
        "template": "/etc/openvpn/server/client-common.txt",
        "ccd": f"/etc/openvpn/ccd/{name}",
    }


def _generate_ovpn_from_existing_cert(name: str) -> bool:
    """Regenerate /root/name.ovpn when the cert already exists.

    Nyr's installer creates /etc/openvpn/server/easy-rsa/pki/inline/private/<name>.inline
    and combines it with client-common.txt. If a user already exists but the cached
    /root/*.ovpn was deleted after a port/protocol change, this recreates it without
    trying to add a duplicate client through the interactive installer.
    """
    paths = _client_paths(name)
    try:
        if not os.path.exists(paths["template"]) or not os.path.exists(paths["inline"]):
            return False
        with open(paths["ovpn"], "w") as out:
            subprocess.run(
                ["grep", "-vh", "^#", paths["template"], paths["inline"]],
                stdout=out,
                check=True,
                timeout=30,
            )
        os.chmod(paths["ovpn"], 0o600)
        logger.info("Regenerated existing OVPN file for '%s'", name)
        return True
    except Exception as e:
        logger.error("Failed to regenerate OVPN for '%s': %s", name, e)
        return False


def create_user_on_server(name, max_logins: int = 1) -> bool:
    try:
        paths = _client_paths(name)

        # Already generated -> success, but refresh the cached .ovpn from the
        # current template when the inline cert exists. This prevents stale
        # downloads after server-level changes such as port/protocol/cipher/MTU.
        if os.path.exists(paths["ovpn"]):
            if os.path.exists(paths["inline"]):
                _generate_ovpn_from_existing_cert(name)
            os.makedirs("/etc/openvpn/ccd", exist_ok=True)
            open(paths["ccd"], "a").close()
            set_user_limit(name, max_logins if max_logins is not None else 1)
            return True

        # Certificate exists but /root/*.ovpn is missing (common after settings
        # changes). Regenerate from the existing inline cert instead of calling
        # the interactive installer and getting stuck on "invalid name".
        if os.path.exists(paths["crt"]) or os.path.exists(paths["inline"]):
            if _generate_ovpn_from_existing_cert(name):
                os.makedirs("/etc/openvpn/ccd", exist_ok=True)
                open(paths["ccd"], "a").close()
                set_user_limit(name, max_logins if max_logins is not None else 1)
                return True
            logger.error("Client '%s' exists but OVPN regeneration failed", name)
            return False

        if not os.path.exists(script_path):
            logger.error("OpenVPN installer script not found at %s", script_path)
            return False

        env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
        bash = pexpect.spawn(
            "/usr/bin/bash",
            [script_path],
            env=env,
            encoding="utf-8",
            timeout=180,
        )

        bash.expect(r"Option:|Select an option:", timeout=90)
        bash.sendline("1")

        bash.expect(r"Name:", timeout=90)
        bash.sendline(name)
        bash.expect(pexpect.EOF, timeout=240)
        bash.close()

        # Nyr's script writes the file to the script directory (/root). If not,
        # try to generate it from the produced inline certificate.
        if not os.path.exists(paths["ovpn"]):
            _generate_ovpn_from_existing_cert(name)

        os.makedirs("/etc/openvpn/ccd", exist_ok=True)
        open(paths["ccd"], "a").close()
        set_user_limit(name, max_logins if max_logins is not None else 1)

        return os.path.exists(paths["ovpn"])

    except pexpect.TIMEOUT:
        logger.error("Timeout occurred while creating OpenVPN client '%s'", name)
        return False
    except pexpect.EOF:
        logger.error("OpenVPN installer closed earlier than expected while creating '%s'", name)
        return os.path.exists(_client_paths(name)["ovpn"])
    except Exception as e:
        logger.error("Error creating OpenVPN client '%s': %s", name, e)
        return False

def delete_user_on_server(name) -> bool | str:
    try:
        if not os.path.exists(script_path):
            logger.error("script not found at %s", script_path)
            return False

        env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
        bash = pexpect.spawn(
            "/usr/bin/bash", [script_path], env=env, encoding="utf-8", timeout=120
        )

        try:
            bash.expect(r"Option:|Select an option:", timeout=20)
        except pexpect.TIMEOUT:
            logger.warning("Did not see main menu prompt, attempting to continue")

        bash.sendline("2")

        try:
            bash.expect(
                r"Select the client to revoke:|Select the client to revoke", timeout=20
            )
        except pexpect.TIMEOUT:
            logger.info("Didn't match full header")

        bash.expect(r"Client:", timeout=20)
        list_output = bash.before

        pattern = re.compile(r"\s*(\d+)\)\s*(.+)")
        matches = pattern.findall(list_output)

        user_number = None
        for num, user in matches:
            if user.strip() == name:
                user_number = num
                break

        if not user_number:
            logger.error("User '%s' not found for delete!", name)
            bash.close(force=True)
            return "not_found"

        logger.info("Revoking user '%s' -> number %s", name, user_number)
        bash.sendline(user_number)

        try:
            bash.expect(
                r"Confirm .*revocation\?.*\[y/N\]:|Confirm .*revocation\?.*:|Confirm .*revocation\?",
                timeout=20,
            )
            bash.sendline("y")
        except pexpect.TIMEOUT:
            logger.warning("Confirmation prompt not seen; trying to continue")

        bash.expect(pexpect.EOF, timeout=120)
        bash.close()

        # remove local .ovpn file if exists
        file_to_delete = f"/root/{name}.ovpn"
        if os.path.exists(file_to_delete):
            try:
                os.remove(file_to_delete)
                logger.info("Removed %s", file_to_delete)
            except Exception as e:
                logger.error("Error deleting file %s: %s", file_to_delete, e)
                return True

        ccd_file = f"/etc/openvpn/ccd/{name}"
        if os.path.exists(ccd_file):
            try:
                os.remove(ccd_file)
                logger.info("Removed %s", ccd_file)
            except Exception as e:
                logger.error("Error deleting file %s: %s", ccd_file, e)
                return True

        # Drop the stored login limit for this client.
        remove_user_limit(name)

        return True

    except Exception as e:
        logger.exception("Error in delete_user_on_server: %s", e)
        return False


def change_user_status(name: str, status: str) -> bool:
    """
    Soft enable/disable for a user.

    We only touch the CCD file.
    We deliberately do NOT restart OpenVPN here.

    Why?
    - Restarting would disconnect ALL users on the node (bad UX).
    - Removing the CCD file is enough to block NEW connections for this user.
    - Existing sessions will continue until they naturally disconnect or the
      connection limit / traffic enforcement kicks in via client-connect script.
    - This makes editing data limit / expiry date non-disruptive for other users.
    """
    ccd_file = f"/etc/openvpn/ccd/{name}"

    if status == "deactivate":
        if os.path.exists(ccd_file):
            try:
                os.remove(ccd_file)
                logger.info("Soft-disabled user (removed CCD): %s", name)
            except Exception as e:
                logger.error("Error removing CCD for %s: %s", name, e)
                return False
        return True

    elif status == "activate":
        try:
            os.makedirs("/etc/openvpn/ccd", exist_ok=True)
            with open(ccd_file, "w") as f:
                f.write("")
            logger.info("Soft-enabled user (created CCD): %s", name)
            return True
        except Exception as e:
            logger.error("Error creating CCD for %s: %s", name, e)
            return False

    return False


def restart_openvpn_service() -> bool:
    """
    Full OpenVPN restart.
    Only used for server-level changes (port/protocol, multi-login script setup).
    User enable/disable no longer calls this (soft CCD toggle only).
    """
    try:
        os.system("systemctl restart openvpn-server@server")
        logger.info("OpenVPN service restarted successfully.")
        return True
    except Exception as e:
        logger.error(f"Failed to restart OpenVPN service: {e}")
        return False


async def download_ovpn_file(name: str) -> str | None:
    """Return a fresh OVPN file path without infinite recursion.

    The /root/<name>.ovpn file is a cache generated from
    /etc/openvpn/server/client-common.txt + the client's inline certificate.
    Server settings can change later (port/protocol/DNS/cipher/MTU), so a
    previously cached file may become stale. On every download, regenerate from
    the current template whenever the inline cert exists.
    """
    paths = _client_paths(name)
    file_path = paths["ovpn"]

    if os.path.exists(paths["inline"]):
        if _generate_ovpn_from_existing_cert(name):
            return file_path

    if os.path.exists(file_path):
        return file_path

    if create_user_on_server(name):
        return file_path if os.path.exists(file_path) else None

    return None


def get_users_usage() -> UsersUsage | None:
    users = {}
    sessions: dict = {}
    file_path = "/var/log/openvpn-status.log"
    if not os.path.exists(file_path):
        logger.warning("OpenVPN status log not found: %s", file_path)
        return None
    try:
        with open(file_path) as f:
            lines = f.readlines()
    except Exception as e:
        logger.error("Failed to read OpenVPN status log: %s", e)
        return None

    for line in lines:
        line = line.strip()
        if not (line.startswith("CLIENT_LIST,") or line.startswith("CLIENT_LIST	")):
            continue
        if line.startswith("CLIENT_LIST,Common Name") or line.startswith("CLIENT_LIST	Common Name"):
            continue

        parts = line.split("	") if "	" in line else line.split(",")
        if len(parts) < 7:
            logger.warning("Skipping malformed OpenVPN CLIENT_LIST line: %s", line)
            continue

        username = parts[1]
        real_address = parts[2]  # IP:port, unique per active session
        try:
            bytes_received = int(parts[5] or 0)
            bytes_sent = int(parts[6] or 0)
        except (TypeError, ValueError):
            logger.warning("Skipping CLIENT_LIST line with invalid byte counters: %s", line)
            continue

        total_bytes = bytes_received + bytes_sent

        # Per-CN total (a multi-login user has several rows; sum them).
        users[username] = users.get(username, 0) + total_bytes

        # Per-session breakdown so the panel can diff each session
        # independently and avoid double-counting when one of several
        # simultaneous sessions disconnects.
        sessions.setdefault(username, {})[real_address] = total_bytes

    if users:
        return UsersUsage(users=users, sessions=sessions)
    else:
        return None
