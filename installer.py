import os
import pexpect
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path
from uuid import uuid4

from colorama import Fore, Style, init

init(autoreset=True)

VERSION = "1.3.3"
APP_NAME = "ovnode"
INSTALL_DIR = Path(f"/opt/{APP_NAME}")
REPO = "anonysec/ov"
REPO_SUBDIR = "node"
MAIN_TARBALL_URL = f"https://github.com/{REPO}/archive/refs/heads/main.tar.gz"


def get_uv_path() -> str:
    for candidate in (
        shutil.which("uv"),
        os.path.expanduser("~/.local/bin/uv"),
        "/root/.local/bin/uv",
        "/usr/local/bin/uv",
        "/usr/bin/uv",
    ):
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return "uv"


def command_env() -> dict:
    env = os.environ.copy()
    env["PATH"] = f"{os.path.expanduser('~/.local/bin')}:/root/.local/bin:{env.get('PATH', '')}"
    return env


def run_command(cmd, cwd=None, check=True):
    return subprocess.run(cmd, cwd=cwd, env=command_env(), check=check)


def safe_clear() -> None:
    subprocess.run("clear", shell=True, check=False)


def download_latest_tarball(filename: str) -> None:
    api = f"https://api.github.com/repos/{REPO}/releases/latest"
    url = ""
    try:
        result = subprocess.run(
            ["bash", "-lc", f"curl -fsSL {api!r} | grep '\"tarball_url\"' | cut -d '\"' -f 4"],
            capture_output=True,
            text=True,
            check=False,
        )
        url = result.stdout.strip()
    except Exception:
        url = ""
    if not url:
        url = MAIN_TARBALL_URL
    run_command(["curl", "-L", "--fail", "-o", filename, url])


def extract_repo_subdir(tarball: str, subdir: str, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tarball, "r:gz") as tar:
        members = []
        for member in tar.getmembers():
            parts = member.name.split("/", 2)
            if len(parts) < 3 or parts[1] != subdir:
                continue
            member.name = parts[2]
            if member.name:
                members.append(member)
        if not members:
            raise RuntimeError(f"Could not find '{subdir}/' in downloaded source")
        tar.extractall(destination, members)


def setup_multilogin() -> None:
    server_conf = Path("/etc/openvpn/server/server.conf")
    scripts_dst = Path("/etc/openvpn/scripts")
    limits_dir = Path("/etc/openvpn/limits")
    active_dir = Path("/etc/openvpn/ovpanel-active")
    src_dir = Path(__file__).resolve().parent / "core" / "scripts"

    scripts_dst.mkdir(parents=True, exist_ok=True)
    limits_dir.mkdir(parents=True, exist_ok=True)
    active_dir.mkdir(parents=True, exist_ok=True)

    ovpn_user = "nobody"
    ovpn_group = "nogroup"
    if server_conf.exists():
        for line in server_conf.read_text(encoding="utf-8").splitlines():
            parts = line.strip().split()
            if len(parts) >= 2 and parts[0] == "user":
                ovpn_user = parts[1]
            elif len(parts) >= 2 and parts[0] == "group":
                ovpn_group = parts[1]

    lock_file = active_dir / ".lock"
    lock_file.touch(exist_ok=True)
    try:
        shutil.chown(active_dir, user=ovpn_user, group=ovpn_group)
        shutil.chown(lock_file, user=ovpn_user, group=ovpn_group)
    except Exception:
        pass
    active_dir.chmod(0o755)
    lock_file.chmod(0o664)

    connect_dst = scripts_dst / "ovpanel-client-connect.sh"
    disconnect_dst = scripts_dst / "ovpanel-client-disconnect.sh"
    for name, dst in (
        ("ovpanel-client-connect.sh", connect_dst),
        ("ovpanel-client-disconnect.sh", disconnect_dst),
    ):
        src = src_dir / name
        if src.exists():
            shutil.copyfile(src, dst)
            dst.chmod(0o755)

    if server_conf.exists():
        content = server_conf.read_text(encoding="utf-8")
        existing = {line.strip() for line in content.splitlines()}
        required = [
            "duplicate-cn",
            "script-security 2",
            f"client-connect {connect_dst}",
            f"client-disconnect {disconnect_dst}",
        ]
        add = [line for line in required if line not in existing]
        if add:
            with server_conf.open("a", encoding="utf-8") as f:
                f.write("\n# ovmanager multi-login (per-config connection limit)\n")
                f.write("\n".join(add) + "\n")


def create_ccd() -> None:
    ccd_dir = Path("/etc/openvpn/ccd")
    server_conf = Path("/etc/openvpn/server/server.conf")
    ccd_dir.mkdir(parents=True, exist_ok=True)
    ccd_dir.chmod(0o755)

    if server_conf.exists():
        lines = server_conf.read_text(encoding="utf-8").splitlines(True)
        if not any(line.strip().startswith("client-config-dir ") for line in lines):
            lines.append(f"\nclient-config-dir {ccd_dir}\n")
        if not any(line.strip() == "ccd-exclusive" for line in lines):
            lines.append("ccd-exclusive\n")
        if not any(line.strip().startswith("status ") for line in lines):
            lines.append("status /var/log/openvpn-status.log 10\n")
        if not any(line.strip().startswith("status-version") for line in lines):
            lines.append("status-version 3\n")
        server_conf.write_text("".join(lines), encoding="utf-8")

    setup_multilogin()
    print("Restarting OpenVPN...")
    run_command(["systemctl", "restart", "openvpn-server@server.service"], check=False)


def write_env(service_port: str, api_key: str) -> None:
    Path(".env").write_text(
        f"""# This is the service port for the OVNode
SERVICE_PORT={service_port}

# This is an API key for connecting the master to the node
API_KEY={api_key}

# Development
# DOC=True
# DEBUG=INFO
""",
        encoding="utf-8",
    )


def install_ovnode() -> None:
    os.chdir(Path(__file__).resolve().parent)
    if Path("/etc/openvpn").exists():
        print("OpenVPN already exists. If OVNode is installed, use Update or Restart.")
        input("Press Enter to return to the menu...")
        menu()
        return
    try:
        run_command(["wget", "-4", "https://git.io/vpn", "-O", "/root/openvpn-install.sh"])
        bash = pexpect.spawn("/usr/bin/bash", ["/root/openvpn-install.sh"], encoding="utf-8", timeout=180)
        print("Running OpenVPN installer...")
        prompts = [
            (r"Which IPv4 address should be used.*:", "1"),
            (r"Protocol.*:", "2"),
            (r"Port.*:", "1194"),
            (r"Select a DNS server for the clients.*:", "1"),
            (r"Enter a name for the first client.*:", "first_client"),
            (r"Press any key to continue...", ""),
        ]
        for pattern, reply in prompts:
            try:
                bash.expect(pattern, timeout=10)
                bash.sendline(reply)
            except pexpect.TIMEOUT:
                pass
        bash.expect(pexpect.EOF, timeout=None)
        bash.close()
        create_ccd()

        example_uuid = str(uuid4())
        service_port = input("OVNode service port (default 2083): ").strip() or "2083"
        if not service_port.isdigit() or not (1 <= int(service_port) <= 65535):
            raise ValueError("Service port must be between 1 and 65535")
        api_key = input(f"OVNode API key (example: {example_uuid}): ").strip() or example_uuid
        write_env(service_port, api_key)
        run_ovnode()
        input(f"Successfully installed,\nApi key= {api_key}\nPort= {service_port}\nPress Enter to return to the menu...")
        menu()
    except Exception as e:
        print(Fore.RED + f"Error occurred during installation: {e}" + Style.RESET_ALL)
        input("Press Enter to return to the menu...")
        menu()


def update_ovnode() -> None:
    if not INSTALL_DIR.exists():
        print("OVNode is not installed.")
        input("Press Enter to return to the menu...")
        menu()
        return
    tarball = "/tmp/ovnode-latest.tar.gz"
    env_file = INSTALL_DIR / ".env"
    backup_env = Path("/tmp/ovnode.env.bak")
    try:
        print(Fore.YELLOW + "Downloading latest OVNode..." + Style.RESET_ALL)
        download_latest_tarball(tarball)
        if env_file.exists():
            shutil.copy2(env_file, backup_env)
        shutil.rmtree(INSTALL_DIR, ignore_errors=True)
        INSTALL_DIR.mkdir(parents=True, exist_ok=True)
        extract_repo_subdir(tarball, REPO_SUBDIR, INSTALL_DIR)
        if backup_env.exists():
            shutil.move(str(backup_env), str(env_file))
        os.chdir(INSTALL_DIR)
        run_command([get_uv_path(), "sync", "--refresh"])
        create_ccd()
        run_ovnode()
        print(Fore.GREEN + "OVNode updated successfully!" + Style.RESET_ALL)
        input("Press Enter to return to the menu...")
        menu()
    except Exception as e:
        print(Fore.RED + f"Update failed: {e}" + Style.RESET_ALL)
        input("Press Enter to return to the menu...")
        menu()


def restart_ovnode() -> None:
    if not INSTALL_DIR.exists() and not Path("/etc/openvpn").exists():
        print("OVNode is not installed.")
        input("Press Enter to return to the menu...")
        menu()
        return
    try:
        run_command(["systemctl", "restart", "ovnode"], check=False)
        run_command(["systemctl", "restart", "openvpn-server@server"], check=False)
        print(Fore.GREEN + "OVNode and OpenVPN restarted successfully!" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"Restart failed: {e}" + Style.RESET_ALL)
    input("Press Enter to return to the menu...")
    menu()


def uninstall_ovnode() -> None:
    if not INSTALL_DIR.exists() and not Path("/etc/openvpn").exists():
        print("OVNode is not installed.")
        input("Press Enter to return to the menu...")
        menu()
        return
    uninstall = input("Do you want to uninstall OVNode and OpenVPN? (y/n): ").strip().lower()
    if uninstall not in {"y", "yes"}:
        print("Uninstallation canceled.")
        input("Press Enter to return to the menu...")
        menu()
        return
    try:
        deactivate_ovnode()
        if Path("/root/openvpn-install.sh").exists():
            try:
                bash = pexpect.spawn("bash /root/openvpn-install.sh", timeout=300)
                bash.expect("Option:")
                bash.sendline("3")
                bash.expect("Confirm OpenVPN removal")
                bash.sendline("y")
                bash.expect(pexpect.EOF, timeout=60)
                bash.close()
            except Exception:
                pass
        shutil.rmtree("/etc/openvpn", ignore_errors=True)
        shutil.rmtree(INSTALL_DIR, ignore_errors=True)
        service_file = Path("/etc/systemd/system/ovnode.service")
        if service_file.exists():
            service_file.unlink()
        run_command(["systemctl", "daemon-reload"], check=False)
        run_command(["systemctl", "reset-failed"], check=False)
        print(Fore.GREEN + "OVNode uninstallation completed successfully!" + Style.RESET_ALL)
        print(Fore.YELLOW + "To install OVNode again, run:" + Style.RESET_ALL)
        print("bash <(curl -s https://raw.githubusercontent.com/anonysec/ov/main/node/install.sh)")
        sys.exit(0)
    except Exception as e:
        print(Fore.RED + f"Error occurred during uninstallation: {e}" + Style.RESET_ALL)
        input("Press Enter to return to the menu...")
        menu()


def run_ovnode() -> None:
    service_file = Path("/etc/systemd/system/ovnode.service")
    uv_bin = get_uv_path()
    service_file.write_text(
        f"""[Unit]
Description=OVNode App
After=network.target

[Service]
WorkingDirectory={INSTALL_DIR}
ExecStart={uv_bin} run main.py
Restart=always
RestartSec=5
User=root
Environment="PATH=/root/.local/bin:/usr/local/bin:/usr/bin:/bin"

[Install]
WantedBy=multi-user.target
""",
        encoding="utf-8",
    )
    run_command(["systemctl", "daemon-reload"], check=False)
    run_command(["systemctl", "enable", "ovnode"], check=False)
    run_command(["systemctl", "restart", "ovnode"], check=False)


def deactivate_ovnode() -> None:
    run_command(["systemctl", "stop", "ovnode"], check=False)
    run_command(["systemctl", "disable", "ovnode"], check=False)


def menu() -> None:
    safe_clear()
    print(Fore.BLUE + "=" * 34)
    print(f"Welcome to the OVNode Installer  v{VERSION}")
    print("=" * 34 + Style.RESET_ALL)
    print()
    print("Please choose an option:\n")
    print("  1. Install")
    print("  2. Update")
    print("  3. Restart")
    print("  4. Uninstall")
    print("  5. Exit")
    print()
    choice = input(Fore.YELLOW + "Enter your choice: " + Style.RESET_ALL)
    if choice == "1":
        install_ovnode()
    elif choice == "2":
        update_ovnode()
    elif choice == "3":
        restart_ovnode()
    elif choice == "4":
        uninstall_ovnode()
    elif choice == "5":
        print(Fore.GREEN + "\nExiting..." + Style.RESET_ALL)
        sys.exit(0)
    else:
        print(Fore.RED + "\nInvalid choice. Please try again." + Style.RESET_ALL)
        input(Fore.YELLOW + "Press Enter to continue..." + Style.RESET_ALL)
        menu()


if __name__ == "__main__":
    menu()
