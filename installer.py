import os
import shutil
import subprocess
import sys
import tarfile
import logging
from pathlib import Path
from typing import Optional

from colorama import Fore, Style
import pexpect

# Import our logging utilities
from core.logging_utils import (
    TraceCtx,
    install_log,
    node,  # function returning the node logger
)

VERSION = "1.5.0"
APP_NAME = "ovnode"
INSTALL_DIR = Path(f"/opt/{APP_NAME}")
REPO = "anonysec/OVNode"
REPO_SUBDIR = ""
MAIN_TARBALL_URL = f"https://github.com/{REPO}/archive/refs/heads/main.tar.gz"

# Get the node-specific logger
node_log = node()


@install_log
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


@install_log
def command_env() -> dict:
    env = os.environ.copy()
    env["PATH"] = f"{os.path.expanduser('~/.local/bin')}:/root/.local/bin:{env.get('PATH', '')}"
    return env


@install_log
def run_command(cmd, cwd=None, check=True):
    return subprocess.run(cmd, cwd=cwd, env=command_env(), check=check)


@install_log
def safe_clear() -> None:
    subprocess.run("clear", shell=True, check=False)


@install_log
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
        pass
    if not url:
        url = MAIN_TARBALL_URL
    install_log.event("download.start", url=url, target=filename)
    run_command(["curl", "-L", "--fail", "-o", filename, url])
    install_log.event("download.complete", url=url, target=filename)


@install_log
def extract_repo_subdir(tarball: str, subdir: str, destination: Path) -> None:
    install_log.event("extract.start", tarball=tarball, subdir=subdir or "<repo_root>", destination=str(destination))
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tarball, "r:gz") as tar:
        members = []
        for member in tar.getmembers():
            parts = member.name.split("/", 2)
            if len(parts) < 2:
                continue
            if subdir:
                if len(parts) < 3 or parts[1] != subdir:
                    continue
                new_name = parts[2]
            else:
                new_name = "/".join(parts[1:])
            if not new_name:
                continue
            if member.isdir() and not new_name.endswith("/"):
                new_name += "/"
            member.name = new_name
            members.append(member)
        if not members:
            raise RuntimeError(f"Could not find '{subdir or '<repo_root>'}' in downloaded source")
        members.sort(key=lambda m: m.name)
        tar.extractall(destination, members=members)
    install_log.event("extract.complete", tarball=tarball, extracted=str(destination), count=len(members))


@install_log
def setup_multilogin() -> None:
    server_conf = Path("/etc/openvpn/server/server.conf")
    scripts_dst = Path("/etc/openvpn/scripts")
    limits_dir = Path("/etc/openvpn/limits")
    active_dir = Path("/etc/openvpn/ovpanel-active")
    src_dir = Path(__file__).resolve().parent / "core" / "scripts"

    install_log.event("multilogin.setup", src=str(src_dir))

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
        node_log.shutil_chown(active_dir, user=ovpn_user, group=ovpn_group)
        node_log.shutil_chown(lock_file, user=ovpn_user, group=ovpn_group)
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
            install_log.event("multilogin.script_copied", name=name, dst=str(dst))

    if server_conf.exists():
        content = server_conf.read_text(encoding="utf-8")
        required = [
            "duplicate-cn",
            "script-security 2",
            f"client-connect {connect_dst}",
            f"client-disconnect {disconnect_dst}",
        ]
        add = [line for line in required if line not in content]
        if add:
            with server_conf.open("a", encoding="utf-8") as f:
                f.write("\n# ovmanager multi-login (per-config connection limit)\n")
                f.write("\n".join(add) + "\n")
            install_log.event(
                "multilogin.config_updated",
                added=len(add),
                config=str(server_conf),
            )


@install_log
def create_ccd() -> None:
    ccd_dir = Path("/etc/openvpn/ccd")
    server_conf = Path("/etc/openvpn/server/server.conf")
    ccd_dir.mkdir(parents=True, exist_ok=True)

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
        install_log.event("ccd.configured", ccd_dir=str(ccd_dir))

    setup_multilogin()
    install_log.event("openvpn.restart.requested", method="systemctl restart openvpn-server@server.service")
    try:
        run_command(["systemctl", "restart", "openvpn-server@server.service"], check=False)
    except Exception:
        install_log.warning("systemctl restart failed, falling back to SIGHUP")
        import signal
        pids = list(Path("/run/openvpn-server").glob("*.pid")) if Path("/run/openvpn-server").exists() else []
        if not pids:
            result = subprocess.run(
                ["pgrep", "-f", "openvpn"], capture_output=True, text=True, timeout=5,
            )
            pids = [p for p in result.stdout.strip().split() if p] if result.stdout.strip() else []
        for pid_file in pids:
            try:
                real_path = os.path.realpath(pid_file)
                if not real_path.startswith("/run/openvpn-server/"):
                    continue
                if not os.path.isfile(real_path):
                    continue
                pid = int(open(real_path).read().strip())
                os.kill(pid, signal.SIGHUP)
                install_log.event("openvpn.sighup", pid=pid)
            except Exception as e:
                install_log.warning("sighup.error", pid_file=pid_file, error=str(e))


@install_log
def write_env(service_port: str, api_key: str) -> None:
    content = f"""# This is the service port for the OVNode
SERVICE_PORT={service_port}

# This is an API key for connecting the master to the node
API_KEY={api_key}

# Development
# DOC=True
# DEBUG=INFO
"""
    install_log.event("env.written", path=".env", keys=["SERVICE_PORT", "API_KEY"])
    Path(".env").write_text(content, encoding="utf-8")


@install_log
def install_ovnode() -> None:
    install_log.event("install.start")
    with TraceCtx("install_ovnode") as ctx:
        os.chdir(Path(__file__).resolve().parent)

        if Path("/etc/openvpn").exists():
            msg = "OpenVPN already exists. If OVNode is installed, use Update or Restart."
            install_log.event("install.skip", reason=msg)
            print(msg)
            input("Press Enter to return to the menu...")
            return

        install_log.event("download.initiating", script="https://git.io/vpn")
        run_command(["wget", "-4", "https://git.io/vpn", "-O", "/root/openvpn-install.sh"])
        bash = pexpect.spawn(
            "/usr/bin/bash", ["/root/openvpn-install.sh"], encoding="utf-8", timeout=180
        )
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

        install_log.event("create.ccd")
        create_ccd()

        example_uuid = str(Path("/tmp").joinpath(f"uuid_{hash(datetime.utcnow())}"))
        service_port = input("OVNode service port (default 2083): ").strip() or "2083"
        if not service_port.isdigit() or not (1 <= int(service_port) <= 65535):
            raise ValueError("Service port must be between 1 and 65535")
        api_key = input(f"OVNode API key (example: {example_uuid}): ").strip() or example_uuid

        write_env(service_port, api_key)
        install_log.event("env.written", service_port=service_port, api_key_masked="***")

        run_ovnode()
        msg = (
            f"Successfully installed,\n"
            f"Api key= {api_key}\n"
            f"Port= {service_port}\n"
        )
        print(msg + "Press Enter to return to the menu...")
        input(msg)
        install_log.event("install.complete", service_port=service_port)


@install_log
def update_ovnode() -> None:
    install_log.event("update.start")
    with TraceCtx("ovnode.update") as ctx:
        if not INSTALL_DIR.exists():
            msg = "OVNode is not installed."
            install_log.event("update.skip", reason=msg)
            print(msg)
            input("Press Enter to return to the menu...")
            return

        tarball = "/tmp/ovnode-latest.tar.gz"
        env_file = INSTALL_DIR / ".env"
        backup_env = Path("/tmp/ovnode.env.bak")

        try:
            install_log.event("download.latest")
            download_latest_tarball(tarball)

            if env_file.exists():
                shutil.copy2(env_file, backup_env)

            install_log.event("remove.old", dest=str(INSTALL_DIR))
            shutil.rmtree(INSTALL_DIR, ignore_errors=True)
            INSTALL_DIR.mkdir(parents=True, exist_ok=True)

            install_log.event("extract.latest", tarball=tarball)
            extract_repo_subdir(tarball, REPO_SUBDIR, INSTALL_DIR)

            if backup_env.exists():
                shutil.move(str(backup_env), str(env_file))

            os.chdir(INSTALL_DIR)
            install_log.event("sync.dependencies")
            run_command([get_uv_path(), "sync", "--refresh"])

            create_ccd()
            run_ovnode()

            install_log.event("update.complete")
            print("OVNode updated successfully!")
            input("Press Enter to return to the menu...")
        except Exception as e:
            install_log.event("update.failed", error=str(e))
            print(f"Update failed: {e}")
            input("Press Enter to return to the menu...")


@install_log
def restart_ovnode() -> None:
    install_log.event("restart.start")
    with TraceCtx("ovnode.restart") as ctx:
        if not INSTALL_DIR.exists() and not Path("/etc/openvpn").exists():
            msg = "OVNode is not installed."
            install_log.event("restart.skip", reason=msg)
            print(msg)
            input("Press Enter to return to the menu...")
            return

        try:
            run_command(["systemctl", "restart", "ovnode"], check=False)
            run_command(["systemctl", "restart", "openvpn-server@server"], check=False)
            install_log.event("restart.success")
            print("OVNode and OpenVPN restarted successfully!")
        except Exception as e:
            install_log.event("restart.error", error=str(e))

    input("Press Enter to return to the menu...")


@install_log
def uninstall_ovnode() -> None:
    install_log.event("uninstall.start")
    with TraceCtx("ovnode.uninstall") as ctx:
        if not INSTALL_DIR.exists() and not Path("/etc/openvpn").exists():
            msg = "OVNode is not installed."
            install_log.event("uninstall.skip", reason=msg)
            print(msg)
            input("Press Enter to return to the menu...")
            return

        uninstall = input("Do you want to uninstall OVNode and OpenVPN? (y/n): ").strip().lower()
        if uninstall not in {"y", "yes"}:
            print("Uninstallation canceled.")
            input("Press Enter to return to the menu...")
            return

        try:
            from core.service.user_managment import deactivate_ovnode
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
                    install_log.event("openvpn.uninstalled")
                except Exception as e:
                    install_log.warning("openvpn.uninstall.fallback", error=str(e))

            for p in ["/etc/openvpn", INSTALL_DIR]:
                if p.exists():
                    shutil.rmtree(p, ignore_errors=True)

            service_file = Path("/etc/systemd/system/ovnode.service")
            if service_file.exists():
                service_file.unlink()
            run_command(["systemctl", "daemon-reload"], check=False)
            run_command(["systemctl", "reset-failed"], check=False)

            install_log.audit("uninstall", "ovnode", "success", uid=None, status="completed")
            install_log.event("uninstall.complete")
            print("OVNode uninstallation completed successfully!")
            print("To install OVNode again, run:")
            print("bash <(curl -s https://raw.githubusercontent.com/anonysec/OVNode/main/install.sh)")
        except Exception as e:
            install_log.audit("uninstall", "ovnode", "failed", details=str(e))
            install_log.event("uninstall.failed", error=str(e))
            raise


@install_log
def run_ovnode() -> None:
    install_log.event("service.write", name="ovnode")
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
    install_log.event("service.installed", path=str(service_file))

    install_log.event("systemd.daemon_reload")
    run_command(["systemctl", "daemon-reload"], check=False)

    install_log.event("systemd.enable")
    run_command(["systemctl", "enable", "ovnode"], check=False)

    install_log.event("systemd.restart")
    run_command(["systemctl", "restart", "ovnode"], check=False)


@install_log
def deactivate_ovnode() -> None:
    install_log.event("service.stop")
    run_command(["systemctl", "stop", "ovnode"], check=False)
    install_log.event("service.disable")
    run_command(["systemctl", "disable", "ovnode"], check=False)


@install_log
def menu():
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
        install_log.event("exit")
        print(Fore.GREEN + "\nExiting..." + Style.RESET_ALL)
        sys.exit(0)
    else:
        install_log.event("input.invalid", choice=choice)
        print(Fore.RED + "\nInvalid choice. Please try again." + Style.RESET_ALL)
        input(Fore.YELLOW + "Press Enter to continue..." + Style.RESET_ALL)
        menu()


if __name__ == "__main__":
    menu()
