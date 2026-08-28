# Copyright (c) 2025 anonysec. All rights reserved.
# Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.

"""Static validation of the Docker deployment (no daemon in CI).

The container contract:
- the entrypoint supervises BOTH the agent and the OpenVPN daemon,
- OpenVPN crashing must not kill the API (restart with backoff),
- the image ships every binary the code shells out to,
- compose grants exactly the capabilities the entrypoint needs.
"""

import os
import re
import subprocess

ROOT = os.path.join(os.path.dirname(__file__), "..")
DOCKERFILE = os.path.join(ROOT, "Dockerfile")
ENTRYPOINT = os.path.join(ROOT, "docker", "entrypoint.sh")
COMPOSE = os.path.join(ROOT, "docker-compose.yml")


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


def test_entrypoint_is_valid_bash():
    subprocess.run(["bash", "-n", ENTRYPOINT], check=True)


def test_entrypoint_supervises_both_processes():
    content = _read(ENTRYPOINT)
    assert "python /app/main.py" in content  # the agent
    assert re.search(r"openvpn --cd .* --config", content)  # the VPN itself
    assert "--writepid" in content  # control.py liveness/SIGHUP detection
    assert "backoff" in content  # OpenVPN crash must not kill the API
    assert "OVNODE_SKIP_OPENVPN" in content  # agent-only escape hatch
    assert "trap shutdown TERM INT" in content


def test_entrypoint_handles_networking():
    content = _read(ENTRYPOINT)
    assert "/dev/net/tun" in content
    assert "ip_forward" in content
    assert "MASQUERADE" in content
    assert "OVNODE_EXTRA_PORTS" in content  # multi-port REDIRECT rules


def test_dockerfile_contract():
    content = _read(DOCKERFILE)
    # Multi-stage: deps resolved from the lockfile in a builder layer.
    assert "AS builder" in content
    assert "uv sync --frozen" in content
    assert "COPY --from=builder /app/.venv" in content
    # Every binary the code shells out to must be in the runtime image
    # (the install list spans continuation lines — search the whole file).
    for binary in ("openvpn", "easy-rsa", "iptables", "iproute2", "procps", "tini", "curl"):
        assert binary in content, f"{binary} missing from runtime image"
    # tini is PID 1 (signal forwarding + zombie reaping for hook forks).
    assert re.search(r'ENTRYPOINT \["tini"', content)
    assert "HEALTHCHECK" in content


def test_compose_contract():
    content = _read(COMPOSE)
    assert "network_mode: host" in content
    assert "NET_ADMIN" in content
    assert "SYS_MODULE" not in content  # deliberately dropped: not needed
    assert "/etc/openvpn" in content  # state volume — node survives replacement
    assert "/dev/net/tun:/dev/net/tun" in content
    assert "env_file: .env" in content


def test_dockerignore_keeps_secrets_and_state_out():
    content = _read(os.path.join(ROOT, ".dockerignore"))
    for entry in (".env", ".git", "data", "tests", ".venv"):
        assert re.search(rf"^{re.escape(entry)}$", content, flags=re.MULTILINE), entry
    # But the build must still see the example env and the lockfile.
    assert "!.env.example" in content
    assert not re.search(r"^uv\.lock$", content, flags=re.MULTILINE)
