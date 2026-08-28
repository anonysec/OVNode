# Copyright (c) 2025 anonysec. All rights reserved.
# Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
#
# OVManager Node - Docker image
# Manages OpenVPN locally; OpenVPN + iproute2/iptables are bundled so the node
# is functional inside the container.
FROM python:3.13-slim
ENV PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_NO_CACHE=1 \
    PATH="/app/.venv/bin:/root/.local/bin:${PATH}"

# OpenVPN + networking tools + CA for client cert generation
RUN apt-get update \
    && apt-get install -y --no-install-recommends openvpn iproute2 iptables curl easy-rsa \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependency layer first: reinstalls only when the lockfile changes.
COPY pyproject.toml uv.lock ./
RUN pip install --no-cache-dir uv \
    && (uv sync --frozen --no-dev --no-install-project || uv sync --no-dev --no-install-project)

COPY core/ ./core/
COPY main.py ./

EXPOSE 2083 1194/udp
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -sf http://localhost:2083/sync/health \
        || curl -skf https://localhost:2083/sync/health \
        || exit 1
CMD ["python", "main.py"]
