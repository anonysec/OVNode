# OVManager Node - Docker image
# Manages OpenVPN locally; OpenVPN + iproute2/iptables are bundled so the node
# is functional inside the container.
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 \
    UV_SYSTEM_PYTHON=1 \
    PATH="/root/.local/bin:${PATH}"

# OpenVPN + networking tools for tunnel management
RUN apt-get update \
    && apt-get install -y --no-install-recommends openvpn iproute2 iptables curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml uv.lock* ./
COPY core/ ./core/
COPY . .

RUN pip install --no-cache-dir uv \
    && uv sync --frozen || uv sync

EXPOSE 2083 1194/udp
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -sf http://localhost:2083/sync/health || exit 1
CMD ["sh", "-c", "uv run main.py"]
