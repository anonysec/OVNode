# OVManager Node - Docker image
# Manages OpenVPN locally; OpenVPN + iproute2/iptables are bundled so the node
# is functional inside the container.
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 \
    UV_SYSTEM_PYTHON=1 \
    PATH="/root/.local/bin:${PATH}"

# OpenVPN + networking tools for tunnel management
RUN apt-get update \
    && apt-get install -y --no-install-recommends openvpn iproute2 iptables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml uv.lock* ./
COPY core/ ./core/
COPY . .

RUN pip install --no-cache-dir uv \
    && uv sync --frozen || uv sync

EXPOSE 2083 1194/udp
CMD ["sh", "-c", "uv run main.py"]
