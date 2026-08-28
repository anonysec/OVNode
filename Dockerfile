# Copyright (c) 2025 anonysec. All rights reserved.
# Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.
#
# OVNode — panel-managed OpenVPN node (agent + OpenVPN in one container).
#
# Multi-stage: dependencies are resolved from uv.lock in a builder layer,
# the runtime image ships only the venv + source + OpenVPN. The entrypoint
# (docker/entrypoint.sh) supervises BOTH processes: the sync agent and the
# OpenVPN daemon it configures.

# ── build: locked dependency venv ──────────────────────────────────────
FROM python:3.13-slim AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_NO_CACHE=1

RUN pip install --no-cache-dir uv

WORKDIR /app
COPY pyproject.toml uv.lock ./
# --frozen enforces the lockfile; the fallback keeps image builds working
# from source trees whose lock is mid-update.
RUN uv sync --frozen --no-dev --no-install-project \
    || uv sync --no-dev --no-install-project

# ── runtime ────────────────────────────────────────────────────────────
FROM python:3.13-slim

LABEL org.opencontainers.image.title="OVNode" \
      org.opencontainers.image.description="OVManager OpenVPN node agent" \
      org.opencontainers.image.source="https://github.com/anonysec/OVNode"

ENV PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:${PATH}"

# openvpn + easy-rsa  — the VPN itself and its PKI tooling
# iproute2/iptables   — tun setup, forwarding and NAT from the entrypoint
# procps              — pgrep (process detection fallback in control.py)
# tini                — PID 1: signal forwarding + zombie reaping (hooks fork)
# curl                — container healthcheck
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openvpn easy-rsa iproute2 iptables procps tini curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/.venv ./.venv
COPY core/ ./core/
COPY main.py ./
COPY docker/entrypoint.sh /usr/local/bin/ovnode-entrypoint
RUN chmod 755 /usr/local/bin/ovnode-entrypoint

# All node state lives under /etc/openvpn (PKI + ovnode store) and /app/data
# (agent log). Mount both, and a node survives full container replacement.
VOLUME ["/etc/openvpn", "/app/data"]

EXPOSE 2083 1194/udp 1194/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -sf http://localhost:${SERVICE_PORT:-2083}/sync/health \
        || curl -skf https://localhost:${SERVICE_PORT:-2083}/sync/health \
        || exit 1

ENTRYPOINT ["tini", "--", "ovnode-entrypoint"]
