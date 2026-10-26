# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT
#
# OVNode — panel-managed OpenVPN node (agent + OpenVPN in one container).
#
# Multi-stage: build the Go binary, runtime ships binary + OpenVPN.

# ── build: static Go binary ──────────────────────────────────────────
FROM golang:1.27 AS builder
WORKDIR /src
COPY go.mod ./
COPY cmd/ ./cmd/
COPY internal/ ./internal/
# The binary embeds the shell files the installer and the operator CLI are
# made of, so they have to be in the build context.
COPY assets.go ./
COPY install.sh ovnode.sh lib.sh doctor.sh ./
RUN CGO_ENABLED=0 go build -o /out/ovnode ./cmd/ovnode

# ── runtime ────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="OVNode" \
      org.opencontainers.image.description="OVManager OpenVPN node agent" \
      org.opencontainers.image.source="https://github.com/anonysec/OVNode"

# openvpn + easy-rsa  — the VPN itself and its PKI tooling
# iproute2/iptables   — tun setup, forwarding and NAT from the entrypoint
# procps              — pgrep (process detection fallback in control.py)
# tini                — PID 1: signal forwarding + zombie reaping
# curl                — container healthcheck
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends \
        openvpn easy-rsa iproute2 iptables procps tini curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /out/ovnode /usr/local/bin/ovnode
COPY scripts/compose/entrypoint.sh /usr/local/bin/ovnode-entrypoint
RUN chmod 755 /usr/local/bin/ovnode-entrypoint

VOLUME ["/etc/openvpn", "/app/data"]

EXPOSE 2083 1194/udp 1194/tcp

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/ovnode-entrypoint"]