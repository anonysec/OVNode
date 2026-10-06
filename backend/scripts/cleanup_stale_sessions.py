#!/usr/bin/env python3
# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT
"""Purge stale OpenVPN session markers.

A marker older than OVNODE_SESSION_TTL (default 24h) whose pool IP is no
longer present in the live status file is a corpse left by a crashed daemon or
a dropped disconnect hook: delete it. A marker whose pool IP is still live is
kept. Only ``sessions/*`` is touched — never ``users/<cn>/{limit,disabled,state}``
or the ``.ovpn`` profiles.
"""

import argparse
import json
import os
import sys
import time

SESSIONS_DIR = os.environ.get("OVNODE_SESSIONS_DIR", "/etc/openvpn/ovnode/sessions")
STATUS_FILE = os.environ.get("OVNODE_STATUS_FILE", "/etc/openvpn/server/status.log")


def _ttl() -> int:
    try:
        return int(os.environ.get("OVNODE_SESSION_TTL", "86400"))
    except ValueError:
        return 86400


def _parse_marker(path: str) -> tuple[int, str] | None:
    created = 0
    pool = ""
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                key, _, value = line.partition("=")
                key = key.strip()
                if key == "created":
                    try:
                        created = int(value.strip())
                    except ValueError:
                        created = 0
                elif key == "ifconfig_pool_remote_ip":
                    pool = value.strip()
    except OSError:
        return None
    return created, pool


def _live_pools() -> set[str]:
    pools: set[str] = set()
    try:
        with open(STATUS_FILE, encoding="utf-8", errors="ignore") as f:
            for line in f:
                if not line.startswith("CLIENT_LIST"):
                    continue
                fields = line.rstrip("\n").split("\t")
                if len(fields) >= 4 and fields[3]:
                    pools.add(fields[3])
    except OSError:
        pass
    return pools


def _marker_files() -> list[str]:
    try:
        entries = sorted(os.listdir(SESSIONS_DIR))
    except OSError:
        return []
    return [
        os.path.join(SESSIONS_DIR, name)
        for name in entries
        if not name.startswith(".") and os.path.isfile(os.path.join(SESSIONS_DIR, name))
    ]


def main() -> int:
    argparse.ArgumentParser(description=__doc__).parse_args()
    now = int(time.time())
    ttl = _ttl()
    live = _live_pools()
    scanned = removed = kept = 0
    for path in _marker_files():
        scanned += 1
        parsed = _parse_marker(path)
        if parsed is None:
            kept += 1
            continue
        created, pool = parsed
        age = now - created
        if created > 0 and age > ttl and pool not in live:
            try:
                os.remove(path)
            except OSError as exc:
                print(f"keep {os.path.basename(path)}: remove failed: {exc}", file=sys.stderr)
                kept += 1
                continue
            removed += 1
            print(f"removed stale marker {os.path.basename(path)} (age={age}s)", file=sys.stderr)
        else:
            kept += 1
    print(json.dumps({"removed": removed, "kept": kept, "scanned": scanned}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
