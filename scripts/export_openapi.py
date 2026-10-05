#!/usr/bin/env python3
# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Dump the OVNode OpenAPI schema to scripts/openapi.json without a server.

The schema documents the manager⇄node contract (15 /sync routes); output is
gitignored and regenerated on demand for contract tests and tooling.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# The config requires an API key; test-only value (the schema has no secrets).
os.environ.setdefault("API_KEY", "openapi-export-only-not-a-real-key")
os.environ["DOC"] = "true"
from core.app import api  # noqa: E402

schema = api.openapi()
out = Path(__file__).with_name("openapi.json")
out.write_text(json.dumps(schema, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"wrote {out} ({len(schema.get('paths', {}))} paths)")
