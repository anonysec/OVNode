#!/usr/bin/env python3
# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT
"""PostToolUse hook: report ruff findings for a just-edited Python file.

Read-only on purpose. It never rewrites the file, so it cannot invalidate the
file state Claude Code tracks between edits. It writes at most one JSON object
to stdout, and only when ruff actually reports something; it never rewrites or
summarises the tool result. Exit code is always 0 — a PostToolUse hook cannot
block anyway, and a broken hook must never end the turn.

Run `ruff-on-edit.py --self-test` to check the guard rails.
"""

import io
import json
import os
import subprocess
import sys

MAX_LINES = 20


def _findings(project_dir: str, path: str) -> str:
    ruff = os.path.join(project_dir, ".venv", "bin", "ruff")
    if not os.path.isfile(ruff):
        return ""
    try:
        proc = subprocess.run(
            [ruff, "check", "--no-cache", "--color", "never", "--output-format", "concise", path],
            cwd=project_dir,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if proc.returncode == 0:
        return ""
    lines = (proc.stdout + proc.stderr).strip().splitlines()
    return "\n".join(lines[:MAX_LINES])


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except (ValueError, OSError):
        return 0

    path = str((event.get("tool_input") or {}).get("file_path") or "")
    if not path.endswith(".py") or not os.path.isfile(path):
        return 0

    project_dir = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    findings = _findings(project_dir, path)
    if findings:
        json.dump(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "additionalContext": f"ruff check {path}:\n{findings}",
                }
            },
            sys.stdout,
        )
    return 0


def self_test() -> int:
    cases = [
        {},
        {"tool_input": {}},
        {"tool_input": {"file_path": "/nonexistent/nope.py"}},
        {"tool_input": {"file_path": __file__ + ".md"}},
        {"tool_input": {"file_path": "/etc/hostname"}},
    ]
    for case in cases:
        real_in, real_out = sys.stdin, sys.stdout
        sys.stdin, sys.stdout = io.StringIO(json.dumps(case)), io.StringIO()
        try:
            assert main() == 0, case
            assert sys.stdout.getvalue() == "", case
        finally:
            sys.stdin, sys.stdout = real_in, real_out
    print("self-test ok")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(self_test())
    try:
        sys.exit(main())
    except Exception:
        sys.exit(0)
