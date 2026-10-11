# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""`make lint` must syntax-check every shell file, not just the first —
`bash -n a b c` parses only `a` and treats the rest as its own arguments."""

from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _lint_recipe() -> str:
    text = (REPO / "Makefile").read_text(encoding="utf-8")
    return text.split("lint:")[1].split("\n\n")[0]


def test_makefile_checks_all_shell():
    seg = _lint_recipe()
    assert "bash -n install.sh && bash -n manager.sh" in seg
    assert "bash -n install.sh manager.sh" not in seg
    assert 'for f in scripts/lib/*.sh; do bash -n "$$f" || exit 1; done' in seg
