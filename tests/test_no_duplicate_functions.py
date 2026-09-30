# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Every shell function is defined in exactly one file.

install.sh used to carry a byte-identical copy of the lib and a parity test
held the two together. It sources the lib now, so the drift to guard against
is one function written twice — checked directly rather than by comparing
copies.
"""

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INSTALLER = REPO / "install.sh"
MANAGER = REPO / "manager.sh"
LIBS = sorted((REPO / "scripts" / "lib").glob("*.sh"))

# install.sh and manager.sh are separate programs and each owns an entry
# point, its own argument parser and its own help text: a name here is two
# different functions, not one written twice.
ENTRY_POINTS = {"main", "parse_args", "show_help"}

FILES = [INSTALLER, *LIBS, MANAGER]


def _defines(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    return set(re.findall(r"^([A-Za-z_][A-Za-z0-9_]*)\(\)", text, re.M))


def test_the_libs_exist():
    assert LIBS, "scripts/lib/ is empty — install.sh has nothing to source"


def test_no_function_is_defined_in_two_files():
    seen: dict[str, list[str]] = {}
    for path in FILES:
        for name in _defines(path):
            seen.setdefault(name, []).append(path.name)
    duplicated = {name: where for name, where in seen.items() if len(where) > 1}
    unexpected = {n: f for n, f in duplicated.items() if n not in ENTRY_POINTS}
    assert not unexpected, f"defined in more than one file: {unexpected}"


def test_entry_points_are_not_lib_functions():
    """The exemption must not be able to hide drift: a shared helper belongs
    in a lib, so it can never be excused as a per-script entry point."""
    lib_names = set().union(*(_defines(path) for path in LIBS))
    assert not (ENTRY_POINTS & lib_names), ENTRY_POINTS & lib_names


def test_lib_defines_what_the_manager_calls():
    """render_kv() prints the TLS menu's rows and node_name_from_env() feeds it.
    Both are lib-only, so nothing else would notice them going missing.

    kv became render_kv when output moved to render.sh: it was a fifth copy of
    the same label/value idea, at a different column width."""
    lib_names = set().union(*(_defines(path) for path in LIBS))
    assert {"render_kv", "node_name_from_env"} <= lib_names


def test_the_retired_output_helpers_are_gone():
    """Nothing may reintroduce the old vocabulary.

    line/step/info/warn/field/sep/kv each printed a glyph or a colour inline,
    which is the duplication render.sh exists to remove: the node card and the
    panel card were two copies of one idea, and they had already drifted.
    """
    import re

    retired = ("step", "info", "warn", "field", "sep", "kv", "line", "spinner")
    offenders = {}
    for path in FILES:
        if path.name == "render.sh":
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        hits = {}
        for name in retired:
            pat = re.compile(
                r"^\s*(?:[^#\n]*?(?:&&|\|\||\{|;)\s*)*" + re.escape(name) + r'\s+(?:"|\$\(|e )'
            )
            found = [i for i, ln in enumerate(lines, 1) if pat.search(ln)]
            if found:
                hits[name] = found
        if hits:
            offenders[path.name] = hits
    assert not offenders, f"retired output helpers back in use: {offenders}"


def test_the_installer_fetches_render_sh():
    """render.sh has to be in LIB_FILES, or a curl-piped install sources the old
    common.sh and then dies on the first render_* call — after the installer has
    already started changing the box."""
    import re

    listed = re.search(r"^LIB_FILES=\(([^)]*)\)", INSTALLER.read_text(encoding="utf-8"), re.M)
    assert listed, "install.sh no longer declares LIB_FILES"
    assert "render.sh" in listed.group(1), listed.group(1)


def test_the_installer_names_every_lib():
    """There is no index to glob over a URL, so install.sh fetches the libs
    by the names in LIB_FILES: a lib it does not list is a helper the
    curl-piped installer never defines."""
    listed = re.search(r"^LIB_FILES=\(([^)]*)\)", INSTALLER.read_text(encoding="utf-8"), re.M)
    assert listed, "install.sh no longer declares LIB_FILES"
    assert set(listed.group(1).split()) == {path.name for path in LIBS}
