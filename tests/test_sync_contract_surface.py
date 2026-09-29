# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""The documented sync surface must be the real one.

Four route modules each carried their own copy of the "1:1 with NodeRequests"
endpoint table, and all four had drifted: `POST /sync/users` (bulk limits) and
`POST /sync/renew-cert` were missing. A stale contract list is worse than no
list — it is what a future endpoint gets written against.

This pins the real surface against each module's docstring so the two cannot
separate again.
"""

import re
from pathlib import Path

import pytest

ROUTE_MODULES = ("system", "config", "stats", "users")


def _declared_endpoints(module_name: str) -> set[tuple[str, str]]:
    """(METHOD, path) pairs documented in that module's docstring."""
    import importlib

    module = importlib.import_module(f"core.api.routes.{module_name}")
    doc = module.__doc__ or ""
    found = set()
    for match in re.finditer(r"^\s{4}(GET|POST|PUT|DELETE|PATCH)\s+(/\S+)", doc, re.MULTILINE):
        found.add((match.group(1), match.group(2)))
    return found


def _real_endpoints() -> set[tuple[str, str]]:
    """(METHOD, path) pairs the app actually serves under /sync."""
    import importlib

    real: set[tuple[str, str]] = set()
    for name in ROUTE_MODULES:
        module = importlib.import_module(f"core.api.routes.{name}")
        for route in module.router.routes:
            methods = getattr(route, "methods", None)
            if not methods:
                continue
            for method in methods - {"HEAD", "OPTIONS"}:
                real.add((method, route.path))
    return real


def _all_documented() -> set[tuple[str, str]]:
    documented: set[tuple[str, str]] = set()
    for name in ROUTE_MODULES:
        documented |= _declared_endpoints(name)
    return documented


def test_every_documented_endpoint_exists():
    missing = sorted(_all_documented() - _real_endpoints())
    assert missing == [], f"documented but not served: {missing}"


def test_the_bulk_and_renew_endpoints_are_documented():
    """The two that every copy of the table had lost."""
    documented = _all_documented()
    assert ("POST", "/sync/users") in documented, "POST /sync/users (bulk limits) is undocumented"
    assert ("POST", "/sync/renew-cert") in documented, "POST /sync/renew-cert is undocumented"


README = Path(__file__).resolve().parent.parent / "README.md"


def test_the_readme_table_matches_the_live_router():
    """The README is the canonical public list, so it must not drift either.

    It had: it listed 11 endpoints while the app served 18, missing
    `/sync/restart`, `/sync/update`, `/sync/renew-cert`, `/sync/users`,
    `/sync/user/{uid}/reset-usage`, `/sync/config` and `/sync/logs`. The route
    docstrings were pinned; nothing pinned this, and CONTRIBUTING points readers
    here as the record.
    """
    documented = set()
    for line in README.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^\|\s*`(GET|POST|PUT|DELETE|PATCH) (/sync\S*)`", line)
        if m:
            documented.add((m.group(1), m.group(2)))
    assert documented, "no endpoint rows found in the README table"

    missing = sorted(documented - _real_endpoints())
    assert missing == [], f"the README documents endpoints the app does not serve: {missing}"

    undocumented = sorted(_real_endpoints() - documented)
    assert undocumented == [], f"the app serves endpoints the README does not list: {undocumented}"


@pytest.mark.parametrize("module_name", ROUTE_MODULES)
def test_the_table_is_identical_in_every_module(module_name):
    """Four copies is the bug; they must at least not drift."""
    assert _declared_endpoints(module_name) == _declared_endpoints("config"), (
        f"core/api/routes/{module_name}.py documents a different endpoint set"
    )
