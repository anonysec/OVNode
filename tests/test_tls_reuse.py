# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""A second service on this host must not lose its TLS identity to the node's.

``/etc/ssl/self-signed`` is a shared convention: OVManager keeps its panel
certificate in exactly the two files this node writes, and OVManager's own
single-VPS guide tells operators to install the node on the same host.
``generate_selfsigned`` used to overwrite whatever was there and then
``chmod 600`` the key, which drops the group read the panel's non-root
service account depends on — the panel then stops starting, and nothing in
either project's doctor notices.

An intact pair is now reused untouched. These tests exercise that decision
against real openssl, and pin the structure that keeps it safe.
"""

import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
INSTALLER = REPO / "install.sh"
MANAGER = REPO / "manager.sh"
LIB = REPO / "scripts" / "lib" / "common.sh"


def _shell(script: str) -> subprocess.CompletedProcess:
    """Run a snippet with the shared lib sourced, the way manager.sh does."""
    return subprocess.run(
        ["bash", "-c", 'set -euo pipefail\n. "' + str(LIB) + '"\n' + script],
        capture_output=True,
        text=True,
        timeout=60,
    )


def _usable(key: Path, cert: Path) -> bool:
    """True when the pair would be kept rather than regenerated."""
    return _shell(f'_existing_tls_pair_usable "{key}" "{cert}"').returncode == 0


def _pair(directory: Path, *, not_before: str | None = None, not_after: str | None = None):
    directory.mkdir(parents=True, exist_ok=True)
    key = directory / "privkey.pem"
    cert = directory / "fullchain.pem"
    command = [
        "openssl",
        "req",
        "-x509",
        "-nodes",
        "-newkey",
        "rsa:2048",
        "-keyout",
        str(key),
        "-out",
        str(cert),
        "-subj",
        "/CN=test",
    ]
    if not_before and not_after:
        # -not_before/-not_after are OpenSSL 3.4+; the CI runner ships 3.0, so
        # this one case may skip. Handled below, and it names the reason.
        command += ["-not_before", not_before, "-not_after", not_after]
    else:
        command += ["-days", "3650"]
    done = subprocess.run(command, capture_output=True, text=True, timeout=120)
    if done.returncode != 0:
        # A blanket skip here read as "not covered" for *every* openssl failure,
        # including a genuinely broken command — which is how this test stopped
        # running on CI without anyone noticing. Only the known version gap may
        # skip; anything else fails.
        if not_before and not_after:
            pytest.skip(
                "openssl < 3.4 cannot set -not_before/-not_after, so an arbitrary "
                f"validity window cannot be built: {done.stderr.strip()[:200]}"
            )
        raise AssertionError(
            f"openssl could not build the test certificate: {done.stderr.strip()[:200]}"
        )
    return key, cert


def _body(name: str, *paths: Path) -> str:
    """The named function's text, from the first given file that defines it.

    install.sh sources the shared helpers out of scripts/lib, so a helper
    now lives in one of the two — never in both.
    """
    for path in paths:
        text = path.read_text(encoding="utf-8")
        match = re.search(rf"^{re.escape(name)}\(\) \{{(.*?)^\}}", text, re.M | re.DOTALL)
        if match:
            return match.group(1)
    raise AssertionError(f"{name}() not found in {[p.name for p in paths]}")


def test_an_intact_pair_is_reused(tmp_path):
    key, cert = _pair(tmp_path)
    assert _usable(key, cert), "an existing self-signed pair must be kept as-is"


def test_a_missing_pair_is_not_reused(tmp_path):
    assert not _usable(tmp_path / "privkey.pem", tmp_path / "fullchain.pem")


def test_a_mismatched_pair_is_not_reused(tmp_path):
    """A key that does not match its certificate serves a broken listener,
    so the pair has to be replaced rather than trusted."""
    key_a, _ = _pair(tmp_path / "a")
    _, cert_b = _pair(tmp_path / "b")
    assert not _usable(key_a, cert_b)


def test_an_expired_certificate_is_not_reused(tmp_path):
    key, cert = _pair(tmp_path, not_before="20200101000000Z", not_after="20200102000000Z")
    assert not _usable(key, cert), "an expired certificate must be replaced, not reused"


def test_a_truncated_certificate_is_not_reused(tmp_path):
    """A half-written file must not pass for a usable certificate."""
    key, cert = _pair(tmp_path)
    cert.write_text("", encoding="utf-8")
    assert not _usable(key, cert)


def test_nothing_chmods_before_the_reuse_path_returns():
    """Reuse is only safe if permissions are left exactly as found.

    A chmod ahead of the reuse branch would still strip the panel's group
    read even though its certificate was kept — the failure would just move.
    Compared by line so the word "chmod" in a comment cannot satisfy it.
    """
    body = _body("generate_selfsigned", INSTALLER, LIB)
    assert "_existing_tls_pair_usable" in body
    lines = body.splitlines()
    reuse_line = next(i for i, line in enumerate(lines) if line.strip() == "return 0")
    chmod_line = next(i for i, line in enumerate(lines) if line.strip().startswith("chmod"))
    assert reuse_line < chmod_line, "the reuse path must return before any chmod runs"


def test_regeneration_is_still_reachable_on_request():
    """`ovn tls` option 1 is labelled regenerate, so it must actually do that."""
    assert "TLS_REGENERATE" in _body("generate_selfsigned", INSTALLER, LIB), (
        "there must be a way to ask for a new certificate"
    )
    assert "TLS_REGENERATE=1" in _body("node_tls", MANAGER), (
        "`ovn tls selfsigned` must bypass reuse — asking for a new certificate is "
        "asking for a new certificate, and the panel has pinned the old one"
    )
