# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Atomic writes for non-secret OpenVPN config and policy files.

One implementation instead of the per-module copies that had drifted apart
(``control`` kept a ``.bak``; ``ports`` did not; ``pki`` wrote server.conf
with a plain ``open(..., "w")`` and could truncate the only copy on a crash).

Temp file + fsync + rename: a reader either sees the old file or the new one,
never a half-written one.
"""

from __future__ import annotations

import os
import shutil
import tempfile

from core.logger import logger


def write_text_atomic(
    path: str,
    content: str,
    *,
    mode: int = 0o644,
    keep_backup: bool = False,
    prefix: str = ".tmp-",
) -> None:
    """Write ``content`` to ``path`` atomically.

    ``mode`` is applied to the temp file before the rename (mkstemp creates
    0600), so a dropped-privilege OpenVPN user can still read the result.
    ``keep_backup`` copies the previous file to ``<path>.bak`` first — the
    rollback path in ``control`` depends on those copies existing.
    """
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=prefix)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fchmod(fh.fileno(), mode)
            os.fsync(fh.fileno())
        if keep_backup:
            try:
                if os.path.exists(path):
                    shutil.copy2(path, path + ".bak")
            except OSError as e:
                logger.warning("Could not backup %s: %s", path, e)
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass
