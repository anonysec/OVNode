# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Atomic writes, file locks and the OpenVPN root for the whole domain.

Temp file + fsync + rename: a reader sees the old file or the new one, never
a half-written one — server.conf is the only copy OpenVPN will start from.

Leaf module: it imports nothing else from ``core.openvpn``, so every submodule
(including :mod:`core.openvpn.store`, which the PKI imports) can depend on it
without a circular import.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from contextlib import contextmanager

from core.logger import logger


def openvpn_root() -> str:
    """The OpenVPN root directory.

    Single source for the ``OVNODE_OPENVPN_ROOT`` default; every module that
    needs a path under it calls this or imports a constant derived from it.
    """
    return os.getenv("OVNODE_OPENVPN_ROOT", "/etc/openvpn")


@contextmanager
def file_lock(path: str):
    """Hold an exclusive ``flock`` on ``path`` for the duration of the block.

    Yields ``None`` while the lock is held, or the :class:`OSError` when the
    lock file cannot be *opened* — the caller decides whether to refuse or
    proceed unlocked. A failure to acquire the lock itself (``flock``) is
    re-raised: it means the lock exists but is unusable, so silently
    proceeding unlocked would defeat the mutual exclusion. The lock (and
    file) is always released.
    """
    import fcntl

    fh = None
    err: OSError | None = None
    try:
        fh = open(path, "a")
    except OSError as e:
        err = e
    else:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        except OSError:
            fh.close()
            fh = None
            raise
    try:
        yield err
    finally:
        if fh is not None:
            try:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
            fh.close()


def write_text_atomic(
    path: str,
    content: str,
    *,
    mode: int = 0o644,
    keep_backup: bool = False,
    prefix: str = ".tmp-",
) -> None:
    """Write ``content`` to ``path`` atomically.

    ``mode`` is applied before the rename (mkstemp creates 0600), so a
    dropped-privilege OpenVPN user can still read the result. ``keep_backup``
    copies the previous file to ``<path>.bak`` — ``control``'s rollback path
    depends on those copies existing.
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
