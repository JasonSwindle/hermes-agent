"""Scoped-lock helpers split from :mod:`gateway.status` (re-exported there): the unusable lock-dir
report (#134889 W2) and lock release. Status-module helpers are read through the module at call time
so tests that patch ``gateway.status`` keep steering them."""
from __future__ import annotations

import contextlib
import logging
import os
from pathlib import Path
from typing import Optional

from hermes_dir_acl import unusable_dir_remedy

log = logging.getLogger("gateway.status")


class ScopedLockDirUnusable(PermissionError):
    """This token cannot create, read or replace locks in the scoped-lock dir (#134889 W2).

    On Windows an elevated install/update creates ``gateway-locks`` owned by Administrators with
    no entry for the user; the same user's non-elevated gateway then gets ``Permission denied`` on
    every token lock. Retrying cannot fix an ACL, so the adapter reports it once, names the repair
    and stays down instead of crash-looping. A ``PermissionError`` subclass so existing callers
    keep their handling.
    """


# Lock dirs already reported unusable by this process: WARNING once per dir, DEBUG after, since the
# reconnect watcher and every adapter sharing the dir re-enter the acquire path.
_warned_unusable_lock_dirs: set[Path] = set()


def _unusable_lock_dir(lock_dir: Path, exc: PermissionError) -> ScopedLockDirUnusable:
    level = logging.DEBUG if lock_dir in _warned_unusable_lock_dirs else logging.WARNING
    _warned_unusable_lock_dirs.add(lock_dir)
    log.log(level, "Gateway lock directory %s is not usable by this process (%s); it was likely created "
               "by an elevated (administrator) Hermes. Platforms that need a token lock stay down until it "
               "is repaired. To repair, %s", lock_dir, exc, unusable_dir_remedy(lock_dir))
    return ScopedLockDirUnusable(exc.errno, f"gateway lock directory is not usable: {exc}", str(lock_dir))


def release_scoped_lock(scope: str, identity: str) -> None:
    """Release a scope lock owned by this PID. No start_time equality check: on-disk null vs a live
    fingerprint would wedge reconnects."""
    from gateway import status as _status
    lock_path = _status._get_scope_lock_path(scope, identity)
    if (_status._read_json_file(lock_path) or {}).get("pid") == os.getpid():
        _status._unlink_quietly(lock_path)


def release_all_scoped_locks(
    *, owner_pid: Optional[int] = None, owner_start_time: Optional[int] = None
) -> int:
    """Remove scoped lock files (--replace cleanup); returns the count removed. With ``owner_pid``
    only that gateway's records go (``owner_start_time`` narrows against PID reuse)."""
    from gateway import status as _status
    lock_dir = _status._get_lock_dir()
    if not lock_dir.exists():
        return 0
    removed = 0
    for lock_file in lock_dir.glob("*.lock"):
        if owner_pid is not None:
            record = _status._read_json_file(lock_file) or {}
            if _status._pid_from_record(record) != owner_pid or (
                owner_start_time is not None and record.get("start_time") != owner_start_time
            ):
                continue
        with contextlib.suppress(OSError):
            lock_file.unlink(missing_ok=True)
            removed += 1
    return removed
