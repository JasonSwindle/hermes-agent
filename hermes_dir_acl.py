"""Directories an elevated Windows process creates must stay usable by the same user unelevated.

Since CPython 3.13, ``os.mkdir(path, 0o700)`` on Windows applies a protected DACL of exactly
SYSTEM, Administrators and OWNER RIGHTS. An elevated process's default owner is
``BUILTIN\\Administrators``, so OWNER RIGHTS resolves to Administrators too, and the user's own
non-elevated token (where Administrators is deny-only) gets ``WinError 5`` on the directory and on
everything created inside it (#139845, #139485, the ``gateway-locks`` reports in #134889 W2). A plain
``mkdir`` inherits its parent's ACL instead, which under ``%LOCALAPPDATA%`` names the user, so the
``mode=0o700`` sites are the ones that strand the user.

:func:`make_user_dir` is the one place Hermes state/lock/log directories are created. Off Windows,
or in a non-elevated process, it is exactly ``Path.mkdir``. In an elevated Windows process it adds
an explicit, inheriting full-control ACE for the token's user SID to the directory, so the directory
and every child created later stay usable by that user after elevation ends. An elevated call on an
existing directory re-grants the same ACE, which repairs a directory an earlier elevated run left
behind. A non-elevated process cannot change such a DACL; callers that hit one report it once with
:func:`unusable_dir_remedy`.
"""
from __future__ import annotations

import functools
import logging
import os
import subprocess
import sys
from pathlib import Path

log = logging.getLogger(__name__)

_TOKEN_QUERY = 0x0008
_TOKEN_USER = 1
_TOKEN_ELEVATION = 20


@functools.lru_cache(maxsize=1)
def process_is_elevated() -> bool:
    """True for an elevated (UAC full-token) Windows process; False elsewhere or on any error."""
    if sys.platform != "win32":
        return False
    import ctypes
    from ctypes import wintypes

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                           ctypes.POINTER(wintypes.DWORD)]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)):
        return False
    try:
        elevated, size = wintypes.DWORD(), wintypes.DWORD()
        if not advapi.GetTokenInformation(token, _TOKEN_ELEVATION, ctypes.byref(elevated),
                                          ctypes.sizeof(elevated), ctypes.byref(size)):
            return False
        return bool(elevated.value)
    finally:
        kernel.CloseHandle(token)


def _grant_with_pywin32(path: Path) -> None:
    import ntsecuritycon
    import win32api
    import win32security

    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY)
    user_sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
    descriptor = win32security.GetFileSecurity(str(path), win32security.DACL_SECURITY_INFORMATION)
    dacl = descriptor.GetSecurityDescriptorDacl()
    inherit = win32security.OBJECT_INHERIT_ACE | win32security.CONTAINER_INHERIT_ACE
    if dacl is not None:
        for index in range(dacl.GetAceCount()):
            (ace_type, flags, *_), mask, sid = dacl.GetAce(index)[:3]
            if (ace_type == win32security.ACCESS_ALLOWED_ACE_TYPE and sid == user_sid
                    and mask & ntsecuritycon.FILE_ALL_ACCESS == ntsecuritycon.FILE_ALL_ACCESS
                    and flags & inherit == inherit and not flags & win32security.INHERIT_ONLY_ACE):
                return  # already granted: never grow the DACL on repeat calls
    else:
        dacl = win32security.ACL()
    dacl.AddAccessAllowedAceEx(win32security.ACL_REVISION_DS, inherit, ntsecuritycon.FILE_ALL_ACCESS, user_sid)
    descriptor.SetSecurityDescriptorDacl(True, dacl, False)
    win32security.SetFileSecurity(str(path), win32security.DACL_SECURITY_INFORMATION, descriptor)


def _grant_with_icacls(path: Path) -> None:
    whoami = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True,
                            check=True, encoding="utf-8", errors="replace", timeout=30)
    sid = whoami.stdout.strip().rsplit(",", 1)[-1].strip().strip('"')
    if not sid.upper().startswith("S-1-"):
        raise OSError(f"could not resolve the current user SID from whoami: {whoami.stdout!r}")
    subprocess.run(["icacls", str(path), "/grant", f"*{sid}:(OI)(CI)F", "/Q"], capture_output=True,
                   check=True, timeout=60)


def grant_user_access(path: str | Path) -> bool:
    """Give the token's user an inheriting full-control ACE on *path* when this process is elevated.

    True when a grant was attempted and did not fail; False off Windows, when not elevated, or when
    the grant failed (logged; the directory itself still exists)."""
    if sys.platform != "win32" or not process_is_elevated():
        return False
    target = Path(path)
    try:
        try:
            _grant_with_pywin32(target)
        except ImportError:
            _grant_with_icacls(target)
    except Exception as exc:  # health: allow BLE001 -- pywintypes.error is not an OSError; never fail the mkdir
        log.warning("Could not grant the current user access to %s created while elevated (%s); a "
                    "non-elevated Hermes may not be able to use it. To repair, from an elevated prompt run: "
                    'icacls "%s" /reset /t', target, exc, target)
        return False
    return True


# Dirs this elevated process already granted: the grant reads and may rewrite a DACL, and the
# callers (log handlers, lock acquires) re-enter on hot paths.
_granted: set[Path] = set()


def make_user_dir(path: str | Path, mode: int = 0o777, *, parents: bool = False, exist_ok: bool = False) -> Path:
    """``Path.mkdir`` (same arguments and defaults) that keeps an elevated Windows creation usable
    by the same user unelevated.

    Off Windows or unelevated this is ``Path.mkdir`` and nothing else. Elevated, every directory
    this call created (missing parents included) and the leaf, even when it already existed (the
    repair case), get the user's inheriting full-control ACE once per process."""
    target = Path(path)
    if sys.platform != "win32" or not process_is_elevated():
        target.mkdir(mode=mode, parents=parents, exist_ok=exist_ok)
        return target
    created = []
    probe = target
    while not probe.exists() and probe.parent != probe:
        created.append(probe)
        probe = probe.parent
    target.mkdir(mode=mode, parents=parents, exist_ok=exist_ok)
    for directory in reversed(created or [target]):
        if directory not in _granted and grant_user_access(directory):
            _granted.add(directory)
    return target


def unusable_dir_remedy(path: str | Path) -> str:
    """The one-line repair for a directory this process may not use (owner from an elevated run)."""
    if os.name == "nt":
        return f'from an elevated prompt run: icacls "{path}" /reset /t'
    return f'run: sudo chown -R "$(id -un)" "{path}"'
