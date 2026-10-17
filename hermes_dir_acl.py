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

An elevated grant never goes through a junction, symlink or other reparse point (nor a hard-linked
file): same-user medium-integrity code can swap any entry under the home for a junction to e.g.
``C:\\Program Files\\X``, and a grant that followed it would hand the user full control of the
target across the UAC boundary. The path is lstat-checked first, and the pywin32 grant opens it with
``FILE_FLAG_OPEN_REPARSE_POINT`` and re-checks the handle, so a swap after the check is not followed
either; the icacls fallback passes ``/L``. :func:`grant_tree_user_access` is the recursive form
(the post-update repair), pruning every reparse point instead of descending into it.
"""
from __future__ import annotations

import functools
import logging
import os
import stat
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

log = logging.getLogger(__name__)

_TOKEN_QUERY = 0x0008
_TOKEN_USER = 1
_TOKEN_ELEVATION = 20

FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_READ_CONTROL = 0x00020000
_WRITE_DAC = 0x00040000
_FILE_SHARE_ALL = 0x7  # read | write | delete: never block another Hermes process
_OPEN_EXISTING = 3
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000  # needed to open a directory handle
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000  # open the link itself, never its target


class ReparsePointRefused(OSError):
    """The grant target is (or became) a junction, symlink, other reparse point or hard link."""


def is_reparse_point(path: str | Path) -> bool:
    """True when *path* itself is a symlink, junction or other reparse point (never followed), or
    cannot be lstat-ed at all; the safe answer for "may an elevated grant act on this path"."""
    try:
        st = os.lstat(path)
    except OSError:
        return True
    if stat.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT:
        return True
    isjunction = getattr(os.path, "isjunction", None)  # 3.12+; st_file_attributes covers 3.11
    return bool(isjunction and isjunction(path))


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


def _strip_win32_prefix(path: str) -> str:
    if path.startswith("\\\\?\\UNC\\"):
        return "\\\\" + path[8:]
    return path.removeprefix("\\\\?\\")


def _grant_with_pywin32(path: Path, is_dir: bool, expected: str | None = None) -> None:
    import ntsecuritycon
    import win32api
    import win32file
    import win32security

    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY)
    user_sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
    # Act on the handle, never the name: GetFileSecurity/SetFileSecurity resolve a junction or symlink
    # to its target, so a swap after the lstat check would still redirect the grant.
    handle = win32file.CreateFile(str(path), _READ_CONTROL | _WRITE_DAC, _FILE_SHARE_ALL, None, _OPEN_EXISTING,
                                  _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT, None)
    try:
        if expected is not None:
            # A parent swapped for a junction after the lstat checks resolves the name elsewhere.
            final = _strip_win32_prefix(win32file.GetFinalPathNameByHandle(handle, 0))
            if os.path.normcase(final.rstrip("\\")) != os.path.normcase(expected.rstrip("\\")):
                raise ReparsePointRefused(f"{path} resolves to {final}, not {expected}")
        info = win32file.GetFileInformationByHandle(handle)
        attributes, links = info[0], info[7]
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT:
            raise ReparsePointRefused(f"{path} is a junction, symlink or other reparse point")
        if not attributes & FILE_ATTRIBUTE_DIRECTORY and links > 1:
            raise ReparsePointRefused(f"{path} is a hard link ({links} names); its other names may be outside")
        is_dir = bool(attributes & FILE_ATTRIBUTE_DIRECTORY)
        descriptor = win32security.GetKernelObjectSecurity(handle, win32security.DACL_SECURITY_INFORMATION)
        dacl = descriptor.GetSecurityDescriptorDacl()
        inherit = (win32security.OBJECT_INHERIT_ACE | win32security.CONTAINER_INHERIT_ACE) if is_dir else 0
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
        # The handle form of SetFileSecurity: same semantics (no propagation walk), no name resolution.
        win32security.SetKernelObjectSecurity(handle, win32security.DACL_SECURITY_INFORMATION, descriptor)
    finally:
        handle.Close()


@functools.lru_cache(maxsize=1)
def _whoami_sid() -> str:
    whoami = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True,
                            check=True, encoding="utf-8", errors="replace", timeout=30)
    sid = whoami.stdout.strip().rsplit(",", 1)[-1].strip().strip('"')
    if not sid.upper().startswith("S-1-"):
        raise OSError(f"could not resolve the current user SID from whoami: {whoami.stdout!r}")
    return sid


def _grant_with_icacls(path: Path, is_dir: bool, expected: str | None = None) -> None:
    if is_dir:
        # icacls applies an inheritable ACE through SetNamedSecurityInfo, which also propagates it
        # down the existing subtree; refuse when that subtree holds a link it could descend into.
        nested: list[Path] = []
        for _ in iter_tree_without_reparse_points(path, nested):
            if nested:
                raise ReparsePointRefused(f"{nested[0]} under {path} is a junction or link (icacls fallback)")
    ace = f"*{_whoami_sid()}:(OI)(CI)F" if is_dir else f"*{_whoami_sid()}:F"
    # /L: act on a symbolic link or junction itself, not its target (the lstat check already refused
    # one; this covers a swap between that check and icacls opening the path). Without pywin32 there
    # is no handle to pin, so *expected* cannot be re-checked here.
    subprocess.run(["icacls", str(path), "/grant", ace, "/Q", "/L"], capture_output=True,
                   check=True, timeout=60)


def _hard_linked_file(path: Path) -> bool:
    try:
        st = os.lstat(path)
    except OSError:
        return True
    return not stat.S_ISDIR(st.st_mode) and st.st_nlink > 1


def _grant(path: Path, is_dir: bool = True, expected: str | None = None) -> None:
    """Grant the token's user full control on *path* itself; raise :class:`ReparsePointRefused`
    for a reparse point or hard-linked file (or, with *expected*, a handle that resolves anywhere
    else) and anything else on failure."""
    if is_reparse_point(path) or _hard_linked_file(path):
        raise ReparsePointRefused(f"{path} is a junction, symlink, other reparse point or hard link")
    try:
        _grant_with_pywin32(path, is_dir, expected)
    except ImportError:
        _grant_with_icacls(path, is_dir, expected)


def _components_below_home(path: Path) -> list[Path]:
    """*path* and each ancestor of it strictly below the Hermes home (lexically), outermost first;
    empty when *path* is not under the home. The home itself (and above) is the user's own choice
    and may legitimately be a link; an entry INSIDE it is what same-user code can swap."""
    try:
        from hermes_constants import get_hermes_home
        home = Path(os.path.abspath(get_hermes_home()))
        rel = Path(os.path.abspath(path)).relative_to(home)
    except (ImportError, ValueError, OSError):
        return []
    return [home.joinpath(*rel.parts[:i]) for i in range(1, len(rel.parts) + 1)]


def _expected_final(path: Path) -> str | None:
    """Where *path* must resolve when nothing below the home is a link: the home's real path plus
    the relative parts. None off-home (only the leaf's own open-reparse check applies there)."""
    components = _components_below_home(path)
    if not components:
        return None
    home = components[0].parent
    return os.path.join(os.path.realpath(home), *Path(os.path.abspath(path)).relative_to(home).parts)


def _warn_refused(path: Path, exc: BaseException) -> None:
    log.warning("Not granting the current user access to %s while elevated (%s): an elevated grant "
                "never follows a junction or link out of the Hermes home. If this is your own link, "
                "point HERMES_HOME (or the link) at the real directory.", path, exc)


def grant_user_access(path: str | Path) -> bool:
    """Give the token's user an inheriting full-control ACE on *path* when this process is elevated.

    True when a grant was attempted and did not fail; False off Windows, when not elevated, when
    *path* is a junction/symlink/reparse point (refused, one warning), or when the grant failed
    (logged; the directory itself still exists)."""
    if sys.platform != "win32" or not process_is_elevated():
        return False
    target = Path(path)
    try:
        for component in _components_below_home(target):
            if is_reparse_point(component):
                raise ReparsePointRefused(f"{component} is a junction, symlink or other reparse point")
        _grant(target, expected=_expected_final(target))
    except ReparsePointRefused as exc:
        _warn_refused(target, exc)
        return False
    except Exception as exc:  # health: allow BLE001 -- pywintypes.error is not an OSError; never fail the mkdir
        log.warning("Could not grant the current user access to %s created while elevated (%s); a "
                    "non-elevated Hermes may not be able to use it. To repair, from an elevated prompt run: "
                    'icacls "%s" /reset /t', target, exc, target)
        return False
    return True


def iter_tree_without_reparse_points(root: str | Path, skipped: list[Path]) -> Iterator[tuple[Path, bool]]:
    """Yield ``(path, is_dir)`` for *root* and everything under it, never entering or yielding a
    junction, symlink or other reparse point (each one is appended to *skipped* instead).

    ``os.walk`` is not enough: it follows directory junctions (``os.path.islink`` is False for one).
    Unreadable directories are skipped silently, like ``icacls /C``."""
    root = Path(root)
    if is_reparse_point(root):
        skipped.append(root)
        return
    stack = [root]
    while stack:
        directory = stack.pop()
        yield directory, True
        try:
            with os.scandir(directory) as entries:
                children = [Path(entry.path) for entry in entries]
        except OSError:
            continue
        for child in sorted(children):
            if is_reparse_point(child):
                skipped.append(child)
            elif child.is_dir():
                stack.append(child)
            else:
                yield child, False


def grant_tree_user_access(root: str | Path) -> tuple[int, list[Path], list[tuple[Path, str]]]:
    """Recursive :func:`grant_user_access` (the elevated post-update repair): grant the token's user
    full control on *root* and every directory and file under it, inheriting on directories.

    Returns ``(granted, skipped, failed)``: *skipped* are the reparse points (and hard-linked files)
    that were neither granted nor entered, *failed* the ``(path, reason)`` grants that raised. A
    no-op ``(0, [], [])`` off Windows or when not elevated."""
    if sys.platform != "win32" or not process_is_elevated():
        return 0, [], []
    root = Path(os.path.abspath(root))
    real_root = os.path.realpath(root)
    granted, skipped, failed = 0, [], []
    for path, is_dir in iter_tree_without_reparse_points(root, skipped):
        try:
            _grant(path, is_dir, os.path.join(real_root, *path.relative_to(root).parts))
        except ReparsePointRefused:
            skipped.append(path)
        except Exception as exc:  # health: allow BLE001 -- pywintypes.error is not an OSError; keep going like /C
            failed.append((path, str(exc) or type(exc).__name__))
        else:
            granted += 1
    if skipped:
        log.warning("Elevated ACL repair skipped %d junction/symlink/hard-link entr%s under %s (never "
                    "granted through): %s", len(skipped), "y" if len(skipped) == 1 else "ies", root,
                    ", ".join(str(p) for p in skipped[:5]) + (" ..." if len(skipped) > 5 else ""))
    return granted, skipped, failed


# Dirs this elevated process already granted: the grant reads and may rewrite a DACL, and the
# callers (log handlers, lock acquires) re-enter on hot paths.
_granted: set[Path] = set()


def make_user_dir(path: str | Path, mode: int = 0o777, *, parents: bool = False, exist_ok: bool = False) -> Path:
    """``Path.mkdir`` (same arguments and defaults) that keeps an elevated Windows creation usable
    by the same user unelevated.

    Off Windows or unelevated this is ``Path.mkdir`` and nothing else. Elevated, every directory
    this call created (missing parents included) and the leaf, even when it already existed (the
    repair case), get the user's inheriting full-control ACE once per process, except that a
    component that is a junction/symlink/reparse point stops the grants with one warning."""
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
    to_grant = list(reversed(created or [target]))
    # A junction/symlink planted at (or swapped in for) the leaf, a created component, or any
    # existing ancestor inside the home: grant nothing, one warning (nothing past it is in the home).
    for component in dict.fromkeys([*_components_below_home(target), *to_grant]):
        if is_reparse_point(component):
            _warn_refused(component, ReparsePointRefused("junction, symlink or other reparse point"))
            return target
    for directory in to_grant:
        if directory not in _granted and grant_user_access(directory):
            _granted.add(directory)
    return target


def unusable_dir_remedy(path: str | Path) -> str:
    """The one-line repair for a directory this process may not use (owner from an elevated run)."""
    if os.name == "nt":
        return f'from an elevated prompt run: icacls "{path}" /reset /t'
    return f'run: sudo chown -R "$(id -un)" "{path}"'
