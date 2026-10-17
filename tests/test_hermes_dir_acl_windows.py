"""#139845 / #134889 W8 + W2 on real Windows ACLs.

The reporters' dirs were created by an elevated process: a DACL of SYSTEM + Administrators only, no
entry for the user. Their own non-elevated token holds Administrators as deny-only, so it gets
``WinError 5`` inside. Each probe runs in a child that builds that filtered token itself
(``CreateRestrictedToken``: Administrators deny-only, every privilege but SeChangeNotify removed, so
no SeBackup/SeRestore bypass), impersonates it, and then touches the dir the way production does.

The parent needs an elevated token (the hosted runner has one) to stand in for the elevated
install; ``make_user_dir`` only grants when the creating process is elevated.
"""
import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

pytestmark = pytest.mark.platforms("windows")

_REPO = Path(__file__).resolve().parent.parent

_FILTERED_TOKEN = textwrap.dedent(r"""
    import ctypes, ctypes.wintypes as w, json, os, sys
    from pathlib import Path

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)

    class SID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", w.DWORD)]

    kernel.GetCurrentProcess.restype = w.HANDLE
    advapi.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)]
    advapi.ConvertStringSidToSidW.argtypes = [w.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
    advapi.CreateRestrictedToken.argtypes = [w.HANDLE, w.DWORD, w.DWORD, ctypes.POINTER(SID_AND_ATTRIBUTES),
                                             w.DWORD, ctypes.c_void_p, w.DWORD, ctypes.c_void_p,
                                             ctypes.POINTER(w.HANDLE)]
    advapi.ImpersonateLoggedOnUser.argtypes = [w.HANDLE]
    token = w.HANDLE()
    # TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_IMPERSONATE
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0002 | 0x0008 | 0x0001 | 0x0004,
                                   ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    admins = ctypes.c_void_p()
    if not advapi.ConvertStringSidToSidW("S-1-5-32-544", ctypes.byref(admins)):
        raise ctypes.WinError(ctypes.get_last_error())
    disable = (SID_AND_ATTRIBUTES * 1)(SID_AND_ATTRIBUTES(admins, 0))
    filtered = w.HANDLE()
    # DISABLE_MAX_PRIVILEGE: what a UAC-filtered token keeps, i.e. no backup/restore bypass.
    if not advapi.CreateRestrictedToken(token, 0x1, 1, disable, 0, None, 0, None, ctypes.byref(filtered)):
        raise ctypes.WinError(ctypes.get_last_error())
    if not advapi.ImpersonateLoggedOnUser(filtered):
        raise ctypes.WinError(ctypes.get_last_error())

    def usable(directory):
        try:
            fd = os.open(Path(directory) / "probe.lock", os.O_CREAT | os.O_WRONLY, 0o600)
        except PermissionError:
            return False
        os.close(fd)
        return True
""")

_DROP_PRIVILEGES = textwrap.dedent(r"""
    import ctypes, ctypes.wintypes as w, json, os, sys
    from pathlib import Path

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", w.DWORD), ("HighPart", w.LONG)]

    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Luid", LUID), ("Attributes", w.DWORD)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [("PrivilegeCount", w.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

    kernel.GetCurrentProcess.restype = w.HANDLE
    advapi.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)]
    advapi.LookupPrivilegeValueW.argtypes = [w.LPCWSTR, w.LPCWSTR, ctypes.POINTER(LUID)]
    advapi.AdjustTokenPrivileges.argtypes = [w.HANDLE, w.BOOL, ctypes.POINTER(TOKEN_PRIVILEGES),
                                             w.DWORD, ctypes.c_void_p, ctypes.c_void_p]
    token = w.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0020 | 0x0008, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    for name in ("SeBackupPrivilege", "SeRestorePrivilege"):
        luid = LUID()
        if not advapi.LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
            raise ctypes.WinError(ctypes.get_last_error())
        tp = TOKEN_PRIVILEGES(1, (LUID_AND_ATTRIBUTES * 1)(LUID_AND_ATTRIBUTES(luid, 0x00000004)))
        if not advapi.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None):
            raise ctypes.WinError(ctypes.get_last_error())
""")

_REPORTERS_DACL = ["/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"]


def _elevated() -> bool:
    sys.path.insert(0, str(_REPO))
    from hermes_dir_acl import process_is_elevated
    return process_is_elevated()


def _child(code: str, *args: str, prelude: str = _FILTERED_TOKEN) -> dict:
    child = subprocess.run([sys.executable, "-c", prelude + textwrap.dedent(code), *args], cwd=_REPO,
                           capture_output=True, text=True, check=False, timeout=180)
    assert child.returncode == 0, child.stderr
    return json.loads(child.stdout.strip().splitlines()[-1])


@pytest.fixture()
def reporters_parent(tmp_path):
    if not _elevated():
        pytest.skip("needs an elevated token to stand in for the elevated install")
    parent = tmp_path / "hermes"
    parent.mkdir()
    subprocess.run(["icacls", str(parent), *_REPORTERS_DACL], check=True, capture_output=True)
    yield parent
    subprocess.run(["icacls", str(parent), "/reset", "/t", "/c", "/q"], check=False, capture_output=True)


def test_dir_made_while_elevated_stays_usable_by_the_filtered_token(reporters_parent):
    from hermes_dir_acl import make_user_dir

    plain = reporters_parent / "plain"
    plain.mkdir()  # inherits the reporters' SYSTEM + Administrators DACL
    granted = make_user_dir(reporters_parent / "gateway-locks", 0o700)
    result = _child("""
        print(json.dumps({"plain": usable(sys.argv[1]), "granted": usable(sys.argv[2])}))
    """, str(plain), str(granted))
    assert result["plain"] is False, "the filtered token could use the reporters' DACL: the probe is not faithful"
    assert result["granted"] is True


def test_elevated_rerun_repairs_a_dir_an_earlier_elevated_run_left(reporters_parent):
    from hermes_dir_acl import make_user_dir

    left = reporters_parent / "state"
    left.mkdir()
    before = _child("print(json.dumps({'usable': usable(sys.argv[1])}))", str(left))
    make_user_dir(left)
    make_user_dir(left)  # idempotent: no second ACE
    after = _child("print(json.dumps({'usable': usable(sys.argv[1])}))", str(left))
    acl = subprocess.run(["icacls", str(left)], capture_output=True, text=True, check=True).stdout
    assert before["usable"] is False and after["usable"] is True, acl


def test_token_lock_on_an_unusable_lock_dir_parks_with_one_named_warning(tmp_path):
    """W2: the gateway meets a ``gateway-locks`` it may not create in.

    Same shape as ``tests/tools/test_bot_live_delivery_windows_acl.py`` (proven on the hosted
    runner): an Everyone DENY ACE that no identity escapes, and a child with SeBackup/SeRestore
    removed so ``os.open`` has no bypass. Needs no elevation."""
    lock_dir = tmp_path / "gateway-locks"
    lock_dir.mkdir()
    subprocess.run(["icacls", str(lock_dir), "/deny", "*S-1-1-0:(F)"], check=True, capture_output=True)
    try:
        _w2(lock_dir)
    finally:
        subprocess.run(["icacls", str(lock_dir), "/remove:d", "*S-1-1-0"], check=False, capture_output=True)


def _w2(lock_dir):
    result = _child(r"""
        import logging
        from unittest.mock import MagicMock
        os.environ["HERMES_GATEWAY_LOCK_DIR"] = sys.argv[1]
        records = []
        handler = logging.Handler()
        handler.emit = lambda record: records.append((record.levelname, record.getMessage()))
        logging.getLogger().addHandler(handler)
        logging.getLogger().setLevel(logging.DEBUG)
        from gateway.platforms.base import BasePlatformAdapter

        class Stub(BasePlatformAdapter):
            platform = MagicMock(value="telegram")
            async def connect(self, *, is_reconnect=False): return True
            async def disconnect(self): pass
            async def send(self, *a, **k): pass
            async def get_chat_info(self, chat_id): return {}

        codes = []
        for _ in range(3):  # the reconnect watcher re-enters; one WARNING, never a raise
            a = Stub.__new__(Stub)
            a._running, a._fatal_error_handler, a._status_write_logged = True, None, None
            a._fatal_error_code = a._fatal_error_message = None
            a._fatal_error_retryable = True
            a._platform_lock_scope = a._platform_lock_identity = None
            a._platform_lock_takeover_allowed = a._platform_lock_takeover_attempted = False
            a._write_runtime_status_safe = lambda *x, **k: None
            ok = a._acquire_platform_lock("telegram-bot-token", "tok", "Telegram bot token")
            codes.append([ok, a._fatal_error_code, a._fatal_error_retryable, a._fatal_error_message])
        print(json.dumps({"codes": codes, "warnings": [m for lvl, m in records
                                                      if lvl == "WARNING" and "not usable" in m]}))
    """, str(lock_dir), prelude=_DROP_PRIVILEGES)
    for ok, code, retryable, message in result["codes"]:
        assert (ok, code, retryable) == (False, "lock_dir_unusable", False)
        assert "icacls" in message and "/reset" in message and str(lock_dir) in message
    assert len(result["warnings"]) == 1, result
