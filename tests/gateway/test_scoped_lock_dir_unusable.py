"""#134889 W2: a token-lock dir this user may not write gives one named warning, never a crash loop.

The Windows reports were ``Permission denied`` on ``gateway-locks\\telegram-bot-token-*.lock``; the
leading cause is a ``gateway-locks`` dir created by an elevated install. The POSIX analogue used
here is real, not patched: a lock dir without write permission for this uid. The Windows ACL shape
itself is proved by ``test_scoped_lock_dir_windows_acl.py`` on Windows CI.
"""
import logging
import os
import stat
from typing import Any
from unittest.mock import MagicMock

import pytest

from gateway import status
from gateway.platforms.base import BasePlatformAdapter
from gateway.restart import is_global_startup_conflict

pytestmark = pytest.mark.skipif(os.name == "nt" or os.geteuid() == 0,  # windows-footgun: ok — skipped on nt
                                reason="POSIX mode bits; root ignores them")


class _StubAdapter(BasePlatformAdapter):
    platform = MagicMock(value="telegram")

    async def connect(self, *, is_reconnect: bool = False) -> bool:
        return True

    async def disconnect(self) -> None:
        pass

    async def send(self, *args: Any, **kwargs: Any) -> None:
        pass

    async def get_chat_info(self, chat_id: str) -> dict[str, Any]:
        return {}


def _adapter():
    obj = _StubAdapter.__new__(_StubAdapter)
    obj._running = True
    obj._fatal_error_code = obj._fatal_error_message = obj._fatal_error_handler = None
    obj._fatal_error_retryable = True
    obj._platform_lock_scope = obj._platform_lock_identity = None
    obj._platform_lock_takeover_allowed = obj._platform_lock_takeover_attempted = False
    obj._status_write_logged = None
    obj._write_runtime_status_safe = lambda *a, **k: None
    return obj


@pytest.fixture()
def locked_out_dir(tmp_path, monkeypatch):
    lock_dir = tmp_path / "gateway-locks"
    lock_dir.mkdir()
    lock_dir.chmod(stat.S_IRUSR | stat.S_IXUSR)  # r-x: lists, cannot create the token lock
    monkeypatch.setenv("HERMES_GATEWAY_LOCK_DIR", str(lock_dir))
    getattr(status, "_warned_unusable_lock_dirs", set()).clear()
    yield lock_dir
    lock_dir.chmod(stat.S_IRWXU)


def test_unusable_lock_dir_parks_the_adapter_with_the_repair(locked_out_dir, caplog):
    adapter = _adapter()
    with caplog.at_level(logging.DEBUG, logger="gateway.status"):
        # On main this raised PermissionError out of connect() and the adapter retried forever.
        assert adapter._acquire_platform_lock("telegram-bot-token", "tok", "Telegram bot token") is False
        assert _adapter()._acquire_platform_lock("telegram-bot-token", "tok", "Telegram bot token") is False

    assert adapter._fatal_error_code == "lock_dir_unusable"
    assert adapter._fatal_error_retryable is False
    assert not is_global_startup_conflict(adapter._fatal_error_code)
    assert str(locked_out_dir) in adapter._fatal_error_message
    assert "chown" in adapter._fatal_error_message
    assert adapter._platform_lock_identity is None  # nothing to release
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING and "not usable" in r.getMessage()]
    assert len(warnings) == 1, [r.getMessage() for r in caplog.records]
    assert str(locked_out_dir) in warnings[0].getMessage()


def test_lock_dir_repair_is_picked_up_without_restart(locked_out_dir):
    with pytest.raises(status.ScopedLockDirUnusable):
        status.acquire_scoped_lock("telegram-bot-token", "tok")
    locked_out_dir.chmod(stat.S_IRWXU)
    assert status.acquire_scoped_lock("telegram-bot-token", "tok") == (True, None)
    assert locked_out_dir not in status._warned_unusable_lock_dirs
    status.release_scoped_lock("telegram-bot-token", "tok")


def test_unreadable_stale_token_lock_is_named_not_reported_as_a_holderless_conflict(tmp_path, monkeypatch):
    lock_dir = tmp_path / "gateway-locks"
    lock_dir.mkdir()
    monkeypatch.setenv("HERMES_GATEWAY_LOCK_DIR", str(lock_dir))
    stale = status._get_scope_lock_path("telegram-bot-token", "tok")
    stale.write_text('{"pid": 1}', encoding="utf-8")
    stale.chmod(0)
    lock_dir.chmod(stat.S_IRUSR | stat.S_IXUSR)  # the stale file cannot be read or unlinked either
    try:
        with pytest.raises(status.ScopedLockDirUnusable):
            status.acquire_scoped_lock("telegram-bot-token", "tok")
    finally:
        lock_dir.chmod(stat.S_IRWXU)
        stale.chmod(stat.S_IRUSR | stat.S_IWUSR)
