"""``make_user_dir`` contract off Windows and its grant selection (the Windows ACL effect itself is
proved by ``test_hermes_dir_acl_windows.py`` on Windows CI)."""
import os

import pytest

import hermes_dir_acl


def test_off_windows_it_is_plain_mkdir(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(hermes_dir_acl, "grant_user_access", lambda p: calls.append(p))
    target = hermes_dir_acl.make_user_dir(tmp_path / "a" / "b", 0o700, parents=True)
    assert target.is_dir() and calls == []
    if os.name != "nt":
        assert (target.stat().st_mode & 0o777) == 0o700
    with pytest.raises(FileExistsError):
        hermes_dir_acl.make_user_dir(target)
    with pytest.raises(FileNotFoundError):
        hermes_dir_acl.make_user_dir(tmp_path / "x" / "y")


def test_elevated_grants_every_created_dir_and_an_existing_leaf_once(tmp_path, monkeypatch):
    granted = []
    monkeypatch.setattr(hermes_dir_acl.sys, "platform", "win32")
    monkeypatch.setattr(hermes_dir_acl, "process_is_elevated", lambda: True)
    monkeypatch.setattr(hermes_dir_acl, "grant_user_access", lambda p: granted.append(p) or True)
    monkeypatch.setattr(hermes_dir_acl, "_granted", set())

    leaf = hermes_dir_acl.make_user_dir(tmp_path / "state" / "gateway-locks", parents=True, exist_ok=True)
    assert granted == [tmp_path / "state", leaf]  # parents first, so the leaf inherits from a granted parent
    hermes_dir_acl.make_user_dir(leaf, exist_ok=True)
    assert granted == [tmp_path / "state", leaf]  # memoized per process

    existing = tmp_path / "left-by-an-earlier-elevated-run"
    existing.mkdir()
    hermes_dir_acl.make_user_dir(existing, exist_ok=True)
    assert granted[-1] == existing  # the repair case: re-grant an existing leaf


def test_a_failed_grant_never_fails_the_mkdir_and_is_retried(tmp_path, monkeypatch):
    monkeypatch.setattr(hermes_dir_acl.sys, "platform", "win32")
    monkeypatch.setattr(hermes_dir_acl, "process_is_elevated", lambda: True)
    monkeypatch.setattr(hermes_dir_acl, "_granted", set())
    attempts = []

    def boom(path):
        attempts.append(path)
        raise OSError("access denied")

    monkeypatch.setattr(hermes_dir_acl, "_grant_with_pywin32", boom)
    target = hermes_dir_acl.make_user_dir(tmp_path / "d", exist_ok=True)
    hermes_dir_acl.make_user_dir(target, exist_ok=True)
    assert target.is_dir() and attempts == [target, target]


def test_remedy_names_the_platform_repair(monkeypatch):
    monkeypatch.setattr(hermes_dir_acl.os, "name", "nt")
    assert hermes_dir_acl.unusable_dir_remedy("C:\\x") == 'from an elevated prompt run: icacls "C:\\x" /reset /t'
    monkeypatch.setattr(hermes_dir_acl.os, "name", "posix")
    assert "chown" in hermes_dir_acl.unusable_dir_remedy("/x")
