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

    def boom(path, *_a, **_k):
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


# ── P2-5: an elevated grant never follows a junction/symlink out of the Hermes home ──────────────


@pytest.fixture()
def elevated_windows(tmp_path, monkeypatch):
    """Fake an elevated Windows process; record what the native grant would have touched."""
    home = tmp_path / "home"
    home.mkdir()
    outside = tmp_path / "Program Files" / "X"
    outside.mkdir(parents=True)
    (outside / "app.exe").write_text("x")
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(hermes_dir_acl.sys, "platform", "win32")
    monkeypatch.setattr(hermes_dir_acl, "process_is_elevated", lambda: True)
    monkeypatch.setattr(hermes_dir_acl, "_granted", set())
    touched = []
    monkeypatch.setattr(hermes_dir_acl, "_grant_with_pywin32",
                        lambda path, *_a, **_k: touched.append(os.path.realpath(path)))
    return home, outside, touched


def _escapes(touched, outside):
    return [p for p in touched if p == str(outside) or p.startswith(str(outside) + os.sep)]


def test_make_user_dir_refuses_an_existing_leaf_that_is_a_link(elevated_windows, caplog):
    home, outside, touched = elevated_windows
    (home / "cache").mkdir()
    planted = home / "cache" / "images"
    planted.symlink_to(outside, target_is_directory=True)
    with caplog.at_level("WARNING", logger="hermes_dir_acl"):
        hermes_dir_acl.make_user_dir(planted, parents=True, exist_ok=True)
        hermes_dir_acl.make_user_dir(planted, parents=True, exist_ok=True)
    assert touched == []
    assert [r for r in caplog.records if "never follows a junction" in r.getMessage()]


def test_make_user_dir_refuses_a_link_among_its_ancestors_in_the_home(elevated_windows):
    home, outside, touched = elevated_windows
    (home / "cache").symlink_to(outside, target_is_directory=True)
    made = hermes_dir_acl.make_user_dir(home / "cache" / "images" / "x", parents=True, exist_ok=True)
    assert made.is_dir()  # the mkdir itself still happens (it lands where the user's own link points)
    assert touched == [], "a grant went through a planted link"


def test_grant_user_access_refuses_a_link_directly(elevated_windows):
    home, outside, touched = elevated_windows
    link = home / "logs"
    link.symlink_to(outside, target_is_directory=True)
    assert hermes_dir_acl.grant_user_access(link) is False
    assert hermes_dir_acl.grant_user_access(link / "deeper") is False
    assert touched == []


def test_make_user_dir_still_grants_real_dirs_under_a_linked_home(tmp_path, monkeypatch):
    """HERMES_HOME itself is the user's own choice; only entries INSIDE it are swappable."""
    real = tmp_path / "real-home"
    real.mkdir()
    linked = tmp_path / "linked-home"
    linked.symlink_to(real, target_is_directory=True)
    monkeypatch.setenv("HERMES_HOME", str(linked))
    monkeypatch.setattr(hermes_dir_acl.sys, "platform", "win32")
    monkeypatch.setattr(hermes_dir_acl, "process_is_elevated", lambda: True)
    monkeypatch.setattr(hermes_dir_acl, "_granted", set())
    calls = []
    monkeypatch.setattr(hermes_dir_acl, "_grant_with_pywin32",
                        lambda path, is_dir, expected=None: calls.append((path, expected)))
    hermes_dir_acl.make_user_dir(linked / "state", exist_ok=True)
    assert calls == [(linked / "state", os.path.join(str(real), "state"))]


def test_tree_walk_skips_symlinks_and_never_enters_them(tmp_path):
    root = tmp_path / "home"
    (root / "a" / "b").mkdir(parents=True)
    (root / "a" / "f.txt").write_text("x")
    outside = tmp_path / "outside"
    (outside / "deep").mkdir(parents=True)
    (root / "a" / "jn").symlink_to(outside, target_is_directory=True)
    (root / "flink").symlink_to(outside / "deep")
    skipped = []
    seen = {p.relative_to(root).as_posix(): d for p, d in hermes_dir_acl.iter_tree_without_reparse_points(root, skipped)}
    assert seen == {".": True, "a": True, "a/b": True, "a/f.txt": False}
    assert sorted(p.name for p in skipped) == ["flink", "jn"]


def test_tree_walk_treats_a_reparse_attribute_as_a_link(tmp_path, monkeypatch):
    """A Windows directory junction is not S_ISLNK on every Python; the reparse attribute decides."""
    root = tmp_path / "home"
    (root / "junction").mkdir(parents=True)
    real_lstat = os.lstat

    class Junction:
        def __init__(self, st):
            self._st = st
            self.st_file_attributes = hermes_dir_acl.FILE_ATTRIBUTE_REPARSE_POINT | hermes_dir_acl.FILE_ATTRIBUTE_DIRECTORY

        def __getattr__(self, name):
            return getattr(self._st, name)

    monkeypatch.setattr(hermes_dir_acl.os, "lstat",
                        lambda p, *a, **k: Junction(real_lstat(p)) if str(p).endswith("junction") else real_lstat(p))
    skipped = []
    seen = [p for p, _ in hermes_dir_acl.iter_tree_without_reparse_points(root, skipped)]
    assert seen == [root] and skipped == [root / "junction"]


def test_tree_grant_never_touches_a_target_outside_the_home(elevated_windows):
    home, outside, touched = elevated_windows
    (home / "sessions").mkdir()
    (home / "sessions" / "s.json").write_text("{}")
    (home / "sessions" / "jn").symlink_to(outside, target_is_directory=True)
    (home / "hardlink.exe").hardlink_to(outside / "app.exe")
    granted, skipped, failed = hermes_dir_acl.grant_tree_user_access(home)
    assert _escapes(touched, outside) == [] and failed == []
    assert sorted(p.name for p in skipped) == ["hardlink.exe", "jn"]
    assert granted == 3  # home, sessions, s.json


def test_tree_grant_is_a_noop_unelevated(tmp_path, monkeypatch):
    monkeypatch.setattr(hermes_dir_acl.sys, "platform", "win32")
    monkeypatch.setattr(hermes_dir_acl, "process_is_elevated", lambda: False)
    assert hermes_dir_acl.grant_tree_user_access(tmp_path) == (0, [], [])
