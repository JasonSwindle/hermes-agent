"""Windows update ACL repair contracts (the Windows ACL effect: ``tests/test_hermes_dir_acl_windows.py``)."""

import os
import subprocess
import sys

import hermes_dir_acl
from hermes_cli import update_cmd_maint as maint


def _fake_elevated_windows(monkeypatch, tmp_path, elevated=True):
    granted, runs = [], []
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
    sid_row = '"host\\\\user","S-1-5-21-1-2-3-1001"\n'  # whoami /user /fo csv /nh

    def run(argv, **kw):
        runs.append(argv)
        return subprocess.CompletedProcess(argv, 0, sid_row if argv[0] == "whoami" else "", "")

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(hermes_dir_acl, "process_is_elevated", lambda: elevated)
    monkeypatch.setattr(hermes_dir_acl, "_grant_with_pywin32",
                        lambda path, *_a, **_k: granted.append(os.path.realpath(path)))
    return granted, runs


def test_repair_runs_only_from_an_elevated_update(monkeypatch, tmp_path):
    """A non-elevated update created nothing Administrators-only and could not rewrite it anyway;
    the recursive grant over the whole home is skipped there."""
    (tmp_path / "home").mkdir()
    granted, runs = _fake_elevated_windows(monkeypatch, tmp_path, elevated=False)
    maint._repair_windows_home_acl()
    assert granted == [] and runs == []
    monkeypatch.setattr(hermes_dir_acl, "process_is_elevated", lambda: True)
    maint._repair_windows_home_acl()
    assert granted == [str(tmp_path / "home")]


def test_repair_never_recurses_through_a_link_inside_the_home(monkeypatch, tmp_path):
    """P2-5: ``icacls HOME /grant ... /T`` follows junctions inside the home, so an elevated update
    granted the user full control of whatever a same-user junction pointed at."""
    home = tmp_path / "home"
    (home / "cache").mkdir(parents=True)
    outside = tmp_path / "Program Files" / "X"
    (outside / "bin").mkdir(parents=True)
    (home / "cache" / "images").symlink_to(outside, target_is_directory=True)
    granted, runs = _fake_elevated_windows(monkeypatch, tmp_path)
    maint._repair_windows_home_acl()
    assert not any(argv and argv[0] == "icacls" and "/T" in argv for argv in runs), runs
    assert granted == [str(home), str(home / "cache")]


def test_repair_stays_owed_when_nothing_could_be_granted(monkeypatch, tmp_path):
    import pytest

    (tmp_path / "home").mkdir()
    _fake_elevated_windows(monkeypatch, tmp_path)

    def denied(path, *_a, **_k):
        raise OSError("access denied")

    monkeypatch.setattr(hermes_dir_acl, "_grant_with_pywin32", denied)
    with pytest.raises(RuntimeError, match="could not restore user access"):
        maint._repair_windows_home_acl()
