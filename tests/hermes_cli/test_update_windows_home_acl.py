"""Windows update ACL repair command contracts."""

from hermes_cli.update_cmd_maint import _windows_home_acl_grant_command


def test_windows_home_acl_grant_targets_the_current_user_sid_recursively(tmp_path):
    home = tmp_path / "hermes home"

    assert _windows_home_acl_grant_command(home, "S-1-5-21-100-200-300-400") == [
        "icacls",
        str(home),
        "/grant",
        "*S-1-5-21-100-200-300-400:(OI)(CI)F",
        "/T",
        "/C",
        "/Q",
    ]


def test_repair_runs_only_from_an_elevated_update(monkeypatch, tmp_path):
    """A non-elevated update created nothing Administrators-only and could not rewrite it anyway;
    the recursive icacls over the whole home is skipped there."""
    import subprocess
    import sys

    import hermes_dir_acl
    from hermes_cli import update_cmd_maint as maint

    calls = []
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setattr(maint, "_current_windows_user_sid", lambda: "S-1-5-21-1-2-3-1001")
    monkeypatch.setattr(subprocess, "run", lambda argv, **kw: calls.append((argv, kw)) or
                        subprocess.CompletedProcess(argv, 0, "", ""))
    monkeypatch.setattr(hermes_dir_acl, "process_is_elevated", lambda: False)
    maint._repair_windows_home_acl()
    assert calls == []
    monkeypatch.setattr(hermes_dir_acl, "process_is_elevated", lambda: True)
    maint._repair_windows_home_acl()
    assert calls and calls[0][0][0] == "icacls" and calls[0][1]["timeout"]
