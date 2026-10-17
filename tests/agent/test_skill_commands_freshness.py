"""CFG-8: a skill installed from another terminal reaches the long-lived gateway's slash map.

The one gateway owns every local session for its whole lifetime, so a process-lifetime memo of the
skill command map left ``hermes skills install`` (or a dropped SKILL.md) invisible to Ink's
``/command`` lookup and completion until ``/reload-skills`` or a gateway restart.
"""
from unittest.mock import patch


def _make_skill(skills_dir, name):
    skill_dir = skills_dir / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: Description for {name}.\n---\n\nDo the thing.\n", encoding="utf-8")
    return skill_dir


def test_skill_added_on_disk_after_the_first_scan_is_served_without_reload(tmp_path):
    import shutil

    import agent.skill_commands as sc_mod
    import tools.skills_tool as st
    from agent.skill_commands import get_skill_commands

    with patch("tools.skills_tool.SKILLS_DIR", tmp_path), patch.object(sc_mod, "_skill_commands_by_key", {}):
        st.clear_skills_cache()
        _make_skill(tmp_path, "first")
        assert set(get_skill_commands()) == {"/first"}

        _make_skill(tmp_path, "installed-elsewhere")  # another terminal: no reload_skills() here
        assert set(get_skill_commands()) == {"/first", "/installed-elsewhere"}

        shutil.rmtree(tmp_path / "first")  # an uninstall elsewhere drops its command too
        assert set(get_skill_commands()) == {"/installed-elsewhere"}


def test_unchanged_skills_dirs_reuse_the_published_map(tmp_path):
    import agent.skill_commands as sc_mod
    import tools.skills_tool as st
    from agent.skill_commands import get_skill_commands

    with patch("tools.skills_tool.SKILLS_DIR", tmp_path), patch.object(sc_mod, "_skill_commands_by_key", {}):
        st.clear_skills_cache()
        _make_skill(tmp_path, "steady")
        first = get_skill_commands()
        with patch.object(sc_mod, "scan_skill_commands", side_effect=AssertionError("rescanned")):
            assert get_skill_commands() is first
