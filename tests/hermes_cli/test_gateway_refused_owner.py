"""#139845 / #140252: a same-user gateway that refuses the client is named, not ``authorization``.

#139845: an elevated gateway's pipe/process refuses the non-elevated Desktop (``OpenProcess`` err=5).
#140252: a session-0 S4U boot-task gateway won the control pipe; the interactive Desktop can never
reach it. Both surfaced as ``Gateway inaccessible (authorization)``, which reads as a credential
problem. The probe facts are injected here (no Windows host); ``test_refused_owner_windows.py``
runs the real probes on Windows CI.
"""
from pathlib import Path

import pytest

from gateway import runtime_bootstrap_windows as native
from hermes_cli import gateway_runtime as runtime
from hermes_cli.gateway_runtime_cli import ensure_exit_code


@pytest.mark.parametrize(("facts", "expected"), [
    # #140252: owner in session 0, Desktop in the interactive session 1.
    ({"own_session": 1, "owner_session": 0, "own_elevated": False, "owner_elevated": None}, "gateway_other_session"),
    ({"own_session": 1, "owner_session": 0, "own_elevated": True, "owner_elevated": True}, "gateway_other_session"),
    # #139845: same session, owner elevated (or its token unopenable from a filtered client).
    ({"own_session": 1, "owner_session": 1, "own_elevated": False, "owner_elevated": True}, "gateway_elevated"),
    ({"own_session": 1, "owner_session": 1, "own_elevated": False, "owner_elevated": None}, "gateway_elevated"),
    # Nothing to name: keep the generic code.
    ({"own_session": 1, "owner_session": 1, "own_elevated": False, "owner_elevated": False}, None),
    ({"own_session": 1, "owner_session": 1, "own_elevated": True, "owner_elevated": None}, None),
    ({"own_session": 1, "owner_session": None, "own_elevated": False, "owner_elevated": None}, None),
])
def test_classify_refused_owner(facts, expected):
    assert native.classify_refused_owner(**facts) == expected


def _refusing_owner(monkeypatch, tmp_path: Path, named):
    home = tmp_path / "home"
    home.mkdir()
    (home / "gateway.pid").write_text('{"pid": 23460}', encoding="utf-8")
    monkeypatch.setattr(runtime, "_NATIVE_WINDOWS", True, raising=False)
    seen = []
    monkeypatch.setattr(native, "probe_refused_owner", lambda pid: seen.append(pid) or named)
    return home, seen


def test_refusal_names_the_other_session_owner_with_its_remedy(monkeypatch, tmp_path):
    named = ("gateway_other_session", native.refused_owner_remedy("gateway_other_session", 23460, 0))
    home, seen = _refusing_owner(monkeypatch, tmp_path, named)
    result = runtime._refused(home)
    assert seen == [23460]
    assert (result.state, result.reason_code) == ("inaccessible", "gateway_other_session")
    assert result.detail and "PID 23460" in result.detail and "session 0" in result.detail
    assert ensure_exit_code(result) == 4


def test_refusal_names_the_elevated_owner_with_its_remedy(monkeypatch, tmp_path):
    named = ("gateway_elevated", native.refused_owner_remedy("gateway_elevated", 23460, 1))
    home, _ = _refusing_owner(monkeypatch, tmp_path, named)
    result = runtime._refused(home)
    assert result.reason_code == "gateway_elevated"
    assert result.detail and "administrator" in result.detail and "hermes gateway stop" in result.detail


def test_unnamed_or_unprobeable_refusal_keeps_authorization(monkeypatch, tmp_path):
    home, _ = _refusing_owner(monkeypatch, tmp_path, None)
    assert runtime._refused(home).reason_code == "authorization"
    monkeypatch.setattr(native, "probe_refused_owner", lambda pid: (_ for _ in ()).throw(OSError("x")))
    assert runtime._refused(home).reason_code == "authorization"
    (home / "gateway.pid").unlink()
    assert runtime._refused(home).reason_code == "authorization"


def test_discovery_maps_a_refused_pipe_through_the_named_state(monkeypatch, tmp_path):
    """The real discovery path: ``query_identify`` raising PermissionError is what Windows' pipe
    ``CreateFile`` err=5 / peer-identity refusal produces."""
    from hermes_cli import gateway_runtime_discovery as discovery
    named = ("gateway_elevated", native.refused_owner_remedy("gateway_elevated", 23460, 1))
    home, _ = _refusing_owner(monkeypatch, tmp_path, named)
    monkeypatch.setattr(discovery, "query_identify",
                        lambda *_a, **_k: (_ for _ in ()).throw(PermissionError("runtime control pipe inaccessible")))
    result = runtime.discover_gateway_endpoint(home, timeout=1)
    assert (result.state, result.reason_code) == ("inaccessible", "gateway_elevated")
