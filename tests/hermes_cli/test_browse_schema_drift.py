"""A store that lags SCHEMA_SQL must stay browsable (#140315).

#106742 added four tables and three columns to SCHEMA_SQL under schema_version 31. A named
profile whose state.db had not been opened writable since the update lost its whole session
list on every read-only surface: the browse probe hit ``no such table`` and answered 503
"schema is unavailable or corrupt", and an idle profile never got the writable open that would
have caught it up. These tests build the real pre-merge shape from the pre-#106742 SCHEMA_SQL
(trimmed to what that release declared) and browse it through the real read-only path.
"""
from __future__ import annotations

import sqlite3
from contextlib import closing

import pytest
from fastapi import HTTPException

from hermes_cli.web_server_sessions import _open_session_db_at_path
from hermes_state import SessionDB
from hermes_state_common import SCHEMA_VERSION

_ADDED_TABLES = ("runtime_epoch", "session_admissions", "worker_executions", "worker_receipts")
_ADDED_COLUMNS = (("sessions", "runtime_revision"), ("sessions", "runtime_generation"),
                  ("async_delegations", "owner_execution_id"))


def _pre_merge_store(path, *, version=31):
    """The shape a store kept by the release before #106742 has: built by SessionDB, then the
    tables/columns #106742 added removed again, stamped with the version that release wrote."""
    with SessionDB(db_path=path) as db:
        db.create_session("kept", source="cli")
        db.append_message("kept", role="user", content="history survives")
    with closing(sqlite3.connect(path)) as conn:
        conn.execute("DROP TRIGGER IF EXISTS sessions_runtime_ledger_delete_guard")
        for table in reversed(_ADDED_TABLES):
            conn.execute(f"DROP TABLE {table}")
        conn.execute("DROP INDEX IF EXISTS idx_sessions_local_created_started")
        for table, column in _ADDED_COLUMNS:
            conn.execute(f"ALTER TABLE {table} DROP COLUMN {column}")
        conn.execute("UPDATE schema_version SET version = ?", (version,))
        conn.commit()
    return path


def _tables(path):
    with closing(sqlite3.connect(path)) as conn:
        return {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def _profile_home(tmp_path, name="scribe"):
    home = tmp_path / "profiles" / name
    home.mkdir(parents=True)
    (home / "config.yaml").write_text("{}\n", encoding="utf-8")
    return home


def test_unowned_lagging_store_browses_after_one_reconcile(tmp_path):
    path = _pre_merge_store(_profile_home(tmp_path) / "state.db")

    db = _open_session_db_at_path(path, read_only=True)
    try:
        assert [row["id"] for row in db.list_sessions_rich(limit=10, compact_rows=True)] == ["kept"]
        assert [m["content"] for m in db.get_messages("kept")] == ["history survives"]
    finally:
        db.close()
    assert set(_ADDED_TABLES) <= _tables(path)

    # Once: the second browse is a pure read-only open (no write, no new DDL).
    before = path.read_bytes()
    db = _open_session_db_at_path(path, read_only=True)
    db.close()
    assert path.read_bytes() == before


def test_owned_lagging_store_is_not_written_and_names_the_remedy(tmp_path):
    from gateway.runtime_ownership import ProfileOwnership

    home = _profile_home(tmp_path)
    path = _pre_merge_store(home / "state.db")
    before = path.read_bytes()
    owner = ProfileOwnership()  # what a running gateway holds on its profile
    owner.reserve([home])
    try:
        with pytest.raises(HTTPException) as caught:
            _open_session_db_at_path(path, read_only=True)
    finally:
        owner.close()
    assert caught.value.status_code == 503
    detail = str(caught.value.detail)
    assert "running gateway owns it" in detail
    assert "gateway restart" in detail
    assert "corrupt" not in detail
    assert path.read_bytes() == before
    assert not set(_ADDED_TABLES) & _tables(path)


def test_corrupt_store_still_returns_503(tmp_path):
    """Corruption is not drift: the open fails with the corrupt-store 503 and nothing is written."""
    path = tmp_path / "state.db"
    with SessionDB(db_path=path) as db:
        db.create_session("kept", source="cli")
    with closing(sqlite3.connect(path)) as conn:
        if conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal":
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        page_size = conn.execute("PRAGMA page_size").fetchone()[0]
    with open(path, "r+b") as fh:  # sqlite_master (page 1 b-tree) overwritten past the header
        fh.seek(100)
        fh.write(b"\xde\xad\xbe\xef" * ((page_size - 100) // 4))
    before = path.read_bytes()

    with pytest.raises(HTTPException) as caught:
        _open_session_db_at_path(path, read_only=True).close()
    assert caught.value.status_code == 503
    assert caught.value.detail["error"] == "state_db_corrupt"
    assert path.read_bytes() == before


def test_missing_history_table_is_refused_not_recreated(tmp_path):
    path = _pre_merge_store(tmp_path / "state.db")
    with closing(sqlite3.connect(path)) as conn:
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.execute("DROP TABLE messages")
        conn.commit()
    before = path.read_bytes()
    with pytest.raises(HTTPException) as caught:
        _open_session_db_at_path(path, read_only=True)
    assert caught.value.status_code == 503
    assert "sessions recover" in str(caught.value.detail)
    assert path.read_bytes() == before


def test_version_bump_migration_is_additive_and_idempotent(tmp_path):
    path = _pre_merge_store(tmp_path / "state.db")
    assert SCHEMA_VERSION > 31

    for _ in range(2):
        with SessionDB(db_path=path) as db:
            assert db._conn.execute("SELECT version FROM schema_version").fetchone()[0] == SCHEMA_VERSION
            assert db._conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0] == 1
    assert set(_ADDED_TABLES) <= _tables(path)
    with closing(sqlite3.connect(path)) as conn:
        for table, column in _ADDED_COLUMNS:
            assert column in {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}

    # A browse-reconciled store (still stamped 31) also upgrades cleanly on the owner's open.
    other = _pre_merge_store(tmp_path / "other.db")
    _open_session_db_at_path(other, read_only=True).close()
    with SessionDB(db_path=other) as db:
        assert db._conn.execute("SELECT version FROM schema_version").fetchone()[0] == SCHEMA_VERSION


def test_messages_route_for_lagging_profile(monkeypatch, tmp_path):
    """``GET /api/sessions/<id>/messages?profile=<name>`` was the 503 in the report."""
    try:
        from starlette.testclient import TestClient
    except ImportError:
        pytest.skip("fastapi/starlette not installed")
    from hermes_cli import profiles as profiles_mod
    from hermes_cli.web_server import _SESSION_HEADER_NAME, _SESSION_TOKEN, app

    home = _profile_home(tmp_path)
    _pre_merge_store(home / "state.db")
    monkeypatch.setattr(profiles_mod, "profile_exists", lambda name: name == "scribe")
    monkeypatch.setattr(profiles_mod, "get_profile_dir", lambda name: home)
    client = TestClient(app)
    client.headers[_SESSION_HEADER_NAME] = _SESSION_TOKEN

    response = client.get("/api/sessions/kept/messages?profile=scribe")
    assert response.status_code == 200, response.text
    assert [m["content"] for m in response.json()["messages"]] == ["history survives"]


# ── Desktop/dashboard HTTP surfaces on this process's own store (moved from test_web_server.py) ──


@pytest.fixture
def own_store_client(monkeypatch, _isolate_hermes_home):
    try:
        from starlette.testclient import TestClient
    except ImportError:
        pytest.skip("fastapi/starlette not installed")
    import hermes_state
    from hermes_cli.web_routers import profiles as profiles_routes
    from hermes_cli.web_server import _SESSION_HEADER_NAME, _SESSION_TOKEN, app
    from hermes_constants import get_hermes_home

    monkeypatch.setattr(profiles_routes, "_SIDEBAR_CACHE_TTL_SECONDS", 0.0)
    path = get_hermes_home() / "state.db"
    monkeypatch.setattr(hermes_state, "DEFAULT_DB_PATH", path)
    (get_hermes_home() / "config.yaml").write_text("{}\n", encoding="utf-8")
    with SessionDB(db_path=path) as db:
        db.create_session("stale-schema", source="cli")
        db.append_message("stale-schema", role="user", content="hi")
    client = TestClient(app)
    client.headers[_SESSION_HEADER_NAME] = _SESSION_TOKEN
    return client, path


def _drop_session_column(path, column):
    with closing(sqlite3.connect(path)) as conn:
        # SQLite refuses DROP COLUMN while an index references it; a pre-column store has neither.
        conn.execute("DROP INDEX IF EXISTS idx_sessions_effective_activity")
        conn.execute(f"ALTER TABLE sessions DROP COLUMN {column}")
        conn.commit()


def _session_columns(path):
    with closing(sqlite3.connect(path)) as conn:
        return {row[1] for row in conn.execute("PRAGMA table_info(sessions)")}


def _owned(home):
    from gateway.runtime_ownership import ProfileOwnership
    owner = ProfileOwnership()  # what a running gateway holds on its profile
    owner.reserve([home])
    return owner


@pytest.mark.parametrize("missing_column", ["archived", "pinned", "last_activity_at"])
def test_session_list_reconciles_once_only_when_unowned(own_store_client, missing_column):
    client, path = own_store_client
    _drop_session_column(path, missing_column)

    before = path.read_bytes()
    owner = _owned(path.parent)
    try:
        response = client.get("/api/sessions?limit=50&offset=0")
        sidebar = client.get("/api/profiles/sessions/sidebar").json()
    finally:
        owner.close()
    assert response.status_code == 503
    assert "gateway owns it" in response.json()["detail"]
    # A failed read is a retryable failed load naming the drift, never an empty list.
    assert "behind this Hermes version" in sidebar["errors"][0]["error"]
    assert "sessions" not in sidebar["recents"] and sidebar["recents"]["failed"] is True
    assert path.read_bytes() == before
    assert missing_column not in _session_columns(path)

    response = client.get("/api/sessions?limit=50&offset=0")
    assert response.status_code == 200
    assert [row["id"] for row in response.json()["sessions"]] == ["stale-schema"]
    assert missing_column in _session_columns(path)


def test_startup_eager_reconcile_heals_only_an_unowned_stale_store(own_store_client):
    """After `hermes update` an old-schema store must not fail every poll (#79531/#80037); the
    dashboard is never a second writer while a gateway owns it (#107688)."""
    from hermes_cli import web_server_lifecycle

    _client, path = own_store_client
    _drop_session_column(path, "last_read_at")
    owner = _owned(path.parent)
    try:
        web_server_lifecycle._eager_reconcile_own_session_db()
    finally:
        owner.close()
    assert "last_read_at" not in _session_columns(path)

    web_server_lifecycle._eager_reconcile_own_session_db()
    assert "last_read_at" in _session_columns(path)


# ── Independent review round 1 ──


def _lagging_store_with_history(home, rows=400):
    """A real store with enough history for a multi-page ``messages`` b-tree, one column dropped."""
    path = home / "state.db"
    with SessionDB(db_path=path) as db:
        db.create_session("kept", source="cli")
        for i in range(rows):
            db.append_message("kept", role="user", content=f"history {i} " * 40)
    with closing(sqlite3.connect(path)) as conn:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.execute("DROP INDEX IF EXISTS idx_sessions_effective_activity")
        conn.execute("ALTER TABLE sessions DROP COLUMN last_read_at")
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    return path


def _file_state(path):
    """Main file plus WAL content (an empty sidecar a reader creates is not a write)."""
    wal = path.with_name(path.name + "-wal")
    return path.read_bytes(), wal.read_bytes() if wal.exists() else b""


def test_corrupt_non_root_page_plus_drift_is_not_written(tmp_path):
    """P1-1: the drift probe fails before any damaged page is read, so only an integrity check
    under the lock keeps browse from running ALTER TABLE on a corrupt file."""
    path = _lagging_store_with_history(_profile_home(tmp_path))
    with closing(sqlite3.connect(path)) as conn:
        page_size = conn.execute("PRAGMA page_size").fetchone()[0]
        root = conn.execute("SELECT rootpage FROM sqlite_master WHERE name='messages'").fetchone()[0]
        pages = conn.execute("PRAGMA page_count").fetchone()[0]
    victim = max(root + 5, pages // 2)  # a messages leaf, never page 1 / sqlite_master
    with open(path, "r+b") as fh:
        fh.seek((victim - 1) * page_size + 8)
        fh.write(b"\xde\xad\xbe\xef" * ((page_size - 16) // 4))
    with closing(sqlite3.connect(f"file:{path}?mode=ro", uri=True)) as conn:
        assert conn.execute("PRAGMA quick_check").fetchone()[0] != "ok"
    before = _file_state(path)

    with pytest.raises(HTTPException) as caught:
        _open_session_db_at_path(path, read_only=True).close()
    assert caught.value.status_code == 503
    assert caught.value.detail["error"] == "state_db_corrupt"
    assert _file_state(path) == before
    assert "last_read_at" not in _session_columns(path)
