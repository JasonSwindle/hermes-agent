"""Additive state.db schema drift: detection, the one-shot browse reconcile, and explicit repair.

Drift (a declared table/column missing) is not corruption. Browsing catches an unowned store up
once, additive DDL only (:func:`reconcile_drift_for_browse`); ``hermes sessions repair`` reconciles
a protected snapshot so failed DDL never leaves the store partly upgraded or escalates into FTS
surgery (:func:`repair_declarative_schema`). Neither runs while a gateway owns the store.
"""
import contextlib
import logging
import sqlite3
from contextlib import closing
from pathlib import Path


def schema_drift_reason(path: Path):
    """Return a missing declared table/column, not a corruption diagnosis."""
    from hermes_state_schema import schema_read_probe_statements
    from hermes_cli.sqlite_safe_read import connect_tracked

    with closing(connect_tracked(path.resolve().as_uri() + '?mode=ro', uri=True, tracking_path=path)) as conn:
        try:
            for statement in schema_read_probe_statements():
                conn.execute(statement).fetchone()
        except sqlite3.OperationalError as exc:
            from hermes_state_repair import _schema_not_built
            if _schema_not_built(exc):
                return str(exc)
            raise
    return None


def _reconcile_snapshot(path, guard):
    from hermes_state_repair import (
        _copy_database_snapshot, _db_opens_cleanly, _repair_conn,
        _repair_scratch_space_error, _unlink_db_triple,
    )
    from hermes_state_schema import SessionSchemaMixin, reconcile_state_schema

    scratch = path.with_name(path.name + '.reconcile-scratch')
    if error := _repair_scratch_space_error(path):
        raise RuntimeError(error)
    if error := _unlink_db_triple(scratch):
        raise RuntimeError(error)
    try:
        _copy_database_snapshot(path, scratch, source_connection=guard)
        with _repair_conn(scratch) as conn:
            _require_history_tables(conn)
            # Old indexed columns must exist before the canonical DDL can create
            # their indexes. Reuse the column owner; the final probe fails closed
            # if an additive change is not possible. Missing tables are created below.
            object.__new__(SessionSchemaMixin)._reconcile_columns(conn.cursor())
            reconcile_state_schema(conn)
            conn.commit()
        if reason := schema_drift_reason(scratch):
            raise RuntimeError(f'schema reconciliation incomplete: {reason}')
        if reason := _db_opens_cleanly(scratch):
            raise RuntimeError(f'reconciled snapshot is unhealthy: {reason}')
        _copy_database_snapshot(scratch, path, destination_connection=guard)
    finally:
        if error := _unlink_db_triple(scratch):
            import logging
            logging.getLogger(__name__).warning('Could not remove reconciliation snapshot: %s', error)


def _require_history_tables(conn):
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if {'sessions', 'messages'} - tables:
        raise RuntimeError('canonical history tables are missing; use sessions recover, not additive reconciliation')


def _reconcile_locked(path, backup, report):
    from hermes_state_repair import (
        _backup_db_file, _db_opens_cleanly, _exclusive_repair_db_guard,
        _live_writer_holds_db,
    )

    if _live_writer_holds_db(path):
        raise RuntimeError('a live writer still holds state.db; stop it and retry')
    from hermes_cli.sqlite_safe_read import connect_tracked
    with closing(connect_tracked(path.resolve().as_uri() + '?mode=ro', uri=True, tracking_path=path)) as conn:
        _require_history_tables(conn)
    if schema_drift_reason(path) is None:
        report.update(repaired=True, strategy='already_healthy')
        return
    # Additive repair is not a substitute for corruption recovery.
    if reason := _db_opens_cleanly(path):
        raise RuntimeError(reason)
    if backup:
        bpath, error = _backup_db_file(path)
        if bpath is None:
            raise RuntimeError(f'pre-repair backup refused: {error}')
        report['backup_path'] = str(bpath)
    with _exclusive_repair_db_guard(path) as (guard, error):
        if guard is None:
            raise RuntimeError(f'could not acquire exclusive state.db repair ownership: {error}')
        _reconcile_snapshot(path, guard)
        report.update(repaired=True, strategy='reconcile_declarative_schema')


# Browse-time reconcile (#140315). A store whose tables/columns lag SCHEMA_SQL is not corrupt:
# a writable open would catch it up, but an idle profile with no gateway never gets one, so every
# read-only surface (sidebar, /api/sessions/<id>/messages?profile=) lost its whole history.
# Catch it up ONCE, additive DDL only, in one short transaction, and only while holding that
# profile's gateway runtime lock. When a gateway owns the store it is the only writer: refuse
# by name with the remedy instead of becoming a second one.
_BROWSE_RECONCILE_BUSY_S = 2.0


class DeclarativeDriftError(RuntimeError):
    """The store lags SCHEMA_SQL (missing table/column) and browsing could not catch it up."""

    def __init__(self, detail: str, *, owned: bool = False):
        super().__init__(detail)
        self.owned = owned


def is_declarative_drift_error(exc: BaseException) -> bool:
    """``no such table/column`` from a schema read probe: drift, never corruption."""
    from hermes_state_repair import _schema_not_built
    return isinstance(exc, sqlite3.OperationalError) and _schema_not_built(exc)


def _owner_remedy(home: Path) -> tuple[str, str]:
    from gateway.status import _profile_label_for_home  # never raises: None when unknown
    label = _profile_label_for_home(home)
    if label and label != 'default':
        return label, f'hermes -p {label} gateway restart'
    return label or str(home), 'hermes gateway restart'


def _apply_additive_schema(path: Path) -> None:
    """Missing SCHEMA_SQL tables and columns, in ONE ``BEGIN IMMEDIATE`` transaction.

    No data migration, no FTS work, no schema_version stamp (that stays the owner's: the
    version gates data migrations this path does not run). Every statement is additive and
    idempotent, so a failure rolls the store back to exactly what it was."""
    from hermes_cli.sqlite_safe_read import connect_tracked
    from hermes_state_common import SCHEMA_SQL
    from hermes_state_repair import _reapply_durability_barriers
    from hermes_state_schema import SessionSchemaMixin

    with closing(connect_tracked(path, tracking_path=path, timeout=_BROWSE_RECONCILE_BUSY_S,
                                 isolation_level=None)) as conn:
        _reapply_durability_barriers(conn)
        conn.execute('BEGIN IMMEDIATE')
        try:
            cursor = conn.cursor()
            shim = object.__new__(SessionSchemaMixin)
            # Columns first: SCHEMA_SQL indexes may name columns an old table lacks.
            shim._reconcile_columns(cursor)
            SessionSchemaMixin._execute_ddl_script_transactional(cursor, SCHEMA_SQL)
            shim._reconcile_columns(cursor)  # tables the script just created are complete; no-op
            conn.execute('COMMIT')
        except BaseException:
            with contextlib.suppress(sqlite3.Error):
                conn.execute('ROLLBACK')
            raise


class CorruptStoreError(sqlite3.DatabaseError):
    """The lagging store is also damaged: browsing must not write DDL into it. Worded like sqlite's
    own malformed-image error so every caller maps it to the corrupt-store status (``hermes doctor``)."""

    def __init__(self, detail: str):
        super().__init__(f'database disk image is malformed (quick_check: {detail})')


def _quick_check_problem(path: Path):
    """``PRAGMA quick_check`` on a read-only connection: None when ``ok``, else the first problems."""
    from hermes_cli.sqlite_safe_read import connect_tracked
    try:
        with closing(connect_tracked(path.resolve().as_uri() + '?mode=ro', uri=True, tracking_path=path)) as conn:
            rows = conn.execute('PRAGMA quick_check').fetchall()
    except sqlite3.DatabaseError as exc:
        from hermes_state_errors import is_malformed_db_error
        if is_malformed_db_error(exc):
            return str(exc)
        raise
    problems = [str(r[0]) for r in rows if r and str(r[0]).lower() != 'ok']
    return '; '.join(problems[:3]) or None


def reconcile_drift_for_browse(path: Path) -> bool:
    """Catch a lagging store up for a read-only browse; True when DDL ran, False when already current.

    Raises :class:`DeclarativeDriftError` (``owned=True`` when a running gateway owns the store)
    with a user-facing detail naming the drift and the remedy, and :class:`CorruptStoreError`
    when the lagging store is also damaged. Never touches a store missing its history tables:
    recreating them empty would hide lost sessions."""
    from gateway.runtime_ownership import OwnershipConflict, exclusive_maintenance

    reason = schema_drift_reason(path)
    if reason is None:
        return False
    from hermes_cli.sqlite_safe_read import connect_tracked
    with closing(connect_tracked(path.resolve().as_uri() + '?mode=ro', uri=True, tracking_path=path)) as conn:
        try:
            _require_history_tables(conn)
        except RuntimeError as exc:
            raise DeclarativeDriftError(
                f'Session store is missing its history tables ({reason}); this is not upgrade drift. '
                'Run `hermes sessions recover`.') from exc
    label, remedy = _owner_remedy(path.parent)
    try:
        with exclusive_maintenance([path.parent]):
            # Re-check under the lock: a gateway that started and released between probes
            # (or a sibling browse) may already have caught the store up.
            if schema_drift_reason(path) is None:
                return False
            # A failing column probe hides damage elsewhere in the file: additive DDL is not
            # corruption recovery, so never write into a store that is not clean.
            if problem := _quick_check_problem(path):
                raise CorruptStoreError(problem)
            _apply_additive_schema(path)
    except OwnershipConflict as exc:
        raise DeclarativeDriftError(
            f"Session store for profile '{label}' is behind this Hermes version ({reason}), and a "
            f'running gateway owns it, so browsing will not write to it. Restart that gateway '
            f'(`{remedy}`) to bring the store up to date.', owned=True) from exc
    if after := schema_drift_reason(path):
        raise DeclarativeDriftError(
            f"Session store for profile '{label}' is behind this Hermes version and could not be "
            f'caught up ({after}). Run `hermes sessions repair` for that profile.')
    logging.getLogger(__name__).warning(
        'state.db at %s lagged SCHEMA_SQL (%s); added the missing tables/columns for browsing', path, reason)
    return True


def repair_declarative_schema(path: Path, *, backup: bool = True):
    """Reuse repair's snapshot/SQLite exclusion beneath the runtime owner lock."""
    from gateway.runtime_ownership import OwnershipConflict, exclusive_maintenance
    from hermes_state_repair import _cross_process_repair_lock

    report = {'repaired': False, 'strategy': None, 'backup_path': None, 'error': None}
    try:
        with exclusive_maintenance([path.parent]):
            with _cross_process_repair_lock(path) as holding:
                if not holding:
                    raise RuntimeError('could not obtain the state.db repair lock')
                _reconcile_locked(path, backup, report)
    except (OwnershipConflict, OSError, sqlite3.Error, RuntimeError, TimeoutError) as exc:
        report['error'] = str(exc)
    return report
