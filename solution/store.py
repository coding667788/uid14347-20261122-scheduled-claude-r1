"""Durable SQLite event store.

Design notes
------------
* Every CLI invocation opens the database, runs one ``BEGIN IMMEDIATE``
  transaction, applies the whole batch or nothing, and commits.
* ``journal_mode=WAL`` plus ``synchronous=FULL`` makes a commit durable before
  the process can emit its JSON, so a process that dies after commit but before
  writing stdout is replayed as the *same* result on retry.
* Events are keyed by ``(scope, event_id)`` together with a canonical payload
  digest.  Repeating identical content returns the stored result; reusing the
  identifier with different content is a conflict and rejects the batch.
* History is reconstructed by folding committed events.  State is never
  patched in place, which is what lets ``explain`` show any past commit and
  what stops a later revocation from rewriting an issued receipt.
"""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Iterator

from .canonical import canonical_json, digest
from .errors import CaseError, E_DB

BUSY_TIMEOUT_MS = 30_000
_BEGIN_RETRIES = 8
_COMMIT_RETRIES = 8

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policies (
    version         INTEGER PRIMARY KEY,
    fingerprint     TEXT NOT NULL,
    policy_json     TEXT NOT NULL,
    batch_no        INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS batches (
    batch_no        INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_key       TEXT NOT NULL UNIQUE,
    payload_digest  TEXT NOT NULL,
    request_digest  TEXT NOT NULL,
    committed_at    TEXT NOT NULL,
    result_json     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_no        INTEGER NOT NULL,
    scope           TEXT NOT NULL,
    event_id        TEXT NOT NULL,
    event_type      TEXT NOT NULL,
    payload_digest  TEXT NOT NULL,
    payload_json    TEXT NOT NULL,
    result_json     TEXT NOT NULL,
    UNIQUE (scope, event_id)
);

CREATE INDEX IF NOT EXISTS events_by_batch ON events(batch_no);
CREATE INDEX IF NOT EXISTS events_by_scope ON events(scope, seq);

CREATE TABLE IF NOT EXISTS receipts (
    receipt_id      TEXT PRIMARY KEY,
    request_id      TEXT NOT NULL,
    subject_id      TEXT NOT NULL,
    resource        TEXT NOT NULL,
    operation       TEXT NOT NULL,
    op_version      INTEGER NOT NULL,
    risk            TEXT NOT NULL,
    generation      TEXT NOT NULL,
    challenge_id    TEXT NOT NULL,
    policy_version  INTEGER NOT NULL,
    receipt_number  INTEGER NOT NULL,
    proof_ids_json  TEXT NOT NULL,
    payload_json    TEXT NOT NULL,
    batch_no        INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS receipts_by_request ON receipts(request_id, receipt_number);
"""


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@dataclass
class StoredEvent:
    seq: int
    batch_no: int
    scope: str
    event_id: str
    event_type: str
    payload_digest: str
    payload_json: str
    result_json: str


class EventStore:
    """Thin, explicit wrapper around one SQLite connection."""

    def __init__(self, path: str, *, writable: bool = True):
        self.path = path
        self.writable = writable
        self.conn: sqlite3.Connection | None = None

    # -- lifecycle ---------------------------------------------------------
    def __enter__(self) -> "EventStore":
        self.open()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def open(self) -> None:
        if self.path != ":memory:":
            directory = os.path.dirname(os.path.abspath(self.path))
            if directory and not os.path.isdir(directory):
                raise CaseError(E_DB, "db", f"directory does not exist: {directory}")
        try:
            self.conn = sqlite3.connect(
                self.path,
                timeout=BUSY_TIMEOUT_MS / 1000.0,
                isolation_level=None,  # transactions are explicit
            )
        except sqlite3.Error as exc:  # pragma: no cover - environment failure
            raise CaseError(E_DB, "db", f"cannot open database: {exc}") from exc
        self.conn.row_factory = sqlite3.Row
        try:
            self.conn.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
            # Schema creation is idempotent and must happen even for read-only
            # commands, so a query against a fresh file reports an empty ledger
            # instead of "no such table".
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=FULL")
            self.conn.executescript(SCHEMA_SQL)
            if not self.writable:
                self.conn.execute("PRAGMA query_only=ON")
        except sqlite3.Error as exc:  # pragma: no cover - environment failure
            raise CaseError(E_DB, "db", f"cannot prepare database: {exc}") from exc

    def close(self) -> None:
        if self.conn is not None:
            with contextlib.suppress(sqlite3.Error):
                self.conn.close()
            self.conn = None

    # -- transactions ------------------------------------------------------
    @contextlib.contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Run a ``BEGIN IMMEDIATE`` transaction, retrying on lock contention."""
        assert self.conn is not None, "store is not open"
        conn = self.conn
        for attempt in range(1, _BEGIN_RETRIES + 1):
            try:
                conn.execute("BEGIN IMMEDIATE")
                break
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc).lower() and "busy" not in str(exc).lower():
                    raise CaseError(E_DB, "db", f"cannot start transaction: {exc}") from exc
                if attempt == _BEGIN_RETRIES:
                    raise CaseError(E_DB, "db", f"database stayed locked: {exc}") from exc
                time.sleep(min(0.02 * (2 ** attempt), 0.5))
        try:
            yield conn
        except BaseException:
            with contextlib.suppress(sqlite3.Error):
                conn.execute("ROLLBACK")
            raise
        else:
            last: Exception | None = None
            for _ in range(_COMMIT_RETRIES):
                try:
                    conn.execute("COMMIT")
                    return
                except sqlite3.OperationalError as exc:  # pragma: no cover - heavy contention
                    last = exc
                    if "locked" not in str(exc).lower() and "busy" not in str(exc).lower():
                        break
                    time.sleep(0.05)
            with contextlib.suppress(sqlite3.Error):
                conn.execute("ROLLBACK")
            raise CaseError(E_DB, "db", f"commit failed: {last}")

    # -- batches -----------------------------------------------------------
    def get_batch(self, batch_key: str) -> sqlite3.Row | None:
        assert self.conn is not None
        return self.conn.execute("SELECT * FROM batches WHERE batch_key = ?", (batch_key,)).fetchone()

    def all_batches(self) -> list[sqlite3.Row]:
        assert self.conn is not None
        return self.conn.execute("SELECT * FROM batches ORDER BY batch_no").fetchall()

    def batch_count(self) -> int:
        assert self.conn is not None
        row = self.conn.execute("SELECT COUNT(*) AS n FROM batches").fetchone()
        return int(row["n"])

    def insert_batch(
        self,
        conn: sqlite3.Connection,
        *,
        batch_key: str,
        payload_digest: str,
        request_digest: str,
        result: dict[str, Any],
    ) -> int:
        cursor = conn.execute(
            "INSERT INTO batches(batch_key, payload_digest, request_digest, committed_at, result_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (batch_key, payload_digest, request_digest, _now_iso(), canonical_json(result)),
        )
        return int(cursor.lastrowid)

    # -- policies ----------------------------------------------------------
    def get_policy_row(self, version: int) -> sqlite3.Row | None:
        assert self.conn is not None
        return self.conn.execute("SELECT * FROM policies WHERE version = ?", (version,)).fetchone()

    def policies_upto(self, upto_batch: int | None) -> list[sqlite3.Row]:
        assert self.conn is not None
        if upto_batch is None:
            return self.conn.execute("SELECT * FROM policies ORDER BY version").fetchall()
        return self.conn.execute(
            "SELECT * FROM policies WHERE batch_no <= ? ORDER BY version", (upto_batch,)
        ).fetchall()

    def insert_policy(
        self, conn: sqlite3.Connection, *, version: int, fingerprint: str, policy: dict[str, Any], batch_no: int
    ) -> None:
        conn.execute(
            "INSERT INTO policies(version, fingerprint, policy_json, batch_no) VALUES (?, ?, ?, ?)",
            (version, fingerprint, canonical_json(policy), batch_no),
        )

    # -- events ------------------------------------------------------------
    def get_event(self, scope: str, event_id: str) -> StoredEvent | None:
        assert self.conn is not None
        row = self.conn.execute(
            "SELECT * FROM events WHERE scope = ? AND event_id = ?", (scope, event_id)
        ).fetchone()
        return None if row is None else self._to_stored(row)

    def events_upto(self, upto_batch: int | None) -> list[StoredEvent]:
        assert self.conn is not None
        if upto_batch is None:
            rows = self.conn.execute("SELECT * FROM events ORDER BY seq").fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM events WHERE batch_no <= ? ORDER BY seq", (upto_batch,)
            ).fetchall()
        return [self._to_stored(r) for r in rows]

    def events_for_batch(self, batch_no: int) -> list[StoredEvent]:
        assert self.conn is not None
        rows = self.conn.execute(
            "SELECT * FROM events WHERE batch_no = ? ORDER BY seq", (batch_no,)
        ).fetchall()
        return [self._to_stored(r) for r in rows]

    @staticmethod
    def _to_stored(row: sqlite3.Row) -> StoredEvent:
        return StoredEvent(
            seq=int(row["seq"]),
            batch_no=int(row["batch_no"]),
            scope=str(row["scope"]),
            event_id=str(row["event_id"]),
            event_type=str(row["event_type"]),
            payload_digest=str(row["payload_digest"]),
            payload_json=str(row["payload_json"]),
            result_json=str(row["result_json"]),
        )

    def insert_event(
        self,
        conn: sqlite3.Connection,
        *,
        batch_no: int,
        scope: str,
        event: dict[str, Any],
        result: dict[str, Any],
    ) -> None:
        conn.execute(
            "INSERT INTO events(batch_no, scope, event_id, event_type, payload_digest, payload_json, result_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                batch_no,
                scope,
                str(event["event_id"]),
                str(event["type"]),
                digest(event),
                canonical_json(event),
                canonical_json(result),
            ),
        )

    # -- receipts ----------------------------------------------------------
    def receipt(self, receipt_id: str) -> sqlite3.Row | None:
        assert self.conn is not None
        return self.conn.execute("SELECT * FROM receipts WHERE receipt_id = ?", (receipt_id,)).fetchone()

    def receipts_upto(self, upto_batch: int | None) -> list[sqlite3.Row]:
        assert self.conn is not None
        if upto_batch is None:
            return self.conn.execute("SELECT * FROM receipts ORDER BY batch_no, receipt_id").fetchall()
        return self.conn.execute(
            "SELECT * FROM receipts WHERE batch_no <= ? ORDER BY batch_no, receipt_id", (upto_batch,)
        ).fetchall()

    def insert_receipt(
        self,
        conn: sqlite3.Connection,
        *,
        payload: dict[str, Any],
        request_id: str,
        subject_id: str,
        batch_no: int,
    ) -> None:
        conn.execute(
            "INSERT INTO receipts(receipt_id, request_id, subject_id, resource, operation, op_version, "
            "risk, generation, challenge_id, policy_version, receipt_number, proof_ids_json, payload_json, batch_no) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                str(payload["receipt_id"]),
                request_id,
                subject_id,
                str(payload["resource"]),
                str(payload["operation"]),
                int(payload["op_version"]),
                str(payload["risk"]),
                str(payload["generation"]),
                str(payload["challenge_id"]),
                int(payload["policy_version"]),
                int(payload["number"]),
                json.dumps(_proof_ids(payload), ensure_ascii=False),
                canonical_json(payload),
                batch_no,
            ),
        )

    def meta_get(self, key: str) -> str | None:
        assert self.conn is not None
        row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return None if row is None else str(row["value"])


def _proof_ids(payload: dict[str, Any]) -> list[str]:
    ids: list[str] = []
    for key in ("stage1", "stage2"):
        entry = payload.get(key)
        if entry:
            ids.extend(entry["proof_ids"])
    return sorted(set(ids))
