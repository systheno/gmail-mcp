"""SQLite storage for non-secret state.

Holds account metadata, the audit log, and the idempotency cache. Secrets never
land here -- refresh tokens live only in encrypted per-account files under the
secrets directory (see :mod:`crypto` and :mod:`accounts`).

Access is synchronous under a process-wide lock. Every statement is a local,
indexed, sub-millisecond operation in WAL mode, so blocking the event loop for
that long is cheaper and far less error-prone than a connection-affine thread
pool. Connections are short-lived, which keeps the CLI and the server able to
touch the same database concurrently.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

_SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    alias            TEXT PRIMARY KEY,
    account_id       TEXT NOT NULL UNIQUE,
    email_address    TEXT,
    scopes           TEXT NOT NULL,
    read_only        INTEGER NOT NULL DEFAULT 0,
    status           TEXT NOT NULL DEFAULT 'pending',
    status_reason    TEXT,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    authorized_at    TEXT,
    last_used_at     TEXT
);

CREATE TABLE IF NOT EXISTS audit (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ts             TEXT NOT NULL,
    account        TEXT,
    tool           TEXT NOT NULL,
    operation      TEXT NOT NULL,
    target_type    TEXT,
    target_ids     TEXT,
    target_count   INTEGER NOT NULL DEFAULT 0,
    outcome        TEXT NOT NULL,
    error_code     TEXT,
    detail         TEXT,
    duration_ms    INTEGER,
    request_id     TEXT,
    principal      TEXT
);
CREATE INDEX IF NOT EXISTS audit_ts_idx ON audit (ts DESC);
CREATE INDEX IF NOT EXISTS audit_account_idx ON audit (account, ts DESC);

CREATE TABLE IF NOT EXISTS idempotency (
    key         TEXT PRIMARY KEY,
    account     TEXT NOT NULL,
    tool        TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    response    TEXT NOT NULL,
    created_at  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idempotency_created_idx ON idempotency (created_at);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

_lock = threading.RLock()


class Database:
    """Thin owner of the SQLite file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._initialized = False

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        with _lock:
            conn = sqlite3.connect(self.path, timeout=10.0, isolation_level=None)
            conn.row_factory = sqlite3.Row
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA foreign_keys=ON")
                conn.execute("PRAGMA busy_timeout=10000")
                if not self._initialized:
                    conn.executescript(_SCHEMA)
                    conn.execute(
                        "INSERT INTO meta (key, value) VALUES ('schema_version', ?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                        (str(_SCHEMA_VERSION),),
                    )
                    self._initialized = True
                yield conn
            finally:
                conn.close()

    def initialize(self) -> None:
        """Create the schema eagerly and lock the file down."""
        with self.connect():
            pass
        try:
            self.path.chmod(0o600)
        except OSError:  # pragma: no cover - unusual filesystems
            pass
