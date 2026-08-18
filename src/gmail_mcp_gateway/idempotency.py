"""Duplicate-request suppression for mutating tools.

An agent that retries after a timeout, or a transport that redelivers, should
not create two drafts. Every mutating tool accepts an optional
``client_request_id``; the first call stores its result, and a repeat with the
same id returns the stored result instead of acting again.

The stored fingerprint is a hash of the *arguments*. Reusing an id with
different arguments is a client bug and is rejected rather than silently
returning the wrong cached response.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from .db import Database
from .errors import ErrorCode, GatewayError

MAX_KEY_CHARS = 200


def fingerprint(payload: dict[str, Any]) -> str:
    """Stable hash of tool arguments, independent of key order."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def validate_key(key: str) -> str:
    if not isinstance(key, str) or not key.strip():
        raise GatewayError(ErrorCode.INVALID_INPUT, "client_request_id must be a non-empty string")
    cleaned = key.strip()
    if len(cleaned) > MAX_KEY_CHARS:
        raise GatewayError(
            ErrorCode.INVALID_INPUT, f"client_request_id exceeds {MAX_KEY_CHARS} characters"
        )
    return cleaned


class IdempotencyCache:
    def __init__(self, db: Database, *, ttl_seconds: int) -> None:
        self._db = db
        self._ttl = ttl_seconds

    def _scoped(self, account: str, tool: str, key: str) -> str:
        return f"{account}\x1f{tool}\x1f{key}"

    def lookup(
        self, *, account: str, tool: str, key: str, args_fingerprint: str
    ) -> dict[str, Any] | None:
        scoped = self._scoped(account, tool, validate_key(key))
        with self._db.connect() as conn:
            row = conn.execute(
                "SELECT fingerprint, response, created_at FROM idempotency WHERE key = ?",
                (scoped,),
            ).fetchone()
        if row is None:
            return None
        if time.time() - row["created_at"] > self._ttl:
            with self._db.connect() as conn:
                conn.execute("DELETE FROM idempotency WHERE key = ?", (scoped,))
            return None
        if row["fingerprint"] != args_fingerprint:
            raise GatewayError(
                ErrorCode.INVALID_INPUT,
                "client_request_id was already used for this account and tool with "
                "different arguments; use a fresh id for a different request",
                details={"client_request_id": key},
            )
        cached = json.loads(row["response"])
        if isinstance(cached, dict):
            cached["deduplicated"] = True
        return cached

    def store(
        self,
        *,
        account: str,
        tool: str,
        key: str,
        args_fingerprint: str,
        response: dict[str, Any],
    ) -> None:
        scoped = self._scoped(account, tool, validate_key(key))
        with self._db.connect() as conn:
            conn.execute(
                "INSERT INTO idempotency (key, account, tool, fingerprint, response, created_at) "
                "VALUES (?,?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET "
                "fingerprint=excluded.fingerprint, response=excluded.response, "
                "created_at=excluded.created_at",
                (
                    scoped,
                    account,
                    tool,
                    args_fingerprint,
                    json.dumps(response, default=str),
                    time.time(),
                ),
            )

    def prune(self) -> int:
        with self._db.connect() as conn:
            cursor = conn.execute(
                "DELETE FROM idempotency WHERE created_at < ?", (time.time() - self._ttl,)
            )
            return cursor.rowcount or 0
