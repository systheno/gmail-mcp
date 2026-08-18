"""Audit trail for state-changing operations.

Every mutation attempt is recorded with account, timestamp, operation, affected
ids, and outcome -- successes and failures alike, because a rejected attempt to
trash a thread is exactly the event an operator wants to see.

What is deliberately *not* recorded: OAuth tokens, message bodies, attachment
contents, draft text, and subjects. The log answers "what changed, to what, when,
and did it work"; it is not a mailbox archive. Detail strings pass through the
same redaction filter used for logging.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Iterable

from .db import Database
from .logging_setup import redact

OUTCOME_SUCCESS = "success"
OUTCOME_FAILURE = "failure"
OUTCOME_DENIED = "denied"

#: Ids recorded per event before the list is summarised.
_MAX_RECORDED_IDS = 25
_MAX_DETAIL_CHARS = 500


@dataclass(slots=True)
class AuditEvent:
    id: int
    ts: str
    account: str | None
    tool: str
    operation: str
    target_type: str | None
    target_ids: list[str]
    target_count: int
    outcome: str
    error_code: str | None
    detail: str | None
    duration_ms: int | None
    request_id: str | None
    principal: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.ts,
            "account": self.account,
            "tool": self.tool,
            "operation": self.operation,
            "target_type": self.target_type,
            "target_ids": self.target_ids,
            "target_count": self.target_count,
            "outcome": self.outcome,
            "error_code": self.error_code,
            "detail": self.detail,
            "duration_ms": self.duration_ms,
            "request_id": self.request_id,
            "principal": self.principal,
        }


class AuditLog:
    def __init__(self, db: Database, *, retention_days: int = 90) -> None:
        self._db = db
        self._retention_days = retention_days

    def record(
        self,
        *,
        tool: str,
        operation: str,
        outcome: str,
        account: str | None = None,
        target_type: str | None = None,
        target_ids: Iterable[str] | None = None,
        error_code: str | None = None,
        detail: str | None = None,
        duration_ms: int | None = None,
        request_id: str | None = None,
        principal: str | None = None,
    ) -> None:
        ids = [str(i) for i in (target_ids or [])]
        stored_ids = ids[:_MAX_RECORDED_IDS]
        if len(ids) > _MAX_RECORDED_IDS:
            stored_ids.append(f"...+{len(ids) - _MAX_RECORDED_IDS} more")

        safe_detail = redact(detail)[:_MAX_DETAIL_CHARS] if detail else None

        with self._db.connect() as conn:
            conn.execute(
                "INSERT INTO audit (ts, account, tool, operation, target_type, target_ids, "
                "target_count, outcome, error_code, detail, duration_ms, request_id, principal) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    datetime.now(UTC).isoformat(timespec="milliseconds"),
                    account,
                    tool,
                    operation,
                    target_type,
                    ",".join(stored_ids) if stored_ids else None,
                    len(ids),
                    outcome,
                    error_code,
                    safe_detail,
                    duration_ms,
                    request_id,
                    principal,
                ),
            )

    def recent(
        self,
        *,
        limit: int = 50,
        account: str | None = None,
        tool: str | None = None,
        outcome: str | None = None,
        since: datetime | None = None,
    ) -> list[AuditEvent]:
        clauses: list[str] = []
        params: list[Any] = []
        if account:
            clauses.append("account = ?")
            params.append(account)
        if tool:
            clauses.append("tool = ?")
            params.append(tool)
        if outcome:
            clauses.append("outcome = ?")
            params.append(outcome)
        if since:
            clauses.append("ts >= ?")
            params.append(since.astimezone(UTC).isoformat(timespec="milliseconds"))

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(max(1, min(limit, 1000)))

        with self._db.connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM audit {where} ORDER BY id DESC LIMIT ?", params
            ).fetchall()

        return [
            AuditEvent(
                id=row["id"],
                ts=row["ts"],
                account=row["account"],
                tool=row["tool"],
                operation=row["operation"],
                target_type=row["target_type"],
                target_ids=[i for i in (row["target_ids"] or "").split(",") if i],
                target_count=row["target_count"],
                outcome=row["outcome"],
                error_code=row["error_code"],
                detail=row["detail"],
                duration_ms=row["duration_ms"],
                request_id=row["request_id"],
                principal=row["principal"],
            )
            for row in rows
        ]

    def counts_by_outcome(self, *, since: datetime | None = None) -> dict[str, int]:
        clause, params = "", []
        if since:
            clause = "WHERE ts >= ?"
            params.append(since.astimezone(UTC).isoformat(timespec="milliseconds"))
        with self._db.connect() as conn:
            rows = conn.execute(
                f"SELECT outcome, COUNT(*) AS n FROM audit {clause} GROUP BY outcome", params
            ).fetchall()
        return {row["outcome"]: row["n"] for row in rows}

    def prune(self) -> int:
        if self._retention_days <= 0:
            return 0
        cutoff = (datetime.now(UTC) - timedelta(days=self._retention_days)).isoformat()
        with self._db.connect() as conn:
            cursor = conn.execute("DELETE FROM audit WHERE ts < ?", (cutoff,))
            return cursor.rowcount or 0
