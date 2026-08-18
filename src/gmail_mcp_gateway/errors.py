"""Structured error taxonomy.

Every failure that reaches an MCP client passes through :class:`GatewayError`.
Raw exceptions (httpx errors, JSON decode errors, Google API payloads) are
translated at the boundary so that clients never see internal tracebacks,
internal file paths, or anything derived from credentials.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any


class ErrorCode(StrEnum):
    """Stable, machine-readable error identifiers."""

    # --- client-side problems -------------------------------------------------
    INVALID_INPUT = "invalid_input"
    UNKNOWN_ACCOUNT = "unknown_account"
    NOT_FOUND = "not_found"
    TOO_LARGE = "too_large"
    BATCH_TOO_LARGE = "batch_too_large"
    RATE_LIMITED = "rate_limited"

    # --- policy: the gateway refuses on purpose -------------------------------
    FORBIDDEN_OPERATION = "forbidden_operation"
    FORBIDDEN_LABEL = "forbidden_label"
    SCOPE_INSUFFICIENT = "scope_insufficient"
    ACCOUNT_READ_ONLY = "account_read_only"

    # --- authorization state --------------------------------------------------
    NEEDS_REAUTH = "needs_reauth"
    AUTH_FAILED = "auth_failed"

    # --- upstream / transient -------------------------------------------------
    UPSTREAM_RATE_LIMITED = "upstream_rate_limited"
    UPSTREAM_ERROR = "upstream_error"
    UPSTREAM_UNAVAILABLE = "upstream_unavailable"
    NETWORK_ERROR = "network_error"
    TIMEOUT = "timeout"

    # --- gateway itself -------------------------------------------------------
    INTERNAL_ERROR = "internal_error"
    CONFIG_ERROR = "config_error"


#: Errors where retrying the identical request may succeed later.
RETRYABLE = frozenset(
    {
        ErrorCode.RATE_LIMITED,
        ErrorCode.UPSTREAM_RATE_LIMITED,
        ErrorCode.UPSTREAM_UNAVAILABLE,
        ErrorCode.NETWORK_ERROR,
        ErrorCode.TIMEOUT,
    }
)


class GatewayError(Exception):
    """An error safe to expose to an MCP client.

    ``message`` must never interpolate a token, client secret, raw email body,
    or attachment content. Anything sensitive belongs in the server-side log
    (which is itself redacted), not in the client-visible payload.
    """

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        *,
        details: dict[str, Any] | None = None,
        retry_after_seconds: float | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}
        self.retry_after_seconds = retry_after_seconds

    @property
    def retryable(self) -> bool:
        return self.code in RETRYABLE

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "error": {
                "code": str(self.code),
                "message": self.message,
                "retryable": self.retryable,
            }
        }
        if self.details:
            payload["error"]["details"] = self.details
        if self.retry_after_seconds is not None:
            payload["error"]["retry_after_seconds"] = round(self.retry_after_seconds, 3)
        return payload

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"[{self.code}] {self.message}"


class ForbiddenOperation(GatewayError):
    """Raised when something tries to reach a capability this gateway denies.

    Reaching this class from inside the gateway means a policy layer caught an
    attempt that should have been impossible to express. It is deliberately a
    distinct type so tests can assert on it.
    """

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(ErrorCode.FORBIDDEN_OPERATION, message, details=details)


class NeedsReauth(GatewayError):
    def __init__(self, account: str, reason: str = "refresh token is no longer valid") -> None:
        super().__init__(
            ErrorCode.NEEDS_REAUTH,
            f"Account '{account}' must be re-authorized: {reason}. "
            f"An operator must run: gmail-mcp-gateway accounts reauth {account}",
            details={"account": account},
        )
