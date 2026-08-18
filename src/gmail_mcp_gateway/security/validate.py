"""Input validation for everything a client can influence.

Pydantic already enforces types and bounds at the tool boundary; this module
carries the semantic rules that a type cannot express -- above all, refusing any
value that would let a client inject a header into a draft.
"""

from __future__ import annotations

import re
from typing import Iterable

from ..errors import ErrorCode, GatewayError

# Deliberately permissive on the local part (RFC 5322 allows a lot) but strict
# about the structural characters that matter, and hard-limited in length.
_EMAIL = re.compile(r"^[^\s@,;:<>\\\"]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9\-\.]{0,251}[A-Za-z0-9])?$")
_DOMAIN_LABEL = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?$")

#: Any of these in a header value means an attempted header injection.
_HEADER_FORBIDDEN = ("\r", "\n", "\x00")

MAX_SUBJECT_CHARS = 998  # RFC 5322 line length limit for a single header
MAX_QUERY_CHARS = 2048
MAX_EMAIL_CHARS = 320


def validate_header_text(value: str, *, field: str, max_chars: int) -> str:
    """Reject control characters that would split or forge a MIME header."""
    if not isinstance(value, str):
        raise GatewayError(ErrorCode.INVALID_INPUT, f"{field} must be a string")
    for bad in _HEADER_FORBIDDEN:
        if bad in value:
            raise GatewayError(
                ErrorCode.INVALID_INPUT,
                f"{field} may not contain line breaks or null bytes "
                "(this would allow header injection)",
            )
    if len(value) > max_chars:
        raise GatewayError(
            ErrorCode.INVALID_INPUT, f"{field} exceeds {max_chars} characters"
        )
    return value


def validate_email_address(address: str, *, field: str = "address") -> str:
    """Validate a bare email address for use in a draft header."""
    if not isinstance(address, str):
        raise GatewayError(ErrorCode.INVALID_INPUT, f"{field} must be a string")
    candidate = address.strip()
    validate_header_text(candidate, field=field, max_chars=MAX_EMAIL_CHARS)
    if not _EMAIL.match(candidate):
        raise GatewayError(
            ErrorCode.INVALID_INPUT,
            f"{field} is not a valid email address: expected 'user@example.com', "
            "without a display name or angle brackets",
        )
    domain = candidate.rsplit("@", 1)[1]
    if not domain or domain.startswith(".") or domain.endswith(".") or ".." in domain:
        raise GatewayError(ErrorCode.INVALID_INPUT, f"{field} has a malformed domain")
    for label in domain.split("."):
        if not _DOMAIN_LABEL.match(label):
            raise GatewayError(ErrorCode.INVALID_INPUT, f"{field} has a malformed domain")
    return candidate


def validate_recipients(
    addresses: Iterable[str] | None, *, field: str, max_count: int
) -> list[str]:
    if not addresses:
        return []
    unique: list[str] = []
    seen: set[str] = set()
    for raw in addresses:
        address = validate_email_address(raw, field=field)
        key = address.lower()
        if key not in seen:
            seen.add(key)
            unique.append(address)
    if len(unique) > max_count:
        raise GatewayError(
            ErrorCode.INVALID_INPUT,
            f"{field} has {len(unique)} recipients, over the limit of {max_count}",
        )
    return unique


def validate_search_query(query: str | None) -> str | None:
    """Bound a Gmail search expression.

    Gmail search syntax is passed through: it is a query language over the
    caller's own mailbox with no write semantics, so the risk is resource use,
    not privilege. Length and control characters are what get checked.
    """
    if query is None:
        return None
    if not isinstance(query, str):
        raise GatewayError(ErrorCode.INVALID_INPUT, "query must be a string")
    cleaned = query.strip()
    if not cleaned:
        return None
    if any(bad in cleaned for bad in _HEADER_FORBIDDEN):
        raise GatewayError(
            ErrorCode.INVALID_INPUT, "query may not contain line breaks or null bytes"
        )
    if len(cleaned) > MAX_QUERY_CHARS:
        raise GatewayError(
            ErrorCode.INVALID_INPUT, f"query exceeds {MAX_QUERY_CHARS} characters"
        )
    return cleaned


def validate_id_batch(ids: Iterable[str], *, field: str, max_count: int) -> list[str]:
    """Validate and de-duplicate a batch of message or thread ids."""
    from ..gmail.allowlist import validate_path_param

    unique: list[str] = []
    seen: set[str] = set()
    for raw in ids:
        identifier = validate_path_param(field, raw)
        if identifier not in seen:
            seen.add(identifier)
            unique.append(identifier)
    if not unique:
        raise GatewayError(ErrorCode.INVALID_INPUT, f"{field} must contain at least one id")
    if len(unique) > max_count:
        raise GatewayError(
            ErrorCode.BATCH_TOO_LARGE,
            f"batch contains {len(unique)} ids, over the limit of {max_count}; "
            "split the request into smaller batches",
            details={"limit": max_count, "received": len(unique)},
        )
    return unique


def validate_body_text(text: str, *, max_chars: int) -> str:
    """Validate a draft body. Null bytes are rejected; newlines are fine here."""
    if not isinstance(text, str):
        raise GatewayError(ErrorCode.INVALID_INPUT, "body must be a string")
    if "\x00" in text:
        raise GatewayError(ErrorCode.INVALID_INPUT, "body may not contain null bytes")
    if len(text) > max_chars:
        raise GatewayError(
            ErrorCode.INVALID_INPUT,
            f"body is {len(text)} characters, over the limit of {max_chars}",
        )
    return text
