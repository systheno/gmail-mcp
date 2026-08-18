"""The security boundary: an explicit allowlist of Gmail API endpoints.

Every HTTP request the gateway makes to Gmail must name an :class:`Endpoint`
defined in this module. There is no code path that accepts a caller-supplied
URL, path, or HTTP method, so "arbitrary Gmail API request" is not a capability
that exists to be abused -- not by a compromised MCP client, and not by a bug in
a tool handler.

Three independent checks apply, in order:

1. **Allowlist.** The endpoint must be one of the constants below. Endpoints are
   module-level frozen objects, so a caller can only reference one that was
   written here by hand.
2. **Path construction.** Path parameters are percent-encoded with an empty safe
   set and validated against a strict id pattern, so no value can introduce a
   ``/``, ``..``, or query string and thereby reach a different endpoint.
3. **Denylist.** The fully-resolved path and method are re-checked against
   forbidden substrings immediately before the request goes out. This catches a
   mistake in (1) or (2) rather than trusting them.

Deliberately absent, and asserted absent by the test suite:

    POST   users/*/messages/send          POST users/*/drafts/*/send
    POST   users/*/messages/*/trash       POST users/*/messages/*/untrash
    POST   users/*/threads/*/trash        DELETE users/*/messages/*
    POST   users/*/messages/batchDelete   DELETE users/*/drafts/*
    *      users/*/settings/**            POST users/*/watch | stop
    POST   users/*/messages/import        POST users/*/messages (raw insert)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Final
from urllib.parse import quote

from ..errors import ErrorCode, ForbiddenOperation, GatewayError

GMAIL_API_BASE: Final = "https://gmail.googleapis.com/gmail/v1"

# Gmail ids are hex-ish strings; labels are like "Label_12", "INBOX",
# "CATEGORY_PERSONAL". This pattern is intentionally narrower than anything
# Gmail actually issues, and rejects every character that could alter a path.
_ID_PATTERN: Final = re.compile(r"^[A-Za-z0-9_\-]{1,256}$")

# Substrings that must never appear in a resolved path, whatever the allowlist
# says. Checked against the path with separators, e.g. "/messages/send".
_FORBIDDEN_PATH_SUBSTRINGS: Final = (
    "/send",
    "/trash",
    "/untrash",
    "/delete",
    "batchdelete",
    "/settings",
    "/import",
    "/insert",
    "/watch",
    "/stop",
    "/forwardingaddresses",
    "/sendas",
    "/filters",
    "/delegates",
    "/pop",
    "/imap",
    "/vacation",
    "/language",
    "/autoforwarding",
)

#: Only these HTTP methods are ever used. DELETE and PATCH are absent by design.
_ALLOWED_METHODS: Final = frozenset({"GET", "POST", "PUT"})


@dataclass(frozen=True, slots=True)
class Endpoint:
    """A single permitted (method, path template) pair."""

    name: str
    method: str
    template: str
    #: Query parameters this endpoint may carry. Anything else is rejected.
    query_params: frozenset[str] = frozenset()
    #: True if this endpoint changes mailbox state (drives auditing).
    mutating: bool = False

    def __post_init__(self) -> None:
        if self.method not in _ALLOWED_METHODS:
            raise ForbiddenOperation(f"endpoint {self.name} uses method {self.method}")


_COMMON_LIST_PARAMS: Final = frozenset({"pageToken", "maxResults"})

# --------------------------------------------------------------------------- #
# Reads
# --------------------------------------------------------------------------- #

GET_PROFILE = Endpoint(
    name="users.getProfile",
    method="GET",
    template="/users/{userId}/profile",
)

LIST_MESSAGES = Endpoint(
    name="users.messages.list",
    method="GET",
    template="/users/{userId}/messages",
    query_params=_COMMON_LIST_PARAMS | {"q", "labelIds", "includeSpamTrash"},
)

GET_MESSAGE = Endpoint(
    name="users.messages.get",
    method="GET",
    template="/users/{userId}/messages/{id}",
    query_params=frozenset({"format", "metadataHeaders"}),
)

GET_ATTACHMENT = Endpoint(
    name="users.messages.attachments.get",
    method="GET",
    template="/users/{userId}/messages/{messageId}/attachments/{id}",
)

LIST_THREADS = Endpoint(
    name="users.threads.list",
    method="GET",
    template="/users/{userId}/threads",
    query_params=_COMMON_LIST_PARAMS | {"q", "labelIds", "includeSpamTrash"},
)

GET_THREAD = Endpoint(
    name="users.threads.get",
    method="GET",
    template="/users/{userId}/threads/{id}",
    query_params=frozenset({"format", "metadataHeaders"}),
)

LIST_LABELS = Endpoint(
    name="users.labels.list",
    method="GET",
    template="/users/{userId}/labels",
)

LIST_DRAFTS = Endpoint(
    name="users.drafts.list",
    method="GET",
    template="/users/{userId}/drafts",
    query_params=_COMMON_LIST_PARAMS | {"q", "includeSpamTrash"},
)

GET_DRAFT = Endpoint(
    name="users.drafts.get",
    method="GET",
    template="/users/{userId}/drafts/{id}",
    query_params=frozenset({"format"}),
)

# --------------------------------------------------------------------------- #
# Permitted mutations
#
# Note what is *not* here: no drafts.send, no messages.send, no trash, no
# delete. users.drafts.create and users.drafts.update store a draft; neither
# transmits mail. Label mutation is further constrained by labels.py, which
# rejects TRASH and SPAM -- adding those labels via messages.modify would
# otherwise be a back door into trashing and spam-reporting.
# --------------------------------------------------------------------------- #

MODIFY_MESSAGE = Endpoint(
    name="users.messages.modify",
    method="POST",
    template="/users/{userId}/messages/{id}/modify",
    mutating=True,
)

BATCH_MODIFY_MESSAGES = Endpoint(
    name="users.messages.batchModify",
    method="POST",
    template="/users/{userId}/messages/batchModify",
    mutating=True,
)

MODIFY_THREAD = Endpoint(
    name="users.threads.modify",
    method="POST",
    template="/users/{userId}/threads/{id}/modify",
    mutating=True,
)

CREATE_DRAFT = Endpoint(
    name="users.drafts.create",
    method="POST",
    template="/users/{userId}/drafts",
    mutating=True,
)

UPDATE_DRAFT = Endpoint(
    name="users.drafts.update",
    method="PUT",
    template="/users/{userId}/drafts/{id}",
    mutating=True,
)


#: The complete set of endpoints this application can reach.
ALLOWED_ENDPOINTS: Final[frozenset[Endpoint]] = frozenset(
    {
        GET_PROFILE,
        LIST_MESSAGES,
        GET_MESSAGE,
        GET_ATTACHMENT,
        LIST_THREADS,
        GET_THREAD,
        LIST_LABELS,
        LIST_DRAFTS,
        GET_DRAFT,
        MODIFY_MESSAGE,
        BATCH_MODIFY_MESSAGES,
        MODIFY_THREAD,
        CREATE_DRAFT,
        UPDATE_DRAFT,
    }
)

_TEMPLATE_PARAM = re.compile(r"\{([A-Za-z][A-Za-z0-9_]*)\}")


def validate_path_param(name: str, value: str) -> str:
    """Reject any path parameter that could escape its segment."""
    if not isinstance(value, str) or not _ID_PATTERN.match(value):
        raise GatewayError(
            ErrorCode.INVALID_INPUT,
            f"invalid {name}: must be 1-256 characters of letters, digits, '-' or '_'",
        )
    return value


def build_path(endpoint: Endpoint, params: dict[str, str]) -> str:
    """Resolve an endpoint template into a concrete, verified path."""
    if endpoint not in ALLOWED_ENDPOINTS:
        raise ForbiddenOperation(
            "refusing to call an endpoint outside the allowlist",
            details={"endpoint": endpoint.name},
        )

    required = set(_TEMPLATE_PARAM.findall(endpoint.template))
    supplied = set(params)
    if required != supplied:
        raise GatewayError(
            ErrorCode.INTERNAL_ERROR,
            f"endpoint {endpoint.name} expects path parameters "
            f"{sorted(required)}, got {sorted(supplied)}",
        )

    def _sub(match: re.Match[str]) -> str:
        name = match.group(1)
        value = validate_path_param(name, params[name])
        # safe="" forbids '/' surviving encoding, so a parameter cannot add a
        # path segment even if _ID_PATTERN were ever loosened.
        return quote(value, safe="")

    path = _TEMPLATE_PARAM.sub(_sub, endpoint.template)
    assert_path_permitted(endpoint.method, path)
    return path


def assert_path_permitted(method: str, path: str) -> None:
    """Final gate: re-check the resolved method and path against the denylist.

    This runs immediately before the request is issued, independently of how the
    path was produced.
    """
    if method not in _ALLOWED_METHODS:
        raise ForbiddenOperation(f"HTTP method {method} is not permitted by this gateway")

    lowered = path.lower()
    for needle in _FORBIDDEN_PATH_SUBSTRINGS:
        if needle in lowered:
            raise ForbiddenOperation(
                "refusing to issue a request to a forbidden Gmail endpoint",
                details={"reason": f"path contains '{needle}'"},
            )
    if not lowered.startswith("/users/"):
        raise ForbiddenOperation("refusing to issue a request outside /users/")


def _scalar_query_value(key: str, value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        if "\n" in value or "\r" in value or "\x00" in value:
            raise GatewayError(
                ErrorCode.INVALID_INPUT,
                f"query parameter {key} contains a line break or null byte",
            )
        return value
    raise GatewayError(ErrorCode.INTERNAL_ERROR, f"query parameter {key} has unsupported type")


def validate_query(endpoint: Endpoint, query: dict[str, object]) -> dict[str, Any]:
    """Drop nothing silently: an unexpected query parameter is an error.

    List values are preserved for the parameters Gmail expects to be repeated
    (``metadataHeaders``, ``labelIds``); each element is validated individually.
    """
    unexpected = set(query) - set(endpoint.query_params)
    if unexpected:
        raise GatewayError(
            ErrorCode.INTERNAL_ERROR,
            f"endpoint {endpoint.name} does not accept query parameter(s): "
            f"{', '.join(sorted(unexpected))}",
        )
    resolved: dict[str, Any] = {}
    for key, value in query.items():
        if value is None:
            continue
        if isinstance(value, (list, tuple)):
            if len(value) > 100:
                raise GatewayError(
                    ErrorCode.INVALID_INPUT, f"query parameter {key} has too many values"
                )
            resolved[key] = [_scalar_query_value(key, item) for item in value]
        else:
            resolved[key] = _scalar_query_value(key, value)
    return resolved
