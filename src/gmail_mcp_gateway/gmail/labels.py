"""Label policy.

This module closes a back door that the endpoint allowlist alone leaves open.
``users.messages.modify`` is a permitted endpoint -- it is how archiving and
read/unread state work -- but Gmail treats TRASH and SPAM as ordinary labels.
Adding the ``TRASH`` label moves a message to the bin; adding ``SPAM`` reports
it as spam. Both are explicitly forbidden capabilities, so every label id in a
mutation is checked here before any request is issued.

Removal is constrained too: removing ``TRASH`` would untrash a message and
removing ``SPAM`` would unmark spam. Neither is a supported capability, and
silently allowing them would put mailbox state changes outside the audit story
this gateway promises.
"""

from __future__ import annotations

from typing import Final, Iterable

from ..errors import ErrorCode, GatewayError

#: System labels a client may add or remove.
MUTABLE_SYSTEM_LABELS: Final[frozenset[str]] = frozenset(
    {
        "INBOX",  # remove = archive, add = move back to inbox
        "UNREAD",  # remove = mark read, add = mark unread
        "STARRED",
        "IMPORTANT",
        "CATEGORY_PERSONAL",
        "CATEGORY_SOCIAL",
        "CATEGORY_PROMOTIONS",
        "CATEGORY_UPDATES",
        "CATEGORY_FORUMS",
    }
)

#: System labels no client may touch, in either direction.
FORBIDDEN_LABELS: Final[frozenset[str]] = frozenset(
    {
        "TRASH",  # add = move to trash        (forbidden capability)
        "SPAM",  # add = report as spam       (forbidden capability)
        "SENT",  # Gmail-managed
        "DRAFT",  # Gmail-managed
        "CHAT",  # Gmail-managed
    }
)

#: Every label id Gmail reserves. Anything else is a user-created label.
_SYSTEM_LABELS: Final[frozenset[str]] = MUTABLE_SYSTEM_LABELS | FORBIDDEN_LABELS

_WHY: Final[dict[str, str]] = {
    "TRASH": "moving messages to Trash is a forbidden capability of this gateway",
    "SPAM": "marking messages as spam is a forbidden capability of this gateway",
    "SENT": "the SENT label is managed by Gmail and cannot be modified",
    "DRAFT": "the DRAFT label is managed by Gmail and cannot be modified",
    "CHAT": "the CHAT label is managed by Gmail and cannot be modified",
}


def is_system_label(label_id: str) -> bool:
    return label_id in _SYSTEM_LABELS


def validate_label_ids(label_ids: Iterable[str], *, action: str) -> list[str]:
    """Validate label ids for an add/remove mutation.

    ``action`` is "add" or "remove", used only for the error message.
    """
    validated: list[str] = []
    seen: set[str] = set()
    for raw in label_ids:
        if not isinstance(raw, str) or not raw.strip():
            raise GatewayError(ErrorCode.INVALID_INPUT, "label id must be a non-empty string")
        label_id = raw.strip()

        if label_id in FORBIDDEN_LABELS:
            raise GatewayError(
                ErrorCode.FORBIDDEN_LABEL,
                f"refusing to {action} label '{label_id}': "
                f"{_WHY.get(label_id, 'this label is not modifiable')}",
                details={"label_id": label_id, "action": action},
            )

        # Case-insensitive check so 'trash' or 'Trash' cannot slip past. Gmail
        # system label ids are uppercase; a user label id never collides.
        upper = label_id.upper()
        if upper in FORBIDDEN_LABELS:
            raise GatewayError(
                ErrorCode.FORBIDDEN_LABEL,
                f"refusing to {action} label '{label_id}': "
                f"{_WHY.get(upper, 'this label is not modifiable')}",
                details={"label_id": label_id, "action": action},
            )

        if label_id not in seen:
            seen.add(label_id)
            validated.append(label_id)

    return validated


def assert_modify_body_safe(body: dict[str, object]) -> None:
    """Last check on a messages/threads ``modify`` request body.

    Runs after the body is assembled, immediately before it is sent, so a
    mistake anywhere upstream still cannot produce a trash or spam mutation.
    """
    allowed_keys = {"addLabelIds", "removeLabelIds", "ids"}
    unexpected = set(body) - allowed_keys
    if unexpected:
        raise GatewayError(
            ErrorCode.INTERNAL_ERROR,
            f"modify body contains unexpected field(s): {', '.join(sorted(unexpected))}",
        )
    for key in ("addLabelIds", "removeLabelIds"):
        values = body.get(key) or []
        if not isinstance(values, list):
            raise GatewayError(ErrorCode.INTERNAL_ERROR, f"{key} must be a list")
        for value in values:
            if not isinstance(value, str) or value.upper() in FORBIDDEN_LABELS:
                raise GatewayError(
                    ErrorCode.FORBIDDEN_LABEL,
                    f"refusing to send a modify request touching label '{value}'",
                    details={"label_id": str(value)},
                )
