"""Build draft messages from typed fields.

The gateway never accepts a raw RFC 5322 message from a client. Drafts are
assembled here from validated components, which removes header injection as a
class of bug: a client supplies a subject *string* and a list of *addresses*,
never header text.

Bodies are plain text only. Accepting client HTML would mean storing
attacker-influenced markup that a mail client later renders, and nothing in the
supported feature set needs it -- the human who reviews a draft in Gmail can
format it there.

Creating or updating a draft never transmits mail. Gmail's ``drafts.create`` and
``drafts.update`` store a message; only ``drafts.send`` transmits, and that
endpoint is absent from the allowlist.
"""

from __future__ import annotations

import base64
from email.message import EmailMessage
from email.utils import formataddr
from typing import Any

from ..config import Limits
from ..errors import ErrorCode, GatewayError
from ..security.validate import (
    MAX_SUBJECT_CHARS,
    validate_body_text,
    validate_email_address,
    validate_header_text,
    validate_recipients,
)

#: References headers grow without bound on long threads; cap what we echo back.
_MAX_REFERENCES = 40


def build_draft_mime(
    *,
    limits: Limits,
    to: list[str] | None = None,
    cc: list[str] | None = None,
    bcc: list[str] | None = None,
    subject: str = "",
    body: str = "",
    from_address: str | None = None,
    in_reply_to: str | None = None,
    references: list[str] | None = None,
) -> str:
    """Return the base64url-encoded RFC 5322 message for a draft."""
    recipients_to = validate_recipients(to, field="to", max_count=limits.max_recipients)
    recipients_cc = validate_recipients(cc, field="cc", max_count=limits.max_recipients)
    recipients_bcc = validate_recipients(bcc, field="bcc", max_count=limits.max_recipients)

    clean_subject = validate_header_text(subject or "", field="subject", max_chars=MAX_SUBJECT_CHARS)
    clean_body = validate_body_text(body or "", max_chars=limits.max_draft_body_chars)

    message = EmailMessage()
    if recipients_to:
        message["To"] = ", ".join(recipients_to)
    if recipients_cc:
        message["Cc"] = ", ".join(recipients_cc)
    if recipients_bcc:
        message["Bcc"] = ", ".join(recipients_bcc)
    if clean_subject:
        message["Subject"] = clean_subject
    if from_address:
        # Only ever the authorized account's own address, supplied by the
        # gateway rather than the client.
        message["From"] = formataddr(("", validate_email_address(from_address, field="from")))

    if in_reply_to:
        token = validate_header_text(in_reply_to, field="in_reply_to", max_chars=998).strip()
        if not (token.startswith("<") and token.endswith(">")):
            raise GatewayError(
                ErrorCode.INVALID_INPUT, "in_reply_to must be a Message-ID in angle brackets"
            )
        message["In-Reply-To"] = token

    if references:
        tokens: list[str] = []
        for raw in references[-_MAX_REFERENCES:]:
            token = validate_header_text(raw, field="references", max_chars=998).strip()
            if token.startswith("<") and token.endswith(">"):
                tokens.append(token)
        if tokens:
            message["References"] = " ".join(tokens)

    message.set_content(clean_body, subtype="plain", charset="utf-8")

    raw = message.as_bytes()
    if len(raw) > limits.max_draft_body_chars * 4 + 65536:
        raise GatewayError(ErrorCode.TOO_LARGE, "assembled draft is too large")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def reply_headers(
    original: dict[str, Any],
    *,
    quote_subject: bool = True,
) -> dict[str, Any]:
    """Derive threading headers for a reply to a parsed message view.

    Follows RFC 5322 section 3.6.4: ``In-Reply-To`` is the parent's Message-ID
    and ``References`` is the parent's References plus the parent's Message-ID.
    Gmail additionally requires the draft to carry the parent's ``threadId``, and
    a subject that matches the thread, or it will start a new conversation.
    """
    parent_message_id = original.get("message_id_header")
    references = list(original.get("references") or [])
    if parent_message_id and parent_message_id not in references:
        references.append(parent_message_id)

    subject = original.get("subject") or ""
    if quote_subject and subject and not subject.strip().lower().startswith("re:"):
        subject = f"Re: {subject}"

    return {
        "in_reply_to": parent_message_id,
        "references": references[-_MAX_REFERENCES:],
        "subject": subject[:MAX_SUBJECT_CHARS],
        "thread_id": original.get("thread_id"),
    }


def reply_recipients(
    original: dict[str, Any],
    *,
    self_address: str | None,
    reply_all: bool,
) -> dict[str, list[str]]:
    """Choose To/Cc for a reply, excluding the account's own address.

    Reply-To wins over From when present, per RFC 5322.
    """
    own = (self_address or "").lower()

    def _emails(entries: Any) -> list[str]:
        result = []
        for entry in entries or []:
            if isinstance(entry, dict) and entry.get("email"):
                result.append(entry["email"])
        return result

    primary = _emails(original.get("reply_to")) or _emails([original.get("from")])
    to = [address for address in primary if address.lower() != own]

    cc: list[str] = []
    if reply_all:
        seen = {address.lower() for address in to} | {own}
        for address in _emails(original.get("to")) + _emails(original.get("cc")):
            if address.lower() not in seen:
                seen.add(address.lower())
                cc.append(address)

    # If the only participant was the account itself, reply to it rather than
    # producing a draft with no recipients.
    if not to and not cc and primary:
        to = primary[:1]

    return {"to": to, "cc": cc}
