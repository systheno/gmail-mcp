"""Turn Gmail's MIME payloads into clean structures for LLM consumption.

Everything in this module treats message content as hostile input:

* HTML is *converted to text*, never rendered and never returned as markup.
  ``<script>``, ``<style>``, and every other tag is discarded rather than
  escaped, so there is nothing left for a downstream renderer to execute.
* Invisible and direction-overriding Unicode is stripped. These characters let
  an attacker show a human reviewer one thing while an LLM reads another, which
  is a prompt-injection primitive rather than a rendering curiosity. The count of
  removed characters is reported so a caller can notice the attempt.
* Attachments are described, never decoded here, and their filenames are
  sanitized before they can touch a filesystem.
* Bodies are truncated to a configured budget with an explicit ``truncated`` flag.
"""

from __future__ import annotations

import base64
import binascii
import html as html_module
import re
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from email.header import decode_header, make_header
from email.utils import getaddresses, parsedate_to_datetime
from typing import Any, Iterator

from ..errors import ErrorCode, GatewayError

# --------------------------------------------------------------------------- #
# Primitives
# --------------------------------------------------------------------------- #


def decode_base64url(data: str) -> bytes:
    """Decode Gmail's URL-safe, unpadded base64."""
    if not isinstance(data, str):
        raise GatewayError(ErrorCode.UPSTREAM_ERROR, "expected base64 string from Gmail")
    padding = "=" * (-len(data) % 4)
    try:
        return base64.urlsafe_b64decode(data + padding)
    except (binascii.Error, ValueError) as exc:
        raise GatewayError(ErrorCode.UPSTREAM_ERROR, "Gmail returned undecodable content") from exc


# Zero-width, bidirectional-override, and other invisible formatting characters.
_INVISIBLE = re.compile(
    "["
    "­"  # soft hyphen
    "​-‏"  # zero-width space/non-joiner/joiner, LRM, RLM
    "‪-‮"  # bidi embedding and override
    "⁠-⁤"  # word joiner, invisible operators
    "⁦-⁩"  # bidi isolates
    "﻿"  # BOM / zero-width no-break space
    "￹-￻"  # interlinear annotation
    "\U000e0000-\U000e007f"  # tag characters (invisible ASCII smuggling)
    "]"
)

# C0 controls except tab, newline, carriage return.
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


@dataclass(slots=True)
class Sanitized:
    text: str
    removed_characters: int


def sanitize_text(value: str) -> Sanitized:
    """Strip invisible and control characters; normalise line endings."""
    if not value:
        return Sanitized("", 0)
    original_length = len(value)
    value = unicodedata.normalize("NFC", value)
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    value = _INVISIBLE.sub("", value)
    value = _CONTROL.sub("", value)
    return Sanitized(value, max(0, original_length - len(value)))


def _truncate(text: str, max_chars: int) -> tuple[str, bool]:
    if max_chars <= 0 or len(text) <= max_chars:
        return text, False
    return text[:max_chars], True


# --------------------------------------------------------------------------- #
# HTML -> text
# --------------------------------------------------------------------------- #

_DROP_ELEMENTS = re.compile(
    r"<(script|style|head|noscript|template|svg|math|iframe|object|embed)\b[^>]*>.*?</\1\s*>",
    re.IGNORECASE | re.DOTALL,
)
_UNCLOSED_DROP = re.compile(
    r"<(script|style|head|noscript|template|svg|math|iframe|object|embed)\b[^>]*>.*",
    re.IGNORECASE | re.DOTALL,
)
_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_BLOCK_BREAK = re.compile(
    r"</?(p|div|br|tr|li|h[1-6]|table|blockquote|section|article|header|footer|ul|ol|pre)\b[^>]*>",
    re.IGNORECASE,
)
_ANY_TAG = re.compile(r"<[^>]*>")
_BLANK_RUN = re.compile(r"\n{3,}")
_TRAILING_SPACE = re.compile(r"[ \t]+\n")


def html_to_text(markup: str) -> str:
    """Flatten HTML to plain text.

    Tags are removed outright, not escaped: the result is never markup, so it
    cannot be executed by anything that later renders it. Script-bearing
    elements are dropped with their contents so their source does not survive as
    text either.
    """
    if not markup:
        return ""
    text = _COMMENT.sub(" ", markup)
    # Repeat: nested droppable elements need more than one pass.
    for _ in range(3):
        text, count = _DROP_ELEMENTS.subn(" ", text)
        if not count:
            break
    # A truncated or malformed document can leave an unterminated <script>;
    # discard everything after it rather than emitting the source.
    text = _UNCLOSED_DROP.sub(" ", text)
    text = _BLOCK_BREAK.sub("\n", text)
    text = _ANY_TAG.sub("", text)
    text = html_module.unescape(text)
    text = text.replace("\xa0", " ")
    text = _TRAILING_SPACE.sub("\n", text)
    text = _BLANK_RUN.sub("\n\n", text)
    return text.strip()


# --------------------------------------------------------------------------- #
# Headers
# --------------------------------------------------------------------------- #


def decode_mime_header(value: str) -> str:
    """Decode RFC 2047 encoded-words (``=?utf-8?B?...?=``) into text."""
    if not value:
        return ""
    try:
        decoded = str(make_header(decode_header(value)))
    except (UnicodeDecodeError, LookupError, ValueError):
        decoded = value
    return sanitize_text(decoded).text.replace("\n", " ").strip()


def header_map(payload: dict[str, Any]) -> dict[str, str]:
    """Case-insensitive header lookup, last value wins."""
    result: dict[str, str] = {}
    for entry in payload.get("headers") or []:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        value = entry.get("value")
        if isinstance(name, str) and isinstance(value, str):
            result[name.lower()] = value
    return result


def parse_addresses(raw: str) -> list[dict[str, str]]:
    """Split an address header into ``{name, email}`` entries."""
    if not raw:
        return []
    parsed: list[dict[str, str]] = []
    for name, address in getaddresses([raw]):
        clean_name = decode_mime_header(name)
        clean_address = sanitize_text(address).text.strip()
        if not clean_address and not clean_name:
            continue
        parsed.append({"name": clean_name, "email": clean_address})
    return parsed


def parse_timestamp(headers: dict[str, str], internal_date: str | None) -> dict[str, Any]:
    """Prefer Gmail's authoritative internalDate; fall back to the Date header."""
    result: dict[str, Any] = {"iso": None, "epoch_ms": None, "source": None}
    if internal_date:
        try:
            epoch_ms = int(internal_date)
            result.update(
                iso=datetime.fromtimestamp(epoch_ms / 1000, UTC).isoformat(),
                epoch_ms=epoch_ms,
                source="internal_date",
            )
            return result
        except (ValueError, OSError, OverflowError):
            pass
    if raw := headers.get("date"):
        try:
            parsed = parsedate_to_datetime(raw)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            result.update(
                iso=parsed.isoformat(),
                epoch_ms=int(parsed.timestamp() * 1000),
                source="date_header",
            )
        except (TypeError, ValueError):
            pass
    return result


# --------------------------------------------------------------------------- #
# Body and attachments
# --------------------------------------------------------------------------- #

_CHARSET = re.compile(r'charset\s*=\s*"?([\w\-\.:]+)"?', re.IGNORECASE)
_FILENAME_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")
_RESERVED_NAMES = frozenset(
    {"con", "prn", "aux", "nul"} | {f"com{i}" for i in range(1, 10)} | {f"lpt{i}" for i in range(1, 10)}
)


def sanitize_filename(name: str, *, fallback: str = "attachment") -> str:
    """Reduce an attacker-controlled filename to a safe basename.

    Path separators, traversal sequences, leading dots, and NTFS-reserved names
    are all removed. The result is only ever used as a *suggestion*; the actual
    on-disk name is chosen by the gateway (see :mod:`..security.paths`).
    """
    decoded = decode_mime_header(name or "")
    # Take the basename under both separator conventions before anything else.
    decoded = decoded.replace("\\", "/").split("/")[-1]
    decoded = decoded.strip().strip(".")
    cleaned = _FILENAME_UNSAFE.sub("_", decoded)
    cleaned = re.sub(r"_{2,}", "_", cleaned).strip("._")
    if not cleaned:
        return fallback
    stem = cleaned.split(".")[0].lower()
    if stem in _RESERVED_NAMES:
        cleaned = f"file_{cleaned}"
    return cleaned[:128]


def iter_parts(payload: dict[str, Any], *, _depth: int = 0) -> Iterator[dict[str, Any]]:
    """Depth-first walk over MIME parts, with a bound on nesting."""
    if not isinstance(payload, dict) or _depth > 20:
        return
    yield payload
    for part in payload.get("parts") or []:
        if isinstance(part, dict):
            yield from iter_parts(part, _depth=_depth + 1)


def _decode_part_text(part: dict[str, Any]) -> str:
    body = part.get("body") or {}
    data = body.get("data")
    if not data:
        return ""
    raw = decode_base64url(data)
    charset = "utf-8"
    if match := _CHARSET.search(part.get("mimeType", "") or ""):
        charset = match.group(1)
    else:
        headers = header_map(part)
        if match := _CHARSET.search(headers.get("content-type", "")):
            charset = match.group(1)
    try:
        return raw.decode(charset, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


def _is_attachment(part: dict[str, Any]) -> bool:
    body = part.get("body") or {}
    if body.get("attachmentId"):
        return True
    headers = header_map(part)
    disposition = headers.get("content-disposition", "").lower()
    return disposition.startswith("attachment") and bool(part.get("filename"))


def extract_body(payload: dict[str, Any], *, max_chars: int) -> dict[str, Any]:
    """Return the best plain-text rendering of a message body."""
    plain_chunks: list[str] = []
    html_chunks: list[str] = []

    for part in iter_parts(payload):
        if part.get("parts"):
            continue  # container, not content
        if _is_attachment(part):
            continue
        mime = (part.get("mimeType") or "").lower()
        if mime.startswith("text/plain"):
            plain_chunks.append(_decode_part_text(part))
        elif mime.startswith("text/html"):
            html_chunks.append(_decode_part_text(part))

    if plain_chunks:
        source = "text/plain"
        raw_text = "\n\n".join(chunk for chunk in plain_chunks if chunk.strip())
    elif html_chunks:
        source = "text/html (converted to text)"
        raw_text = "\n\n".join(
            html_to_text(chunk) for chunk in html_chunks if chunk and chunk.strip()
        )
    else:
        source = "none"
        raw_text = ""

    sanitized = sanitize_text(raw_text)
    text, truncated = _truncate(sanitized.text, max_chars)

    return {
        "text": text,
        "source": source,
        "truncated": truncated,
        "total_characters": len(sanitized.text),
        "removed_hidden_characters": sanitized.removed_characters,
    }


def extract_attachments(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Describe attachments without decoding any of them."""
    attachments: list[dict[str, Any]] = []
    for index, part in enumerate(iter_parts(payload)):
        if not _is_attachment(part):
            continue
        body = part.get("body") or {}
        headers = header_map(part)
        raw_name = part.get("filename") or ""
        attachments.append(
            {
                "attachment_id": body.get("attachmentId"),
                "part_id": part.get("partId") or str(index),
                "filename": sanitize_filename(raw_name),
                "original_filename_differs": sanitize_filename(raw_name)
                != decode_mime_header(raw_name),
                "mime_type": (part.get("mimeType") or "application/octet-stream").split(";")[0],
                "size_bytes": int(body.get("size") or 0),
                "inline": headers.get("content-disposition", "").lower().startswith("inline"),
                "content_id": sanitize_text(headers.get("content-id", "")).text.strip("<>") or None,
            }
        )
    return attachments


# --------------------------------------------------------------------------- #
# Message and thread views
# --------------------------------------------------------------------------- #

SYSTEM_LABEL_NAMES = {
    "INBOX": "Inbox",
    "SENT": "Sent",
    "DRAFT": "Draft",
    "SPAM": "Spam",
    "TRASH": "Trash",
    "UNREAD": "Unread",
    "STARRED": "Starred",
    "IMPORTANT": "Important",
}


def parse_message(
    message: dict[str, Any],
    *,
    max_body_chars: int,
    include_body: bool = True,
    label_names: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build the structured view of one message returned to MCP clients."""
    payload = message.get("payload") or {}
    headers = header_map(payload)
    label_ids = [str(label) for label in (message.get("labelIds") or [])]
    names = label_names or {}

    view: dict[str, Any] = {
        "id": message.get("id"),
        "thread_id": message.get("threadId"),
        "subject": decode_mime_header(headers.get("subject", "")),
        "from": (parse_addresses(headers.get("from", "")) or [None])[0],
        "to": parse_addresses(headers.get("to", "")),
        "cc": parse_addresses(headers.get("cc", "")),
        "bcc": parse_addresses(headers.get("bcc", "")),
        "reply_to": parse_addresses(headers.get("reply-to", "")),
        "timestamp": parse_timestamp(headers, message.get("internalDate")),
        "labels": {
            "ids": label_ids,
            "names": [names.get(lid, SYSTEM_LABEL_NAMES.get(lid, lid)) for lid in label_ids],
        },
        "is_unread": "UNREAD" in label_ids,
        "is_starred": "STARRED" in label_ids,
        "is_important": "IMPORTANT" in label_ids,
        "in_inbox": "INBOX" in label_ids,
        "is_draft": "DRAFT" in label_ids,
        "snippet": sanitize_text(html_module.unescape(message.get("snippet") or "")).text,
        "size_estimate_bytes": message.get("sizeEstimate"),
        "message_id_header": sanitize_text(headers.get("message-id", "")).text.strip() or None,
        "in_reply_to": sanitize_text(headers.get("in-reply-to", "")).text.strip() or None,
        "references": sanitize_text(headers.get("references", "")).text.split() or [],
        "has_attachments": False,
        "attachments": [],
        "content_is_untrusted": True,
    }

    attachments = extract_attachments(payload)
    view["attachments"] = attachments
    view["has_attachments"] = bool(attachments)

    if include_body:
        view["body"] = extract_body(payload, max_chars=max_body_chars)
    return view


def parse_thread(
    thread: dict[str, Any],
    *,
    max_body_chars: int,
    include_bodies: bool = True,
    label_names: dict[str, str] | None = None,
) -> dict[str, Any]:
    messages = [
        parse_message(
            message,
            max_body_chars=max_body_chars,
            include_body=include_bodies,
            label_names=label_names,
        )
        for message in (thread.get("messages") or [])
        if isinstance(message, dict)
    ]
    subject = messages[0]["subject"] if messages else ""
    participants: dict[str, dict[str, str]] = {}
    for message in messages:
        candidates = [message.get("from")] + message.get("to", []) + message.get("cc", [])
        for entry in candidates:
            if entry and entry.get("email"):
                participants.setdefault(entry["email"].lower(), entry)

    return {
        "id": thread.get("id"),
        "subject": subject,
        "message_count": len(messages),
        "participants": list(participants.values()),
        "history_id": thread.get("historyId"),
        "snippet": sanitize_text(html_module.unescape(thread.get("snippet") or "")).text,
        "messages": messages,
        "content_is_untrusted": True,
    }
