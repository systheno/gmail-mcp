"""Draft composition: header injection defenses and correct threading."""

from __future__ import annotations

import base64
import email
from email.message import Message

import pytest

from gmail_mcp_gateway.config import Limits
from gmail_mcp_gateway.errors import ErrorCode, GatewayError
from gmail_mcp_gateway.gmail.compose import build_draft_mime, reply_headers, reply_recipients
from gmail_mcp_gateway.gmail.parse import parse_message

from .conftest import FakeGmail, make_message

LIMITS = Limits()


def _parsed(raw_b64: str) -> Message:
    return email.message_from_bytes(base64.urlsafe_b64decode(raw_b64 + "=" * (-len(raw_b64) % 4)))


def _body_text(message: Message) -> str:
    payload = message.get_payload(decode=True)
    assert isinstance(payload, bytes)
    return payload.decode("utf-8")


# --------------------------------------------------------------------------- #
# Header injection
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "malicious",
    [
        "Hello\r\nBcc: attacker@evil.example",
        "Hello\nBcc: attacker@evil.example",
        "Hello\r\n\r\nInjected body",
        "Hello\x00",
    ],
)
def test_subject_cannot_inject_a_header(malicious):
    with pytest.raises(GatewayError) as info:
        build_draft_mime(limits=LIMITS, to=["a@example.com"], subject=malicious, body="x")
    assert info.value.code is ErrorCode.INVALID_INPUT


@pytest.mark.parametrize(
    "malicious",
    [
        "victim@example.com\r\nBcc: attacker@evil.example",
        "victim@example.com\nCc: attacker@evil.example",
        "Alice <alice@example.com>",  # display names are not accepted
        "<alice@example.com>",
        "not-an-email",
        "a@@example.com",
        "a@",
        "@example.com",
        "a@example..com",
        "a@-example.com",
        "a b@example.com",
    ],
)
def test_recipient_addresses_are_strictly_validated(malicious):
    with pytest.raises(GatewayError) as info:
        build_draft_mime(limits=LIMITS, to=[malicious], subject="s", body="b")
    assert info.value.code is ErrorCode.INVALID_INPUT


def test_injection_attempt_never_reaches_the_assembled_message():
    """Even if validation were bypassed, the assembled MIME has one Bcc source."""
    raw = build_draft_mime(
        limits=LIMITS,
        to=["a@example.com"],
        bcc=["hidden@example.com"],
        subject="Normal subject",
        body="Body line one\nBcc: attacker@evil.example\n",
    )
    message = _parsed(raw)
    assert message.get_all("Bcc") == ["hidden@example.com"]
    # The body text that looks like a header stays in the body.
    assert "attacker@evil.example" in _body_text(message)


def test_body_may_contain_newlines():
    raw = build_draft_mime(limits=LIMITS, to=["a@example.com"], body="line 1\nline 2\n\nline 4")
    assert "line 4" in _body_text(_parsed(raw))


def test_null_bytes_in_body_are_rejected():
    with pytest.raises(GatewayError):
        build_draft_mime(limits=LIMITS, to=["a@example.com"], body="bad\x00body")


def test_unicode_subject_and_body_round_trip():
    raw = build_draft_mime(
        limits=LIMITS, to=["a@example.com"], subject="Grüße 😀", body="naïve café 日本語"
    )
    message = _parsed(raw)
    from email.header import decode_header, make_header

    assert "Grüße" in str(make_header(decode_header(message["Subject"])))
    assert "日本語" in _body_text(message)


def test_recipients_are_deduplicated_case_insensitively():
    raw = build_draft_mime(
        limits=LIMITS,
        to=["Alice@Example.com", "alice@example.com", "bob@example.com"],
        body="x",
    )
    assert _parsed(raw)["To"].count("@") == 2


def test_too_many_recipients_is_rejected():
    limits = Limits(max_recipients=3)
    with pytest.raises(GatewayError):
        build_draft_mime(
            limits=limits, to=[f"user{i}@example.com" for i in range(5)], body="x"
        )


def test_oversized_body_is_rejected():
    limits = Limits(max_draft_body_chars=100)
    with pytest.raises(GatewayError):
        build_draft_mime(limits=limits, to=["a@example.com"], body="x" * 101)


# --------------------------------------------------------------------------- #
# Threading
# --------------------------------------------------------------------------- #


def test_reply_headers_follow_rfc5322():
    original = parse_message(
        make_message(
            message_id_header="<parent@example.com>",
            references="<grandparent@example.com>",
            subject="Budget review",
        ),
        max_body_chars=0,
        include_body=False,
    )
    headers = reply_headers(original)
    assert headers["in_reply_to"] == "<parent@example.com>"
    assert headers["references"] == ["<grandparent@example.com>", "<parent@example.com>"]
    assert headers["subject"] == "Re: Budget review"
    assert headers["thread_id"] == "thr1"


def test_reply_subject_is_not_double_prefixed():
    original = parse_message(make_message(subject="Re: Budget"), max_body_chars=0, include_body=False)
    assert reply_headers(original)["subject"] == "Re: Budget"


def test_reply_to_header_wins_over_from():
    original = parse_message(
        make_message(sender="Alice <alice@example.com>"), max_body_chars=0, include_body=False
    )
    original["reply_to"] = [{"name": "", "email": "list@example.com"}]
    recipients = reply_recipients(original, self_address="me@example.com", reply_all=False)
    assert recipients["to"] == ["list@example.com"]


def test_reply_excludes_the_accounts_own_address():
    original = parse_message(
        make_message(sender="Alice <alice@example.com>", to="me@example.com, dave@example.com"),
        max_body_chars=0,
        include_body=False,
    )
    recipients = reply_recipients(original, self_address="me@example.com", reply_all=True)
    assert "me@example.com" not in recipients["to"] + recipients["cc"]
    assert recipients["to"] == ["alice@example.com"]
    assert "dave@example.com" in recipients["cc"]


def test_reply_without_reply_all_has_no_cc():
    original = parse_message(
        make_message(to="me@example.com, dave@example.com", cc="carol@example.com"),
        max_body_chars=0,
        include_body=False,
    )
    recipients = reply_recipients(original, self_address="me@example.com", reply_all=False)
    assert recipients["cc"] == []


def test_replying_to_yourself_still_produces_a_recipient():
    original = parse_message(
        make_message(sender="Me <me@example.com>", to="me@example.com"),
        max_body_chars=0,
        include_body=False,
    )
    recipients = reply_recipients(original, self_address="me@example.com", reply_all=False)
    assert recipients["to"] == ["me@example.com"]


def test_references_chain_is_bounded():
    original = parse_message(make_message(), max_body_chars=0, include_body=False)
    original["references"] = [f"<m{i}@example.com>" for i in range(200)]
    assert len(reply_headers(original)["references"]) <= 40


# --------------------------------------------------------------------------- #
# Draft operations through the service
# --------------------------------------------------------------------------- #


async def test_created_draft_has_the_expected_headers(service, gmail: FakeGmail):
    await service.drafts_create(
        alias="personal",
        to=["bob@example.com"],
        cc=["carol@example.com"],
        subject="Status update",
        body="All good.",
    )
    raw = gmail.bodies[-1]["message"]["raw"]
    message = _parsed(raw)
    assert message["To"] == "bob@example.com"
    assert message["Cc"] == "carol@example.com"
    assert message["Subject"] == "Status update"
    assert "All good." in _body_text(message)


async def test_drafts_list_fetches_metadata_for_real_gmail_stubs(
    service, gmail: FakeGmail
):
    created = await service.drafts_create(
        alias="personal",
        to=["bob@example.com"],
        subject="Listed subject",
        body="Listed body",
    )
    before = len(gmail.requests)

    result = await service.drafts_list(alias="personal")

    assert result["count"] == 1
    assert result["drafts"][0]["draft_id"] == created["draft_id"]
    assert result["drafts"][0]["subject"] == "Listed subject"
    assert result["drafts"][0]["to"] == [{"name": "", "email": "bob@example.com"}]
    recent_paths = [path for _, path in gmail.requests[before:]]
    assert any(path.endswith(f"/drafts/{created['draft_id']}") for path in recent_paths)


async def test_reply_draft_carries_thread_id_and_threading_headers(service, gmail: FakeGmail):
    result = await service.drafts_reply(
        alias="personal", message_id="msg1", body="Sounds good."
    )
    payload = gmail.bodies[-1]["message"]
    assert payload["threadId"] == "thr1"

    message = _parsed(payload["raw"])
    assert message["In-Reply-To"] == "<parent@example.com>"
    assert "<parent@example.com>" in message["References"]
    assert message["Subject"].startswith("Re: ")
    assert result["in_reply_to_message_id"] == "msg1"
    assert result["sendable_by_gateway"] is False


async def test_reply_all_includes_other_participants(service, gmail: FakeGmail):
    gmail.messages["msg2"] = make_message(
        "msg2",
        sender="Alice <alice@example.com>",
        to="me@example.com, dave@example.com",
        cc="carol@example.com",
    )
    await service.drafts_reply(alias="personal", message_id="msg2", body="ack", reply_all=True)
    message = _parsed(gmail.bodies[-1]["message"]["raw"])
    assert message["To"] == "alice@example.com"
    assert "dave@example.com" in message["Cc"]
    assert "carol@example.com" in message["Cc"]
    assert "me@example.com" not in (message["To"] + (message["Cc"] or ""))


async def test_update_preserves_untouched_fields(service, gmail: FakeGmail):
    created = await service.drafts_create(
        alias="personal", to=["bob@example.com"], subject="Original", body="First draft"
    )
    await service.drafts_update(alias="personal", draft_id=created["draft_id"], body="Second draft")

    message = _parsed(gmail.bodies[-1]["message"]["raw"])
    assert message["To"] == "bob@example.com"
    assert message["Subject"] == "Original"
    assert "Second draft" in _body_text(message)


async def test_update_can_clear_a_recipient_field(service, gmail: FakeGmail):
    created = await service.drafts_create(
        alias="personal", to=["bob@example.com"], cc=["carol@example.com"], body="x"
    )
    await service.drafts_update(alias="personal", draft_id=created["draft_id"], cc=[])
    assert _parsed(gmail.bodies[-1]["message"]["raw"])["Cc"] is None


async def test_updating_a_reply_keeps_it_in_its_thread(service, gmail: FakeGmail):
    created = await service.drafts_reply(alias="personal", message_id="msg1", body="draft one")
    await service.drafts_update(alias="personal", draft_id=created["draft_id"], body="draft two")

    payload = gmail.bodies[-1]["message"]
    assert payload["threadId"] == "thr1"
    assert _parsed(payload["raw"])["In-Reply-To"] == "<parent@example.com>"


async def test_draft_update_uses_put_not_delete_and_recreate(service, gmail: FakeGmail):
    created = await service.drafts_create(alias="personal", to=["b@example.com"], body="x")
    before = len(gmail.requests)
    await service.drafts_update(alias="personal", draft_id=created["draft_id"], body="y")
    methods = [method for method, _ in gmail.requests[before:]]
    assert "PUT" in methods
    assert "DELETE" not in methods


async def test_reply_to_a_message_without_a_thread_is_rejected(service, gmail: FakeGmail):
    orphan = make_message("msg9")
    orphan["threadId"] = None
    gmail.messages["msg9"] = orphan
    with pytest.raises(GatewayError):
        await service.drafts_reply(alias="personal", message_id="msg9", body="hi")
