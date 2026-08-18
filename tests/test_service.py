"""Service behaviour: reads, mutations, limits, reliability, and auditing."""

from __future__ import annotations

import asyncio
import base64
import time

import pytest

from gmail_mcp_gateway.accounts import STATUS_NEEDS_REAUTH, Credential
from gmail_mcp_gateway.errors import ErrorCode, GatewayError

from .conftest import FakeGmail, make_message

# --------------------------------------------------------------------------- #
# Accounts
# --------------------------------------------------------------------------- #


def test_accounts_list_reports_capabilities(service):
    result = service.accounts_list()
    entry = result["accounts"][0]
    assert entry["alias"] == "personal"
    assert entry["email_address"] == "me@example.com"
    assert entry["can_mutate"] is True
    assert "drafts_create" in entry["granted_capabilities"]
    assert "send" not in entry["granted_capabilities"]


async def test_accounts_status_performs_a_live_check(service):
    result = await service.accounts_status("personal")
    entry = result["accounts"][0]
    assert entry["live_check"]["ok"] is True
    assert entry["messages_total"] == 42


def test_read_only_account_advertises_no_write_capability(service, readonly_account):
    entry = next(a for a in service.accounts_list()["accounts"] if a["alias"] == "archive")
    assert entry["can_mutate"] is False
    assert "archive" not in entry["granted_capabilities"]
    assert "drafts_create" not in entry["granted_capabilities"]
    assert "search" in entry["granted_capabilities"]


async def test_unknown_account_is_rejected_before_any_request(service, gmail: FakeGmail):
    with pytest.raises(GatewayError) as info:
        await service.search(alias="nosuch")
    assert info.value.code is ErrorCode.UNKNOWN_ACCOUNT
    assert not gmail.requests


async def test_account_needing_reauth_is_refused_with_operator_instructions(service, store):
    store.set_status("personal", STATUS_NEEDS_REAUTH, "token revoked")
    with pytest.raises(GatewayError) as info:
        await service.get_message(alias="personal", message_id="msg1")
    assert info.value.code is ErrorCode.NEEDS_REAUTH
    assert "accounts auth personal" in info.value.message


@pytest.mark.parametrize("alias", ["../etc", "Personal", "a" * 40, "", "has space", "x;y"])
async def test_malformed_account_aliases_are_rejected(service, alias):
    with pytest.raises(GatewayError):
        await service.search(alias=alias)


# --------------------------------------------------------------------------- #
# Reading
# --------------------------------------------------------------------------- #


async def test_search_returns_structured_metadata(service):
    result = await service.search(alias="personal", query="is:unread", detail="metadata")
    assert result["count"] == 1
    message = result["messages"][0]
    assert message["subject"] == "Quarterly report"
    assert message["from"]["email"] == "alice@example.com"
    assert message["is_unread"] is True
    assert "body" not in message
    assert result["content_is_untrusted"] is True


async def test_search_with_detail_ids_makes_no_per_message_request(service, gmail: FakeGmail):
    await service.search(alias="personal", detail="ids")
    assert not [p for p in gmail.paths() if p.endswith("/messages/msg1")]


async def test_search_with_detail_full_includes_bodies(service):
    result = await service.search(alias="personal", detail="full")
    assert "Here is the report" in result["messages"][0]["body"]["text"]


async def test_search_query_is_passed_through_to_gmail(service, gmail: FakeGmail):
    await service.search(alias="personal", query="from:alice has:attachment", detail="ids")
    request = next(url for url in gmail.request_urls if "/messages?" in url)
    assert "q=from%3Aalice+has%3Aattachment" in request
    # The validated query is echoed back so the caller can confirm it.
    result = await service.search(alias="personal", query="  is:unread  ", detail="ids")
    assert result["query"] == "is:unread"


async def test_oversized_query_is_rejected(service):
    with pytest.raises(GatewayError):
        await service.search(alias="personal", query="x" * 5000)


async def test_query_with_a_newline_is_rejected(service):
    with pytest.raises(GatewayError):
        await service.search(alias="personal", query="is:unread\nfrom:evil")


async def test_search_limit_is_capped(service):
    result = await service.search(alias="personal", limit=10_000, detail="ids")
    assert result["count"] <= service.limits.max_page_size


async def test_get_message_returns_full_metadata(service):
    result = await service.get_message(alias="personal", message_id="msg1")
    message = result["message"]
    assert message["thread_id"] == "thr1"
    assert message["timestamp"]["iso"].startswith("2025-")
    assert message["labels"]["ids"] == ["INBOX", "UNREAD"]
    assert message["body"]["text"].startswith("Here is the report")


async def test_get_thread_returns_every_message(service):
    result = await service.get_thread(alias="personal", thread_id="thr1")
    thread = result["thread"]
    assert thread["message_count"] == 1
    assert thread["subject"] == "Quarterly report"
    assert any(p["email"] == "alice@example.com" for p in thread["participants"])


async def test_missing_message_maps_to_not_found(service):
    with pytest.raises(GatewayError) as info:
        await service.get_message(alias="personal", message_id="nosuchmessage")
    assert info.value.code is ErrorCode.NOT_FOUND


# --------------------------------------------------------------------------- #
# Labels and inbox management
# --------------------------------------------------------------------------- #


async def test_labels_list_flags_unmodifiable_labels(service):
    result = await service.labels_list(alias="personal")
    by_id = {entry["id"]: entry for entry in result["labels"]}
    assert by_id["TRASH"]["modifiable_by_gateway"] is False
    assert by_id["SPAM"]["modifiable_by_gateway"] is False
    assert by_id["Label_7"]["modifiable_by_gateway"] is True


async def test_archive_removes_only_the_inbox_label(service, gmail: FakeGmail):
    result = await service.archive(alias="personal", message_ids=["msg1"])
    assert result["labels_removed"] == ["INBOX"]
    body = gmail.bodies[-1]
    assert body["removeLabelIds"] == ["INBOX"]
    assert "addLabelIds" not in body
    assert gmail.messages["msg1"]["labelIds"] == ["UNREAD"]


async def test_mark_read_and_unread_round_trip(service, gmail: FakeGmail):
    await service.mark_read(alias="personal", message_ids=["msg1"])
    assert "UNREAD" not in gmail.messages["msg1"]["labelIds"]
    await service.mark_unread(alias="personal", message_ids=["msg1"])
    assert "UNREAD" in gmail.messages["msg1"]["labelIds"]


async def test_labels_can_be_applied_by_display_name(service, gmail: FakeGmail):
    result = await service.labels_add(alias="personal", labels=["Receipts"], message_ids=["msg1"])
    assert result["labels_added"] == ["Label_7"]
    assert gmail.bodies[-1]["addLabelIds"] == ["Label_7"]


async def test_unknown_label_is_rejected_with_a_sample_of_known_ones(service):
    with pytest.raises(GatewayError) as info:
        await service.labels_add(alias="personal", labels=["Nonexistent"], message_ids=["msg1"])
    assert info.value.code is ErrorCode.NOT_FOUND
    assert "known_labels_sample" in info.value.details


async def test_threads_use_per_thread_modify(service, gmail: FakeGmail):
    result = await service.archive(alias="personal", thread_ids=["thr1"])
    assert result["thread_ids"] == ["thr1"]
    assert any(p.endswith("/threads/thr1/modify") for p in gmail.paths())


async def test_batch_over_the_limit_is_rejected(service, gmail: FakeGmail):
    too_many = [f"msg{i}" for i in range(service.limits.max_batch_ids + 1)]
    with pytest.raises(GatewayError) as info:
        await service.archive(alias="personal", message_ids=too_many)
    assert info.value.code is ErrorCode.BATCH_TOO_LARGE
    assert not gmail.bodies


async def test_mutation_without_targets_is_rejected(service):
    with pytest.raises(GatewayError):
        await service.archive(alias="personal")


async def test_duplicate_ids_in_a_batch_are_collapsed(service, gmail: FakeGmail):
    result = await service.archive(alias="personal", message_ids=["msg1", "msg1", "msg1"])
    assert result["message_ids"] == ["msg1"]


# --------------------------------------------------------------------------- #
# Attachments
# --------------------------------------------------------------------------- #


@pytest.fixture
def message_with_attachment(gmail: FakeGmail):
    gmail.messages["msg1"] = make_message(
        attachments=[{"filename": "report.pdf", "attachment_id": "att0", "size": 23}]
    )
    return gmail


async def test_attachments_list_describes_without_downloading(service, message_with_attachment):
    result = await service.attachments_list(alias="personal", message_id="msg1")
    assert result["count"] == 1
    assert result["attachments"][0]["filename"] == "report.pdf"
    assert not any("/attachments/" in p for p in message_with_attachment.paths())


async def test_small_attachment_is_returned_inline(service, message_with_attachment):
    result = await service.attachments_get(
        alias="personal", message_id="msg1", attachment_id="att0"
    )
    assert result["delivery"] == "inline"
    assert base64.b64decode(result["content_base64"]).startswith(b"%PDF")
    assert result["executed"] is False


async def test_attachment_can_be_written_to_the_confined_directory(
    service, message_with_attachment, config
):
    result = await service.attachments_get(
        alias="personal", message_id="msg1", attachment_id="att0", mode="file"
    )
    assert result["delivery"] == "file"
    path = config.attachments_dir.resolve()
    assert str(path) in result["path"]
    assert open(result["path"], "rb").read().startswith(b"%PDF")


async def test_attachment_filename_hint_cannot_escape_the_directory(
    service, message_with_attachment, config
):
    result = await service.attachments_get(
        alias="personal",
        message_id="msg1",
        attachment_id="att0",
        mode="file",
        filename_hint="../../../../tmp/pwned.sh",
    )
    written = result["path"]
    assert ".." not in written
    assert written.startswith(str(config.attachments_dir.resolve()))
    assert "pwned" in written  # the name survives; the path does not


async def test_attachment_from_another_message_is_refused(service, message_with_attachment):
    with pytest.raises(GatewayError) as info:
        await service.attachments_get(
            alias="personal", message_id="msg1", attachment_id="not-in-this-message"
        )
    assert info.value.code is ErrorCode.NOT_FOUND


async def test_attachment_over_the_size_limit_is_refused(service, gmail: FakeGmail):
    gmail.messages["msg1"] = make_message(
        attachments=[
            {"filename": "huge.bin", "attachment_id": "att0", "size": 999_999_999}
        ]
    )
    with pytest.raises(GatewayError) as info:
        await service.attachments_get(alias="personal", message_id="msg1", attachment_id="att0")
    assert info.value.code is ErrorCode.TOO_LARGE


async def test_inline_mode_refuses_an_oversized_attachment(service, gmail: FakeGmail):
    service.limits = type(service.limits)(max_inline_attachment_bytes=4)
    gmail.messages["msg1"] = make_message(
        attachments=[{"filename": "r.pdf", "attachment_id": "att0", "size": 23}]
    )
    with pytest.raises(GatewayError) as info:
        await service.attachments_get(
            alias="personal", message_id="msg1", attachment_id="att0", mode="inline"
        )
    assert info.value.code is ErrorCode.TOO_LARGE


# --------------------------------------------------------------------------- #
# Reliability
# --------------------------------------------------------------------------- #


async def test_transient_upstream_errors_are_retried(service, gmail: FakeGmail, monkeypatch):
    monkeypatch.setattr("asyncio.sleep", lambda _: _noop())
    gmail.force_status = [503, 500]
    result = await service.get_message(alias="personal", message_id="msg1")
    assert result["message"]["id"] == "msg1"
    assert len(gmail.requests) >= 3


async def _noop():
    return None


async def test_retries_stop_at_the_configured_limit(service, gmail: FakeGmail, monkeypatch):
    monkeypatch.setattr("asyncio.sleep", lambda _: _noop())
    gmail.force_status = [503] * 20
    with pytest.raises(GatewayError) as info:
        await service.get_message(alias="personal", message_id="msg1")
    assert info.value.code is ErrorCode.UPSTREAM_UNAVAILABLE
    assert info.value.retryable is True
    assert len(gmail.requests) == service.limits.max_attempts


async def test_rate_limit_returns_a_retry_hint(service, store, account, monkeypatch):
    from gmail_mcp_gateway.security.ratelimit import RateLimiter

    # The first read costs two tokens: the message plus the label index, which
    # is then cached. The second read has only its own token to pay with.
    service._client._limiter = RateLimiter(rate_per_minute=60, burst=2, max_concurrency=4)
    await service.get_message(alias="personal", message_id="msg1")
    with pytest.raises(GatewayError) as info:
        await service.get_message(alias="personal", message_id="msg1")
    assert info.value.code is ErrorCode.RATE_LIMITED
    assert info.value.retry_after_seconds is not None
    assert info.value.retry_after_seconds > 0


async def test_expired_access_token_triggers_one_refresh(service, gmail: FakeGmail, store, account, monkeypatch):
    refreshed: list[str] = []

    def fake_refresh(client, credential):
        refreshed.append("called")
        credential.access_token = "ya29.new-token"
        credential.access_token_expires_at = time.time() + 3600
        return credential

    monkeypatch.setattr("gmail_mcp_gateway.gmail.client.refresh_access_token", fake_refresh)
    store.save_credential(
        account,
        Credential(
            refresh_token="1//fake",
            client_id="test",
            scopes=["https://www.googleapis.com/auth/gmail.modify"],
            access_token="ya29.expired",
            access_token_expires_at=time.time() - 10,
        ),
    )
    service._client.forget("personal")

    await service.get_message(alias="personal", message_id="msg1")
    assert refreshed == ["called"]


async def test_refresh_failure_marks_the_account_for_reauth(service, store, account, monkeypatch):
    def failing_refresh(client, credential):
        raise GatewayError(ErrorCode.NEEDS_REAUTH, "invalid_grant")

    monkeypatch.setattr("gmail_mcp_gateway.gmail.client.refresh_access_token", failing_refresh)
    store.save_credential(
        account,
        Credential(
            refresh_token="1//revoked",
            client_id="test",
            scopes=["https://www.googleapis.com/auth/gmail.modify"],
            access_token=None,
            access_token_expires_at=0,
        ),
    )
    service._client.forget("personal")

    with pytest.raises(GatewayError) as info:
        await service.get_message(alias="personal", message_id="msg1")
    assert info.value.code is ErrorCode.NEEDS_REAUTH
    assert store.get("personal").status == STATUS_NEEDS_REAUTH


async def test_network_failure_is_reported_without_internal_detail(config, store, account, oauth_env):
    import httpx

    from gmail_mcp_gateway.audit import AuditLog
    from gmail_mcp_gateway.auth.oauth import OAuthClient
    from gmail_mcp_gateway.db import Database
    from gmail_mcp_gateway.gmail.client import GmailClient
    from gmail_mcp_gateway.idempotency import IdempotencyCache
    from gmail_mcp_gateway.security.paths import AttachmentVault
    from gmail_mcp_gateway.security.ratelimit import RateLimiter
    from gmail_mcp_gateway.service import GmailService

    def explode(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused to 10.0.0.1:443")

    database = Database(config.db_path)
    database.initialize()
    service = GmailService(
        config=config,
        store=store,
        client=GmailClient(
            store=store,
            oauth_client=OAuthClient.load(config),
            limits=config.limits,
            limiter=RateLimiter(rate_per_minute=6000, burst=500, max_concurrency=4),
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(explode)),
        ),
        audit=AuditLog(database),
        idempotency=IdempotencyCache(database, ttl_seconds=60),
        vault=AttachmentVault(config.attachments_dir, max_bytes=1000),
    )
    with pytest.raises(GatewayError) as info:
        await service.get_message(alias="personal", message_id="msg1")
    assert info.value.code is ErrorCode.NETWORK_ERROR
    assert "10.0.0.1" not in info.value.message


# --------------------------------------------------------------------------- #
# Idempotency and auditing
# --------------------------------------------------------------------------- #


async def test_repeated_request_id_does_not_act_twice(service, gmail: FakeGmail):
    first = await service.drafts_create(
        alias="personal", to=["b@example.com"], body="hi", client_request_id="req-1"
    )
    creates_before = len([p for p in gmail.paths() if p.endswith("/drafts")])

    second = await service.drafts_create(
        alias="personal", to=["b@example.com"], body="hi", client_request_id="req-1"
    )
    creates_after = len([p for p in gmail.paths() if p.endswith("/drafts")])

    assert second["draft_id"] == first["draft_id"]
    assert second["deduplicated"] is True
    assert creates_after == creates_before


async def test_concurrent_request_id_does_not_act_twice(service, gmail: FakeGmail, monkeypatch):
    original_call = service._client.call
    mutation_started = asyncio.Event()
    arrivals = 0

    async def delayed_call(account, endpoint, **kwargs):
        nonlocal arrivals
        if endpoint.name == "users.drafts.create":
            arrivals += 1
            mutation_started.set()
            await asyncio.sleep(0)
        return await original_call(account, endpoint, **kwargs)

    monkeypatch.setattr(service._client, "call", delayed_call)
    results = await asyncio.gather(
        service.drafts_create(
            alias="personal", to=["b@example.com"], body="hi", client_request_id="req-race"
        ),
        service.drafts_create(
            alias="personal", to=["b@example.com"], body="hi", client_request_id="req-race"
        ),
    )

    assert mutation_started.is_set()
    assert arrivals == 1
    assert results[0]["draft_id"] == results[1]["draft_id"]
    assert sum(bool(result.get("deduplicated")) for result in results) == 1


async def test_reusing_a_request_id_with_different_arguments_is_an_error(service):
    await service.drafts_create(
        alias="personal", to=["b@example.com"], body="hi", client_request_id="req-2"
    )
    with pytest.raises(GatewayError) as info:
        await service.drafts_create(
            alias="personal", to=["b@example.com"], body="DIFFERENT", client_request_id="req-2"
        )
    assert info.value.code is ErrorCode.INVALID_INPUT


async def test_successful_mutation_is_audited(service, audit):
    await service.archive(alias="personal", message_ids=["msg1"])
    events = audit.recent(limit=10)
    event = next(e for e in events if e.operation == "archive")
    assert event.account == "personal"
    assert event.outcome == "success"
    assert event.target_ids == ["msg1"]
    assert event.duration_ms is not None


async def test_refused_mutation_is_audited_as_denied(service, audit):
    with pytest.raises(GatewayError):
        await service.labels_add(alias="personal", labels=["TRASH"], message_ids=["msg1"])
    event = next(e for e in audit.recent(limit=20) if e.operation == "labels_add")
    assert event.outcome == "denied"
    assert event.target_ids == ["msg1"]
    assert event.error_code == str(ErrorCode.FORBIDDEN_LABEL)


async def test_audit_never_records_message_bodies(service, audit):
    await service.drafts_create(
        alias="personal",
        to=["b@example.com"],
        subject="Very Secret Subject",
        body="TOP SECRET BODY CONTENT",
    )
    blob = repr([e.to_dict() for e in audit.recent(limit=10)])
    assert "TOP SECRET BODY CONTENT" not in blob
    assert "Very Secret Subject" not in blob


async def test_reads_are_not_audited_as_mutations(service, audit):
    await service.get_message(alias="personal", message_id="msg1")
    await service.search(alias="personal", detail="ids")
    assert audit.recent(limit=10) == []
