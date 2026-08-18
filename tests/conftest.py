"""Test fixtures: an in-memory Gmail that records every request it receives.

The recorder is the point. Several tests assert not just that an operation was
refused, but that *no HTTP request to a forbidden endpoint was ever issued* --
which is the property that actually matters.
"""

from __future__ import annotations

import base64
import re
import time
from pathlib import Path
from typing import Any

import httpx
import pytest

from gmail_mcp_gateway.accounts import Account, AccountStore, Credential
from gmail_mcp_gateway.audit import AuditLog
from gmail_mcp_gateway.config import Config, Limits
from gmail_mcp_gateway.db import Database
from gmail_mcp_gateway.gmail.client import GmailClient
from gmail_mcp_gateway.idempotency import IdempotencyCache
from gmail_mcp_gateway.security.paths import AttachmentVault
from gmail_mcp_gateway.security.ratelimit import RateLimiter
from gmail_mcp_gateway.service import GmailService

#: Any request path matching one of these means the security boundary failed.
FORBIDDEN_PATH_PATTERNS = [
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"/send\b",
        r"/trash\b",
        r"/untrash\b",
        r"/settings\b",
        r"/batchDelete\b",
        r"/import\b",
        r"/insert\b",
        r"/watch\b",
        r"/stop\b",
    )
]


def _b64(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii").rstrip("=")


def make_message(
    message_id: str = "msg1",
    *,
    thread_id: str = "thr1",
    subject: str = "Quarterly report",
    sender: str = "Alice Smith <alice@example.com>",
    to: str = "me@example.com",
    cc: str = "",
    labels: list[str] | None = None,
    body_text: str = "Here is the report you asked for.",
    body_html: str | None = None,
    attachments: list[dict[str, Any]] | None = None,
    message_id_header: str = "<parent@example.com>",
    references: str = "",
) -> dict[str, Any]:
    headers = [
        {"name": "Subject", "value": subject},
        {"name": "From", "value": sender},
        {"name": "To", "value": to},
        {"name": "Date", "value": "Tue, 12 Aug 2025 10:04:00 +0000"},
        {"name": "Message-ID", "value": message_id_header},
    ]
    if cc:
        headers.append({"name": "Cc", "value": cc})
    if references:
        headers.append({"name": "References", "value": references})

    parts: list[dict[str, Any]] = [
        {
            "partId": "0",
            "mimeType": "text/plain",
            "filename": "",
            "headers": [{"name": "Content-Type", "value": "text/plain; charset=UTF-8"}],
            "body": {"size": len(body_text), "data": _b64(body_text)},
        }
    ]
    if body_html is not None:
        parts.append(
            {
                "partId": "1",
                "mimeType": "text/html",
                "filename": "",
                "headers": [{"name": "Content-Type", "value": "text/html; charset=UTF-8"}],
                "body": {"size": len(body_html), "data": _b64(body_html)},
            }
        )
    for index, attachment in enumerate(attachments or []):
        parts.append(
            {
                "partId": str(len(parts)),
                "mimeType": attachment.get("mime_type", "application/pdf"),
                "filename": attachment["filename"],
                "headers": [
                    {"name": "Content-Disposition", "value": f"attachment; filename=\"{attachment['filename']}\""}
                ],
                "body": {
                    "size": attachment.get("size", 1234),
                    "attachmentId": attachment.get("attachment_id", f"att{index}"),
                },
            }
        )

    return {
        "id": message_id,
        "threadId": thread_id,
        "labelIds": labels if labels is not None else ["INBOX", "UNREAD"],
        "snippet": body_text[:80],
        "internalDate": "1755000240000",
        "sizeEstimate": 4096,
        "payload": {
            "mimeType": "multipart/mixed",
            "filename": "",
            "headers": headers,
            "body": {"size": 0},
            "parts": parts,
        },
    }


class FakeGmail:
    """Minimal Gmail API over httpx.MockTransport, with request recording."""

    def __init__(self) -> None:
        self.requests: list[tuple[str, str]] = []
        self.request_urls: list[str] = []
        self.bodies: list[dict[str, Any]] = []
        self.messages: dict[str, dict[str, Any]] = {"msg1": make_message()}
        self.threads: dict[str, dict[str, Any]] = {
            "thr1": {"id": "thr1", "historyId": "1", "snippet": "…", "messages": [self.messages["msg1"]]}
        }
        self.drafts: dict[str, dict[str, Any]] = {}
        self.attachments: dict[str, bytes] = {"att0": b"%PDF-1.4 fake pdf bytes"}
        self.labels = [
            {"id": "INBOX", "name": "INBOX", "type": "system"},
            {"id": "UNREAD", "name": "UNREAD", "type": "system"},
            {"id": "TRASH", "name": "TRASH", "type": "system"},
            {"id": "SPAM", "name": "SPAM", "type": "system"},
            {"id": "STARRED", "name": "STARRED", "type": "system"},
            {"id": "Label_7", "name": "Receipts", "type": "user"},
            {"id": "Label_9", "name": "Follow up", "type": "user"},
        ]
        self.next_draft = 1
        #: Force the next N responses to this status, for retry tests.
        self.force_status: list[int] = []

    # -- helpers ---------------------------------------------------------

    def assert_no_forbidden_requests(self) -> None:
        for method, path in self.requests:
            for pattern in FORBIDDEN_PATH_PATTERNS:
                assert not pattern.search(path), f"forbidden request issued: {method} {path}"
            assert method in {"GET", "POST", "PUT"}, f"forbidden method: {method} {path}"

    def paths(self) -> list[str]:
        return [path for _, path in self.requests]

    # -- transport -------------------------------------------------------

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        method = request.method
        self.requests.append((method, path))
        self.request_urls.append(str(request.url))

        if self.force_status:
            status = self.force_status.pop(0)
            return httpx.Response(status, json={"error": {"message": "forced", "errors": [{"reason": "backendError"}]}})

        body: dict[str, Any] = {}
        if request.content:
            import json as _json

            body = _json.loads(request.content)
            self.bodies.append(body)

        base = "/gmail/v1/users/me"

        if path == f"{base}/profile":
            return httpx.Response(
                200,
                json={"emailAddress": "me@example.com", "messagesTotal": 42, "threadsTotal": 20},
            )

        if path == f"{base}/labels":
            return httpx.Response(200, json={"labels": self.labels})

        if path == f"{base}/messages" and method == "GET":
            return httpx.Response(
                200,
                json={
                    "messages": [
                        {"id": mid, "threadId": msg["threadId"]}
                        for mid, msg in self.messages.items()
                    ],
                    "resultSizeEstimate": len(self.messages),
                },
            )

        # Checked before the generic /messages/{id} route, which would otherwise
        # shadow it.
        if path == f"{base}/messages/batchModify" and method == "POST":
            for message_id in body.get("ids", []):
                message = self.messages.get(message_id)
                if message is None:
                    continue
                labels = set(message["labelIds"])
                labels |= set(body.get("addLabelIds") or [])
                labels -= set(body.get("removeLabelIds") or [])
                message["labelIds"] = sorted(labels)
            return httpx.Response(204)

        if (match := re.fullmatch(rf"{base}/messages/([^/]+)", path)) and method == "GET":
            message = self.messages.get(match.group(1))
            if message is None:
                return httpx.Response(404, json={"error": {"message": "Not Found"}})
            return httpx.Response(200, json=message)

        if match := re.fullmatch(rf"{base}/messages/([^/]+)/attachments/([^/]+)", path):
            data = self.attachments.get(match.group(2))
            if data is None:
                return httpx.Response(404, json={"error": {"message": "Not Found"}})
            return httpx.Response(
                200,
                json={
                    "size": len(data),
                    "data": base64.urlsafe_b64encode(data).decode("ascii").rstrip("="),
                },
            )

        if match := re.fullmatch(rf"{base}/threads/([^/]+)/modify", path):
            return httpx.Response(200, json={"id": match.group(1)})

        if match := re.fullmatch(rf"{base}/threads/([^/]+)", path):
            thread = self.threads.get(match.group(1))
            if thread is None:
                return httpx.Response(404, json={"error": {"message": "Not Found"}})
            return httpx.Response(200, json=thread)

        if path == f"{base}/drafts" and method == "GET":
            # Gmail returns stubs here; clients must call drafts.get for fields.
            return httpx.Response(
                200,
                json={
                    "drafts": [
                        {
                            "id": draft["id"],
                            "message": {
                                "id": draft["message"]["id"],
                                "threadId": draft["message"]["threadId"],
                            },
                        }
                        for draft in self.drafts.values()
                    ]
                },
            )

        if path == f"{base}/drafts" and method == "POST":
            draft_id = f"draft{self.next_draft}"
            self.next_draft += 1
            message = body.get("message", {})
            record = {
                "id": draft_id,
                "message": {
                    "id": f"m_{draft_id}",
                    "threadId": message.get("threadId", f"t_{draft_id}"),
                    "labelIds": ["DRAFT"],
                    "raw": message.get("raw"),
                    "payload": self._payload_from_raw(message.get("raw", "")),
                },
            }
            self.drafts[draft_id] = record
            return httpx.Response(200, json=record)

        if match := re.fullmatch(rf"{base}/drafts/([^/]+)", path):
            draft_id = match.group(1)
            if method == "PUT":
                message = body.get("message", {})
                record = self.drafts.get(draft_id, {"id": draft_id, "message": {}})
                record["message"] = {
                    "id": f"m_{draft_id}",
                    "threadId": message.get("threadId", f"t_{draft_id}"),
                    "labelIds": ["DRAFT"],
                    "raw": message.get("raw"),
                    "payload": self._payload_from_raw(message.get("raw", "")),
                }
                self.drafts[draft_id] = record
                return httpx.Response(200, json=record)
            record = self.drafts.get(draft_id)
            if record is None:
                return httpx.Response(404, json={"error": {"message": "Not Found"}})
            return httpx.Response(200, json=record)

        return httpx.Response(
            404, json={"error": {"message": f"fake gmail has no route for {method} {path}"}}
        )

    @staticmethod
    def _payload_from_raw(raw: str) -> dict[str, Any]:
        """Turn a stored draft back into a Gmail-shaped payload."""
        import email

        if not raw:
            return {"headers": [], "body": {"size": 0}}
        decoded = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        parsed = email.message_from_bytes(decoded)
        text = ""
        if parsed.is_multipart():
            for part in parsed.walk():
                if part.get_content_type() == "text/plain":
                    payload = part.get_payload(decode=True)
                    text = payload.decode("utf-8", "replace") if isinstance(payload, bytes) else ""
                    break
        else:
            payload = parsed.get_payload(decode=True)
            text = payload.decode("utf-8", "replace") if isinstance(payload, bytes) else ""
        return {
            "mimeType": "text/plain",
            "filename": "",
            "headers": [{"name": key, "value": value} for key, value in parsed.items()],
            "body": {"size": len(text), "data": _b64(text)},
        }


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return Config(
        config_dir=tmp_path / "config",
        data_dir=tmp_path / "data",
        secrets_dir=tmp_path / "secrets",
        limits=Limits(max_batch_ids=10, rate_per_minute=6000, rate_burst=500),
    )


@pytest.fixture
def oauth_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GMAIL_MCP_OAUTH_CLIENT_ID", "test.apps.googleusercontent.com")
    monkeypatch.setenv("GMAIL_MCP_OAUTH_CLIENT_SECRET", "GOCSPX-test-secret")
    monkeypatch.delenv("GMAIL_MCP_MASTER_KEY", raising=False)


@pytest.fixture
def store(config: Config, oauth_env: None) -> AccountStore:
    return AccountStore(config)


@pytest.fixture
def account(store: AccountStore) -> Account:
    created = store.create("personal")
    store.save_credential(
        created,
        Credential(
            refresh_token="1//fake-refresh-token",
            client_id="test.apps.googleusercontent.com",
            scopes=["https://www.googleapis.com/auth/gmail.modify"],
            access_token="ya29.fake-access-token",
            # Far future so no refresh is attempted during tests.
            access_token_expires_at=time.time() + 86_400,
        ),
    )
    store.mark_authorized(
        "personal", "me@example.com", ["https://www.googleapis.com/auth/gmail.modify"]
    )
    return store.get("personal")


@pytest.fixture
def readonly_account(store: AccountStore) -> Account:
    created = store.create("archive", read_only=True)
    store.save_credential(
        created,
        Credential(
            refresh_token="1//fake-refresh-token-ro",
            client_id="test.apps.googleusercontent.com",
            scopes=["https://www.googleapis.com/auth/gmail.readonly"],
            access_token="ya29.fake-access-token-ro",
            access_token_expires_at=time.time() + 86_400,
        ),
    )
    store.mark_authorized(
        "archive", "ro@example.com", ["https://www.googleapis.com/auth/gmail.readonly"]
    )
    return store.get("archive")


@pytest.fixture
def gmail() -> FakeGmail:
    return FakeGmail()


@pytest.fixture
def service(
    config: Config, store: AccountStore, account: Account, gmail: FakeGmail, oauth_env: None
) -> GmailService:
    from gmail_mcp_gateway.auth.oauth import OAuthClient

    http_client = httpx.AsyncClient(transport=httpx.MockTransport(gmail.handler))
    database = Database(config.db_path)
    database.initialize()

    client = GmailClient(
        store=store,
        oauth_client=OAuthClient.load(config),
        limits=config.limits,
        limiter=RateLimiter(
            rate_per_minute=config.limits.rate_per_minute,
            burst=config.limits.rate_burst,
            max_concurrency=config.limits.max_concurrency,
        ),
        http_client=http_client,
    )
    return GmailService(
        config=config,
        store=store,
        client=client,
        audit=AuditLog(database, retention_days=90),
        idempotency=IdempotencyCache(database, ttl_seconds=3600),
        vault=AttachmentVault(config.attachments_dir, max_bytes=config.limits.max_attachment_bytes),
    )


@pytest.fixture
def audit(config: Config) -> AuditLog:
    database = Database(config.db_path)
    database.initialize()
    return AuditLog(database, retention_days=90)
