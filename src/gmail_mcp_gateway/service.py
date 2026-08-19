"""The supported operations, and nothing else.

This layer is the complete list of things the gateway can do to a mailbox. Each
method maps onto allowlisted endpoints in :mod:`.gmail.allowlist` and returns a
structure ready for an MCP client. There is no passthrough method, no method
that accepts an endpoint or URL, and no way to compose these primitives into
sending, trashing, or deleting mail.

Mutations additionally run through:

  * :func:`.gmail.labels.validate_label_ids` -- blocks TRASH and SPAM,
  * :class:`.idempotency.IdempotencyCache` -- suppresses duplicate requests,
  * :class:`.audit.AuditLog` -- records account, time, operation, ids, outcome.
"""

from __future__ import annotations

import asyncio
import base64
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, Awaitable, Callable, Iterable

from .accounts import STATUS_ACTIVE, Account, AccountStore
from .audit import OUTCOME_DENIED, OUTCOME_FAILURE, OUTCOME_SUCCESS, AuditLog
from .config import Config
from .errors import ErrorCode, GatewayError
from .gmail import allowlist as ep
from .gmail.client import GmailClient
from .gmail.compose import build_draft_mime, reply_headers, reply_recipients
from .gmail.labels import (
    FORBIDDEN_LABELS,
    MUTABLE_SYSTEM_LABELS,
    assert_modify_body_safe,
    validate_label_ids,
)
from .gmail.parse import parse_message, parse_thread, sanitize_filename, sanitize_text
from .idempotency import IdempotencyCache, fingerprint
from .logging_setup import get_logger
from .security.paths import AttachmentVault
from .security.validate import (
    MAX_SUBJECT_CHARS,
    validate_body_text,
    validate_header_text,
    validate_id_batch,
    validate_recipients,
    validate_search_query,
)

_log = get_logger("service")

#: Headers requested when a message is fetched in metadata form.
_METADATA_HEADERS = [
    "Subject",
    "From",
    "To",
    "Cc",
    "Bcc",
    "Reply-To",
    "Date",
    "Message-ID",
    "In-Reply-To",
    "References",
]

_LABEL_CACHE_TTL_SECONDS = 300.0


class GmailService:
    def __init__(
        self,
        *,
        config: Config,
        store: AccountStore,
        client: GmailClient,
        audit: AuditLog,
        idempotency: IdempotencyCache,
        vault: AttachmentVault,
    ) -> None:
        self.config = config
        self.limits = config.limits
        self._store = store
        self._client = client
        self._audit = audit
        self._idempotency = idempotency
        self._vault = vault
        self._label_cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}
        # Serialize calls sharing an idempotency key. Without this, two requests
        # arriving together can both miss the cache and perform the mutation.
        self._mutation_locks: dict[tuple[str, str, str], tuple[asyncio.Lock, int]] = {}
        self._mutation_locks_guard = asyncio.Lock()

    async def aclose(self) -> None:
        """Release the upstream HTTP connection pool."""
        await self._client.aclose()

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    def _account(self, alias: str) -> Account:
        account = self._store.get(alias)
        if account.status != STATUS_ACTIVE:
            raise GatewayError(
                ErrorCode.NEEDS_REAUTH,
                f"account '{alias}' is not authorized (status: {account.status}). "
                f"An operator must run: gmail-mcp-gateway accounts auth {alias}",
                details={"account": alias, "status": account.status},
            )
        return account

    def _require_mutable(self, account: Account) -> Account:
        if not account.can_mutate:
            raise GatewayError(
                ErrorCode.ACCOUNT_READ_ONLY,
                f"account '{account.alias}' was authorized read-only and cannot be modified",
                details={"account": account.alias},
            )
        return account

    @asynccontextmanager
    async def _mutation_lock(
        self, account: str, tool: str, request_id: str
    ) -> AsyncIterator[None]:
        """Serialize one idempotency key and discard idle locks.

        The reference count includes the current holder and queued callers, so
        cleanup cannot remove a lock while another request is waiting for it.
        """
        key = (account, tool, request_id)
        async with self._mutation_locks_guard:
            lock, users = self._mutation_locks.get(key, (asyncio.Lock(), 0))
            self._mutation_locks[key] = (lock, users + 1)
        try:
            async with lock:
                yield
        finally:
            async with self._mutation_locks_guard:
                current_lock, users = self._mutation_locks[key]
                if users == 1:
                    del self._mutation_locks[key]
                else:
                    self._mutation_locks[key] = (current_lock, users - 1)

    async def _mutate(
        self,
        *,
        account: Account,
        tool: str,
        operation: str,
        target_type: str,
        target_ids: Iterable[str],
        args: dict[str, Any],
        client_request_id: str | None,
        action: Callable[[], Awaitable[dict[str, Any]]],
        detail: str | None = None,
        principal: str | None = None,
    ) -> dict[str, Any]:
        """Run a mutation with concurrency-safe deduplication and auditing."""
        if client_request_id:
            async with self._mutation_lock(account.alias, tool, client_request_id):
                return await self._mutate_once(
                    account=account,
                    tool=tool,
                    operation=operation,
                    target_type=target_type,
                    target_ids=target_ids,
                    args=args,
                    client_request_id=client_request_id,
                    action=action,
                    detail=detail,
                    principal=principal,
                )
        return await self._mutate_once(
            account=account,
            tool=tool,
            operation=operation,
            target_type=target_type,
            target_ids=target_ids,
            args=args,
            client_request_id=None,
            action=action,
            detail=detail,
            principal=principal,
        )

    async def _mutate_once(
        self,
        *,
        account: Account,
        tool: str,
        operation: str,
        target_type: str,
        target_ids: Iterable[str],
        args: dict[str, Any],
        client_request_id: str | None,
        action: Callable[[], Awaitable[dict[str, Any]]],
        detail: str | None,
        principal: str | None,
    ) -> dict[str, Any]:
        ids = list(target_ids)
        args_hash = fingerprint({"tool": tool, **args})

        if client_request_id:
            cached = await asyncio.to_thread(
                self._idempotency.lookup,
                account=account.alias,
                tool=tool,
                key=client_request_id,
                args_fingerprint=args_hash,
            )
            if cached is not None:
                _log.info("deduplicated %s for account=%s", tool, account.alias)
                return cached

        started = time.monotonic()
        try:
            result = await action()
        except GatewayError as exc:
            await asyncio.to_thread(
                self._audit.record,
                tool=tool,
                operation=operation,
                outcome=OUTCOME_DENIED
                if exc.code
                in {
                    ErrorCode.FORBIDDEN_OPERATION,
                    ErrorCode.FORBIDDEN_LABEL,
                    ErrorCode.ACCOUNT_READ_ONLY,
                }
                else OUTCOME_FAILURE,
                account=account.alias,
                target_type=target_type,
                target_ids=ids,
                error_code=str(exc.code),
                detail=exc.message,
                duration_ms=int((time.monotonic() - started) * 1000),
                request_id=client_request_id,
                principal=principal,
            )
            raise

        await asyncio.to_thread(
            self._audit.record,
            tool=tool,
            operation=operation,
            outcome=OUTCOME_SUCCESS,
            account=account.alias,
            target_type=target_type,
            target_ids=ids or [str(i) for i in result.get("ids", [])],
            detail=detail,
            duration_ms=int((time.monotonic() - started) * 1000),
            request_id=client_request_id,
            principal=principal,
        )
        await asyncio.to_thread(self._store.touch_used, account.alias)

        if client_request_id:
            await asyncio.to_thread(
                self._idempotency.store,
                account=account.alias,
                tool=tool,
                key=client_request_id,
                args_fingerprint=args_hash,
                response=result,
            )
        return result

    async def _audit_preflight_failure(
        self,
        *,
        account: Account,
        tool: str,
        operation: str,
        target_ids: Iterable[str],
        error: GatewayError,
        principal: str | None,
        request_id: str | None,
    ) -> None:
        """Record a mutation rejected before its upstream action is built."""
        await asyncio.to_thread(
            self._audit.record,
            tool=tool,
            operation=operation,
            outcome=OUTCOME_DENIED
            if error.code
            in {
                ErrorCode.FORBIDDEN_OPERATION,
                ErrorCode.FORBIDDEN_LABEL,
                ErrorCode.ACCOUNT_READ_ONLY,
            }
            else OUTCOME_FAILURE,
            account=account.alias,
            target_type="message_or_thread",
            target_ids=target_ids,
            error_code=str(error.code),
            detail=error.message,
            request_id=request_id,
            principal=principal,
        )

    async def _label_index(self, account: Account) -> dict[str, str]:
        """Map label id -> display name, cached briefly per account."""
        labels = await self._labels_raw(account)
        return {str(label.get("id")): str(label.get("name", label.get("id"))) for label in labels}

    async def _labels_raw(self, account: Account) -> list[dict[str, Any]]:
        cached = self._label_cache.get(account.alias)
        now = time.monotonic()
        if cached and now - cached[0] < _LABEL_CACHE_TTL_SECONDS:
            return cached[1]
        body = await self._client.call(account, ep.LIST_LABELS)
        labels = [entry for entry in (body.get("labels") or []) if isinstance(entry, dict)]
        self._label_cache[account.alias] = (now, labels)
        return labels

    async def _resolve_labels(
        self, account: Account, values: Iterable[str], *, action: str, for_mutation: bool = True
    ) -> list[str]:
        """Accept label ids or display names; return validated label ids.

        ``for_mutation`` applies the TRASH/SPAM policy. It is off when resolving
        a *search filter*: reading what is in Trash or Spam is permitted (as is
        ``include_spam_trash``), while moving mail into either is not.
        """
        labels = await self._labels_raw(account)
        by_id = {str(entry.get("id")) for entry in labels}
        by_name = {str(entry.get("name", "")).lower(): str(entry.get("id")) for entry in labels}

        resolved: list[str] = []
        for raw in values:
            if not isinstance(raw, str) or not raw.strip():
                raise GatewayError(ErrorCode.INVALID_INPUT, "label must be a non-empty string")
            value = raw.strip()
            if value in by_id:
                resolved.append(value)
            elif value.lower() in by_name:
                resolved.append(by_name[value.lower()])
            elif value.upper() in MUTABLE_SYSTEM_LABELS or value.upper() in FORBIDDEN_LABELS:
                # Let the policy check below produce the precise refusal.
                resolved.append(value.upper())
            else:
                known = sorted(name for name in by_name if name)[:20]
                raise GatewayError(
                    ErrorCode.NOT_FOUND,
                    f"no label named or with id '{value}' in account '{account.alias}'",
                    details={"known_labels_sample": known},
                )
        if for_mutation:
            return validate_label_ids(resolved, action=action)
        # Read path: de-duplicate but apply no mutation policy.
        return list(dict.fromkeys(resolved))

    # ------------------------------------------------------------------ #
    # Accounts
    # ------------------------------------------------------------------ #

    def accounts_list(self) -> dict[str, Any]:
        accounts = self._store.list()
        return {
            "accounts": [account.public_view() for account in accounts],
            "count": len(accounts),
        }

    async def accounts_status(self, alias: str | None = None) -> dict[str, Any]:
        """Report authorization health. Performs a live check when possible."""
        accounts = [self._store.get(alias)] if alias else self._store.list()
        results: list[dict[str, Any]] = []

        for account in accounts:
            view = account.public_view()
            view["credential_present"] = self._store.has_credential(account)
            view["live_check"] = {"attempted": False, "ok": None, "error": None}

            if account.status == STATUS_ACTIVE and view["credential_present"]:
                view["live_check"]["attempted"] = True
                try:
                    profile = await self._client.call(account, ep.GET_PROFILE)
                except GatewayError as exc:
                    view["live_check"].update(ok=False, error=str(exc.code))
                else:
                    view["live_check"]["ok"] = True
                    view["messages_total"] = profile.get("messagesTotal")
                    view["threads_total"] = profile.get("threadsTotal")
                    if address := profile.get("emailAddress"):
                        view["email_address"] = address
            results.append(view)

        return {"accounts": results, "count": len(results)}

    # ------------------------------------------------------------------ #
    # Reading
    # ------------------------------------------------------------------ #

    async def search(
        self,
        *,
        alias: str,
        query: str | None = None,
        label_ids: list[str] | None = None,
        limit: int = 25,
        page_token: str | None = None,
        include_spam_trash: bool = False,
        detail: str = "metadata",
    ) -> dict[str, Any]:
        account = self._account(alias)
        if detail not in {"ids", "metadata", "full"}:
            raise GatewayError(
                ErrorCode.INVALID_INPUT, "detail must be one of: ids, metadata, full"
            )
        limit = max(1, min(limit, self.limits.max_page_size))
        if detail in {"metadata", "full"}:
            # Gmail's list endpoint returns only ids. Enriching each result needs
            # a separate upstream call, so bound the fan-out below the default
            # per-account burst budget. Callers needing a large mailbox scan use
            # detail="ids" and then fetch selected messages explicitly.
            limit = min(limit, self.limits.max_metadata_page_size)

        gmail_query = validate_search_query(query)
        resolved_labels = (
            await self._resolve_labels(
                account, label_ids, action="filter by", for_mutation=False
            )
            if label_ids
            else None
        )

        list_query: dict[str, Any] = {"includeSpamTrash": include_spam_trash}
        if gmail_query:
            list_query["q"] = gmail_query
        if resolved_labels:
            list_query["labelIds"] = resolved_labels
        if page_token:
            list_query["pageToken"] = ep.validate_path_param("page_token", page_token)

        stubs, next_token = await self._client.paginate(
            account, ep.LIST_MESSAGES, item_key="messages", query=list_query, limit=limit
        )
        ids = [str(stub["id"]) for stub in stubs if stub.get("id")]

        if detail == "ids":
            messages: list[dict[str, Any]] = [
                {"id": stub.get("id"), "thread_id": stub.get("threadId")} for stub in stubs
            ]
        else:
            label_names = await self._label_index(account)
            fetched = await asyncio.gather(
                *(self._fetch_message(account, mid, detail) for mid in ids)
            )
            messages = [
                parse_message(
                    raw,
                    max_body_chars=self.limits.max_body_chars,
                    include_body=(detail == "full"),
                    label_names=label_names,
                )
                for raw in fetched
            ]

        self._store.touch_used(account.alias)
        return {
            "account": account.alias,
            "query": gmail_query,
            "detail": detail,
            "messages": messages,
            "count": len(messages),
            "next_page_token": next_token,
            "has_more": bool(next_token),
            "content_is_untrusted": True,
        }

    async def _fetch_message(
        self, account: Account, message_id: str, detail: str
    ) -> dict[str, Any]:
        query: dict[str, Any] = {"format": "full" if detail == "full" else "metadata"}
        if detail != "full":
            query["metadataHeaders"] = _METADATA_HEADERS
        return await self._client.call(
            account, ep.GET_MESSAGE, path_params={"id": message_id}, query=query
        )

    async def get_message(
        self, *, alias: str, message_id: str, include_body: bool = True
    ) -> dict[str, Any]:
        account = self._account(alias)
        message_id = ep.validate_path_param("message_id", message_id)
        raw = await self._fetch_message(account, message_id, "full" if include_body else "metadata")
        label_names = await self._label_index(account)
        view = parse_message(
            raw,
            max_body_chars=self.limits.max_body_chars,
            include_body=include_body,
            label_names=label_names,
        )
        self._store.touch_used(account.alias)
        return {"account": account.alias, "message": view, "content_is_untrusted": True}

    async def get_thread(
        self, *, alias: str, thread_id: str, include_bodies: bool = True
    ) -> dict[str, Any]:
        account = self._account(alias)
        thread_id = ep.validate_path_param("thread_id", thread_id)
        query: dict[str, Any] = {"format": "full" if include_bodies else "metadata"}
        if not include_bodies:
            query["metadataHeaders"] = _METADATA_HEADERS
        raw = await self._client.call(
            account, ep.GET_THREAD, path_params={"id": thread_id}, query=query
        )
        label_names = await self._label_index(account)
        view = parse_thread(
            raw,
            max_body_chars=self.limits.max_body_chars,
            include_bodies=include_bodies,
            label_names=label_names,
        )
        self._store.touch_used(account.alias)
        return {"account": account.alias, "thread": view, "content_is_untrusted": True}

    # ------------------------------------------------------------------ #
    # Attachments
    # ------------------------------------------------------------------ #

    async def attachments_list(self, *, alias: str, message_id: str) -> dict[str, Any]:
        account = self._account(alias)
        message_id = ep.validate_path_param("message_id", message_id)
        raw = await self._fetch_message(account, message_id, "full")
        view = parse_message(raw, max_body_chars=0, include_body=False)
        return {
            "account": account.alias,
            "message_id": message_id,
            "attachments": view["attachments"],
            "count": len(view["attachments"]),
        }

    async def attachments_get(
        self,
        *,
        alias: str,
        message_id: str,
        attachment_id: str,
        mode: str = "auto",
        filename_hint: str | None = None,
    ) -> dict[str, Any]:
        """Fetch one attachment.

        ``mode`` selects delivery: ``inline`` returns base64 in the tool result,
        ``file`` writes into the gateway's attachment directory, ``auto`` picks
        inline for small files. The client never chooses a path -- only a name
        hint, which is sanitized and may be ignored.
        """
        account = self._account(alias)
        if mode not in {"auto", "inline", "file"}:
            raise GatewayError(ErrorCode.INVALID_INPUT, "mode must be auto, inline, or file")

        message_id = ep.validate_path_param("message_id", message_id)
        attachment_id = ep.validate_path_param("attachment_id", attachment_id)

        # Read the parent message first so the attachment's real name, type, and
        # size come from the message structure rather than from the client.
        raw_message = await self._fetch_message(account, message_id, "full")
        parsed = parse_message(raw_message, max_body_chars=0, include_body=False)
        descriptor = next(
            (a for a in parsed["attachments"] if a.get("attachment_id") == attachment_id), None
        )
        if descriptor is None:
            raise GatewayError(
                ErrorCode.NOT_FOUND,
                "that attachment does not belong to this message",
                details={"message_id": message_id},
            )

        declared = int(descriptor.get("size_bytes") or 0)
        if declared > self.limits.max_attachment_bytes:
            raise GatewayError(
                ErrorCode.TOO_LARGE,
                f"attachment is {declared} bytes, over this gateway's "
                f"{self.limits.max_attachment_bytes}-byte limit",
                details={"size_bytes": declared},
            )

        body = await self._client.call(
            account,
            ep.GET_ATTACHMENT,
            path_params={"messageId": message_id, "id": attachment_id},
            cost=2.0,
        )
        data = base64.urlsafe_b64decode(str(body.get("data", "")) + "==")
        if len(data) > self.limits.max_attachment_bytes:
            raise GatewayError(ErrorCode.TOO_LARGE, "attachment exceeds the size limit")

        name = descriptor["filename"]
        if filename_hint:
            hinted = sanitize_filename(filename_hint)
            if hinted:
                name = hinted

        result: dict[str, Any] = {
            "account": account.alias,
            "message_id": message_id,
            "attachment_id": attachment_id,
            "filename": name,
            "mime_type": descriptor["mime_type"],
            "size_bytes": len(data),
            "executed": False,
            "note": "Attachment content is untrusted data. The gateway does not "
            "open, parse, or execute it.",
        }

        inline_ok = mode == "inline" or (
            mode == "auto" and len(data) <= self.limits.max_inline_attachment_bytes
        )
        if inline_ok:
            if len(data) > self.limits.max_inline_attachment_bytes:
                raise GatewayError(
                    ErrorCode.TOO_LARGE,
                    f"attachment is {len(data)} bytes, over the "
                    f"{self.limits.max_inline_attachment_bytes}-byte inline limit; "
                    "request mode='file' instead",
                )
            result["delivery"] = "inline"
            result["content_base64"] = base64.b64encode(data).decode("ascii")
        else:
            stored = await asyncio.to_thread(
                self._vault.store,
                account=account.alias,
                message_id=message_id,
                attachment_id=attachment_id,
                filename=name,
                data=data,
            )
            result["delivery"] = "file"
            result["path"] = str(stored.path)
            result["filename"] = stored.filename

        self._store.touch_used(account.alias)
        return result

    # ------------------------------------------------------------------ #
    # Labels
    # ------------------------------------------------------------------ #

    async def labels_list(self, *, alias: str) -> dict[str, Any]:
        account = self._account(alias)
        labels = await self._labels_raw(account)
        entries = []
        for label in labels:
            label_id = str(label.get("id", ""))
            entries.append(
                {
                    "id": label_id,
                    "name": sanitize_text(str(label.get("name", ""))).text,
                    "type": label.get("type", "user"),
                    "messages_total": label.get("messagesTotal"),
                    "messages_unread": label.get("messagesUnread"),
                    "threads_total": label.get("threadsTotal"),
                    "threads_unread": label.get("threadsUnread"),
                    "modifiable_by_gateway": label_id.upper() not in FORBIDDEN_LABELS,
                }
            )
        entries.sort(key=lambda entry: (entry["type"] != "system", entry["name"].lower()))
        return {"account": account.alias, "labels": entries, "count": len(entries)}

    # ------------------------------------------------------------------ #
    # Mutations: labels, archive, read state
    # ------------------------------------------------------------------ #

    async def _apply_labels(
        self,
        *,
        account: Account,
        message_ids: list[str] | None,
        thread_ids: list[str] | None,
        add: list[str],
        remove: list[str],
    ) -> dict[str, Any]:
        """Issue the modify calls. Both label lists are already validated."""
        body: dict[str, Any] = {}
        if add:
            body["addLabelIds"] = add
        if remove:
            body["removeLabelIds"] = remove
        if not body:
            raise GatewayError(ErrorCode.INVALID_INPUT, "no label changes were requested")

        # Independent final check on the exact body about to be transmitted.
        assert_modify_body_safe(body)

        touched_messages: list[str] = []
        touched_threads: list[str] = []

        if message_ids:
            batch_body = dict(body)
            batch_body["ids"] = message_ids
            assert_modify_body_safe(batch_body)
            await self._client.call(
                account,
                ep.BATCH_MODIFY_MESSAGES,
                json_body=batch_body,
                cost=max(1.0, len(message_ids) / 10),
            )
            touched_messages = message_ids

        if thread_ids:
            # Gmail has no batch endpoint for threads; fan out under the
            # gateway's global concurrency cap.
            await asyncio.gather(
                *(
                    self._client.call(
                        account, ep.MODIFY_THREAD, path_params={"id": tid}, json_body=dict(body)
                    )
                    for tid in thread_ids
                )
            )
            touched_threads = thread_ids

        return {
            "account": account.alias,
            "message_ids": touched_messages,
            "thread_ids": touched_threads,
            "labels_added": add,
            "labels_removed": remove,
            "affected_count": len(touched_messages) + len(touched_threads),
        }

    def _validate_targets(
        self, message_ids: list[str] | None, thread_ids: list[str] | None
    ) -> tuple[list[str], list[str]]:
        messages = (
            validate_id_batch(message_ids, field="message_id", max_count=self.limits.max_batch_ids)
            if message_ids
            else []
        )
        threads = (
            validate_id_batch(thread_ids, field="thread_id", max_count=self.limits.max_batch_ids)
            if thread_ids
            else []
        )
        if not messages and not threads:
            raise GatewayError(
                ErrorCode.INVALID_INPUT, "provide at least one message_id or thread_id"
            )
        if len(messages) + len(threads) > self.limits.max_batch_ids:
            raise GatewayError(
                ErrorCode.BATCH_TOO_LARGE,
                f"combined batch exceeds the limit of {self.limits.max_batch_ids} ids",
            )
        return messages, threads

    async def _label_mutation(
        self,
        *,
        alias: str,
        tool: str,
        operation: str,
        message_ids: list[str] | None,
        thread_ids: list[str] | None,
        add: list[str],
        remove: list[str],
        client_request_id: str | None,
        principal: str | None = None,
        detail: str | None = None,
    ) -> dict[str, Any]:
        account = self._require_mutable(self._account(alias))
        messages, threads = self._validate_targets(message_ids, thread_ids)

        return await self._mutate(
            account=account,
            tool=tool,
            operation=operation,
            target_type="message" if messages else "thread",
            target_ids=messages + threads,
            args={
                "message_ids": messages,
                "thread_ids": threads,
                "add": add,
                "remove": remove,
            },
            client_request_id=client_request_id,
            principal=principal,
            detail=detail,
            action=lambda: self._apply_labels(
                account=account,
                message_ids=messages,
                thread_ids=threads,
                add=add,
                remove=remove,
            ),
        )

    async def archive(
        self,
        *,
        alias: str,
        message_ids: list[str] | None = None,
        thread_ids: list[str] | None = None,
        client_request_id: str | None = None,
        principal: str | None = None,
    ) -> dict[str, Any]:
        """Remove INBOX. Archiving never deletes; the mail stays in All Mail."""
        return await self._label_mutation(
            alias=alias,
            tool="gmail_archive",
            operation="archive",
            message_ids=message_ids,
            thread_ids=thread_ids,
            add=[],
            remove=["INBOX"],
            client_request_id=client_request_id,
            principal=principal,
            detail="removed INBOX label",
        )

    async def mark_read(
        self,
        *,
        alias: str,
        message_ids: list[str] | None = None,
        thread_ids: list[str] | None = None,
        client_request_id: str | None = None,
        principal: str | None = None,
    ) -> dict[str, Any]:
        return await self._label_mutation(
            alias=alias,
            tool="gmail_mark_read",
            operation="mark_read",
            message_ids=message_ids,
            thread_ids=thread_ids,
            add=[],
            remove=["UNREAD"],
            client_request_id=client_request_id,
            principal=principal,
            detail="removed UNREAD label",
        )

    async def mark_unread(
        self,
        *,
        alias: str,
        message_ids: list[str] | None = None,
        thread_ids: list[str] | None = None,
        client_request_id: str | None = None,
        principal: str | None = None,
    ) -> dict[str, Any]:
        return await self._label_mutation(
            alias=alias,
            tool="gmail_mark_unread",
            operation="mark_unread",
            message_ids=message_ids,
            thread_ids=thread_ids,
            add=["UNREAD"],
            remove=[],
            client_request_id=client_request_id,
            principal=principal,
            detail="added UNREAD label",
        )

    async def labels_add(
        self,
        *,
        alias: str,
        labels: list[str],
        message_ids: list[str] | None = None,
        thread_ids: list[str] | None = None,
        client_request_id: str | None = None,
        principal: str | None = None,
    ) -> dict[str, Any]:
        account = self._account(alias)
        try:
            self._require_mutable(account)
            resolved = await self._resolve_labels(account, labels, action="add")
        except GatewayError as exc:
            await self._audit_preflight_failure(
                account=account,
                tool="gmail_labels_add",
                operation="labels_add",
                target_ids=(message_ids or []) + (thread_ids or []),
                error=exc,
                principal=principal,
                request_id=client_request_id,
            )
            raise
        return await self._label_mutation(
            alias=alias,
            tool="gmail_labels_add",
            operation="labels_add",
            message_ids=message_ids,
            thread_ids=thread_ids,
            add=resolved,
            remove=[],
            client_request_id=client_request_id,
            principal=principal,
            detail=f"added labels: {', '.join(resolved)}",
        )

    async def labels_remove(
        self,
        *,
        alias: str,
        labels: list[str],
        message_ids: list[str] | None = None,
        thread_ids: list[str] | None = None,
        client_request_id: str | None = None,
        principal: str | None = None,
    ) -> dict[str, Any]:
        account = self._account(alias)
        try:
            self._require_mutable(account)
            resolved = await self._resolve_labels(account, labels, action="remove")
        except GatewayError as exc:
            await self._audit_preflight_failure(
                account=account,
                tool="gmail_labels_remove",
                operation="labels_remove",
                target_ids=(message_ids or []) + (thread_ids or []),
                error=exc,
                principal=principal,
                request_id=client_request_id,
            )
            raise
        return await self._label_mutation(
            alias=alias,
            tool="gmail_labels_remove",
            operation="labels_remove",
            message_ids=message_ids,
            thread_ids=thread_ids,
            add=[],
            remove=resolved,
            client_request_id=client_request_id,
            principal=principal,
            detail=f"removed labels: {', '.join(resolved)}",
        )

    # ------------------------------------------------------------------ #
    # Drafts
    # ------------------------------------------------------------------ #

    async def drafts_list(
        self,
        *,
        alias: str,
        query: str | None = None,
        limit: int = 25,
        page_token: str | None = None,
    ) -> dict[str, Any]:
        account = self._account(alias)
        limit = max(1, min(limit, self.limits.max_page_size))
        list_query: dict[str, Any] = {}
        if cleaned := validate_search_query(query):
            list_query["q"] = cleaned
        if page_token:
            list_query["pageToken"] = ep.validate_path_param("page_token", page_token)

        stubs, next_token = await self._client.paginate(
            account, ep.LIST_DRAFTS, item_key="drafts", query=list_query, limit=limit
        )

        label_names = await self._label_index(account)
        # Gmail's drafts.list response contains only draft/message/thread ids.
        # Fetch metadata concurrently so the advertised subject, recipients,
        # snippet, and timestamp are populated against the real API.
        draft_ids = [str(stub["id"]) for stub in stubs if stub.get("id")]
        detailed = await asyncio.gather(
            *(self._draft_metadata(account, draft_id) for draft_id in draft_ids)
        )
        drafts = []
        for raw in detailed:
            message = raw.get("message") or {}
            summary = parse_message(
                message, max_body_chars=0, include_body=False, label_names=label_names
            )
            drafts.append(
                {
                    "draft_id": raw.get("id"),
                    "message_id": message.get("id"),
                    "thread_id": message.get("threadId"),
                    "subject": summary["subject"],
                    "to": summary["to"],
                    "snippet": summary["snippet"],
                    "timestamp": summary["timestamp"],
                }
            )

        return {
            "account": account.alias,
            "drafts": drafts,
            "count": len(drafts),
            "next_page_token": next_token,
            "has_more": bool(next_token),
        }

    async def _draft_metadata(self, account: Account, draft_id: str) -> dict[str, Any]:
        return await self._client.call(
            account,
            ep.GET_DRAFT,
            path_params={"id": ep.validate_path_param("draft_id", draft_id)},
            query={"format": "metadata"},
        )

    async def _raw_draft(self, account: Account, draft_id: str) -> dict[str, Any]:
        return await self._client.call(
            account,
            ep.GET_DRAFT,
            path_params={"id": draft_id},
            query={"format": "full"},
        )

    async def drafts_get(self, *, alias: str, draft_id: str) -> dict[str, Any]:
        account = self._account(alias)
        draft_id = ep.validate_path_param("draft_id", draft_id)
        raw = await self._raw_draft(account, draft_id)
        label_names = await self._label_index(account)
        message = parse_message(
            raw.get("message") or {},
            max_body_chars=self.limits.max_body_chars,
            include_body=True,
            label_names=label_names,
        )
        return {
            "account": account.alias,
            "draft": {
                "draft_id": raw.get("id"),
                "thread_id": message.get("thread_id"),
                "message": message,
                "sendable_by_gateway": False,
            },
            "content_is_untrusted": True,
        }

    def _draft_result(self, account: Account, raw: dict[str, Any], action: str) -> dict[str, Any]:
        message = raw.get("message") or {}
        return {
            "account": account.alias,
            "action": action,
            "draft_id": raw.get("id"),
            "message_id": message.get("id"),
            "thread_id": message.get("threadId"),
            "sendable_by_gateway": False,
            "note": "The draft is saved in Gmail. This gateway cannot send it; "
            "a human must send it from a Gmail client.",
        }

    async def drafts_create(
        self,
        *,
        alias: str,
        to: list[str] | None = None,
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        subject: str = "",
        body: str = "",
        client_request_id: str | None = None,
        principal: str | None = None,
    ) -> dict[str, Any]:
        account = self._require_mutable(self._account(alias))

        recipients_to = validate_recipients(to, field="to", max_count=self.limits.max_recipients)
        recipients_cc = validate_recipients(cc, field="cc", max_count=self.limits.max_recipients)
        recipients_bcc = validate_recipients(bcc, field="bcc", max_count=self.limits.max_recipients)
        clean_subject = validate_header_text(
            subject or "", field="subject", max_chars=MAX_SUBJECT_CHARS
        )
        clean_body = validate_body_text(body or "", max_chars=self.limits.max_draft_body_chars)

        raw_mime = build_draft_mime(
            limits=self.limits,
            to=recipients_to,
            cc=recipients_cc,
            bcc=recipients_bcc,
            subject=clean_subject,
            body=clean_body,
        )

        async def _create() -> dict[str, Any]:
            created = await self._client.call(
                account, ep.CREATE_DRAFT, json_body={"message": {"raw": raw_mime}}
            )
            return self._draft_result(account, created, "created")

        return await self._mutate(
            account=account,
            tool="gmail_drafts_create",
            operation="draft_create",
            target_type="draft",
            target_ids=[],
            args={
                "to": recipients_to,
                "cc": recipients_cc,
                "bcc": recipients_bcc,
                "subject": clean_subject,
                "body_hash": fingerprint({"body": clean_body}),
            },
            client_request_id=client_request_id,
            principal=principal,
            detail=f"created draft to {len(recipients_to)} recipient(s)",
            action=_create,
        )

    async def drafts_reply(
        self,
        *,
        alias: str,
        message_id: str,
        body: str,
        reply_all: bool = False,
        additional_cc: list[str] | None = None,
        client_request_id: str | None = None,
        principal: str | None = None,
    ) -> dict[str, Any]:
        """Create a reply draft inside the original thread."""
        account = self._require_mutable(self._account(alias))
        message_id = ep.validate_path_param("message_id", message_id)
        clean_body = validate_body_text(body or "", max_chars=self.limits.max_draft_body_chars)

        raw_parent = await self._fetch_message(account, message_id, "full")
        parent = parse_message(raw_parent, max_body_chars=0, include_body=False)

        threading = reply_headers(parent)
        recipients = reply_recipients(
            parent, self_address=account.email_address, reply_all=reply_all
        )
        extra_cc = validate_recipients(
            additional_cc, field="additional_cc", max_count=self.limits.max_recipients
        )
        seen = {address.lower() for address in recipients["to"] + recipients["cc"]}
        recipients["cc"].extend(a for a in extra_cc if a.lower() not in seen)

        if not recipients["to"] and not recipients["cc"]:
            raise GatewayError(
                ErrorCode.INVALID_INPUT,
                "the original message has no usable reply address",
                details={"message_id": message_id},
            )

        thread_id = threading["thread_id"]
        if not thread_id:
            raise GatewayError(
                ErrorCode.NOT_FOUND, "the original message has no thread", details={"message_id": message_id}
            )

        raw_mime = build_draft_mime(
            limits=self.limits,
            to=recipients["to"],
            cc=recipients["cc"],
            subject=threading["subject"],
            body=clean_body,
            in_reply_to=threading["in_reply_to"],
            references=threading["references"],
        )

        async def _create() -> dict[str, Any]:
            created = await self._client.call(
                account,
                ep.CREATE_DRAFT,
                # threadId is what makes Gmail file the draft in the existing
                # conversation; In-Reply-To/References make other clients agree.
                json_body={"message": {"raw": raw_mime, "threadId": thread_id}},
            )
            result = self._draft_result(account, created, "created_reply")
            result["in_reply_to_message_id"] = message_id
            result["to"] = recipients["to"]
            result["cc"] = recipients["cc"]
            result["subject"] = threading["subject"]
            return result

        return await self._mutate(
            account=account,
            tool="gmail_drafts_reply",
            operation="draft_reply",
            target_type="message",
            target_ids=[message_id],
            args={
                "message_id": message_id,
                "reply_all": reply_all,
                "additional_cc": extra_cc,
                "body_hash": fingerprint({"body": clean_body}),
            },
            client_request_id=client_request_id,
            principal=principal,
            detail=f"created reply draft in thread {thread_id}",
            action=_create,
        )

    async def drafts_update(
        self,
        *,
        alias: str,
        draft_id: str,
        to: list[str] | None = None,
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
        subject: str | None = None,
        body: str | None = None,
        client_request_id: str | None = None,
        principal: str | None = None,
    ) -> dict[str, Any]:
        """Edit a draft. Omitted fields keep their existing values.

        Gmail's drafts.update replaces the whole message, so the current draft is
        read first and merged with the requested changes. Thread membership and
        reply headers are carried over so editing a reply does not detach it from
        its conversation.
        """
        account = self._require_mutable(self._account(alias))
        draft_id = ep.validate_path_param("draft_id", draft_id)

        existing_raw = await self._raw_draft(account, draft_id)
        existing = parse_message(
            existing_raw.get("message") or {},
            max_body_chars=self.limits.max_draft_body_chars,
            include_body=True,
        )

        def _existing_addresses(field: str) -> list[str]:
            return [
                entry["email"]
                for entry in (existing.get(field) or [])
                if isinstance(entry, dict) and entry.get("email")
            ]

        new_to = (
            validate_recipients(to, field="to", max_count=self.limits.max_recipients)
            if to is not None
            else _existing_addresses("to")
        )
        new_cc = (
            validate_recipients(cc, field="cc", max_count=self.limits.max_recipients)
            if cc is not None
            else _existing_addresses("cc")
        )
        new_bcc = (
            validate_recipients(bcc, field="bcc", max_count=self.limits.max_recipients)
            if bcc is not None
            else _existing_addresses("bcc")
        )
        new_subject = (
            validate_header_text(subject, field="subject", max_chars=MAX_SUBJECT_CHARS)
            if subject is not None
            else existing.get("subject", "")
        )
        new_body = (
            validate_body_text(body, max_chars=self.limits.max_draft_body_chars)
            if body is not None
            else (existing.get("body") or {}).get("text", "")
        )

        raw_mime = build_draft_mime(
            limits=self.limits,
            to=new_to,
            cc=new_cc,
            bcc=new_bcc,
            subject=new_subject,
            body=new_body,
            in_reply_to=existing.get("in_reply_to"),
            references=existing.get("references") or [],
        )

        message_payload: dict[str, Any] = {"raw": raw_mime}
        if thread_id := existing.get("thread_id"):
            message_payload["threadId"] = thread_id

        async def _update() -> dict[str, Any]:
            updated = await self._client.call(
                account,
                ep.UPDATE_DRAFT,
                path_params={"id": draft_id},
                json_body={"id": draft_id, "message": message_payload},
            )
            result = self._draft_result(account, updated, "updated")
            result["draft_id"] = result["draft_id"] or draft_id
            return result

        return await self._mutate(
            account=account,
            tool="gmail_drafts_update",
            operation="draft_update",
            target_type="draft",
            target_ids=[draft_id],
            args={
                "draft_id": draft_id,
                "to": new_to,
                "cc": new_cc,
                "bcc": new_bcc,
                "subject": new_subject,
                "body_hash": fingerprint({"body": new_body}),
            },
            client_request_id=client_request_id,
            principal=principal,
            detail="updated draft",
            action=_update,
        )
