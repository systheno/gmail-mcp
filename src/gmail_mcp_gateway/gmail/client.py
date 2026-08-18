"""The only code in the gateway that talks to Gmail over the network.

Every call goes through :meth:`GmailClient.call`, which requires an
:class:`~.allowlist.Endpoint` constant. There is no method that accepts a URL, a
path string, or an HTTP verb from a caller, so no tool -- and no bug in a tool --
can reach an endpoint that is not written down in :mod:`.allowlist`.

Also handled here: access-token refresh with per-account locking, retry with
exponential backoff and jitter, ``Retry-After`` support, pagination, and the
translation of Gmail's error payloads into :class:`GatewayError`.
"""

from __future__ import annotations

import asyncio
import random
from typing import Any

import httpx

from ..accounts import STATUS_ACTIVE, STATUS_NEEDS_REAUTH, Account, AccountStore, Credential
from ..auth.oauth import OAuthClient, refresh_access_token
from ..config import Limits
from ..errors import ErrorCode, GatewayError, NeedsReauth
from ..logging_setup import get_logger, redact
from ..security.ratelimit import RateLimiter
from .allowlist import (
    GMAIL_API_BASE,
    Endpoint,
    assert_path_permitted,
    build_path,
    validate_query,
)

_log = get_logger("gmail")

#: Gmail is always addressed as the authenticated user. This is never a
#: caller-supplied value, so one account's token can never be pointed at
#: another mailbox.
_USER_ID = "me"

_RETRYABLE_403_REASONS = frozenset(
    {"ratelimitexceeded", "userratelimitexceeded", "backenderror", "quotaexceeded"}
)


def _extract_error(payload: dict[str, Any]) -> tuple[str, str]:
    """Pull (reason, message) out of a Google error envelope, safely."""
    error = payload.get("error")
    if not isinstance(error, dict):
        return "", ""
    message = str(error.get("message", ""))[:300]
    reason = ""
    errors = error.get("errors")
    if isinstance(errors, list) and errors and isinstance(errors[0], dict):
        reason = str(errors[0].get("reason", ""))
    if not reason:
        reason = str(error.get("status", ""))
    return reason.lower(), redact(message)


class GmailClient:
    def __init__(
        self,
        *,
        store: AccountStore,
        oauth_client: OAuthClient,
        limits: Limits,
        limiter: RateLimiter,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._store = store
        self._oauth = oauth_client
        self._limits = limits
        self._limiter = limiter
        self._http = http_client or httpx.AsyncClient(
            timeout=httpx.Timeout(limits.request_timeout_seconds),
            follow_redirects=False,
            headers={"User-Agent": "gmail-mcp-gateway/1.0"},
        )
        self._owns_http = http_client is None
        self._credentials: dict[str, Credential] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    async def aclose(self) -> None:
        if self._owns_http:
            await self._http.aclose()

    # --- credentials ----------------------------------------------------------

    def _lock_for(self, alias: str) -> asyncio.Lock:
        lock = self._locks.get(alias)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[alias] = lock
        return lock

    def forget(self, alias: str) -> None:
        """Drop cached credentials, e.g. after re-authorization or removal."""
        self._credentials.pop(alias, None)
        self._locks.pop(alias, None)

    async def _access_token(self, account: Account, *, force_refresh: bool = False) -> str:
        async with self._lock_for(account.alias):
            credential = self._credentials.get(account.alias)
            if credential is None:
                credential = await asyncio.to_thread(self._store.load_credential, account)
                self._credentials[account.alias] = credential

            if not force_refresh and credential.is_access_token_fresh():
                return credential.access_token or ""

            try:
                credential = await asyncio.to_thread(
                    refresh_access_token, self._oauth, credential
                )
            except GatewayError as exc:
                if exc.code is ErrorCode.NEEDS_REAUTH:
                    await asyncio.to_thread(
                        self._store.set_status,
                        account.alias,
                        STATUS_NEEDS_REAUTH,
                        "Google rejected the stored refresh token",
                    )
                    self._credentials.pop(account.alias, None)
                    raise NeedsReauth(account.alias) from exc
                raise

            self._credentials[account.alias] = credential
            await asyncio.to_thread(self._store.save_credential, account, credential)
            if account.status != STATUS_ACTIVE:
                await asyncio.to_thread(
                    self._store.set_status, account.alias, STATUS_ACTIVE, None
                )
            return credential.access_token or ""

    # --- requests -------------------------------------------------------------

    async def call(
        self,
        account: Account,
        endpoint: Endpoint,
        *,
        path_params: dict[str, str] | None = None,
        query: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        cost: float = 1.0,
    ) -> dict[str, Any]:
        """Issue one allowlisted Gmail API request and return the parsed body."""
        if endpoint.mutating and not account.can_mutate:
            raise GatewayError(
                ErrorCode.ACCOUNT_READ_ONLY,
                f"account '{account.alias}' was authorized read-only; "
                "it cannot perform mailbox mutations",
                details={"account": account.alias},
            )

        params = {"userId": _USER_ID, **(path_params or {})}
        path = build_path(endpoint, params)
        resolved_query = validate_query(endpoint, query or {})

        await self._limiter.acquire(account.alias, cost=cost)

        # Final independent gate, immediately before the wire.
        assert_path_permitted(endpoint.method, path)

        url = f"{GMAIL_API_BASE}{path}"
        attempt = 0
        force_refresh = False
        already_refreshed = False
        last_error: GatewayError | None = None

        while attempt < self._limits.max_attempts:
            attempt += 1
            token = await self._access_token(account, force_refresh=force_refresh)
            force_refresh = False
            headers = {
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            }

            try:
                async with self._limiter.concurrency():
                    response = await self._http.request(
                        endpoint.method,
                        url,
                        params=resolved_query or None,
                        json=json_body,
                        headers=headers,
                    )
            except httpx.TimeoutException as exc:
                last_error = GatewayError(
                    ErrorCode.TIMEOUT,
                    f"Gmail request timed out after "
                    f"{self._limits.request_timeout_seconds:.0f}s",
                    details={"endpoint": endpoint.name},
                )
                _log.warning("%s timed out (attempt %d): %s", endpoint.name, attempt, type(exc).__name__)
            except httpx.HTTPError as exc:
                last_error = GatewayError(
                    ErrorCode.NETWORK_ERROR,
                    f"network failure talking to Gmail: {type(exc).__name__}",
                    details={"endpoint": endpoint.name},
                )
                _log.warning("%s network error (attempt %d): %s", endpoint.name, attempt, type(exc).__name__)
            else:
                if response.status_code < 300:
                    if not response.content:
                        return {}
                    try:
                        body = response.json()
                    except ValueError as exc:
                        raise GatewayError(
                            ErrorCode.UPSTREAM_ERROR, "Gmail returned a malformed response"
                        ) from exc
                    return body if isinstance(body, dict) else {"value": body}

                # 401 once means the access token expired mid-flight; refresh and
                # retry. Twice means the grant itself is gone.
                if response.status_code == 401 and not already_refreshed:
                    already_refreshed = True
                    force_refresh = True
                    _log.info("access token rejected for '%s'; refreshing", account.alias)
                    continue

                error = self._translate(response, endpoint, account)
                if not error.retryable:
                    raise error
                last_error = error

            if attempt < self._limits.max_attempts:
                await asyncio.sleep(self._backoff(attempt, last_error))

        assert last_error is not None
        raise last_error

    def _backoff(self, attempt: int, error: GatewayError | None) -> float:
        if error is not None and error.retry_after_seconds:
            return min(error.retry_after_seconds, self._limits.backoff_max_seconds)
        # Full jitter: avoids synchronised retries across concurrent tool calls.
        ceiling = min(
            self._limits.backoff_max_seconds,
            self._limits.backoff_base_seconds * (2 ** (attempt - 1)),
        )
        return random.uniform(0.0, ceiling)

    def _translate(
        self, response: httpx.Response, endpoint: Endpoint, account: Account
    ) -> GatewayError:
        """Map a Gmail error response onto the gateway's error taxonomy."""
        try:
            payload = response.json()
        except ValueError:
            payload = {}
        reason, message = _extract_error(payload if isinstance(payload, dict) else {})
        status = response.status_code

        retry_after: float | None = None
        if raw := response.headers.get("Retry-After"):
            try:
                retry_after = float(raw)
            except ValueError:
                retry_after = None

        details = {"endpoint": endpoint.name, "account": account.alias}

        if status == 401:
            return NeedsReauth(account.alias, "Google rejected the access token")

        if status == 403:
            if reason in _RETRYABLE_403_REASONS:
                return GatewayError(
                    ErrorCode.UPSTREAM_RATE_LIMITED,
                    "Gmail rate limit reached; the gateway will back off and retry",
                    details=details,
                    retry_after_seconds=retry_after,
                )
            if "insufficient" in reason or "insufficient" in message.lower():
                return GatewayError(
                    ErrorCode.SCOPE_INSUFFICIENT,
                    f"account '{account.alias}' lacks the Gmail permission this "
                    "operation needs; re-authorize it",
                    details=details,
                )
            return GatewayError(
                ErrorCode.UPSTREAM_ERROR,
                f"Gmail refused the request: {message or 'forbidden'}",
                details=details,
            )

        if status == 404:
            return GatewayError(
                ErrorCode.NOT_FOUND,
                "the requested message, thread, draft, or label does not exist "
                "in this account",
                details=details,
            )

        if status == 429:
            return GatewayError(
                ErrorCode.UPSTREAM_RATE_LIMITED,
                "Gmail rate limit reached; the gateway will back off and retry",
                details=details,
                retry_after_seconds=retry_after,
            )

        if status >= 500:
            return GatewayError(
                ErrorCode.UPSTREAM_UNAVAILABLE,
                f"Gmail is temporarily unavailable (HTTP {status})",
                details=details,
                retry_after_seconds=retry_after,
            )

        if status == 400:
            return GatewayError(
                ErrorCode.INVALID_INPUT,
                f"Gmail rejected the request: {message or 'bad request'}",
                details=details,
            )

        return GatewayError(
            ErrorCode.UPSTREAM_ERROR,
            f"unexpected Gmail response (HTTP {status})",
            details=details,
        )

    # --- pagination -----------------------------------------------------------

    async def paginate(
        self,
        account: Account,
        endpoint: Endpoint,
        *,
        item_key: str,
        query: dict[str, Any] | None = None,
        limit: int,
        page_size: int | None = None,
    ) -> tuple[list[dict[str, Any]], str | None]:
        """Accumulate up to ``limit`` items, following ``nextPageToken``.

        Returns the items and the token for the page after the last one consumed
        (``None`` when the listing is exhausted), so a client can resume without
        the gateway holding cursor state.
        """
        limit = min(limit, self._limits.max_total_results)
        collected: list[dict[str, Any]] = []
        page_token: str | None = (query or {}).get("pageToken")
        base_query = {k: v for k, v in (query or {}).items() if k != "pageToken"}

        while len(collected) < limit:
            remaining = limit - len(collected)
            request_query = dict(base_query)
            request_query["maxResults"] = min(
                page_size or self._limits.max_page_size, remaining, 500
            )
            if page_token:
                request_query["pageToken"] = page_token

            body = await self.call(account, endpoint, query=request_query)
            items = body.get(item_key) or []
            if isinstance(items, list):
                collected.extend(item for item in items if isinstance(item, dict))

            page_token = body.get("nextPageToken")
            if not page_token:
                break

        # A surviving page_token means the listing continues past ``limit``; the
        # client passes it back to resume, so no cursor state lives in the server.
        return collected[:limit], page_token
