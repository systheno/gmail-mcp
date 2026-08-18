"""Google OAuth 2.0: authorization code + PKCE over a loopback redirect.

Design notes:

* The client secret and every token stay inside this process. No MCP tool
  reaches this module, and nothing here is reachable from a tool handler except
  :func:`refresh_access_token`, which returns a credential object that the Gmail
  client consumes internally and never serialises.

* Authorization is an *administrative* action performed by a human via the CLI.
  A compromised MCP client cannot trigger it.

* ``access_type=offline`` plus ``prompt=consent`` guarantees a refresh token, so
  the gateway runs unattended after the one interactive step.

* The scopes Google actually granted are compared against what was requested.
  Google lets a user untick individual permissions on the consent screen; if the
  grant comes back short, authorization fails loudly instead of leaving an
  account that half-works.
"""

from __future__ import annotations

import base64
import hashlib
import http.server
import json
import secrets
import socket
import threading
import time
import urllib.parse
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from ..accounts import Credential
from ..config import DENIED_SCOPE_MARKERS, Config
from ..crypto import read_private_file
from ..errors import ErrorCode, GatewayError
from ..logging_setup import get_logger

AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
REVOKE_ENDPOINT = "https://oauth2.googleapis.com/revoke"

_log = get_logger("oauth")


@dataclass(frozen=True, slots=True)
class OAuthClient:
    client_id: str
    client_secret: str

    @staticmethod
    def load(config: Config) -> OAuthClient:
        """Load the OAuth client from the environment or the secrets directory."""
        import os

        env_id = os.environ.get("GMAIL_MCP_OAUTH_CLIENT_ID")
        env_secret = os.environ.get("GMAIL_MCP_OAUTH_CLIENT_SECRET")
        if env_id and env_secret:
            return OAuthClient(client_id=env_id, client_secret=env_secret)

        path = config.oauth_client_file
        if not path.is_file():
            raise GatewayError(
                ErrorCode.CONFIG_ERROR,
                "no OAuth client configured. Create a Desktop-app OAuth client in the "
                "Google Cloud console with the Gmail API enabled, then either save the "
                f"downloaded JSON to {path} (mode 0600) or set "
                "GMAIL_MCP_OAUTH_CLIENT_ID and GMAIL_MCP_OAUTH_CLIENT_SECRET.",
            )
        try:
            raw = json.loads(read_private_file(path).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise GatewayError(
                ErrorCode.CONFIG_ERROR, f"{path.name} is not valid JSON"
            ) from exc

        # Accept the console's download format or a flat {client_id, client_secret}.
        block = raw.get("installed") or raw.get("web") or raw
        client_id = block.get("client_id")
        client_secret = block.get("client_secret")
        if not client_id or not client_secret:
            raise GatewayError(
                ErrorCode.CONFIG_ERROR,
                f"{path.name} is missing client_id or client_secret",
            )
        if raw.get("web"):
            _log.warning(
                "OAuth client is a 'web' type; a 'Desktop app' client is recommended "
                "for loopback authorization"
            )
        return OAuthClient(client_id=client_id, client_secret=client_secret)


def assert_scopes_allowed(scopes: list[str]) -> None:
    """Refuse to request anything outside Gmail, or any settings/full-mailbox scope."""
    for scope in scopes:
        lowered = scope.lower()
        for marker in DENIED_SCOPE_MARKERS:
            if marker in lowered:
                raise GatewayError(
                    ErrorCode.FORBIDDEN_OPERATION,
                    f"refusing to request forbidden OAuth scope containing '{marker}'",
                )
        if not lowered.startswith("https://www.googleapis.com/auth/gmail."):
            raise GatewayError(
                ErrorCode.FORBIDDEN_OPERATION,
                f"refusing to request non-Gmail OAuth scope: {scope}",
            )


# --------------------------------------------------------------------------- #
# Loopback receiver
# --------------------------------------------------------------------------- #

_SUCCESS_PAGE = (
    "<!doctype html><meta charset=utf-8><title>Authorized</title>"
    "<body style='font-family:system-ui;padding:3rem;max-width:34rem'>"
    "<h1>Account authorized</h1>"
    "<p>The Gmail MCP Gateway stored a refresh token for this account. "
    "You can close this tab and return to the terminal.</p>"
)
_FAILURE_PAGE = (
    "<!doctype html><meta charset=utf-8><title>Authorization failed</title>"
    "<body style='font-family:system-ui;padding:3rem;max-width:34rem'>"
    "<h1>Authorization failed</h1><p>Check the terminal for details.</p>"
)


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    """Single-shot handler that captures ?code=&state= from the redirect."""

    result: dict[str, str] = {}
    expected_path = "/oauth2/callback"

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path != self.expected_path:
            self.send_error(404)
            return
        params = dict(urllib.parse.parse_qsl(parsed.query))
        type(self).result = params
        ok = "code" in params and "error" not in params
        body = (_SUCCESS_PAGE if ok else _FAILURE_PAGE).encode("utf-8")
        self.send_response(200 if ok else 400)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        # This page is a local dead end; forbid it becoming a referrer leak.
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        """Silence stdlib request logging; the query string carries the auth code."""


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


# --------------------------------------------------------------------------- #
# Flows
# --------------------------------------------------------------------------- #


def _token_request(payload: dict[str, str], *, timeout: float = 30.0) -> dict[str, Any]:
    try:
        response = httpx.post(
            TOKEN_ENDPOINT,
            data=payload,
            timeout=timeout,
            headers={"Accept": "application/json"},
        )
    except httpx.HTTPError as exc:
        raise GatewayError(
            ErrorCode.NETWORK_ERROR, f"could not reach Google's token endpoint: {type(exc).__name__}"
        ) from exc

    try:
        body = response.json()
    except ValueError:
        body = {}

    if response.status_code >= 400:
        error = str(body.get("error", "unknown_error"))
        description = str(body.get("error_description", ""))
        # invalid_grant means the refresh token is revoked, expired, or the user
        # changed their password. It is never retryable.
        code = ErrorCode.NEEDS_REAUTH if error == "invalid_grant" else ErrorCode.AUTH_FAILED
        raise GatewayError(
            code,
            f"Google rejected the token request: {error}"
            + (f" ({description})" if description else ""),
            details={"oauth_error": error},
        )
    return body


def authorize_account(
    *,
    client: OAuthClient,
    scopes: list[str],
    login_hint: str | None = None,
    open_browser: bool = True,
    port: int = 0,
    timeout_seconds: float = 300.0,
) -> Credential:
    """Run the interactive authorization-code + PKCE flow. Blocking, CLI-only."""
    assert_scopes_allowed(scopes)

    verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).decode("ascii").rstrip("=")
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
        .decode("ascii")
        .rstrip("=")
    )
    state = secrets.token_urlsafe(32)

    bind_port = port or _free_port()
    redirect_uri = f"http://127.0.0.1:{bind_port}/oauth2/callback"

    query = {
        "client_id": client.client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(scopes),
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "access_type": "offline",
        "prompt": "consent",
        "include_granted_scopes": "false",
    }
    if login_hint:
        query["login_hint"] = login_hint
    auth_url = f"{AUTH_ENDPOINT}?{urllib.parse.urlencode(query)}"

    _CallbackHandler.result = {}
    server = http.server.HTTPServer(("127.0.0.1", bind_port), _CallbackHandler)
    server.timeout = 1.0
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.2})
    thread.daemon = True
    thread.start()

    try:
        print("\nOpen this URL to authorize the account:\n")
        print(f"  {auth_url}\n")
        if open_browser:
            try:
                webbrowser.open(auth_url)
            except Exception:  # pragma: no cover - headless hosts
                pass
        print(f"Waiting for the redirect to {redirect_uri} ...")
        print("(If this host has no browser, forward the port: "
              f"ssh -L {bind_port}:127.0.0.1:{bind_port} <this-host>)\n")

        deadline = time.monotonic() + timeout_seconds
        while not _CallbackHandler.result and time.monotonic() < deadline:
            time.sleep(0.2)
        params = _CallbackHandler.result
    finally:
        server.shutdown()
        server.server_close()

    if not params:
        raise GatewayError(
            ErrorCode.AUTH_FAILED, f"timed out after {timeout_seconds:.0f}s waiting for consent"
        )
    if "error" in params:
        raise GatewayError(
            ErrorCode.AUTH_FAILED, f"authorization was denied: {params['error']}"
        )
    if not secrets.compare_digest(params.get("state", ""), state):
        raise GatewayError(
            ErrorCode.AUTH_FAILED,
            "OAuth state mismatch; the redirect did not originate from this request",
        )

    body = _token_request(
        {
            "client_id": client.client_id,
            "client_secret": client.client_secret,
            "code": params["code"],
            "code_verifier": verifier,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
        }
    )

    refresh_token = body.get("refresh_token")
    if not refresh_token:
        raise GatewayError(
            ErrorCode.AUTH_FAILED,
            "Google did not return a refresh token. Remove this app's access at "
            "https://myaccount.google.com/permissions and authorize again.",
        )

    granted = [s for s in str(body.get("scope", "")).split(" ") if s]
    missing = set(scopes) - set(granted)
    if missing:
        raise GatewayError(
            ErrorCode.SCOPE_INSUFFICIENT,
            "consent screen did not grant every required permission "
            f"(missing: {', '.join(sorted(missing))}). Authorize again and leave all "
            "requested permissions ticked.",
        )
    # Belt and braces: a grant broader than we asked for is also a failure.
    assert_scopes_allowed(granted)

    return Credential(
        refresh_token=refresh_token,
        client_id=client.client_id,
        scopes=granted or scopes,
        access_token=body.get("access_token"),
        access_token_expires_at=time.time() + float(body.get("expires_in", 0) or 0),
        token_type=body.get("token_type", "Bearer"),
    )


def refresh_access_token(client: OAuthClient, credential: Credential) -> Credential:
    """Exchange the refresh token for a fresh access token."""
    body = _token_request(
        {
            "client_id": client.client_id,
            "client_secret": client.client_secret,
            "refresh_token": credential.refresh_token,
            "grant_type": "refresh_token",
        }
    )
    credential.access_token = body.get("access_token")
    credential.access_token_expires_at = time.time() + float(body.get("expires_in", 0) or 0)
    credential.token_type = body.get("token_type", "Bearer")
    if scope := body.get("scope"):
        credential.scopes = [s for s in str(scope).split(" ") if s]
    if not credential.access_token:
        raise GatewayError(ErrorCode.AUTH_FAILED, "token refresh returned no access token")
    return credential


def revoke_refresh_token(credential: Credential, *, timeout: float = 30.0) -> bool:
    """Ask Google to revoke the grant. Returns True if Google confirmed."""
    try:
        response = httpx.post(
            REVOKE_ENDPOINT,
            data={"token": credential.refresh_token},
            timeout=timeout,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    except httpx.HTTPError as exc:
        _log.warning("revocation request failed: %s", type(exc).__name__)
        return False
    if response.status_code == 200:
        return True
    # 400 with invalid_token means it was already revoked -- treat as success.
    if response.status_code == 400:
        return True
    _log.warning("revocation returned HTTP %s", response.status_code)
    return False


def oauth_client_path_hint(config: Config) -> Path:
    return config.oauth_client_file
