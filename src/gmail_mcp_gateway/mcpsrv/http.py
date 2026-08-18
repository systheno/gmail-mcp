"""Streamable HTTP transport with gateway-level authentication.

Used when the gateway runs as a standalone service rather than as a stdio child
of its client. Three things are enforced before any MCP traffic is processed:

* **Bind address.** 127.0.0.1 by default. A non-loopback bind requires an
  explicit opt-in *and* at least one configured token; otherwise the server
  refuses to start rather than silently exposing a mailbox.
* **Bearer authentication.** Every request to the MCP path must carry a gateway
  token. Tokens are stored as SHA-256 hashes and compared in constant time. They
  are entirely separate from Google credentials -- a client holding one can reach
  the allowlisted tool surface and nothing else.
* **DNS-rebinding protection.** Host and Origin are checked by the SDK's
  transport security layer, so a browser page on another origin cannot drive the
  local endpoint.
"""

from __future__ import annotations

import ipaddress
import json
import secrets
from datetime import UTC, datetime
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

from ..config import Config
from ..crypto import hash_token, read_private_file, write_private_file
from ..errors import ErrorCode, GatewayError
from ..logging_setup import get_logger
from .principal import set_principal

_log = get_logger("http")

TOKEN_BYTES = 32


# --------------------------------------------------------------------------- #
# Token store
# --------------------------------------------------------------------------- #


def load_tokens(config: Config) -> list[dict[str, Any]]:
    path = config.gateway_tokens_file
    if not path.is_file():
        return []
    try:
        payload = json.loads(read_private_file(path).decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise GatewayError(
            ErrorCode.CONFIG_ERROR, f"{path.name} is not valid JSON"
        ) from exc
    tokens = payload.get("tokens")
    return [t for t in tokens if isinstance(t, dict)] if isinstance(tokens, list) else []


def save_tokens(config: Config, tokens: list[dict[str, Any]]) -> None:
    payload = json.dumps({"version": 1, "tokens": tokens}, indent=2).encode("utf-8")
    write_private_file(config.gateway_tokens_file, payload)


def create_token(config: Config, name: str) -> str:
    """Mint a new gateway token. The plaintext is returned once and never stored."""
    if not name or len(name) > 64:
        raise GatewayError(ErrorCode.INVALID_INPUT, "token name must be 1-64 characters")
    tokens = load_tokens(config)
    if any(entry.get("name") == name for entry in tokens):
        raise GatewayError(ErrorCode.INVALID_INPUT, f"a token named '{name}' already exists")

    plaintext = secrets.token_urlsafe(TOKEN_BYTES)
    tokens.append(
        {
            "name": name,
            "hash": hash_token(plaintext),
            "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
        }
    )
    save_tokens(config, tokens)
    return plaintext


def revoke_token(config: Config, name: str) -> bool:
    tokens = load_tokens(config)
    remaining = [entry for entry in tokens if entry.get("name") != name]
    if len(remaining) == len(tokens):
        return False
    save_tokens(config, remaining)
    return True


# --------------------------------------------------------------------------- #
# Middleware
# --------------------------------------------------------------------------- #


class BearerAuthMiddleware:
    """Require a valid gateway token on the MCP endpoint."""

    def __init__(self, app: ASGIApp, *, tokens: list[dict[str, Any]], protected_prefix: str):
        self._app = app
        self._prefix = protected_prefix
        self._by_hash = {
            str(entry["hash"]): str(entry.get("name", "unnamed"))
            for entry in tokens
            if entry.get("hash")
        }

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not scope.get("path", "").startswith(self._prefix):
            await self._app(scope, receive, send)
            return

        request = Request(scope, receive)
        header = request.headers.get("authorization", "")
        scheme, _, credential = header.partition(" ")

        principal: str | None = None
        if scheme.lower() == "bearer" and credential:
            candidate = hash_token(credential.strip())
            # Compare against every hash so timing does not reveal which token
            # prefix matched.
            for stored_hash, name in self._by_hash.items():
                if secrets.compare_digest(candidate, stored_hash):
                    principal = name

        if principal is None:
            _log.warning(
                "rejected unauthenticated MCP request from %s",
                scope.get("client", ("unknown", 0))[0],
            )
            response = JSONResponse(
                {
                    "error": {
                        "code": "unauthorized",
                        "message": "a valid gateway bearer token is required",
                    }
                },
                status_code=401,
                headers={"WWW-Authenticate": 'Bearer realm="gmail-mcp-gateway"'},
            )
            await response(scope, receive, send)
            return

        set_principal(principal)
        await self._app(scope, receive, send)


def _is_loopback(host: str) -> bool:
    if host in {"localhost", ""}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_bind_safety(config: Config, tokens: list[dict[str, Any]]) -> None:
    """Refuse configurations that would expose the endpoint unintentionally."""
    host = config.http.host
    if not tokens:
        raise GatewayError(
            ErrorCode.CONFIG_ERROR,
            "the HTTP transport requires at least one gateway token. Run: "
            "gmail-mcp-gateway token create <name>",
        )
    if _is_loopback(host):
        return
    if not config.http.allow_remote_bind:
        raise GatewayError(
            ErrorCode.CONFIG_ERROR,
            f"refusing to bind {host}: it is not a loopback address. Bind 127.0.0.1 "
            "and reach it over an SSH tunnel, or set http.allow_remote_bind = true "
            "if this really is a trusted private interface.",
        )
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    # is_global is the right predicate here: is_private would accept the
    # documentation ranges (203.0.113.0/24 and friends), and 0.0.0.0 must stay
    # permitted so the gateway can bind inside a container.
    if address is not None and address.is_global:
        raise GatewayError(
            ErrorCode.CONFIG_ERROR,
            f"refusing to bind the internet-routable address {host}; this gateway "
            "must not be exposed to the public internet",
        )
    _log.warning(
        "binding non-loopback address %s: ensure a firewall restricts access and "
        "that TLS is terminated in front of the gateway",
        host,
    )


def build_http_app(config: Config, server: MCPServer) -> Starlette:
    """Build the authenticated Streamable HTTP application."""
    tokens = load_tokens(config)
    check_bind_safety(config, tokens)

    allowed_hosts = [
        "127.0.0.1",
        "localhost",
        f"127.0.0.1:{config.http.port}",
        f"localhost:{config.http.port}",
    ]
    if not _is_loopback(config.http.host):
        allowed_hosts += [config.http.host, f"{config.http.host}:{config.http.port}"]

    app = server.streamable_http_app(
        streamable_http_path=config.http.path,
        host=config.http.host,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=allowed_hosts,
            allowed_origins=[f"http://{host}" for host in allowed_hosts],
        ),
    )

    async def healthz(request: Request) -> Response:
        """Liveness only. Deliberately reveals nothing about accounts or config."""
        return JSONResponse({"status": "ok", "service": "gmail-mcp-gateway"})

    app.add_route("/healthz", healthz, methods=["GET"])
    app.add_middleware(
        BearerAuthMiddleware, tokens=tokens, protected_prefix=config.http.path
    )
    _log.info(
        "streamable HTTP transport ready on http://%s:%d%s with %d token(s)",
        config.http.host,
        config.http.port,
        config.http.path,
        len(tokens),
    )
    return app
