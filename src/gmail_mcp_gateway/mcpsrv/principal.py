"""Which caller is making the current request.

Under stdio the peer is the process the operator launched, so the principal is
constant. Under HTTP it is the name of the gateway token that authenticated the
session, set by the auth middleware and read here for the audit log. It is never
derived from anything inside a tool's arguments.
"""

from __future__ import annotations

from contextvars import ContextVar

_principal: ContextVar[str] = ContextVar("gmail_mcp_principal", default="stdio")


def set_principal(name: str) -> None:
    _principal.set(name)


def current_principal() -> str:
    return _principal.get()
