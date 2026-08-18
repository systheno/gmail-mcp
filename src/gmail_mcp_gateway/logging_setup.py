"""Logging that cannot accidentally emit a credential.

Two rules are enforced mechanically rather than by convention:

1. Log records pass through :class:`RedactingFilter`, which rewrites anything
   shaped like an OAuth token, client secret, bearer header, or authorization
   code -- in the message, the args, and any exception text.
2. On stdio transport, stdout is the MCP wire. Logs therefore always go to
   stderr; a stray ``print`` to stdout would corrupt the protocol.
"""

from __future__ import annotations

import logging
import re
import sys
from typing import Any

LOGGER_NAME = "gmail_mcp_gateway"

_REDACTED = "[redacted]"

# Patterns are intentionally broad. A false positive costs a little log
# readability; a false negative writes a live credential to disk.
_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Google access tokens.
    (re.compile(r"ya29\.[\w\-\.]+"), _REDACTED),
    # Google refresh tokens.
    (re.compile(r"\b1//[\w\-]{10,}"), _REDACTED),
    # OAuth client secrets issued by Google Cloud Console.
    (re.compile(r"GOCSPX-[\w\-]+"), _REDACTED),
    # Authorization: Bearer / Basic headers.
    (re.compile(r"(?i)\b(bearer|basic)\s+[\w\-\._~\+/=]{8,}"), r"\1 " + _REDACTED),
    # JWT-shaped strings.
    (re.compile(r"\beyJ[\w\-]{5,}\.[\w\-]{5,}\.[\w\-]{5,}"), _REDACTED),
    # Query-string and JSON credential fields.
    (
        re.compile(
            r"(?i)(\"?(?:access_token|refresh_token|client_secret|id_token|code|"
            r"code_verifier|authorization|api_key|password|token)\"?\s*[:=]\s*\"?)"
            r"([^\s,\"'&}]+)"
        ),
        r"\1" + _REDACTED,
    ),
)


def redact(text: str) -> str:
    """Strip anything credential-shaped from ``text``."""
    for pattern, repl in _PATTERNS:
        text = pattern.sub(repl, text)
    return text


def _redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {k: _redact_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(_redact_value(v) for v in value)
    return value


class RedactingFilter(logging.Filter):
    """Rewrite credential-shaped substrings on every record that passes."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = _redact_value(record.args)
            else:
                record.args = tuple(_redact_value(a) for a in record.args)
        # Exception text is rendered lazily; pre-render and scrub it so a
        # raised exception carrying a token cannot slip through.
        if record.exc_info and record.exc_info[1] is not None:
            record.exc_text = redact(
                logging.Formatter().formatException(record.exc_info)  # type: ignore[arg-type]
            )
            record.exc_info = None
        return True


def setup_logging(level: str = "INFO", *, stream: Any = None) -> logging.Logger:
    """Configure the gateway logger. Idempotent."""
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False

    for existing in list(logger.handlers):
        logger.removeHandler(existing)

    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
    )
    handler.addFilter(RedactingFilter())
    logger.addHandler(handler)

    # httpx logs full request URLs at INFO, which can carry query parameters.
    # Keep it quiet rather than relying on redaction alone.
    for noisy in ("httpx", "httpcore", "uvicorn.access"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    return logger


def get_logger(suffix: str | None = None) -> logging.Logger:
    return logging.getLogger(f"{LOGGER_NAME}.{suffix}" if suffix else LOGGER_NAME)
