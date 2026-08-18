"""Configuration and on-disk layout.

Three directories are kept deliberately separate so an operator can give each a
different backing store (read-only config in git, data on a volume, secrets on a
tmpfs or injected by a secret manager):

  config   $GMAIL_MCP_CONFIG_DIR   default ~/.config/gmail-mcp-gateway
  data     $GMAIL_MCP_DATA_DIR     default ~/.local/share/gmail-mcp-gateway
  secrets  $GMAIL_MCP_SECRETS_DIR  default <data>/secrets

Nothing in the config directory is secret. Everything in the secrets directory
is, and is created 0700/0600.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from .errors import ErrorCode, GatewayError

APP_NAME = "gmail-mcp-gateway"

# Google's OAuth scope for read + label/draft mutation. Deliberately a single
# scope: Google publishes no scope that grants draft creation without also
# granting send, so gmail.modify is the narrowest scope covering the supported
# feature set. What it excludes matters:
#
#   * messages.delete / permanent deletion  -> needs https://mail.google.com/
#   * every gmail.settings.* capability     -> forwarding, filters, POP/IMAP
#
# so those are impossible at Google's authorization layer, not merely blocked
# here. Send / trash / spam ARE within this scope and are blocked by the
# gateway's own allowlist (see gmail/allowlist.py).
SCOPE_MODIFY = "https://www.googleapis.com/auth/gmail.modify"

# Optional per-account hardening: an account added with --read-only gets a token
# that Google itself will refuse to use for any mutation.
SCOPE_READONLY = "https://www.googleapis.com/auth/gmail.readonly"

#: Scopes this gateway will never request, checked at authorization time.
DENIED_SCOPE_MARKERS = (
    "mail.google.com",
    "gmail.settings",
    "calendar",
    "drive",
    "docs",
    "contacts",
    "spreadsheets",
    "cloud-platform",
)


def _env_path(var: str) -> Path | None:
    raw = os.environ.get(var)
    return Path(raw).expanduser() if raw else None


def _xdg(var: str, fallback: str) -> Path:
    raw = os.environ.get(var)
    base = Path(raw).expanduser() if raw else Path.home() / fallback
    return base / APP_NAME


@dataclass(frozen=True, slots=True)
class Limits:
    """Request, batch, and rate limits. All are enforced in application code."""

    #: Max message/thread ids accepted by one batch mutation.
    max_batch_ids: int = 100
    #: Max results per search/list page handed back to a client.
    max_page_size: int = 100
    #: Hard cap on total items a paginating helper will accumulate.
    max_total_results: int = 500
    #: Characters of body text returned per message before truncation.
    max_body_chars: int = 100_000
    #: Attachment bytes the gateway will fetch at all.
    max_attachment_bytes: int = 25 * 1024 * 1024
    #: Attachment bytes returned inline (base64) in a tool result.
    max_inline_attachment_bytes: int = 1 * 1024 * 1024
    #: Draft body characters accepted from a client.
    max_draft_body_chars: int = 200_000
    #: Recipients per header field on a draft.
    max_recipients: int = 100

    #: Token bucket: sustained operations/minute per account.
    rate_per_minute: int = 240
    #: Token bucket: burst capacity per account.
    rate_burst: int = 60
    #: Concurrent in-flight Gmail API calls across the whole gateway.
    max_concurrency: int = 8

    #: Upstream retry policy.
    max_attempts: int = 5
    backoff_base_seconds: float = 0.5
    backoff_max_seconds: float = 20.0
    request_timeout_seconds: float = 30.0

    #: How long a client_request_id is remembered for deduplication.
    idempotency_ttl_seconds: int = 24 * 3600

    def __post_init__(self) -> None:
        positive = {
            "max_batch_ids": self.max_batch_ids,
            "max_page_size": self.max_page_size,
            "max_total_results": self.max_total_results,
            "max_body_chars": self.max_body_chars,
            "max_attachment_bytes": self.max_attachment_bytes,
            "max_inline_attachment_bytes": self.max_inline_attachment_bytes,
            "max_draft_body_chars": self.max_draft_body_chars,
            "max_recipients": self.max_recipients,
            "rate_per_minute": self.rate_per_minute,
            "rate_burst": self.rate_burst,
            "max_concurrency": self.max_concurrency,
            "max_attempts": self.max_attempts,
            "backoff_max_seconds": self.backoff_max_seconds,
            "request_timeout_seconds": self.request_timeout_seconds,
            "idempotency_ttl_seconds": self.idempotency_ttl_seconds,
        }
        invalid = sorted(name for name, value in positive.items() if value <= 0)
        if self.backoff_base_seconds < 0:
            invalid.append("backoff_base_seconds")
        if invalid:
            raise GatewayError(
                ErrorCode.CONFIG_ERROR,
                f"limit values must be positive: {', '.join(invalid)}",
            )
        if self.max_inline_attachment_bytes > self.max_attachment_bytes:
            raise GatewayError(
                ErrorCode.CONFIG_ERROR,
                "max_inline_attachment_bytes cannot exceed max_attachment_bytes",
            )
        if self.backoff_base_seconds > self.backoff_max_seconds:
            raise GatewayError(
                ErrorCode.CONFIG_ERROR,
                "backoff_base_seconds cannot exceed backoff_max_seconds",
            )


@dataclass(frozen=True, slots=True)
class HttpConfig:
    """Streamable HTTP transport settings."""

    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 8765
    path: str = "/mcp"
    #: Refuse to bind a non-loopback address unless explicitly acknowledged.
    allow_remote_bind: bool = False

    def __post_init__(self) -> None:
        if not 1 <= self.port <= 65535:
            raise GatewayError(ErrorCode.CONFIG_ERROR, "http.port must be between 1 and 65535")
        if not self.path.startswith("/") or any(char in self.path for char in "?#\r\n"):
            raise GatewayError(
                ErrorCode.CONFIG_ERROR,
                "http.path must be an absolute path without a query, fragment, or line break",
            )


@dataclass(frozen=True, slots=True)
class Config:
    config_dir: Path
    data_dir: Path
    secrets_dir: Path
    limits: Limits = field(default_factory=Limits)
    http: HttpConfig = field(default_factory=HttpConfig)
    log_level: str = "INFO"
    #: Retain audit rows this long; 0 disables pruning.
    audit_retention_days: int = 90

    # --- derived paths --------------------------------------------------------
    @property
    def config_file(self) -> Path:
        return self.config_dir / "config.toml"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "gateway.db"

    @property
    def attachments_dir(self) -> Path:
        """The one and only directory attachments may ever be written to."""
        return self.data_dir / "attachments"

    @property
    def master_key_file(self) -> Path:
        return self.secrets_dir / "master.key"

    @property
    def oauth_client_file(self) -> Path:
        return self.secrets_dir / "oauth_client.json"

    @property
    def credentials_dir(self) -> Path:
        """Per-account encrypted credentials, one file each."""
        return self.secrets_dir / "credentials"

    @property
    def gateway_tokens_file(self) -> Path:
        """Hashed bearer tokens for the HTTP transport."""
        return self.secrets_dir / "gateway_tokens.json"

    def ensure_dirs(self) -> None:
        """Create the directory tree with restrictive permissions."""
        for path in (self.config_dir, self.data_dir, self.attachments_dir):
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
        for path in (self.secrets_dir, self.credentials_dir):
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
            # mkdir's mode is masked by umask; force it.
            path.chmod(0o700)


def _coerce_section(raw: Any, cls: type, name: str) -> dict[str, Any]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise GatewayError(ErrorCode.CONFIG_ERROR, f"config section [{name}] must be a table")
    known = {f for f in cls.__dataclass_fields__}
    unknown = set(raw) - known
    if unknown:
        raise GatewayError(
            ErrorCode.CONFIG_ERROR,
            f"unknown key(s) in [{name}]: {', '.join(sorted(unknown))}",
        )
    return raw


def _env_bool(var: str) -> bool | None:
    raw = os.environ.get(var)
    if raw is None:
        return None
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(var: str) -> int | None:
    raw = os.environ.get(var)
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError as exc:
        raise GatewayError(ErrorCode.CONFIG_ERROR, f"{var} must be an integer") from exc


def load_config() -> Config:
    """Build config from defaults, then config.toml, then environment."""
    config_dir = _env_path("GMAIL_MCP_CONFIG_DIR") or _xdg("XDG_CONFIG_HOME", ".config")
    data_dir = _env_path("GMAIL_MCP_DATA_DIR") or _xdg("XDG_DATA_HOME", ".local/share")
    secrets_dir = _env_path("GMAIL_MCP_SECRETS_DIR") or data_dir / "secrets"

    cfg = Config(config_dir=config_dir, data_dir=data_dir, secrets_dir=secrets_dir)

    config_file = cfg.config_file
    if config_file.is_file():
        try:
            raw = tomllib.loads(config_file.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
            raise GatewayError(
                ErrorCode.CONFIG_ERROR, f"could not parse {config_file.name}: {exc}"
            ) from exc

        top = {k: v for k, v in raw.items() if k not in {"limits", "http"}}
        for key in top:
            if key not in {"log_level", "audit_retention_days"}:
                raise GatewayError(ErrorCode.CONFIG_ERROR, f"unknown config key: {key}")
        cfg = replace(
            cfg,
            limits=Limits(**_coerce_section(raw.get("limits"), Limits, "limits")),
            http=HttpConfig(**_coerce_section(raw.get("http"), HttpConfig, "http")),
            **top,
        )

    # Environment overrides win; they are what a container or systemd unit sets.
    http_overrides: dict[str, Any] = {}
    if (v := os.environ.get("GMAIL_MCP_HTTP_HOST")) is not None:
        http_overrides["host"] = v
    if (v := _env_int("GMAIL_MCP_HTTP_PORT")) is not None:
        http_overrides["port"] = v
    if (v := _env_bool("GMAIL_MCP_HTTP_ENABLED")) is not None:
        http_overrides["enabled"] = v
    if (v := _env_bool("GMAIL_MCP_ALLOW_REMOTE_BIND")) is not None:
        http_overrides["allow_remote_bind"] = v
    if http_overrides:
        cfg = replace(cfg, http=replace(cfg.http, **http_overrides))

    if (v := os.environ.get("GMAIL_MCP_LOG_LEVEL")) is not None:
        cfg = replace(cfg, log_level=v.upper())

    if cfg.log_level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        raise GatewayError(ErrorCode.CONFIG_ERROR, f"invalid log_level: {cfg.log_level}")

    return cfg
