"""Account registry: metadata in SQLite, credentials in sealed per-account files.

The split is deliberate. Anything an MCP client may legitimately learn about an
account (alias, address, status, scopes) is queryable metadata. Anything that
grants access (refresh token, access token) lives in an encrypted file that only
this module reads, and is never returned by any code path reachable from a tool
handler -- see :meth:`Account.public_view`.
"""

from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .config import SCOPE_MODIFY, SCOPE_READONLY, Config
from .crypto import SecretBox, load_or_create_master_key, read_private_file, write_private_file
from .db import Database
from .errors import ErrorCode, GatewayError

ALIAS_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")

STATUS_PENDING = "pending"
STATUS_ACTIVE = "active"
STATUS_NEEDS_REAUTH = "needs_reauth"


def validate_alias(alias: str) -> str:
    """Aliases are used in filenames, key derivation, and logs -- keep them tight."""
    if not isinstance(alias, str) or not ALIAS_PATTERN.match(alias):
        raise GatewayError(
            ErrorCode.INVALID_INPUT,
            "account alias must be 1-32 characters of lowercase letters, digits, "
            "'-' or '_', starting with a letter or digit",
        )
    return alias


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


@dataclass(slots=True)
class Credential:
    """Decrypted OAuth material. Never leaves this process."""

    refresh_token: str
    client_id: str
    scopes: list[str]
    access_token: str | None = None
    access_token_expires_at: float = 0.0
    token_type: str = "Bearer"

    def is_access_token_fresh(self, skew_seconds: float = 120.0) -> bool:
        return bool(self.access_token) and time.time() + skew_seconds < self.access_token_expires_at

    def to_payload(self) -> dict[str, Any]:
        return {
            "refresh_token": self.refresh_token,
            "client_id": self.client_id,
            "scopes": self.scopes,
            "access_token": self.access_token,
            "access_token_expires_at": self.access_token_expires_at,
            "token_type": self.token_type,
        }

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> Credential:
        return cls(
            refresh_token=payload["refresh_token"],
            client_id=payload.get("client_id", ""),
            scopes=list(payload.get("scopes") or []),
            access_token=payload.get("access_token"),
            access_token_expires_at=float(payload.get("access_token_expires_at") or 0.0),
            token_type=payload.get("token_type") or "Bearer",
        )


@dataclass(slots=True, frozen=True)
class Account:
    alias: str
    account_id: str
    email_address: str | None
    scopes: list[str]
    read_only: bool
    status: str
    status_reason: str | None
    created_at: str
    updated_at: str
    authorized_at: str | None
    last_used_at: str | None

    @property
    def can_mutate(self) -> bool:
        return not self.read_only and SCOPE_MODIFY in self.scopes

    def public_view(self) -> dict[str, Any]:
        """The only representation exposed to MCP clients.

        Contains no token material and no ``account_id`` (which is the HKDF salt
        input and the credential filename).
        """
        return {
            "alias": self.alias,
            "email_address": self.email_address,
            "status": self.status,
            "status_reason": self.status_reason,
            "read_only": self.read_only,
            "can_mutate": self.can_mutate,
            "authorized_at": self.authorized_at,
            "last_used_at": self.last_used_at,
            "granted_capabilities": sorted(_capabilities_for(self)),
        }


def _capabilities_for(account: Account) -> set[str]:
    """What this account can actually do, given its status and granted scope."""
    if account.status != STATUS_ACTIVE:
        return set()
    # Both gmail.readonly and gmail.modify permit every read path, drafts included.
    caps = {
        "search",
        "read_messages",
        "read_threads",
        "read_attachments",
        "list_labels",
        "drafts_list",
        "drafts_read",
    }
    if account.can_mutate:
        caps |= {
            "drafts_create",
            "drafts_update",
            "archive",
            "mark_read",
            "mark_unread",
            "labels_add",
            "labels_remove",
        }
    return caps


def _row_to_account(row: Any) -> Account:
    return Account(
        alias=row["alias"],
        account_id=row["account_id"],
        email_address=row["email_address"],
        scopes=[s for s in (row["scopes"] or "").split(" ") if s],
        read_only=bool(row["read_only"]),
        status=row["status"],
        status_reason=row["status_reason"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        authorized_at=row["authorized_at"],
        last_used_at=row["last_used_at"],
    )


class AccountStore:
    def __init__(self, config: Config, db: Database | None = None) -> None:
        self.config = config
        self.config.ensure_dirs()
        self.db = db or Database(config.db_path)
        self.db.initialize()
        self._box = SecretBox(load_or_create_master_key(config.master_key_file))

    # --- metadata -------------------------------------------------------------

    def list(self) -> list[Account]:
        with self.db.connect() as conn:
            rows = conn.execute("SELECT * FROM accounts ORDER BY alias").fetchall()
        return [_row_to_account(r) for r in rows]

    def get(self, alias: str) -> Account:
        validate_alias(alias)
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM accounts WHERE alias = ?", (alias,)).fetchone()
        if row is None:
            known = ", ".join(a.alias for a in self.list()) or "none configured"
            raise GatewayError(
                ErrorCode.UNKNOWN_ACCOUNT,
                f"no such account: '{alias}' (configured accounts: {known})",
                details={"account": alias},
            )
        return _row_to_account(row)

    def exists(self, alias: str) -> bool:
        try:
            self.get(alias)
        except GatewayError:
            return False
        return True

    def create(self, alias: str, *, read_only: bool = False) -> Account:
        validate_alias(alias)
        if self.exists(alias):
            raise GatewayError(
                ErrorCode.INVALID_INPUT, f"account '{alias}' already exists"
            )
        scopes = [SCOPE_READONLY] if read_only else [SCOPE_MODIFY]
        now = _now()
        with self.db.connect() as conn:
            conn.execute(
                "INSERT INTO accounts (alias, account_id, email_address, scopes, read_only, "
                "status, status_reason, created_at, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    alias,
                    uuid.uuid4().hex,
                    None,
                    " ".join(scopes),
                    int(read_only),
                    STATUS_PENDING,
                    "never authorized",
                    now,
                    now,
                ),
            )
        return self.get(alias)

    def set_status(self, alias: str, status: str, reason: str | None = None) -> None:
        with self.db.connect() as conn:
            conn.execute(
                "UPDATE accounts SET status = ?, status_reason = ?, updated_at = ? "
                "WHERE alias = ?",
                (status, reason, _now(), alias),
            )

    def touch_used(self, alias: str) -> None:
        with self.db.connect() as conn:
            conn.execute("UPDATE accounts SET last_used_at = ? WHERE alias = ?", (_now(), alias))

    def mark_authorized(self, alias: str, email_address: str, scopes: list[str]) -> None:
        now = _now()
        with self.db.connect() as conn:
            conn.execute(
                "UPDATE accounts SET email_address = ?, scopes = ?, status = ?, "
                "status_reason = NULL, authorized_at = ?, updated_at = ? WHERE alias = ?",
                (email_address, " ".join(scopes), STATUS_ACTIVE, now, now, alias),
            )

    def delete(self, alias: str) -> None:
        account = self.get(alias)
        self._credential_path(account).unlink(missing_ok=True)
        with self.db.connect() as conn:
            conn.execute("DELETE FROM accounts WHERE alias = ?", (alias,))

    # --- credentials ----------------------------------------------------------

    def _credential_path(self, account: Account) -> Path:
        return self.config.credentials_dir / f"{account.account_id}.cred"

    def save_credential(self, account: Account, credential: Credential) -> None:
        blob = self._box.seal(account.account_id, credential.to_payload())
        write_private_file(self._credential_path(account), blob)

    def load_credential(self, account: Account) -> Credential:
        path = self._credential_path(account)
        if not path.is_file():
            raise GatewayError(
                ErrorCode.NEEDS_REAUTH,
                f"account '{account.alias}' has no stored credential; "
                f"an operator must run: gmail-mcp-gateway accounts auth {account.alias}",
                details={"account": account.alias},
            )
        payload = self._box.open(account.account_id, read_private_file(path))
        return Credential.from_payload(payload)

    def has_credential(self, account: Account) -> bool:
        return self._credential_path(account).is_file()
