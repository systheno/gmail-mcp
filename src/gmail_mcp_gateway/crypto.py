"""Envelope encryption for stored credentials.

A single 32-byte master key lives either in the environment
(``GMAIL_MCP_MASTER_KEY``, base64) or in a 0600 file inside the secrets
directory. Each account's credential blob is sealed with AES-256-GCM under a
*separate* key derived per account:

    account_key = HKDF-SHA256(master, info="gmail-mcp-gateway:account:<id>")

and the account id is also passed as AES-GCM associated data. Two consequences
matter for the multi-account requirement:

  * compromising one account's derived key does not yield another's;
  * a credential file copied from account A into account B's slot fails to
    decrypt, so credentials cannot be silently cross-wired.

Honest threat model: this protects credentials at rest against backups, stray
copies, and disk images. It does not defend against an attacker who already
executes code as the gateway's user -- that attacker can read the master key.
Filesystem permissions remain the primary boundary.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import stat
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .errors import ErrorCode, GatewayError

_MASTER_KEY_BYTES = 32
_NONCE_BYTES = 12
_ENV_VAR = "GMAIL_MCP_MASTER_KEY"
_HKDF_INFO_PREFIX = b"gmail-mcp-gateway:account:"


def _require_private_file(path: Path) -> None:
    """Refuse to read a secret that is group- or world-readable."""
    mode = path.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise GatewayError(
            ErrorCode.CONFIG_ERROR,
            f"{path.name} is accessible to other users; run: chmod 600 {path}",
        )


def load_or_create_master_key(key_file: Path) -> bytes:
    """Return the master key, generating and persisting one if absent."""
    env_value = os.environ.get(_ENV_VAR)
    if env_value:
        # Tolerate the whitespace that survives copy-paste, `$(openssl ...)`,
        # and env-file quoting.
        env_value = env_value.strip().strip("'\"").strip()
        try:
            key = base64.b64decode(env_value, validate=True)
        except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
            raise GatewayError(
                ErrorCode.CONFIG_ERROR, f"{_ENV_VAR} must be base64-encoded"
            ) from exc
        if len(key) != _MASTER_KEY_BYTES:
            raise GatewayError(
                ErrorCode.CONFIG_ERROR,
                f"{_ENV_VAR} must decode to {_MASTER_KEY_BYTES} bytes",
            )
        return key

    if key_file.is_file():
        _require_private_file(key_file)
        try:
            key = base64.b64decode(key_file.read_text(encoding="utf-8").strip(), validate=True)
        except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
            raise GatewayError(
                ErrorCode.CONFIG_ERROR, f"{key_file.name} is corrupt (not base64)"
            ) from exc
        if len(key) != _MASTER_KEY_BYTES:
            raise GatewayError(ErrorCode.CONFIG_ERROR, f"{key_file.name} is corrupt (bad length)")
        return key

    key = secrets.token_bytes(_MASTER_KEY_BYTES)
    key_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Create with the final mode already applied; never widen it afterwards.
    fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(base64.b64encode(key).decode("ascii"))
    return key


def _derive(master: bytes, account_id: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_HKDF_INFO_PREFIX + account_id.encode("utf-8"),
    ).derive(master)


class SecretBox:
    """Seals and opens per-account credential blobs."""

    def __init__(self, master_key: bytes) -> None:
        if len(master_key) != _MASTER_KEY_BYTES:
            raise GatewayError(ErrorCode.CONFIG_ERROR, "master key has the wrong length")
        self._master = master_key

    def seal(self, account_id: str, payload: dict[str, Any]) -> bytes:
        aead = AESGCM(_derive(self._master, account_id))
        nonce = secrets.token_bytes(_NONCE_BYTES)
        plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        ciphertext = aead.encrypt(nonce, plaintext, account_id.encode("utf-8"))
        return nonce + ciphertext

    def open(self, account_id: str, blob: bytes) -> dict[str, Any]:
        if len(blob) <= _NONCE_BYTES:
            raise GatewayError(ErrorCode.CONFIG_ERROR, "stored credential is truncated")
        aead = AESGCM(_derive(self._master, account_id))
        try:
            plaintext = aead.decrypt(
                blob[:_NONCE_BYTES], blob[_NONCE_BYTES:], account_id.encode("utf-8")
            )
        except InvalidTag as exc:
            raise GatewayError(
                ErrorCode.CONFIG_ERROR,
                "stored credential failed authentication: wrong master key, "
                "or the file was modified or moved between accounts",
            ) from exc
        return json.loads(plaintext.decode("utf-8"))


def write_private_file(path: Path, data: bytes) -> None:
    """Atomically write ``data`` to ``path`` with 0600 permissions."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(f".{path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def read_private_file(path: Path) -> bytes:
    _require_private_file(path)
    return path.read_bytes()


def hash_token(token: str) -> str:
    """SHA-256 of a gateway bearer token, for storage and comparison."""
    import hashlib

    return hashlib.sha256(token.encode("utf-8")).hexdigest()
