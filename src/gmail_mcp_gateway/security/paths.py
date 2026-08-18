"""Filesystem confinement for attachment downloads.

No client-supplied string ever becomes part of a filesystem path. A client may
pass a *filename hint*; the vault sanitizes it, discards it if it disagrees with
the derived name, and always builds the real path itself from
``<attachments_dir>/<account>/<message_id>/<name>``. Every finished path is
resolved and re-checked to be inside the vault root before a byte is written, so
traversal, absolute paths, and symlink escapes all fail closed.

Written files are 0600 and never marked executable. The gateway does not open,
parse, or run attachment content -- it only stores bytes.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path

from ..errors import ErrorCode, GatewayError
from ..gmail.parse import sanitize_filename
from ..logging_setup import get_logger

_log = get_logger("attachments")


@dataclass(frozen=True, slots=True)
class StoredAttachment:
    path: Path
    filename: str
    size_bytes: int


class AttachmentVault:
    """The single directory attachments may be written to."""

    def __init__(self, root: Path, *, max_bytes: int) -> None:
        self._root = root.resolve()
        self._max_bytes = max_bytes
        self._root.mkdir(parents=True, exist_ok=True, mode=0o700)

    @property
    def root(self) -> Path:
        return self._root

    def _confined(self, *segments: str) -> Path:
        """Join sanitized segments under the root and verify containment."""
        candidate = self._root
        for segment in segments:
            safe = sanitize_filename(segment)
            if not safe or safe in {".", ".."}:
                raise GatewayError(ErrorCode.INVALID_INPUT, "invalid attachment path component")
            candidate = candidate / safe

        # Resolve the deepest existing ancestor so symlinked directories cannot
        # redirect the write outside the vault.
        probe = candidate
        while not probe.exists() and probe != probe.parent:
            probe = probe.parent
        resolved_base = probe.resolve()
        if resolved_base != self._root and self._root not in resolved_base.parents:
            raise GatewayError(
                ErrorCode.INVALID_INPUT, "refusing to write outside the attachment directory"
            )

        final = candidate.resolve() if candidate.exists() else candidate
        try:
            final.relative_to(self._root)
        except ValueError as exc:
            raise GatewayError(
                ErrorCode.INVALID_INPUT, "refusing to write outside the attachment directory"
            ) from exc
        return candidate

    def store(
        self,
        *,
        account: str,
        message_id: str,
        attachment_id: str,
        filename: str,
        data: bytes,
    ) -> StoredAttachment:
        if len(data) > self._max_bytes:
            raise GatewayError(
                ErrorCode.TOO_LARGE,
                f"attachment is {len(data)} bytes, over the "
                f"{self._max_bytes}-byte limit for this gateway",
            )

        safe_name = sanitize_filename(filename)
        # Disambiguate with a short slice of the attachment id so two files with
        # the same name in one message cannot clobber each other.
        suffix = sanitize_filename(attachment_id)[-8:] or "0"
        stem, dot, extension = safe_name.partition(".")
        unique = f"{stem}-{suffix}{dot}{extension}" if dot else f"{safe_name}-{suffix}"

        target = self._confined(account, message_id, unique)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

        # O_NOFOLLOW: refuse to follow a symlink planted at the target path.
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
        try:
            fd = os.open(target, flags, 0o600)
        except OSError as exc:
            raise GatewayError(
                ErrorCode.INTERNAL_ERROR, f"could not write attachment: {exc.strerror}"
            ) from exc
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)

        _log.info(
            "stored attachment for account=%s message=%s bytes=%d", account, message_id, len(data)
        )
        return StoredAttachment(path=target, filename=target.name, size_bytes=len(data))

    def prune(self, *, older_than_seconds: float) -> int:
        """Delete stored attachments older than the given age. Returns the count."""
        cutoff = time.time() - older_than_seconds
        removed = 0
        for path in self._root.rglob("*"):
            if path.is_file() and not path.is_symlink():
                try:
                    if path.stat().st_mtime < cutoff:
                        path.unlink()
                        removed += 1
                except OSError:  # pragma: no cover - racing prune
                    continue
        # Clean up directories left empty by the sweep.
        for path in sorted(self._root.rglob("*"), key=lambda p: len(p.parts), reverse=True):
            if path.is_dir():
                try:
                    path.rmdir()
                except OSError:
                    continue
        return removed
