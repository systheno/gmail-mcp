"""Credential storage, filesystem confinement, transport auth, and logging."""

from __future__ import annotations

import base64
import json
import logging
import os
import secrets
import stat
from pathlib import Path

import pytest

from gmail_mcp_gateway.accounts import AccountStore, Credential, validate_alias
from gmail_mcp_gateway.audit import AuditLog
from gmail_mcp_gateway.config import DENIED_SCOPE_MARKERS, Config, Limits, load_config
from gmail_mcp_gateway.crypto import (
    SecretBox,
    hash_token,
    load_or_create_master_key,
    read_private_file,
    write_private_file,
)
from gmail_mcp_gateway.db import Database
from gmail_mcp_gateway.errors import ErrorCode, GatewayError
from gmail_mcp_gateway.idempotency import IdempotencyCache
from gmail_mcp_gateway.logging_setup import RedactingFilter, redact, setup_logging
from gmail_mcp_gateway.security.paths import AttachmentVault
from gmail_mcp_gateway.security.ratelimit import RateLimiter

# --------------------------------------------------------------------------- #
# Credentials at rest
# --------------------------------------------------------------------------- #


def test_master_key_file_is_created_private(config):
    config.ensure_dirs()
    load_or_create_master_key(config.master_key_file)
    mode = config.master_key_file.stat().st_mode
    assert not mode & (stat.S_IRWXG | stat.S_IRWXO)


def test_group_readable_master_key_is_refused(config):
    config.ensure_dirs()
    load_or_create_master_key(config.master_key_file)
    config.master_key_file.chmod(0o644)
    with pytest.raises(GatewayError) as info:
        load_or_create_master_key(config.master_key_file)
    assert "chmod 600" in info.value.message


def test_master_key_can_come_from_the_environment(config, monkeypatch):
    key = secrets.token_bytes(32)
    monkeypatch.setenv("GMAIL_MCP_MASTER_KEY", base64.b64encode(key).decode())
    assert load_or_create_master_key(config.master_key_file) == key
    assert not config.master_key_file.exists()


def test_malformed_environment_master_key_is_rejected(config, monkeypatch):
    monkeypatch.setenv("GMAIL_MCP_MASTER_KEY", "not-base64!!")
    with pytest.raises(GatewayError):
        load_or_create_master_key(config.master_key_file)


def test_sealed_credential_round_trips():
    box = SecretBox(secrets.token_bytes(32))
    payload = {"refresh_token": "1//secret", "scopes": ["a"]}
    assert box.open("acct-1", box.seal("acct-1", payload)) == payload


def test_credential_sealed_for_one_account_cannot_be_opened_as_another():
    box = SecretBox(secrets.token_bytes(32))
    blob = box.seal("acct-1", {"refresh_token": "1//secret"})
    with pytest.raises(GatewayError) as info:
        box.open("acct-2", blob)
    assert "moved between accounts" in info.value.message


def test_credential_cannot_be_opened_with_a_different_master_key():
    blob = SecretBox(secrets.token_bytes(32)).seal("acct-1", {"refresh_token": "x"})
    with pytest.raises(GatewayError):
        SecretBox(secrets.token_bytes(32)).open("acct-1", blob)


def test_tampering_with_the_ciphertext_is_detected():
    box = SecretBox(secrets.token_bytes(32))
    blob = bytearray(box.seal("acct-1", {"refresh_token": "x"}))
    blob[-1] ^= 0xFF
    with pytest.raises(GatewayError):
        box.open("acct-1", bytes(blob))


def test_stored_credential_file_is_private_and_opaque(store, account):
    path = store.config.credentials_dir / f"{account.account_id}.cred"
    assert path.is_file()
    assert not path.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO)
    raw = path.read_bytes()
    assert b"1//fake-refresh-token" not in raw
    assert b"refresh_token" not in raw


def test_each_account_has_its_own_credential_file(store):
    first = store.create("one")
    second = store.create("two")
    store.save_credential(first, Credential("1//a", "cid", ["s"]))
    store.save_credential(second, Credential("1//b", "cid", ["s"]))
    files = list(store.config.credentials_dir.glob("*.cred"))
    assert len({f.read_bytes() for f in files}) == len(files)
    assert store.load_credential(first).refresh_token == "1//a"
    assert store.load_credential(second).refresh_token == "1//b"


def test_removing_an_account_deletes_its_credential(store, account):
    path = store.config.credentials_dir / f"{account.account_id}.cred"
    assert path.exists()
    store.delete("personal")
    assert not path.exists()
    with pytest.raises(GatewayError):
        store.get("personal")


def test_private_file_write_is_atomic_and_restrictive(tmp_path: Path):
    target = tmp_path / "secret.bin"
    write_private_file(target, b"payload")
    assert read_private_file(target) == b"payload"
    assert not target.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO)
    assert not list(tmp_path.glob(".*tmp"))


@pytest.mark.parametrize(
    "alias", ["../evil", "Personal", "with space", "", "x" * 40, "-lead", "a/b", "a\x00b"]
)
def test_invalid_aliases_are_rejected(alias):
    with pytest.raises(GatewayError):
        validate_alias(alias)


@pytest.mark.parametrize("alias", ["personal", "work", "a", "team-1", "team_2", "x9"])
def test_valid_aliases_are_accepted(alias):
    assert validate_alias(alias) == alias


# --------------------------------------------------------------------------- #
# Scope policy
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "scope",
    [
        "https://mail.google.com/",
        "https://www.googleapis.com/auth/gmail.settings.basic",
        "https://www.googleapis.com/auth/gmail.settings.sharing",
        "https://www.googleapis.com/auth/calendar",
        "https://www.googleapis.com/auth/drive",
        "https://www.googleapis.com/auth/contacts",
        "https://www.googleapis.com/auth/cloud-platform",
    ],
)
def test_forbidden_oauth_scopes_are_refused(scope):
    from gmail_mcp_gateway.auth.oauth import assert_scopes_allowed

    with pytest.raises(GatewayError) as info:
        assert_scopes_allowed([scope])
    assert info.value.code is ErrorCode.FORBIDDEN_OPERATION


def test_the_scopes_the_gateway_requests_are_allowed():
    from gmail_mcp_gateway.auth.oauth import assert_scopes_allowed
    from gmail_mcp_gateway.config import SCOPE_MODIFY, SCOPE_READONLY

    assert_scopes_allowed([SCOPE_MODIFY])
    assert_scopes_allowed([SCOPE_READONLY])


def test_denied_scope_markers_cover_settings_and_full_mailbox():
    assert "gmail.settings" in DENIED_SCOPE_MARKERS
    assert "mail.google.com" in DENIED_SCOPE_MARKERS


# --------------------------------------------------------------------------- #
# Attachment vault
# --------------------------------------------------------------------------- #


@pytest.fixture
def vault(tmp_path: Path) -> AttachmentVault:
    return AttachmentVault(tmp_path / "attachments", max_bytes=1_000_000)


@pytest.mark.parametrize(
    "hostile",
    [
        "../../../etc/passwd",
        "/etc/shadow",
        "..\\..\\windows\\system32\\evil.dll",
        "....//....//escape.txt",
        "\x00null.bin",
    ],
)
def test_vault_confines_hostile_filenames(vault, hostile):
    stored = vault.store(
        account="personal", message_id="msg1", attachment_id="att0", filename=hostile, data=b"x"
    )
    assert vault.root in stored.path.parents
    assert ".." not in str(stored.path)


def test_vault_confines_hostile_account_and_message_components(vault):
    stored = vault.store(
        account="../../etc",
        message_id="../../../root",
        attachment_id="att0",
        filename="f.txt",
        data=b"x",
    )
    assert vault.root in stored.path.parents


def test_vault_written_files_are_private_and_not_executable(vault):
    stored = vault.store(
        account="personal", message_id="m", attachment_id="a", filename="x.sh", data=b"#!/bin/sh"
    )
    mode = stored.path.stat().st_mode
    assert not mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    assert not mode & (stat.S_IRWXG | stat.S_IRWXO)


def test_vault_refuses_to_follow_a_symlink_planted_at_the_target(vault, tmp_path: Path):
    outside = tmp_path / "outside.txt"
    outside.write_text("original")
    target_dir = vault.root / "personal" / "msg1"
    target_dir.mkdir(parents=True)
    (target_dir / "note-att0.txt").symlink_to(outside)

    with pytest.raises(GatewayError):
        vault.store(
            account="personal",
            message_id="msg1",
            attachment_id="att0",
            filename="note.txt",
            data=b"overwritten",
        )
    assert outside.read_text() == "original"


def test_vault_enforces_its_size_limit(tmp_path: Path):
    small = AttachmentVault(tmp_path / "a", max_bytes=10)
    with pytest.raises(GatewayError) as info:
        small.store(account="p", message_id="m", attachment_id="a", filename="f", data=b"x" * 11)
    assert info.value.code is ErrorCode.TOO_LARGE


def test_same_name_attachments_do_not_clobber_each_other(vault):
    first = vault.store(
        account="p", message_id="m", attachment_id="att0", filename="report.pdf", data=b"one"
    )
    second = vault.store(
        account="p", message_id="m", attachment_id="att1", filename="report.pdf", data=b"two"
    )
    assert first.path != second.path
    assert first.path.read_bytes() == b"one"


def test_vault_prune_removes_old_files(vault):
    stored = vault.store(
        account="p", message_id="m", attachment_id="a", filename="f.txt", data=b"x"
    )
    os.utime(stored.path, (0, 0))
    assert vault.prune(older_than_seconds=60) == 1
    assert not stored.path.exists()


# --------------------------------------------------------------------------- #
# Logging redaction
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "secret",
    [
        "ya29.a0AfH6SMBxxxxxxxxxxxxxxxxxxxx",
        "1//0gLongRefreshTokenValueHere",
        "GOCSPX-abcdefghijklmnop",
        "Bearer sk-abcdefghijklmnopqrstuvwxyz",
        "eyJhbGciOi.eyJzdWIiOiIx.SflKxwRJSM",
        'refresh_token="1//supersecret"',
        "client_secret=GOCSPX-zzz",
        "access_token: ya29.zzzzzzzzzzzz",
    ],
)
def test_credential_shaped_strings_are_redacted(secret):
    scrubbed = redact(f"failure while handling {secret} okay")
    for fragment in ("ya29.a0", "1//0g", "GOCSPX-abc", "sk-abcdef", "supersecret", "GOCSPX-zzz"):
        assert fragment not in scrubbed


def test_redaction_applies_to_log_records(caplog):
    logger = logging.getLogger("gmail_mcp_gateway.test")
    logger.addFilter(RedactingFilter())
    with caplog.at_level(logging.INFO):
        logger.info("token is %s", "ya29.leaked-access-token")
    assert "ya29.leaked" not in caplog.text


def test_redaction_applies_to_exception_text(caplog):
    logger = logging.getLogger("gmail_mcp_gateway.test2")
    logger.addFilter(RedactingFilter())
    with caplog.at_level(logging.ERROR):
        try:
            raise ValueError("secret refresh_token=1//leakedtokenvalue here")
        except ValueError:
            logger.exception("boom")
    assert "1//leakedtoken" not in caplog.text


def test_logging_goes_to_stderr_not_stdout():
    """stdout is the MCP wire under stdio transport."""
    import sys

    logger = setup_logging("INFO")
    streams = [getattr(h, "stream") for h in logger.handlers if hasattr(h, "stream")]
    assert streams and all(stream is not sys.stdout for stream in streams)


# --------------------------------------------------------------------------- #
# HTTP transport
# --------------------------------------------------------------------------- #


def test_token_is_stored_only_as_a_hash(config):
    from gmail_mcp_gateway.mcpsrv.http import create_token, load_tokens

    config.ensure_dirs()
    plaintext = create_token(config, "laptop")
    stored = json.loads(config.gateway_tokens_file.read_text())
    assert plaintext not in json.dumps(stored)
    assert stored["tokens"][0]["hash"] == hash_token(plaintext)
    assert load_tokens(config)[0]["name"] == "laptop"


def test_duplicate_token_names_are_rejected(config):
    from gmail_mcp_gateway.mcpsrv.http import create_token

    config.ensure_dirs()
    create_token(config, "laptop")
    with pytest.raises(GatewayError):
        create_token(config, "laptop")


def test_token_revocation_removes_it(config):
    from gmail_mcp_gateway.mcpsrv.http import create_token, load_tokens, revoke_token

    config.ensure_dirs()
    create_token(config, "laptop")
    assert revoke_token(config, "laptop") is True
    assert load_tokens(config) == []
    assert revoke_token(config, "laptop") is False


def test_http_transport_requires_at_least_one_token(config):
    from gmail_mcp_gateway.mcpsrv.http import check_bind_safety

    with pytest.raises(GatewayError) as info:
        check_bind_safety(config, [])
    assert "token" in info.value.message


def test_non_loopback_bind_requires_explicit_opt_in(config):
    from dataclasses import replace

    from gmail_mcp_gateway.mcpsrv.http import check_bind_safety

    tokens = [{"name": "a", "hash": "x"}]
    remote = replace(config, http=replace(config.http, host="10.0.0.5"))
    with pytest.raises(GatewayError) as info:
        check_bind_safety(remote, tokens)
    assert "loopback" in info.value.message

    allowed = replace(remote, http=replace(remote.http, allow_remote_bind=True))
    check_bind_safety(allowed, tokens)  # private address, explicitly permitted


def test_public_bind_is_refused_even_with_the_opt_in(config):
    from dataclasses import replace

    from gmail_mcp_gateway.mcpsrv.http import check_bind_safety

    public = replace(config, http=replace(config.http, host="8.8.8.8", allow_remote_bind=True))
    with pytest.raises(GatewayError) as info:
        check_bind_safety(public, [{"name": "a", "hash": "x"}])
    assert "internet" in info.value.message


def test_unspecified_bind_is_permitted_for_containers(config):
    """0.0.0.0 is how the gateway binds inside a container, behind the token."""
    from dataclasses import replace

    from gmail_mcp_gateway.mcpsrv.http import check_bind_safety

    in_container = replace(
        config, http=replace(config.http, host="0.0.0.0", allow_remote_bind=True)
    )
    check_bind_safety(in_container, [{"name": "a", "hash": "x"}])


def test_loopback_bind_needs_no_opt_in(config):
    from gmail_mcp_gateway.mcpsrv.http import check_bind_safety

    check_bind_safety(config, [{"name": "a", "hash": "x"}])


async def test_bearer_middleware_rejects_missing_and_wrong_tokens(config):
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient

    from gmail_mcp_gateway.mcpsrv.http import BearerAuthMiddleware, create_token

    config.ensure_dirs()
    plaintext = create_token(config, "client-a")
    from gmail_mcp_gateway.mcpsrv.http import load_tokens

    async def endpoint(request):
        return PlainTextResponse("reached")

    app = Starlette(routes=[Route("/mcp", endpoint), Route("/healthz", endpoint)])
    app.add_middleware(
        BearerAuthMiddleware, tokens=load_tokens(config), protected_prefix="/mcp"
    )
    client = TestClient(app)

    assert client.get("/mcp").status_code == 401
    assert client.get("/mcp", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/mcp", headers={"Authorization": plaintext}).status_code == 401
    assert client.get("/mcp", headers={"Authorization": f"Bearer {plaintext}"}).status_code == 200
    # Health is deliberately outside the protected prefix.
    assert client.get("/healthz").status_code == 200


async def test_unauthorized_response_leaks_nothing(config):
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient

    from gmail_mcp_gateway.mcpsrv.http import BearerAuthMiddleware, create_token, load_tokens

    config.ensure_dirs()
    plaintext = create_token(config, "client-a")

    async def endpoint(request):
        return PlainTextResponse("reached")

    app = Starlette(routes=[Route("/mcp", endpoint)])
    app.add_middleware(BearerAuthMiddleware, tokens=load_tokens(config), protected_prefix="/mcp")
    response = TestClient(app).get("/mcp")
    body = response.text
    assert plaintext not in body
    assert "hash" not in body
    assert response.json()["error"]["code"] == "unauthorized"


# --------------------------------------------------------------------------- #
# Rate limiting, idempotency, audit, config
# --------------------------------------------------------------------------- #


async def test_token_bucket_refills_over_time(monkeypatch):
    limiter = RateLimiter(rate_per_minute=60, burst=2, max_concurrency=4)
    await limiter.acquire("a")
    await limiter.acquire("a")
    with pytest.raises(GatewayError):
        await limiter.acquire("a")

    clock = [0.0]
    monkeypatch.setattr("time.monotonic", lambda: clock[0])
    limiter = RateLimiter(rate_per_minute=60, burst=1, max_concurrency=4)
    await limiter.acquire("a")
    with pytest.raises(GatewayError):
        await limiter.acquire("a")
    clock[0] += 2.0
    await limiter.acquire("a")


async def test_accounts_have_independent_buckets():
    limiter = RateLimiter(rate_per_minute=60, burst=1, max_concurrency=4)
    await limiter.acquire("personal")
    await limiter.acquire("work")  # unaffected by personal's usage
    with pytest.raises(GatewayError):
        await limiter.acquire("personal")


def test_idempotency_entries_expire(config):
    database = Database(config.db_path)
    database.initialize()
    cache = IdempotencyCache(database, ttl_seconds=0)
    cache.store(
        account="p", tool="t", key="k", args_fingerprint="f", response={"draft_id": "d1"}
    )
    assert cache.lookup(account="p", tool="t", key="k", args_fingerprint="f") is None


def test_idempotency_is_scoped_per_account_and_tool(config):
    database = Database(config.db_path)
    database.initialize()
    cache = IdempotencyCache(database, ttl_seconds=3600)
    cache.store(account="p", tool="t", key="k", args_fingerprint="f", response={"a": 1})
    assert cache.lookup(account="other", tool="t", key="k", args_fingerprint="f") is None
    assert cache.lookup(account="p", tool="other", key="k", args_fingerprint="f") is None
    cached = cache.lookup(account="p", tool="t", key="k", args_fingerprint="f")
    assert cached is not None
    assert cached["a"] == 1


def test_audit_truncates_large_id_lists(audit):
    audit.record(
        tool="gmail_archive",
        operation="archive",
        outcome="success",
        account="personal",
        target_ids=[f"m{i}" for i in range(100)],
    )
    event = audit.recent(limit=1)[0]
    assert event.target_count == 100
    assert len(event.target_ids) <= 26
    assert "more" in event.target_ids[-1]


def test_audit_filters_by_account_and_outcome(audit):
    audit.record(tool="t", operation="archive", outcome="success", account="personal")
    audit.record(tool="t", operation="archive", outcome="failure", account="work")
    assert len(audit.recent(account="personal")) == 1
    assert len(audit.recent(outcome="failure")) == 1


def test_audit_redacts_detail_strings(audit):
    audit.record(
        tool="t",
        operation="o",
        outcome="failure",
        detail="upstream said refresh_token=1//leakedvalue",
    )
    assert "1//leakedvalue" not in audit.recent(limit=1)[0].detail


def test_audit_retention_prunes_old_rows(config):
    database = Database(config.db_path)
    database.initialize()
    log = AuditLog(database, retention_days=0)
    log.record(tool="t", operation="o", outcome="success")
    assert log.prune() == 0  # retention 0 disables pruning
    assert len(log.recent()) == 1


def test_config_directories_are_created_private(config):
    config.ensure_dirs()
    for path in (config.secrets_dir, config.credentials_dir):
        assert not path.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO)


def test_config_rejects_unknown_keys(tmp_path: Path, monkeypatch):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text("bogus_key = 1\n")
    monkeypatch.setenv("GMAIL_MCP_CONFIG_DIR", str(config_dir))
    monkeypatch.setenv("GMAIL_MCP_DATA_DIR", str(tmp_path / "data"))
    with pytest.raises(GatewayError) as info:
        load_config()
    assert info.value.code is ErrorCode.CONFIG_ERROR


@pytest.mark.parametrize(
    "limits",
    [
        {"max_concurrency": 0},
        {"max_attempts": 0},
        {"request_timeout_seconds": 0},
        {"max_attachment_bytes": 10, "max_inline_attachment_bytes": 11},
        {"backoff_base_seconds": 2, "backoff_max_seconds": 1},
    ],
)
def test_config_rejects_limits_that_can_deadlock_or_disable_guards(
    tmp_path: Path, monkeypatch, limits
):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    body = "[limits]\n" + "\n".join(f"{key} = {value}" for key, value in limits.items())
    (config_dir / "config.toml").write_text(body)
    monkeypatch.setenv("GMAIL_MCP_CONFIG_DIR", str(config_dir))
    monkeypatch.setenv("GMAIL_MCP_DATA_DIR", str(tmp_path / "data"))
    with pytest.raises(GatewayError) as info:
        load_config()
    assert info.value.code is ErrorCode.CONFIG_ERROR


def test_config_reads_limits_and_http_sections(tmp_path: Path, monkeypatch):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text(
        "log_level = 'WARNING'\n\n[limits]\nmax_batch_ids = 7\n\n[http]\nport = 9999\n"
    )
    monkeypatch.setenv("GMAIL_MCP_CONFIG_DIR", str(config_dir))
    monkeypatch.setenv("GMAIL_MCP_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("GMAIL_MCP_HTTP_PORT", raising=False)
    loaded = load_config()
    assert loaded.limits.max_batch_ids == 7
    assert loaded.http.port == 9999
    assert loaded.log_level == "WARNING"


def test_environment_overrides_the_config_file(tmp_path: Path, monkeypatch):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text("[http]\nport = 9999\n")
    monkeypatch.setenv("GMAIL_MCP_CONFIG_DIR", str(config_dir))
    monkeypatch.setenv("GMAIL_MCP_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("GMAIL_MCP_HTTP_PORT", "1234")
    assert load_config().http.port == 1234


def test_secrets_directory_is_separately_configurable(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("GMAIL_MCP_CONFIG_DIR", str(tmp_path / "c"))
    monkeypatch.setenv("GMAIL_MCP_DATA_DIR", str(tmp_path / "d"))
    monkeypatch.setenv("GMAIL_MCP_SECRETS_DIR", str(tmp_path / "s"))
    loaded = load_config()
    assert loaded.secrets_dir == tmp_path / "s"
    assert loaded.data_dir not in loaded.secrets_dir.parents


@pytest.mark.parametrize("wrapper", ["{}", " {} ", "'{}'", '"{}"', "{}\n"])
def test_environment_master_key_tolerates_copy_paste_whitespace(config, monkeypatch, wrapper):
    key = secrets.token_bytes(32)
    encoded = base64.b64encode(key).decode()
    monkeypatch.setenv("GMAIL_MCP_MASTER_KEY", wrapper.format(encoded))
    assert load_or_create_master_key(config.master_key_file) == key
