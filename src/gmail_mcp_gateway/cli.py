"""Administrative command line interface.

Account management and OAuth authorization live here rather than in the MCP tool
surface, so a client -- however compromised -- cannot add an account, trigger a
consent flow, mint a gateway token, or read the audit log. Those actions require
shell access as the service user.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import UTC, datetime, timedelta
from typing import Any

from . import __version__
from .accounts import (
    STATUS_ACTIVE,
    STATUS_NEEDS_REAUTH,
    AccountStore,
    validate_alias,
)
from .audit import AuditLog
from .auth.oauth import OAuthClient, authorize_account, revoke_refresh_token
from .config import SCOPE_MODIFY, SCOPE_READONLY, Config, load_config
from .db import Database
from .errors import ErrorCode, GatewayError
from .idempotency import IdempotencyCache
from .logging_setup import setup_logging
from .security.paths import AttachmentVault

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_UNHEALTHY = 2


def _print(*parts: Any) -> None:
    print(*parts, file=sys.stdout)


def _err(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)


def _emit(data: Any, as_json: bool) -> None:
    if as_json:
        _print(json.dumps(data, indent=2, default=str))


# --------------------------------------------------------------------------- #
# Accounts
# --------------------------------------------------------------------------- #


def _authorize(config: Config, store: AccountStore, alias: str, args: argparse.Namespace) -> int:
    account = store.get(alias)
    client = OAuthClient.load(config)
    scopes = [SCOPE_READONLY] if account.read_only else [SCOPE_MODIFY]

    _print(f"\nAuthorizing '{alias}' with scope: {' '.join(scopes)}")
    if account.read_only:
        _print("  (read-only account: Google itself will reject any write)")

    credential = authorize_account(
        client=client,
        scopes=scopes,
        login_hint=getattr(args, "login_hint", None),
        open_browser=not getattr(args, "no_browser", False),
        port=getattr(args, "port", 0) or 0,
    )
    store.save_credential(account, credential)

    # Confirm the grant works and learn the address it belongs to.
    address = asyncio.run(_fetch_profile_address(config, store, alias))
    store.mark_authorized(alias, address, credential.scopes)
    _print(f"\n  authorized: {alias} -> {address}")
    _print("  refresh token stored encrypted; unattended operation is now possible.")
    return EXIT_OK


async def _fetch_profile_address(config: Config, store: AccountStore, alias: str) -> str:
    from .gmail import allowlist as ep
    from .gmail.client import GmailClient
    from .security.ratelimit import RateLimiter

    client = GmailClient(
        store=store,
        oauth_client=OAuthClient.load(config),
        limits=config.limits,
        limiter=RateLimiter(
            rate_per_minute=config.limits.rate_per_minute,
            burst=config.limits.rate_burst,
            max_concurrency=config.limits.max_concurrency,
        ),
    )
    try:
        profile = await client.call(store.get(alias), ep.GET_PROFILE)
        return str(profile.get("emailAddress", "unknown"))
    finally:
        await client.aclose()


def cmd_accounts_add(config: Config, args: argparse.Namespace) -> int:
    store = AccountStore(config)
    alias = validate_alias(args.alias)
    store.create(alias, read_only=args.read_only)
    _print(f"created account '{alias}'")
    try:
        return _authorize(config, store, alias, args)
    except GatewayError:
        _print(f"\naccount '{alias}' was created but is not authorized.")
        _print(f"retry with: gmail-mcp-gateway accounts auth {alias}")
        raise


def cmd_accounts_auth(config: Config, args: argparse.Namespace) -> int:
    store = AccountStore(config)
    return _authorize(config, store, validate_alias(args.alias), args)


def cmd_accounts_list(config: Config, args: argparse.Namespace) -> int:
    store = AccountStore(config)
    accounts = store.list()
    if args.json:
        _emit({"accounts": [a.public_view() for a in accounts], "count": len(accounts)}, True)
        return EXIT_OK

    if not accounts:
        _print("no accounts configured. Add one with:")
        _print("  gmail-mcp-gateway accounts add <alias>")
        return EXIT_OK

    _print(f"{'ALIAS':<16} {'ADDRESS':<34} {'STATUS':<14} {'MODE':<10} AUTHORIZED")
    for account in accounts:
        _print(
            f"{account.alias:<16} "
            f"{(account.email_address or '-'):<34} "
            f"{account.status:<14} "
            f"{('read-only' if account.read_only else 'read+write'):<10} "
            f"{account.authorized_at or '-'}"
        )
    return EXIT_OK


def cmd_accounts_status(config: Config, args: argparse.Namespace) -> int:
    from .mcpsrv.server import build_service

    async def _run() -> dict[str, Any]:
        service = build_service(config)
        try:
            return await service.accounts_status(args.alias)
        finally:
            await service.aclose()

    result = asyncio.run(_run())

    if args.json:
        _emit(result, True)
    else:
        for entry in result["accounts"]:
            check = entry["live_check"]
            state = (
                "reachable"
                if check["ok"]
                else (f"FAILED ({check['error']})" if check["attempted"] else "not checked")
            )
            _print(f"{entry['alias']}: {entry['status']} / {state}")
            _print(f"  address:      {entry.get('email_address') or '-'}")
            _print(f"  credential:   {'present' if entry['credential_present'] else 'MISSING'}")
            _print(f"  capabilities: {', '.join(entry['granted_capabilities']) or 'none'}")
            if entry.get("messages_total") is not None:
                _print(f"  mailbox:      {entry['messages_total']} messages, "
                       f"{entry['threads_total']} threads")
            _print("")

    unhealthy = [
        entry
        for entry in result["accounts"]
        if entry["status"] != STATUS_ACTIVE or entry["live_check"]["ok"] is False
    ]
    return EXIT_UNHEALTHY if unhealthy else EXIT_OK


def cmd_accounts_reauth(config: Config, args: argparse.Namespace) -> int:
    store = AccountStore(config)
    alias = validate_alias(args.alias)
    account = store.get(alias)
    store.set_status(alias, STATUS_NEEDS_REAUTH, "re-authorization requested by operator")
    _print(f"re-authorizing '{alias}' ({account.email_address or 'address unknown'})")
    return _authorize(config, store, alias, args)


def cmd_accounts_remove(config: Config, args: argparse.Namespace) -> int:
    store = AccountStore(config)
    alias = validate_alias(args.alias)
    account = store.get(alias)

    if not args.yes:
        _err(f"refusing to remove '{alias}' without --yes")
        return EXIT_ERROR

    if not args.keep_google_grant and store.has_credential(account):
        credential = store.load_credential(account)
        if revoke_refresh_token(credential):
            _print(f"revoked this gateway's Google access for {account.email_address or alias}")
        else:
            _print("warning: Google did not confirm revocation; review "
                   "https://myaccount.google.com/permissions")

    store.delete(alias)
    _print(f"removed account '{alias}' and deleted its stored credential")
    return EXIT_OK


# --------------------------------------------------------------------------- #
# Gateway tokens
# --------------------------------------------------------------------------- #


def cmd_token_create(config: Config, args: argparse.Namespace) -> int:
    from .mcpsrv.http import create_token

    config.ensure_dirs()
    plaintext = create_token(config, args.name)
    _print(f"\ngateway token '{args.name}' created. It is shown once:\n")
    _print(f"  {plaintext}\n")
    _print("Give it to the MCP client as:  Authorization: Bearer <token>")
    _print("Only a SHA-256 hash is stored; there is no way to recover it later.")
    return EXIT_OK


def cmd_token_list(config: Config, args: argparse.Namespace) -> int:
    from .mcpsrv.http import load_tokens

    tokens = load_tokens(config)
    if args.json:
        _emit({"tokens": [{"name": t["name"], "created_at": t.get("created_at")} for t in tokens]}, True)
        return EXIT_OK
    if not tokens:
        _print("no gateway tokens configured")
        return EXIT_OK
    _print(f"{'NAME':<24} CREATED")
    for token in tokens:
        _print(f"{token.get('name', '?'):<24} {token.get('created_at', '?')}")
    return EXIT_OK


def cmd_token_revoke(config: Config, args: argparse.Namespace) -> int:
    from .mcpsrv.http import revoke_token

    if revoke_token(config, args.name):
        _print(f"revoked gateway token '{args.name}'")
        return EXIT_OK
    _err(f"no gateway token named '{args.name}'")
    return EXIT_ERROR


# --------------------------------------------------------------------------- #
# Audit and maintenance
# --------------------------------------------------------------------------- #


def cmd_audit(config: Config, args: argparse.Namespace) -> int:
    database = Database(config.db_path)
    database.initialize()
    audit = AuditLog(database, retention_days=config.audit_retention_days)

    since = None
    if args.since_hours:
        since = datetime.now(UTC) - timedelta(hours=args.since_hours)

    events = audit.recent(
        limit=args.limit,
        account=args.account,
        tool=args.tool,
        outcome=args.outcome,
        since=since,
    )
    if args.json:
        _emit({"events": [event.to_dict() for event in events], "count": len(events)}, True)
        return EXIT_OK

    if not events:
        _print("no audit events match")
        return EXIT_OK

    _print(f"{'TIME':<26} {'ACCOUNT':<12} {'OPERATION':<16} {'OUTCOME':<9} TARGETS")
    for event in reversed(events):
        targets = ",".join(event.target_ids[:3])
        if event.target_count > 3:
            targets += f" (+{event.target_count - 3})"
        _print(
            f"{event.ts:<26} {(event.account or '-'):<12} {event.operation:<16} "
            f"{event.outcome:<9} {targets or '-'}"
        )
        if event.outcome != "success" and event.detail:
            _print(f"{'':<26} └─ [{event.error_code}] {event.detail}")
    return EXIT_OK


def cmd_prune(config: Config, args: argparse.Namespace) -> int:
    database = Database(config.db_path)
    database.initialize()
    audit_removed = AuditLog(database, retention_days=config.audit_retention_days).prune()
    idem_removed = IdempotencyCache(
        database, ttl_seconds=config.limits.idempotency_ttl_seconds
    ).prune()
    vault = AttachmentVault(config.attachments_dir, max_bytes=config.limits.max_attachment_bytes)
    files_removed = vault.prune(older_than_seconds=args.attachment_age_hours * 3600)

    _print(f"pruned {audit_removed} audit event(s) older than "
           f"{config.audit_retention_days} day(s)")
    _print(f"pruned {idem_removed} expired idempotency record(s)")
    _print(f"pruned {files_removed} stored attachment(s) older than "
           f"{args.attachment_age_hours}h")
    return EXIT_OK


def cmd_health(config: Config, args: argparse.Namespace) -> int:
    """Verify the deployment is coherent. Exit code 2 means unhealthy."""
    checks: list[dict[str, Any]] = []

    def check(name: str, ok: bool, detail: str) -> None:
        checks.append({"check": name, "ok": ok, "detail": detail})

    try:
        config.ensure_dirs()
        check("directories", True, f"config={config.config_dir} data={config.data_dir}")
    except OSError as exc:
        check("directories", False, str(exc))

    try:
        Database(config.db_path).initialize()
        check("database", True, str(config.db_path))
    except Exception as exc:  # noqa: BLE001
        check("database", False, type(exc).__name__)

    try:
        store = AccountStore(config)
        check("master_key", True, "loaded")
    except GatewayError as exc:
        check("master_key", False, exc.message)
        store = None  # type: ignore[assignment]

    try:
        OAuthClient.load(config)
        check("oauth_client", True, "configured")
    except GatewayError as exc:
        check("oauth_client", False, exc.message)

    if store is not None:
        accounts = store.list()
        active = [a for a in accounts if a.status == STATUS_ACTIVE]
        check(
            "accounts",
            bool(accounts) and len(active) == len(accounts),
            f"{len(active)}/{len(accounts)} authorized"
            if accounts
            else "none configured",
        )

    if config.http.enabled:
        from .mcpsrv.http import check_bind_safety, load_tokens

        try:
            tokens = load_tokens(config)
            check_bind_safety(config, tokens)
            check("http_transport", True, f"{config.http.host}:{config.http.port} "
                                          f"({len(tokens)} token(s))")
        except GatewayError as exc:
            check("http_transport", False, exc.message)

    healthy = all(entry["ok"] for entry in checks)

    if args.json:
        _emit({"healthy": healthy, "version": __version__, "checks": checks}, True)
    else:
        for entry in checks:
            mark = "ok  " if entry["ok"] else "FAIL"
            _print(f"[{mark}] {entry['check']:<16} {entry['detail']}")
        _print(f"\ngmail-mcp-gateway {__version__}: "
               f"{'healthy' if healthy else 'UNHEALTHY'}")
    return EXIT_OK if healthy else EXIT_UNHEALTHY


# --------------------------------------------------------------------------- #
# Serving
# --------------------------------------------------------------------------- #


def cmd_serve(config: Config, args: argparse.Namespace) -> int:
    from dataclasses import replace

    from .mcpsrv.server import build_server, build_service

    if args.transport == "http":
        config = replace(
            config,
            http=replace(
                config.http,
                enabled=True,
                host=args.host or config.http.host,
                port=args.port or config.http.port,
            ),
        )

    service = build_service(config)
    server = build_server(config, service)

    if args.transport == "stdio":
        # stdout is the MCP wire from here on; logging already goes to stderr.
        setup_logging(config.log_level, stream=sys.stderr).info(
            "serving MCP over stdio (%d accounts configured)", len(service.accounts_list()["accounts"])
        )
        asyncio.run(server.run_stdio_async())
        return EXIT_OK

    import uvicorn

    from .mcpsrv.http import build_http_app

    app = build_http_app(config, server)
    uvicorn.run(
        app,
        host=config.http.host,
        port=config.http.port,
        log_level=config.log_level.lower(),
        access_log=False,
    )
    return EXIT_OK


# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gmail-mcp-gateway",
        description=(
            "Security-focused MCP gateway for Gmail. Clients can search, read, "
            "organize, and draft. Clients cannot send, trash, or delete."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="override the configured log level",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- serve ---
    serve = subparsers.add_parser("serve", help="run the MCP server")
    serve.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default="stdio",
        help="stdio for a same-host client (default); http for a standalone service",
    )
    serve.add_argument("--host", help="bind address for http (default 127.0.0.1)")
    serve.add_argument("--port", type=int, help="bind port for http (default 8765)")
    serve.set_defaults(func=cmd_serve)

    # --- accounts ---
    accounts = subparsers.add_parser("accounts", help="manage Gmail accounts")
    account_subs = accounts.add_subparsers(dest="accounts_command", required=True)

    def add_auth_flags(target: argparse.ArgumentParser) -> None:
        target.add_argument("--login-hint", help="pre-fill the Google account chooser")
        target.add_argument(
            "--no-browser", action="store_true", help="print the URL instead of opening a browser"
        )
        target.add_argument(
            "--port", type=int, default=0, help="fixed loopback port for the OAuth redirect"
        )

    add = account_subs.add_parser("add", help="add and authorize an account")
    add.add_argument("alias", help="human-readable alias, e.g. personal or work")
    add.add_argument(
        "--read-only",
        action="store_true",
        help="request only gmail.readonly, so Google itself refuses any write",
    )
    add_auth_flags(add)
    add.set_defaults(func=cmd_accounts_add)

    auth = account_subs.add_parser("auth", help="authorize an existing account")
    auth.add_argument("alias")
    add_auth_flags(auth)
    auth.set_defaults(func=cmd_accounts_auth)

    reauth = account_subs.add_parser("reauth", help="re-run authorization for an account")
    reauth.add_argument("alias")
    add_auth_flags(reauth)
    reauth.set_defaults(func=cmd_accounts_reauth)

    listing = account_subs.add_parser("list", help="list configured accounts")
    listing.add_argument("--json", action="store_true")
    listing.set_defaults(func=cmd_accounts_list)

    status = account_subs.add_parser("status", help="check authorization status")
    status.add_argument("alias", nargs="?", help="omit to check every account")
    status.add_argument("--json", action="store_true")
    status.set_defaults(func=cmd_accounts_status)

    remove = account_subs.add_parser("remove", help="revoke and remove an account")
    remove.add_argument("alias")
    remove.add_argument("--yes", action="store_true", help="confirm removal")
    remove.add_argument(
        "--keep-google-grant",
        action="store_true",
        help="delete local credentials without telling Google to revoke them",
    )
    remove.set_defaults(func=cmd_accounts_remove)

    # --- tokens ---
    token = subparsers.add_parser("token", help="manage gateway bearer tokens for HTTP")
    token_subs = token.add_subparsers(dest="token_command", required=True)

    token_create = token_subs.add_parser("create", help="mint a token")
    token_create.add_argument("name", help="label for this client, e.g. laptop-agent")
    token_create.set_defaults(func=cmd_token_create)

    token_list = token_subs.add_parser("list", help="list token names")
    token_list.add_argument("--json", action="store_true")
    token_list.set_defaults(func=cmd_token_list)

    token_revoke = token_subs.add_parser("revoke", help="revoke a token")
    token_revoke.add_argument("name")
    token_revoke.set_defaults(func=cmd_token_revoke)

    # --- audit ---
    audit = subparsers.add_parser("audit", help="inspect recent gateway actions")
    audit.add_argument("--limit", type=int, default=50)
    audit.add_argument("--account")
    audit.add_argument("--tool")
    audit.add_argument("--outcome", choices=["success", "failure", "denied"])
    audit.add_argument("--since-hours", type=float, help="only events from the last N hours")
    audit.add_argument("--json", action="store_true")
    audit.set_defaults(func=cmd_audit)

    # --- maintenance ---
    prune = subparsers.add_parser("prune", help="delete expired audit rows, dedup keys, files")
    prune.add_argument(
        "--attachment-age-hours",
        type=float,
        default=24.0,
        help="delete stored attachments older than this (default 24)",
    )
    prune.set_defaults(func=cmd_prune)

    health = subparsers.add_parser("health", help="verify the deployment is healthy")
    health.add_argument("--json", action="store_true")
    health.set_defaults(func=cmd_health)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        config = load_config()
    except GatewayError as exc:
        _err(exc.message)
        return EXIT_ERROR

    if args.log_level:
        from dataclasses import replace

        config = replace(config, log_level=args.log_level)

    setup_logging(config.log_level)

    try:
        return int(args.func(config, args))
    except GatewayError as exc:
        _err(f"[{exc.code}] {exc.message}")
        return EXIT_ERROR
    except KeyboardInterrupt:
        _print("\ninterrupted")
        return EXIT_ERROR
    except Exception as exc:  # noqa: BLE001
        _err(f"unexpected {type(exc).__name__}: {exc}")
        if config.log_level == "DEBUG":
            raise
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
