#!/usr/bin/env python3
"""Kick the tires against a real Gmail account.

Connects to the gateway over stdio exactly as an MCP client would, runs a
read-only tour of a mailbox, and then tries several forbidden operations to
confirm they are refused.

    uv run python scripts/try-it.py --account personal

Read-only by default. Mutations are opt-in and each is reversible:

    --draft     create, read back, and edit a draft (you delete it in Gmail)
    --archive   archive the newest unread message, then un-archive it

Nothing here can send, trash, or delete mail -- the gateway has no such tool.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

REPO = Path(__file__).resolve().parent.parent
BINARY = REPO / ".venv" / "bin" / "gmail-mcp-gateway"

GREEN, RED, DIM, BOLD, RESET = "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"


def head(text: str) -> None:
    print(f"\n{BOLD}{text}{RESET}")


def ok(text: str) -> None:
    print(f"  {GREEN}ok{RESET}   {text}")


def bad(text: str) -> None:
    print(f"  {RED}FAIL{RESET} {text}")


def note(text: str) -> None:
    print(f"       {DIM}{text}{RESET}")


async def call(session: ClientSession, tool: str, args: dict[str, Any]) -> tuple[bool, Any]:
    """Call a tool. Returns (succeeded, payload-or-error)."""
    result = await session.call_tool(tool, args)
    payload = result.structured_content or json.loads(result.content[0].text)
    return (not result.is_error), payload


async def expect_refusal(session: ClientSession, tool: str, args: dict[str, Any]) -> bool:
    succeeded, payload = await call(session, tool, args)
    if succeeded:
        bad(f"{tool} was ALLOWED -- this is a security failure")
        return False
    code = payload.get("error", {}).get("code", "?")
    ok(f"{tool} refused [{code}]")
    note(payload.get("error", {}).get("message", "")[:100])
    return True


def preflight() -> int:
    """Report setup problems clearly instead of failing at the MCP handshake.

    The gateway refuses to start without an OAuth client or an authorized
    account, which would otherwise surface here as an opaque "Connection
    closed".
    """
    import subprocess

    probe = subprocess.run(
        [str(BINARY), "health", "--json"], capture_output=True, text=True, timeout=60
    )
    try:
        report = json.loads(probe.stdout)
    except json.JSONDecodeError:
        bad("could not run 'gmail-mcp-gateway health'")
        note(probe.stderr.strip()[:300])
        return 1
    if report["healthy"]:
        return 0

    head("Setup is incomplete")
    for check in report["checks"]:
        (ok if check["ok"] else bad)(f"{check['check']:<14} {check['detail']}")
    print("\nFix the failing checks above, then re-run. See the README section")
    print("'Google Cloud setup' and 'Adding accounts'.")
    return 1


async def run(args: argparse.Namespace) -> int:
    params = StdioServerParameters(
        command=str(BINARY), args=["serve", "--transport", "stdio"], env=dict(os.environ)
    )
    failures = 0

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()

            head(f"Connected to {init.server_info.name} {init.server_info.version}")
            tools = sorted(t.name for t in (await session.list_tools()).tools)
            ok(f"{len(tools)} tools exposed")
            note(", ".join(tools))

            forbidden = [t for t in tools if any(b in t for b in ("send", "trash", "delete", "spam"))]
            if forbidden:
                bad(f"forbidden tool names present: {forbidden}")
                failures += 1
            else:
                ok("no send / trash / delete / spam tool exists")

            # --- accounts -------------------------------------------------
            head("Account status")
            succeeded, payload = await call(session, "accounts_status", {"account": args.account})
            if not succeeded:
                bad(f"accounts_status failed: {payload.get('error', {}).get('message')}")
                return 1
            entry = payload["accounts"][0]
            if entry["live_check"]["ok"]:
                ok(f"{entry['alias']} -> {entry['email_address']}")
                note(f"{entry.get('messages_total')} messages, {entry.get('threads_total')} threads")
            else:
                bad(f"{entry['alias']} is not reachable: {entry['live_check']['error']}")
                return 1

            # --- reads ----------------------------------------------------
            head("Labels")
            _, payload = await call(session, "gmail_labels_list", {"account": args.account})
            ok(f"{payload['count']} labels")
            locked = [lbl["id"] for lbl in payload["labels"] if not lbl["modifiable_by_gateway"]]
            note(f"gateway refuses to modify: {', '.join(locked)}")

            head("Search")
            _, payload = await call(
                session,
                "gmail_search",
                {"account": args.account, "query": args.query, "limit": 5, "detail": "metadata"},
            )
            ok(f"{payload['count']} result(s) for {args.query!r}")
            for message in payload["messages"]:
                sender = (message.get("from") or {}).get("email", "?")
                print(f"       {message['timestamp']['iso'][:10]}  {sender:<32.32} {message['subject'][:44]}")

            if not payload["messages"]:
                note("no messages matched; skipping the read tour")
                return failures

            first = payload["messages"][0]
            message_id, thread_id = first["id"], first["thread_id"]

            head("Read one message")
            _, payload = await call(
                session, "gmail_get_message", {"account": args.account, "message_id": message_id}
            )
            message = payload["message"]
            body = message["body"]
            ok(f"body: {body['total_characters']} chars from {body['source']}")
            if body["removed_hidden_characters"]:
                note(f"stripped {body['removed_hidden_characters']} invisible character(s)")
            note(f"untrusted-content flag: {payload['content_is_untrusted']}")
            print(f"{DIM}       ---\n{RESET}" + "\n".join(
                f"{DIM}       | {line[:90]}{RESET}" for line in body["text"].splitlines()[:6]
            ))

            head("Read the thread")
            _, payload = await call(
                session, "gmail_get_thread", {"account": args.account, "thread_id": thread_id}
            )
            ok(f"{payload['thread']['message_count']} message(s), "
               f"{len(payload['thread']['participants'])} participant(s)")

            head("Attachments")
            _, payload = await call(
                session, "gmail_attachments_list", {"account": args.account, "message_id": message_id}
            )
            ok(f"{payload['count']} attachment(s)")
            for att in payload["attachments"]:
                note(f"{att['filename']} ({att['mime_type']}, {att['size_bytes']} bytes)")

            # --- the point of the whole exercise --------------------------
            head("Forbidden operations (all of these must be refused)")
            checks = [
                ("gmail_labels_add", {"account": args.account, "labels": ["TRASH"],
                                      "message_ids": [message_id]}),
                ("gmail_labels_add", {"account": args.account, "labels": ["SPAM"],
                                      "message_ids": [message_id]}),
                ("gmail_labels_remove", {"account": args.account, "labels": ["TRASH"],
                                         "message_ids": [message_id]}),
            ]
            for tool, arguments in checks:
                if not await expect_refusal(session, tool, arguments):
                    failures += 1

            for absent in ("gmail_send", "gmail_drafts_send", "gmail_trash", "gmail_delete",
                           "gmail_raw_request"):
                if absent in tools:
                    bad(f"{absent} exists")
                    failures += 1
            ok("gmail_send / gmail_drafts_send / gmail_trash / gmail_delete / "
               "gmail_raw_request do not exist")

            head("Header injection")
            succeeded, payload = await call(
                session,
                "gmail_drafts_create",
                {"account": args.account, "to": ["a@example.com\r\nBcc: attacker@evil.example"],
                 "body": "test"},
            )
            if succeeded:
                bad("a CRLF in a recipient was accepted")
                failures += 1
            else:
                ok(f"rejected [{payload['error']['code']}]")

            # --- opt-in mutations -----------------------------------------
            if args.draft:
                head("Drafts (creates a real draft you can delete in Gmail)")
                _, created = await call(
                    session,
                    "gmail_drafts_reply",
                    {"account": args.account, "message_id": message_id,
                     "body": "Test draft from the Gmail MCP Gateway. Safe to delete."},
                )
                draft_id = created["draft_id"]
                ok(f"created reply draft {draft_id} in thread {created['thread_id']}")
                note(f"to: {created.get('to')}  subject: {created.get('subject')}")
                note(f"sendable_by_gateway: {created['sendable_by_gateway']}")

                await call(
                    session,
                    "gmail_drafts_update",
                    {"account": args.account, "draft_id": draft_id,
                     "body": "Edited by the gateway. Still safe to delete."},
                )
                ok("edited the draft")

                _, fetched = await call(
                    session, "gmail_drafts_get", {"account": args.account, "draft_id": draft_id}
                )
                ok(f"read it back: {fetched['draft']['message']['body']['text'][:50]!r}")
                note("check Gmail: the draft should sit inside the original conversation")
                note(f"{BOLD}delete it yourself -- this gateway cannot{RESET}")

            if args.archive:
                head("Archive round trip")
                _, payload = await call(
                    session, "gmail_archive",
                    {"account": args.account, "message_ids": [message_id],
                     "client_request_id": "try-it-archive"},
                )
                ok(f"archived {message_id} (removed {payload['labels_removed']})")

                _, payload = await call(
                    session, "gmail_labels_add",
                    {"account": args.account, "labels": ["INBOX"], "message_ids": [message_id]},
                )
                ok("restored it to the inbox")

                _, payload = await call(
                    session, "gmail_archive",
                    {"account": args.account, "message_ids": [message_id],
                     "client_request_id": "try-it-archive"},
                )
                if payload.get("deduplicated"):
                    ok("replaying the same client_request_id was deduplicated, not re-run")
                else:
                    note("idempotency window may have expired; not a failure")

    head("Result")
    if failures:
        bad(f"{failures} check(s) failed")
    else:
        ok("every check passed")
        note("now run: gmail-mcp-gateway audit --limit 20")
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--account", required=True, help="account alias from accounts_list")
    parser.add_argument("--query", default="is:unread", help="Gmail search (default: is:unread)")
    parser.add_argument("--draft", action="store_true", help="also create and edit a real draft")
    parser.add_argument("--archive", action="store_true",
                        help="also archive and un-archive one message")
    args = parser.parse_args()

    if not BINARY.exists():
        print(f"error: {BINARY} not found -- run 'uv sync' first", file=sys.stderr)
        return 1
    if failed := preflight():
        return failed
    return asyncio.run(run(args))


if __name__ == "__main__":
    raise SystemExit(main())
