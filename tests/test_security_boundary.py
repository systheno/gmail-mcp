"""The headline guarantee.

An MCP client must be able to inspect and organize a mailbox and prepare drafts,
while being technically unable to send or delete email through this application.

These tests assert that from several directions at once: the tool surface, the
endpoint allowlist, the label policy, and -- most importantly -- the actual HTTP
traffic the gateway emits while doing real work.
"""

from __future__ import annotations

import asyncio

import pytest

from gmail_mcp_gateway.errors import ErrorCode, ForbiddenOperation, GatewayError
from gmail_mcp_gateway.gmail import allowlist as ep
from gmail_mcp_gateway.mcpsrv.server import EXPOSED_TOOLS, FORBIDDEN_TOOLS, build_server

from .conftest import FakeGmail


# --------------------------------------------------------------------------- #
# 1. The tool surface
# --------------------------------------------------------------------------- #


def test_exposed_tool_set_is_exactly_as_declared(config, oauth_env, gmail, service):
    server = build_server(config, service)
    names = {tool.name for tool in asyncio.run(server.list_tools())}
    assert names == EXPOSED_TOOLS


def test_no_forbidden_tool_is_exposed(config, oauth_env, gmail, service):
    server = build_server(config, service)
    names = {tool.name for tool in asyncio.run(server.list_tools())}
    assert not (names & FORBIDDEN_TOOLS)


@pytest.mark.parametrize(
    "banned_substring", ["send", "trash", "delete", "spam", "settings", "raw", "exec", "shell"]
)
def test_no_tool_name_hints_at_a_forbidden_capability(
    config, oauth_env, gmail, service, banned_substring
):
    server = build_server(config, service)
    for tool in asyncio.run(server.list_tools()):
        assert banned_substring not in tool.name.lower(), tool.name


def test_every_tool_is_documented_and_annotated(config, oauth_env, gmail, service):
    server = build_server(config, service)
    for tool in asyncio.run(server.list_tools()):
        assert tool.description and len(tool.description) > 40, tool.name
        assert tool.annotations is not None, tool.name
        assert tool.input_schema["type"] == "object"


def test_no_tool_accepts_a_url_path_or_endpoint_parameter(config, oauth_env, gmail, service):
    """A generic Gmail proxy would need one of these parameters. None exists."""
    server = build_server(config, service)
    banned = {"url", "path", "endpoint", "method", "raw", "request", "api", "command", "resource"}
    for tool in asyncio.run(server.list_tools()):
        properties = set(tool.input_schema.get("properties", {}))
        assert not (properties & banned), f"{tool.name} exposes {properties & banned}"


# --------------------------------------------------------------------------- #
# 2. The endpoint allowlist
# --------------------------------------------------------------------------- #


def test_allowlist_contains_no_forbidden_endpoint():
    for endpoint in ep.ALLOWED_ENDPOINTS:
        lowered = endpoint.template.lower()
        for banned in ("send", "trash", "delete", "settings", "import", "insert", "watch", "stop"):
            assert banned not in lowered, f"{endpoint.name} reaches {banned}"


def test_allowlist_uses_no_destructive_http_method():
    assert {endpoint.method for endpoint in ep.ALLOWED_ENDPOINTS} <= {"GET", "POST", "PUT"}


@pytest.mark.parametrize(
    ("method", "template"),
    [
        ("POST", "/users/{userId}/messages/send"),
        ("POST", "/users/{userId}/drafts/{id}/send"),
        ("POST", "/users/{userId}/messages/{id}/trash"),
        ("POST", "/users/{userId}/messages/{id}/untrash"),
        ("POST", "/users/{userId}/messages/batchDelete"),
        ("GET", "/users/{userId}/settings/forwardingAddresses"),
        ("POST", "/users/{userId}/settings/filters"),
        ("POST", "/users/{userId}/watch"),
    ],
)
def test_forbidden_endpoints_are_rejected_even_if_constructed(method, template):
    """Fabricating an Endpoint is not enough: build_path checks the allowlist."""
    forged = ep.Endpoint(name="forged", method=method, template=template)
    with pytest.raises(ForbiddenOperation):
        ep.build_path(forged, {"userId": "me", "id": "abc"} if "{id}" in template else {"userId": "me"})


@pytest.mark.parametrize("method", ["DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"])
def test_destructive_http_methods_cannot_be_used(method):
    with pytest.raises(ForbiddenOperation):
        ep.Endpoint(name="forged", method=method, template="/users/{userId}/messages/{id}")


@pytest.mark.parametrize(
    "malicious",
    [
        "../../settings/forwarding",
        "abc/../../messages/send",
        "abc/trash",
        "..",
        "a b",
        "abc?alt=json",
        "abc#frag",
        "abc/",
        "",
        "x" * 300,
        "abc\x00def",
        "abc\nGET /users/me/messages/send",
    ],
)
def test_path_parameters_cannot_escape_their_segment(malicious):
    with pytest.raises(GatewayError) as info:
        ep.build_path(ep.GET_MESSAGE, {"userId": "me", "id": malicious})
    assert info.value.code in {ErrorCode.INVALID_INPUT, ErrorCode.FORBIDDEN_OPERATION}


def test_final_gate_rejects_a_forbidden_path_regardless_of_origin():
    """assert_path_permitted is independent of how the path was built."""
    for path in (
        "/users/me/messages/send",
        "/users/me/drafts/1/send",
        "/users/me/messages/1/trash",
        "/users/me/settings/autoForwarding",
    ):
        with pytest.raises(ForbiddenOperation):
            ep.assert_path_permitted("POST", path)


def test_unexpected_query_parameters_are_rejected():
    with pytest.raises(GatewayError):
        ep.validate_query(ep.GET_MESSAGE, {"format": "full", "uploadType": "media"})


# --------------------------------------------------------------------------- #
# 3. Label policy: the back door into trash and spam
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("label", ["TRASH", "SPAM", "trash", "Spam", "sPaM"])
async def test_adding_trash_or_spam_label_is_refused(service, gmail: FakeGmail, label):
    with pytest.raises(GatewayError) as info:
        await service.labels_add(alias="personal", labels=[label], message_ids=["msg1"])
    assert info.value.code is ErrorCode.FORBIDDEN_LABEL
    gmail.assert_no_forbidden_requests()
    # And no modify call was issued at all.
    assert not any("batchModify" in path for path in gmail.paths())


@pytest.mark.parametrize("label", ["TRASH", "SPAM"])
async def test_removing_trash_or_spam_label_is_refused(service, gmail: FakeGmail, label):
    with pytest.raises(GatewayError) as info:
        await service.labels_remove(alias="personal", labels=[label], message_ids=["msg1"])
    assert info.value.code is ErrorCode.FORBIDDEN_LABEL
    assert not any("batchModify" in path for path in gmail.paths())


async def test_forbidden_label_hidden_among_allowed_ones_is_refused(service, gmail: FakeGmail):
    with pytest.raises(GatewayError) as info:
        await service.labels_add(
            alias="personal", labels=["Receipts", "STARRED", "TRASH"], message_ids=["msg1"]
        )
    assert info.value.code is ErrorCode.FORBIDDEN_LABEL
    assert not any("batchModify" in path for path in gmail.paths())


async def test_forbidden_label_by_display_name_is_refused(service, gmail: FakeGmail):
    """The fake mailbox has a label literally named TRASH; resolving it still fails."""
    with pytest.raises(GatewayError) as info:
        await service.labels_add(alias="personal", labels=["TRASH"], message_ids=["msg1"])
    assert info.value.code is ErrorCode.FORBIDDEN_LABEL


# --------------------------------------------------------------------------- #
# 4. Real traffic: a full workflow emits only allowlisted requests
# --------------------------------------------------------------------------- #


async def test_complete_workflow_never_touches_a_forbidden_endpoint(service, gmail: FakeGmail):
    """Exercise every supported capability, then audit the wire."""
    await service.accounts_status("personal")
    await service.search(alias="personal", query="is:unread", detail="metadata")
    await service.get_message(alias="personal", message_id="msg1")
    await service.get_thread(alias="personal", thread_id="thr1")
    await service.labels_list(alias="personal")
    await service.attachments_list(alias="personal", message_id="msg1")
    await service.mark_read(alias="personal", message_ids=["msg1"])
    await service.mark_unread(alias="personal", message_ids=["msg1"])
    await service.archive(alias="personal", message_ids=["msg1"])
    await service.labels_add(alias="personal", labels=["Receipts"], message_ids=["msg1"])
    await service.labels_remove(alias="personal", labels=["Receipts"], message_ids=["msg1"])
    created = await service.drafts_create(
        alias="personal", to=["bob@example.com"], subject="Hi", body="Hello"
    )
    await service.drafts_list(alias="personal")
    await service.drafts_get(alias="personal", draft_id=created["draft_id"])
    await service.drafts_update(alias="personal", draft_id=created["draft_id"], body="Updated")
    await service.drafts_reply(alias="personal", message_id="msg1", body="Thanks")

    gmail.assert_no_forbidden_requests()
    assert gmail.requests, "the workflow should have issued requests"


async def test_service_exposes_no_method_that_could_send_or_delete(service):
    """No public method on the service layer suggests a forbidden capability."""
    public = {name for name in dir(service) if not name.startswith("_")}
    for banned in ("send", "trash", "delete", "spam", "raw", "request", "proxy"):
        offenders = {name for name in public if banned in name.lower()}
        assert not offenders, offenders


async def test_read_only_account_cannot_mutate(service, readonly_account, gmail: FakeGmail):
    """An account authorized read-only is refused before any request is made."""
    for call in (
        lambda: service.archive(alias="archive", message_ids=["msg1"]),
        lambda: service.mark_read(alias="archive", message_ids=["msg1"]),
        lambda: service.labels_add(alias="archive", labels=["Receipts"], message_ids=["msg1"]),
        lambda: service.drafts_create(alias="archive", to=["b@example.com"], body="x"),
    ):
        with pytest.raises(GatewayError) as info:
            await call()
        assert info.value.code is ErrorCode.ACCOUNT_READ_ONLY

    assert not any(method in {"POST", "PUT"} for method, _ in gmail.requests)


async def test_drafts_are_never_reported_as_sendable(service):
    created = await service.drafts_create(
        alias="personal", to=["bob@example.com"], subject="Hi", body="Hello"
    )
    assert created["sendable_by_gateway"] is False
    fetched = await service.drafts_get(alias="personal", draft_id=created["draft_id"])
    assert fetched["draft"]["sendable_by_gateway"] is False


# --------------------------------------------------------------------------- #
# 5. Credentials never leave the gateway
# --------------------------------------------------------------------------- #


def test_public_account_view_contains_no_credential_material(account):
    view = account.public_view()
    serialized = repr(view)
    for secret in ("refresh_token", "access_token", "client_secret", "1//", "ya29.", "GOCSPX"):
        assert secret not in serialized
    assert "account_id" not in view


async def test_no_tool_result_contains_token_material(service, gmail: FakeGmail):
    results = [
        service.accounts_list(),
        await service.accounts_status(),
        await service.search(alias="personal", detail="metadata"),
        await service.get_message(alias="personal", message_id="msg1"),
    ]
    for result in results:
        blob = repr(result)
        for secret in ("ya29.", "1//fake", "GOCSPX", "refresh_token", "client_secret"):
            assert secret not in blob


# --------------------------------------------------------------------------- #
# 6. Reading Trash and Spam is allowed; writing to them is not
# --------------------------------------------------------------------------- #


async def test_trash_can_be_read_but_not_written(service, gmail: FakeGmail):
    """Reading what is already in Trash is a read. Putting mail there is not."""
    result = await service.search(alias="personal", label_ids=["TRASH"], detail="ids")
    assert "messages" in result

    with pytest.raises(GatewayError) as info:
        await service.labels_add(alias="personal", labels=["TRASH"], message_ids=["msg1"])
    assert info.value.code is ErrorCode.FORBIDDEN_LABEL
    gmail.assert_no_forbidden_requests()


async def test_include_spam_trash_is_permitted_on_reads(service, gmail: FakeGmail):
    await service.search(alias="personal", include_spam_trash=True, detail="ids")
    gmail.assert_no_forbidden_requests()
