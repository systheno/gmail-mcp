"""Administrative CLI. Nothing here is reachable from an MCP client."""

from __future__ import annotations

import json

import pytest

from gmail_mcp_gateway.cli import EXIT_ERROR, EXIT_OK, EXIT_UNHEALTHY, build_parser, main


@pytest.fixture
def cli_env(config, monkeypatch, oauth_env):
    monkeypatch.setenv("GMAIL_MCP_CONFIG_DIR", str(config.config_dir))
    monkeypatch.setenv("GMAIL_MCP_DATA_DIR", str(config.data_dir))
    monkeypatch.setenv("GMAIL_MCP_SECRETS_DIR", str(config.secrets_dir))
    return config


def run(argv: list[str]) -> int:
    return main(argv)


# --------------------------------------------------------------------------- #
# Parser shape
# --------------------------------------------------------------------------- #


def test_a_subcommand_is_required():
    with pytest.raises(SystemExit):
        build_parser().parse_args([])


@pytest.mark.parametrize(
    "argv",
    [
        ["serve"],
        ["serve", "--transport", "http"],
        ["accounts", "add", "personal"],
        ["accounts", "add", "personal", "--read-only"],
        ["accounts", "auth", "personal"],
        ["accounts", "reauth", "personal"],
        ["accounts", "list"],
        ["accounts", "status"],
        ["accounts", "remove", "personal", "--yes"],
        ["token", "create", "laptop"],
        ["token", "list"],
        ["token", "revoke", "laptop"],
        ["audit", "--limit", "10"],
        ["prune"],
        ["health", "--json"],
    ],
)
def test_documented_commands_parse(argv):
    assert build_parser().parse_args(argv).func is not None


@pytest.mark.parametrize(
    "argv",
    [
        ["send"],
        ["gmail", "send"],
        ["accounts", "send"],
        ["trash"],
        ["delete"],
        ["raw"],
    ],
)
def test_no_command_exists_for_a_forbidden_capability(argv):
    """The CLI has no send/trash/delete path either."""
    with pytest.raises(SystemExit):
        build_parser().parse_args(argv)


def test_invalid_transport_is_rejected():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["serve", "--transport", "websocket"])


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #


def test_accounts_list_with_no_accounts_succeeds(cli_env, capsys):
    assert run(["accounts", "list"]) == EXIT_OK
    assert "no accounts configured" in capsys.readouterr().out


def test_accounts_list_json_output(cli_env, store, account, capsys):
    assert run(["accounts", "list", "--json"]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["accounts"][0]["alias"] == "personal"
    assert "refresh_token" not in json.dumps(payload)


def test_accounts_list_never_prints_credentials(cli_env, store, account, capsys):
    run(["accounts", "list"])
    output = capsys.readouterr().out
    for secret in ("1//", "ya29.", "GOCSPX"):
        assert secret not in output


def test_removing_an_account_requires_confirmation(cli_env, store, account, capsys):
    assert run(["accounts", "remove", "personal"]) == EXIT_ERROR
    assert "--yes" in capsys.readouterr().err
    assert store.exists("personal")


def test_removing_an_unknown_account_reports_cleanly(cli_env, capsys):
    assert run(["accounts", "remove", "ghost", "--yes"]) == EXIT_ERROR
    assert "unknown_account" in capsys.readouterr().err


def test_token_lifecycle(cli_env, capsys):
    assert run(["token", "create", "laptop"]) == EXIT_OK
    created = capsys.readouterr().out
    assert "shown once" in created

    assert run(["token", "list", "--json"]) == EXIT_OK
    listed = json.loads(capsys.readouterr().out)
    assert listed["tokens"][0]["name"] == "laptop"
    # Listing must not reveal the secret or its hash.
    assert "hash" not in json.dumps(listed)

    assert run(["token", "revoke", "laptop"]) == EXIT_OK
    assert run(["token", "revoke", "laptop"]) == EXIT_ERROR


def test_audit_command_reports_recent_actions(cli_env, config, capsys):
    from gmail_mcp_gateway.audit import AuditLog
    from gmail_mcp_gateway.db import Database

    database = Database(config.db_path)
    database.initialize()
    AuditLog(database).record(
        tool="gmail_archive",
        operation="archive",
        outcome="success",
        account="personal",
        target_ids=["msg1"],
    )
    assert run(["audit", "--limit", "5"]) == EXIT_OK
    output = capsys.readouterr().out
    assert "archive" in output and "personal" in output and "msg1" in output


def test_audit_json_output_is_machine_readable(cli_env, config, capsys):
    from gmail_mcp_gateway.audit import AuditLog
    from gmail_mcp_gateway.db import Database

    database = Database(config.db_path)
    database.initialize()
    AuditLog(database).record(tool="t", operation="archive", outcome="success", account="p")
    assert run(["audit", "--json"]) == EXIT_OK
    assert json.loads(capsys.readouterr().out)["events"][0]["operation"] == "archive"


def test_audit_filters_are_applied(cli_env, config, capsys):
    from gmail_mcp_gateway.audit import AuditLog
    from gmail_mcp_gateway.db import Database

    database = Database(config.db_path)
    database.initialize()
    log = AuditLog(database)
    log.record(tool="t", operation="archive", outcome="success", account="personal")
    log.record(tool="t", operation="draft_create", outcome="failure", account="work")

    run(["audit", "--account", "work", "--json"])
    events = json.loads(capsys.readouterr().out)["events"]
    assert len(events) == 1 and events[0]["account"] == "work"


def test_prune_reports_what_it_removed(cli_env, capsys):
    assert run(["prune"]) == EXIT_OK
    output = capsys.readouterr().out
    assert "audit event" in output and "attachment" in output


def test_health_is_unhealthy_without_accounts(cli_env, capsys):
    assert run(["health"]) == EXIT_UNHEALTHY
    output = capsys.readouterr().out
    assert "UNHEALTHY" in output
    assert "none configured" in output


def test_health_passes_with_an_authorized_account(cli_env, store, account, capsys):
    assert run(["health"]) == EXIT_OK
    output = capsys.readouterr().out
    assert "healthy" in output
    assert "1/1 authorized" in output


def test_health_json_output(cli_env, store, account, capsys):
    assert run(["health", "--json"]) == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["healthy"] is True
    assert {"database", "master_key", "oauth_client", "accounts"} <= {
        entry["check"] for entry in payload["checks"]
    }


def test_health_reports_a_missing_oauth_client(cli_env, monkeypatch, capsys):
    monkeypatch.delenv("GMAIL_MCP_OAUTH_CLIENT_ID", raising=False)
    monkeypatch.delenv("GMAIL_MCP_OAUTH_CLIENT_SECRET", raising=False)
    assert run(["health", "--json"]) == EXIT_UNHEALTHY
    checks = {c["check"]: c for c in json.loads(capsys.readouterr().out)["checks"]}
    assert checks["oauth_client"]["ok"] is False


def test_health_output_contains_no_secrets(cli_env, store, account, capsys):
    run(["health", "--json"])
    output = capsys.readouterr().out
    for secret in ("GOCSPX", "ya29.", "1//", "master.key\": \""):
        assert secret not in output


def test_unexpected_errors_are_reported_without_a_traceback(cli_env, monkeypatch, capsys):
    """build_parser resolves command functions at call time, so this patch lands."""
    from gmail_mcp_gateway import cli

    def explode(config, args):
        raise RuntimeError("internal boom")

    monkeypatch.setattr(cli, "cmd_health", explode)
    assert run(["health"]) == EXIT_ERROR
    captured = capsys.readouterr()
    assert "unexpected RuntimeError" in captured.err
    assert "Traceback" not in captured.err


def test_gateway_errors_are_reported_with_their_code(cli_env, monkeypatch, capsys):
    from gmail_mcp_gateway import cli
    from gmail_mcp_gateway.errors import ErrorCode, GatewayError

    def refuse(config, args):
        raise GatewayError(ErrorCode.CONFIG_ERROR, "the config is wrong")

    monkeypatch.setattr(cli, "cmd_health", refuse)
    assert run(["health"]) == EXIT_ERROR
    assert "[config_error] the config is wrong" in capsys.readouterr().err
