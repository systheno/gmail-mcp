# Gmail MCP Gateway

An MCP server that gives AI agents full read and organizational access to
multiple Gmail accounts — and no ability to send, trash, or delete mail.

```
                     Gmail MCP Gateway

        ALLOWED                        FORBIDDEN
        ───────                        ─────────
        Search                         Send
        Read messages                  Send draft
        Read threads                   Trash
        Read attachments               Delete
        Create drafts                  Mark spam
        Edit drafts                    Gmail settings
        Archive                        Forwarding rules
        Read / unread                  Arbitrary API calls
        Labels
```

The guarantee is enforced in application code, not by instructions to the
client. A buggy, compromised, or prompt-injected MCP client cannot send email
through this gateway, because no code path exists that would let it.

---

## Contents

- [Quickstart](#quickstart) — from clone to working, in five steps
- [Environment variables](#environment-variables) — what to set, and how to generate it
- [Running it](#running-it) — stdio, HTTP, systemd, Docker
- [Connecting an MCP client](#connecting-an-mcp-client)
- [Tool reference](#tool-reference)
- [Administration](#administration)
- [How the boundary is enforced](#how-the-boundary-is-enforced)
- [Security model](#security-model)
- [Reliability](#reliability)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)

---

## Quickstart

Requires Python 3.11+. Five steps, roughly ten minutes, most of it in the
Google console.

### 1. Install

```bash
git clone <this-repo> gmail-mcp-gateway
cd gmail-mcp-gateway
uv sync                                  # or: python -m venv .venv && .venv/bin/pip install -e .
.venv/bin/gmail-mcp-gateway --version
```

Optionally put it on your `PATH` so the examples below read more naturally:

```bash
export PATH="$PWD/.venv/bin:$PATH"
```

### 2. Create a Google OAuth client

One-time, free, and shared by every account you later add.

1. Create a project at <https://console.cloud.google.com/>.
2. **APIs & Services → Library** → enable **Gmail API**.
3. **APIs & Services → OAuth consent screen** → **External**, fill in the
   required fields, add your own Google account under **Test users**.
4. **Publish app** (still no verification review needed while you are the only
   user). Skipping this leaves the app in "Testing", where Google expires
   refresh tokens after **7 days** and you will be re-authorizing every week.
5. **Credentials → Create credentials → OAuth client ID → Desktop app** →
   **Download JSON**.

You do not select scopes here. The gateway requests exactly what it needs at
authorization time and refuses to request anything outside Gmail.

### 3. Install the OAuth client

```bash
install -Dm600 ~/Downloads/client_secret_*.json \
  ~/.local/share/gmail-mcp-gateway/secrets/oauth_client.json
```

That is the only file you have to place by hand. The encryption key is
generated for you on first run.

### 4. Authorize an account

```bash
gmail-mcp-gateway accounts add personal
```

A browser opens; approve the requested permissions, leaving **every** box
ticked (the gateway fails loudly rather than half-working if a permission is
withheld). A refresh token is stored encrypted, and from here the gateway runs
unattended.

Add as many as you like — each gets its own consent, refresh token, encryption
key, rate-limit bucket, and audit trail:

```bash
gmail-mcp-gateway accounts add work
gmail-mcp-gateway accounts add newsletters --read-only   # Google itself refuses writes
```

### 5. Verify

```bash
gmail-mcp-gateway health          # exit 0 = ready, 2 = something is wrong
```

```
[ok  ] directories      config=/home/you/.config/gmail-mcp-gateway ...
[ok  ] database         /home/you/.local/share/gmail-mcp-gateway/gateway.db
[ok  ] master_key       loaded
[ok  ] oauth_client     configured
[ok  ] accounts         1/1 authorized

gmail-mcp-gateway 1.0.0: healthy
```

Then point your MCP client at it — see [Connecting an MCP
client](#connecting-an-mcp-client) — or take it for a spin first:

```bash
uv run python scripts/try-it.py --account personal
```

---

## Environment variables

**For a normal local install you need none of them.** The quickstart above sets
zero environment variables. Defaults put config in `~/.config`, data and
secrets in `~/.local/share`, and the encryption key generates itself.

These exist for containers, systemd units, and secret managers — places where a
file on disk is the wrong mechanism.

| Variable | Required? | Default | Purpose |
|---|---|---|---|
| `GMAIL_MCP_OAUTH_CLIENT_ID` | no¹ | — | Google OAuth client id |
| `GMAIL_MCP_OAUTH_CLIENT_SECRET` | no¹ | — | Google OAuth client secret |
| `GMAIL_MCP_MASTER_KEY` | no² | auto-generated | base64 32-byte credential encryption key |
| `GMAIL_MCP_CONFIG_DIR` | no | `~/.config/gmail-mcp-gateway` | `config.toml`; nothing secret |
| `GMAIL_MCP_DATA_DIR` | no | `~/.local/share/gmail-mcp-gateway` | `gateway.db`, `attachments/` |
| `GMAIL_MCP_SECRETS_DIR` | no | `<data>/secrets` | keys, OAuth client, credentials |
| `GMAIL_MCP_HTTP_HOST` | no | `127.0.0.1` | HTTP bind address |
| `GMAIL_MCP_HTTP_PORT` | no | `8765` | HTTP bind port |
| `GMAIL_MCP_HTTP_ENABLED` | no | `false` | Enable HTTP transport via config |
| `GMAIL_MCP_ALLOW_REMOTE_BIND` | no | `false` | Permit a non-loopback bind |
| `GMAIL_MCP_LOG_LEVEL` | no | `INFO` | `DEBUG`…`CRITICAL` |

¹ Alternative to `secrets/oauth_client.json`. Provide the file *or* the pair.
² Unset means the gateway creates `secrets/master.key` (mode 0600) on first run.

Environment variables override `config.toml`, which overrides the defaults.

### Generating each value

**OAuth client id and secret** — from the JSON you downloaded in quickstart
step 2. To use environment variables instead of the file:

```bash
jq -r '.installed.client_id'     ~/Downloads/client_secret_*.json
jq -r '.installed.client_secret' ~/Downloads/client_secret_*.json
```

**Master key** — 32 random bytes, base64:

```bash
openssl rand -base64 32
# or, without openssl:
python3 -c "import base64,secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())"
```

> This key decrypts your stored refresh tokens. Changing it after you have
> added accounts makes their credentials unreadable and every account needs
> `accounts reauth`. Back it up wherever you back up the data directory.

**Gateway bearer token** — *not* an environment variable. It is what an MCP
client sends over the HTTP transport, and it is unrelated to any Google
credential. The CLI mints it and stores only a SHA-256 hash:

```bash
gmail-mcp-gateway token create my-agent
```

The plaintext is printed once and goes in the **client's** config.

### Using an env file

The gateway does not read `.env` automatically — a security tool should not
silently absorb secrets from whatever directory it was started in. Copy
[`.env.example`](.env.example), which documents every variable, and load it
explicitly:

```bash
cp .env.example .env       # already covered by .gitignore
$EDITOR .env
set -a && source .env && set +a
gmail-mcp-gateway health
```

systemd uses `EnvironmentFile=`; Docker Compose uses `env_file:`.

---

## Running it

### stdio — the usual choice

The client launches the gateway as a child process and talks over pipes. No
port, no token, no network exposure. Google credentials stay inside the gateway
process; the client sees only tool calls.

```bash
gmail-mcp-gateway serve --transport stdio
```

Run by hand it will appear to hang — that is correct, it is waiting for JSON-RPC
on stdin. Normally your MCP client starts it for you.

### Streamable HTTP — standalone service

For a long-lived service, or a client that cannot spawn processes.

```bash
gmail-mcp-gateway token create my-agent          # once; save the printed token
gmail-mcp-gateway serve --transport http --host 127.0.0.1 --port 8765
```

The endpoint binds loopback, requires a bearer token, and has DNS-rebinding
protection on. `GET /healthz` is unauthenticated and reports liveness only.

Binding a non-loopback address requires `GMAIL_MCP_ALLOW_REMOTE_BIND=true`, and
an internet-routable address is refused even then. For a remote client, tunnel:

```bash
ssh -L 8765:127.0.0.1:8765 gateway-host
```

### systemd

[`deploy/gmail-mcp-gateway.service`](deploy/gmail-mcp-gateway.service) runs as a
dedicated system user in a hardened sandbox — `ProtectSystem=strict`, empty
`CapabilityBoundingSet`, seccomp filter, `NoExecPaths` over the data directory.
Install steps are in the unit's header. Authorize accounts once, interactively,
as the service user before starting it.

### Docker

[`deploy/Dockerfile`](deploy/Dockerfile) and
[`deploy/docker-compose.yml`](deploy/docker-compose.yml) run non-root and
read-only, all capabilities dropped, port published to loopback only. The image
contains no credentials; they live in the `/secrets` volume.

```bash
docker compose -f deploy/docker-compose.yml up -d
```

The Compose project name is pinned to `gmail-mcp`, so the same command targets
the existing gateway container and named volumes regardless of the Compose
file's directory name.

The one-time authorization sequence — placing the OAuth client, running the
consent flow with the redirect port published, minting a token — is in the
compose file's header comments.

---

## Connecting an MCP client

### stdio

```json
{
  "mcpServers": {
    "gmail": {
      "command": "/absolute/path/to/gmail-mcp-gateway/.venv/bin/gmail-mcp-gateway",
      "args": ["serve", "--transport", "stdio"]
    }
  }
}
```

Claude Code:

```bash
claude mcp add gmail -- /absolute/path/to/.venv/bin/gmail-mcp-gateway serve --transport stdio
```

### HTTP

```json
{
  "mcpServers": {
    "gmail": {
      "type": "http",
      "url": "http://127.0.0.1:8765/mcp",
      "headers": { "Authorization": "Bearer <token from `token create`>" }
    }
  }
}
```

Clients never mount or otherwise access Google credential files. Under stdio the
client speaks to a pipe; under HTTP it holds a gateway token unrelated to any
Google credential.

---

## Tool reference

Every tool takes an `account` alias — there is no default account. Mutating
tools accept an optional `client_request_id` for idempotency: repeating a call
with the same id and arguments returns the first result instead of acting twice.

| Tool | What it does |
|---|---|
| `accounts_list` | Aliases, addresses, status, granted capabilities. No credentials. |
| `accounts_status` | Live authorization check per account, plus mailbox totals. |
| `gmail_search` | Gmail search syntax; `detail` of `ids`, `metadata`, or `full`; paginated. |
| `gmail_get_message` | One message: sender, to, cc, bcc, subject, timestamp, labels, read state, body, attachment inventory. |
| `gmail_get_thread` | A whole conversation in order, with participants. |
| `gmail_attachments_list` | Attachment inventory. Downloads nothing. |
| `gmail_attachments_get` | Fetch bytes: inline base64 when small, otherwise written to the gateway's own directory. |
| `gmail_labels_list` | All labels with counts, and whether the gateway will modify each. |
| `gmail_labels_add` | Apply labels by id or name. Refuses `TRASH` and `SPAM`. |
| `gmail_labels_remove` | Remove labels by id or name. Refuses `TRASH` and `SPAM`. |
| `gmail_archive` | Remove `INBOX`. Mail stays in All Mail; reversible. |
| `gmail_mark_read` | Remove `UNREAD`. |
| `gmail_mark_unread` | Add `UNREAD`. |
| `gmail_drafts_list` | Saved drafts with recipients, subject, snippet. |
| `gmail_drafts_get` | One draft in full. |
| `gmail_drafts_create` | New plain-text draft. Saved, never sent. |
| `gmail_drafts_reply` | Reply draft in an existing thread, with correct `In-Reply-To`, `References`, subject, and `threadId`. |
| `gmail_drafts_update` | Edit a draft; omitted fields keep their values, threading is preserved. |

Mutations work on individual messages or threads and on batches (default cap 100
ids). Labels may be given as ids (`Label_7`) or display names (`Receipts`).

Reading and writing are treated asymmetrically where it matters: `gmail_search`
will happily filter on `TRASH` or set `include_spam_trash`, because inspecting
what is already there is a read. Applying those labels is refused, because that
would move mail into Trash or report it as spam.

### Errors

Failures come back as MCP tool errors with `isError: true` and a structured
payload in both the text block and structured content:

```json
{"error": {
  "code": "forbidden_label",
  "message": "refusing to add label 'TRASH': moving messages to Trash is a forbidden capability of this gateway",
  "retryable": false
}}
```

Codes include `invalid_input`, `unknown_account`, `not_found`, `too_large`,
`batch_too_large`, `rate_limited`, `forbidden_operation`, `forbidden_label`,
`account_read_only`, `needs_reauth`, `upstream_rate_limited`,
`upstream_unavailable`, `network_error`, `timeout`, and `internal_error`.
Internal exceptions are logged server-side and reported as a bare
`internal_error` — clients never receive a traceback or an internal path.

---

## Administration

```bash
gmail-mcp-gateway accounts list
gmail-mcp-gateway accounts status               # live Gmail check per account
gmail-mcp-gateway accounts auth <alias>
gmail-mcp-gateway accounts reauth <alias>       # after a revoked or expired grant
gmail-mcp-gateway accounts remove <alias> --yes # revokes at Google, deletes locally

gmail-mcp-gateway token create <name>
gmail-mcp-gateway token list
gmail-mcp-gateway token revoke <name>

gmail-mcp-gateway audit --limit 50              # recent state-changing operations
gmail-mcp-gateway audit --account work --since-hours 24
gmail-mcp-gateway audit --outcome denied --json

gmail-mcp-gateway prune                         # expired audit rows, dedup keys, attachments
gmail-mcp-gateway health --json
```

On a headless host, authorize with the redirect port forwarded:

```bash
# on the server
gmail-mcp-gateway accounts add work --no-browser --port 8899
# on your laptop
ssh -L 8899:127.0.0.1:8899 server
# then open the printed URL locally
```

The audit log records account, timestamp, operation, affected ids, outcome,
error code, duration, and calling principal — for successes, failures, and
refusals alike. It never records tokens, message bodies, subjects, or attachment
contents. Administration is CLI-only: a compromised MCP client cannot add an
account, trigger a consent flow, mint a token, or read the audit log.

### Directory layout

Configuration, data, and secrets are separate and separately overridable, so
each can have a different backing store:

| Role | Variable | Default | Contents |
|---|---|---|---|
| Config | `GMAIL_MCP_CONFIG_DIR` | `~/.config/gmail-mcp-gateway` | `config.toml` — nothing secret |
| Data | `GMAIL_MCP_DATA_DIR` | `~/.local/share/gmail-mcp-gateway` | `gateway.db`, `attachments/` |
| Secrets | `GMAIL_MCP_SECRETS_DIR` | `<data>/secrets` | `master.key`, `oauth_client.json`, `credentials/`, `gateway_tokens.json` |

`config.toml` is optional; see
[`deploy/config.example.toml`](deploy/config.example.toml) for every key —
batch caps, page sizes, body and attachment budgets, rate limits, retry policy,
and idempotency window — with its default.

---

## How the boundary is enforced

Four independent layers. Each alone would block a send; all four have to fail
for a message to leave.

**1. The tool surface.** Eighteen tools exist. There is no `gmail_send`, no
`gmail_trash`, no `gmail_raw_request`, and no tool that accepts a URL, path,
HTTP method, or endpoint name. A generic Gmail proxy is not something the client
can reach because it is not something that was written.
[`mcpsrv/server.py`](src/gmail_mcp_gateway/mcpsrv/server.py)

**2. The endpoint allowlist.** Every HTTP request to Gmail must name one of
fourteen `Endpoint` constants. `users.messages.send`, `users.drafts.send`,
`users.messages.trash`, `users.messages.delete`, and everything under
`users.settings` are simply absent. Path parameters are validated against a
strict id pattern and percent-encoded with an empty safe set, so no value can
introduce a `/` and reach a different endpoint. A denylist re-checks the
resolved method and path immediately before the request goes out, independently
of how it was built. `DELETE` and `PATCH` cannot be issued at all.
[`gmail/allowlist.py`](src/gmail_mcp_gateway/gmail/allowlist.py)

**3. The label policy.** This closes the back door the allowlist leaves open.
`users.messages.modify` is permitted — it is how archiving and read state work —
but Gmail treats `TRASH` and `SPAM` as ordinary labels, so applying one trashes
a message or reports it as spam. Every label id in a mutation is checked, in
both directions, case-insensitively, and the assembled request body is checked
again before transmission.
[`gmail/labels.py`](src/gmail_mcp_gateway/gmail/labels.py)

**4. The OAuth scope.** Accounts are authorized with `gmail.modify` and nothing
else. That scope cannot permanently delete a message (`messages.delete` requires
`https://mail.google.com/`) and cannot touch any Gmail setting, so forwarding
rules, filters, POP/IMAP configuration, and permanent deletion are impossible at
Google's authorization layer rather than merely blocked here. Google publishes no
scope granting draft creation without send, so send is blocked by layers 1–2
instead. Accounts added with `--read-only` get `gmail.readonly`, and Google
itself then rejects every write.

---

## Security model

**Email content is untrusted.** Bodies, subjects, sender names, and attachment
filenames are written by third parties and may contain instructions aimed at the
model reading them. The gateway marks every read result
`content_is_untrusted: true`, and the server instructions tell the client to
treat email as data rather than direction. More usefully, the capabilities that
injected instructions would ask for do not exist.

**HTML is never executed and never returned as markup.** `<script>`, `<style>`,
`<iframe>`, and similar elements are discarded with their contents; all other
tags are stripped. The result is plain text.

**Invisible Unicode is stripped.** Zero-width characters, bidirectional
overrides, and Unicode tag characters let an attacker show a human one thing
while an LLM reads another. They are removed and the count is reported as
`removed_hidden_characters`.

**Attachments are stored, never opened.** The gateway does not parse, render, or
execute attachment content. A client can suggest a filename but never a path:
the destination is always
`<attachments_dir>/<account>/<message_id>/<sanitized-name>`, resolved and
re-checked for containment, written `O_NOFOLLOW` at mode 0600.

**Credentials never reach the client.** Refresh tokens, access tokens, and the
OAuth client secret exist only inside the gateway process. Each account's
credential is sealed with AES-256-GCM under a key derived per account
(`HKDF-SHA256(master, "…account:<id>")`), with the account id as associated data
— so one account's key does not open another's, and a credential file moved
between accounts fails to decrypt. Files are 0600 in a 0700 directory; the
gateway refuses to read a group- or world-readable key.

*Honest scope:* encryption at rest protects against backups, stray copies, and
disk images. It does not defend against an attacker already executing code as
the gateway's user — that attacker can read the master key. Filesystem
permissions remain the primary boundary.

**Logs cannot leak secrets.** Every log record passes a redaction filter that
rewrites anything shaped like a Google access or refresh token, client secret,
bearer header, JWT, or credential-named field — in the message, the arguments,
and the exception text. Under stdio, logs go to stderr because stdout is the
MCP wire.

**Inputs are validated.** Draft recipients must be bare addresses matching a
strict pattern; any CR, LF, or NUL in a header value is rejected as attempted
header injection. Drafts are assembled from typed fields — the gateway never
accepts raw RFC 5322 from a client. Batches, page sizes, body lengths,
attachment sizes, and recipient counts are all capped, and a per-account token
bucket fails fast with a `retry_after_seconds` hint rather than queueing.

### What this does not protect against

- An operator who can execute code as the gateway user.
- A client legitimately using allowed capabilities badly — mass-archiving, say,
  or writing a misleading draft. Archiving and labelling are reversible and
  audited; drafts still require a human to send.
- Google-side compromise or a malicious OAuth client configuration.
- Traffic interception if you expose the HTTP transport without TLS. Keep it on
  loopback or put a TLS-terminating proxy in front.

---

## Reliability

- **Token refresh**: automatic, with a per-account lock so concurrent calls
  refresh once. A `401` triggers exactly one refresh-and-retry.
- **Refresh failure**: `invalid_grant` marks the account `needs_reauth` and
  returns a structured error naming the CLI command to fix it.
- **Rate limits and 5xx**: exponential backoff with full jitter, honouring
  `Retry-After`, up to `max_attempts`.
- **Network failures and timeouts**: retried, then reported as `network_error`
  or `timeout` with no internal detail.
- **Pagination**: `next_page_token` is handed back to the client, so no cursor
  state lives in the server.
- **Duplicate requests**: `client_request_id` suppresses repeats for 24 hours.
  Concurrent repeats are serialized inside the process; reusing an id with
  different arguments is an error, not a silent wrong answer.
- **Backpressure**: Gmail calls share a configurable concurrency semaphore, and
  each account has an independent token bucket. A large search or busy account
  therefore cannot create unbounded upstream concurrency.

### Scaling and deployment topology

Run one gateway process for a given data and secrets directory. SQLite state,
credential files, token-refresh locks, and in-flight idempotency coordination
are intentionally local; pointing multiple replicas at the same volume does
not provide safe active-active operation.

For a larger installation, shard accounts across independent gateway instances,
each with its own config, data, secrets, bearer tokens, and loopback port. This
keeps failures, rate limits, audit trails, and credentials isolated while still
allowing each instance to serve concurrent clients. Increase
`limits.max_concurrency` only after observing Gmail quota use and host capacity;
the default of 8 is conservative. Put a TLS-authenticated routing layer in front
if clients need one shared network address, and route each account alias to its
own instance.

Active-active replicas for the same account would require replacing SQLite and
local credential/idempotency state with coordinated external stores. That is
outside this gateway's current security model; do not scale it by merely adding
workers or sharing its volume.

---

## Testing

```bash
uv sync --all-extras
uv run pytest -q                                    # 334 tests, no Google account needed
uv run pytest tests/test_security_boundary.py -v    # just the guarantee
```

`test_security_boundary.py` drives every supported operation through a mock
Gmail that **fails if a forbidden URL is ever requested**, then tries to trash,
spam, and send by every route available.

Once an account is authorized, exercise it against a real mailbox. The script
connects over stdio exactly as an MCP client would, runs a read-only tour, then
confirms the forbidden operations are refused:

```bash
uv run python scripts/try-it.py --account personal
uv run python scripts/try-it.py --account personal --draft    # also drafts a reply
uv run python scripts/try-it.py --account personal --archive  # archive round trip
```

Read-only unless you pass a mutation flag, and every mutation it makes is
reversible. The draft it creates must be deleted by you — the gateway cannot.

To click around interactively:

```bash
npx @modelcontextprotocol/inspector .venv/bin/gmail-mcp-gateway serve --transport stdio
```

### Layout

```
src/gmail_mcp_gateway/
├── mcpsrv/server.py      the tool surface — the complete client-facing API
├── mcpsrv/http.py        Streamable HTTP transport, bearer auth, bind safety
├── service.py            the supported operations, and nothing else
├── gmail/allowlist.py    the endpoint allowlist  ← security boundary
├── gmail/labels.py       label policy (blocks TRASH/SPAM)  ← security boundary
├── gmail/client.py       the only code that talks to Gmail
├── gmail/parse.py        MIME → structured data, sanitization
├── gmail/compose.py      draft assembly from typed fields
├── security/             validation, rate limiting, path confinement
├── auth/oauth.py         OAuth 2.0 + PKCE, refresh, revoke
├── accounts.py           account registry
├── crypto.py             envelope encryption for credentials
├── audit.py              audit log
└── cli.py                administration
```

Adding a supported operation means: an `Endpoint` in `allowlist.py`, a method in
`service.py`, a tool in `mcpsrv/server.py`, an entry in `EXPOSED_TOOLS`, and
tests. `EXPOSED_TOOLS` and `FORBIDDEN_TOOLS` are asserted against the running
server, so adding a tool without declaring it — or adding a forbidden one —
fails the suite. Keep the gateway focused on Gmail; a different Google product
belongs in a separate MCP service, not in wider scopes here.

---

## Troubleshooting

**`no OAuth client configured`** — quickstart step 3. Either place
`secrets/oauth_client.json` (mode 0600) or set `GMAIL_MCP_OAUTH_CLIENT_ID` and
`GMAIL_MCP_OAUTH_CLIENT_SECRET`.

**`Google did not return a refresh token`** — you have authorized this app
before. Remove its access at <https://myaccount.google.com/permissions> and run
`accounts auth <alias>` again.

**`consent screen did not grant every required permission`** — a permission box
was unticked. Re-run authorization and leave them all ticked. The gateway fails
here on purpose rather than leaving an account that half-works.

**Account goes `needs_reauth` every week** — the OAuth app is still in
"Testing", where Google expires refresh tokens after 7 days. Publish it
(quickstart step 2.4).

**`stored credential failed authentication`** — `GMAIL_MCP_MASTER_KEY` changed,
or the key file was replaced. Restore the original key, or
`accounts reauth <alias>` for each account.

**`<file> is accessible to other users`** — the gateway refuses to read a
group- or world-readable secret. `chmod 600` the file it names.

**`refusing to bind …: it is not a loopback address`** — intended. Bind
127.0.0.1 and use an SSH tunnel, or set `GMAIL_MCP_ALLOW_REMOTE_BIND=true` if it
really is a trusted private interface. Internet-routable addresses are refused
regardless.

**`serve --transport stdio` looks hung** — correct; it is waiting for JSON-RPC
on stdin. Let your MCP client launch it, or use `scripts/try-it.py`.

**Something changed the mailbox and I want to know what** —
`gmail-mcp-gateway audit --limit 50`. Every state change is there, refusals
included.

## License

MIT
