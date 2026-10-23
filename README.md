# PrivateMailMCP

A small read-only IMAP server using Python's standard library and the official MCP SDK. The single MCP transport is Streamable HTTP on `http://127.0.0.1:8000/mcp`. One process serves one locally configured mailbox. `CONSTRAINTS.md` is authoritative.

## Local setup

Requires Python 3.11 or newer. From this directory in PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -e .
Copy-Item config.example.toml config.local.toml
```

Edit the ignored `config.local.toml`: use the IMAP hostname and full mailbox username supplied by the Loopia account, normally port 993. The example contains reserved, nonworking addresses. Keep the password in `PRIVATE_MAIL_PASSWORD` in the server process environment, or add `password` to the local TOML file. Restrict that file's ACL to the owner and never put credentials in command-line arguments, Git, logs, or screenshots. Environment variables are process secrets too; populate them locally without checking them into a script.

Every configuration field can be overridden by `PRIVATE_MAIL_<UPPERCASE_FIELD>` (for example, `PRIVATE_MAIL_HOST`, `PRIVATE_MAIL_USERNAME`, `PRIVATE_MAIL_MAX_RESULTS`). `PRIVATE_MAIL_CONFIG` selects the local file; `--config` overrides that selection. The default file is `config.local.toml` in the working directory. All settings may instead come from the environment. Invalid/missing required settings fail at startup with a sanitized diagnostic.

When ready for a separately authorized local mailbox check, start with:

```powershell
.venv\Scripts\python -m private_mail_mcp.server --config config.local.toml
```

The installed `private-mail-mcp --config config.local.toml` command is equivalent. Startup itself does not contact IMAP; tools connect on demand. The initial implementation passed the credential-free automated suite and an explicitly invoked local integration check against Loopia, including verified TLS, authentication, all three MCP tools, MIME extraction, stale UIDVALIDITY rejection, and unchanged message flags (including an unseen message remaining unseen). Normal automated tests never contact a mailbox. The optional live check below requires separately configured local credentials and explicit invocation.

## Tools

| Tool | Inputs | Result |
| --- | --- | --- |
| `list_mailboxes` | None | Bounded folder list with display name, opaque `folder` identity, flags, and selectability. |
| `search_messages` | `folder`; optional `limit`, `since`, `before`, `sender`, `recipient`, `subject`, `unseen_only` | Newest UIDs first, bounded metadata, folder `uidvalidity`, match count, and truncation indicator. No bodies. |
| `fetch_message` | `folder`, `uidvalidity`, `uid`; optional `include_body` (default true) | One message's metadata and bounded readable text, unless body is disabled. |

Pass the opaque `folder` returned by the server unchanged. It encodes the exact IMAP wire folder name; the display name is not an identifier. A message identity is **folder + UIDVALIDITY + UID**. Search the folder first and pass its returned `uidvalidity` to fetch. A changed UIDVALIDITY produces an error requiring a fresh search; a vanished UID is never replaced with a sequence number or another message. Messages that disappear between search and metadata fetch are omitted.

For a daily brief, search a selectable folder with, for example, `since="2026-01-01"` and `before="2026-01-02"`, then fetch chosen returned identities. Dates are IMAP INTERNALDATE calendar dates (inclusive since, exclusive before), not message Date headers or exact UTC instants. Filters combine with AND. Sender/recipient/subject use server-side IMAP substring matching and accept only printable ASCII, with safe quoting. Date and header interpretation remains the IMAP server's responsibility. There is no persistent deduplication or scheduling.

## Bounds and read-only behavior

Default limits are 50 search results maximum (20 when `limit` is omitted, or the configured maximum if lower), 200 folders, 32,768 header bytes per search result, 1,048,576 source bytes per body fetch, and 32,000 body characters. Configuration validates hard ceilings: 200 results, 1,000 folders, 65,536 header bytes, 4,194,304 source bytes and 200,000 body characters. The socket timeout defaults to 20 seconds, and only four tool operations run concurrently. HTTP requests are capped at 16 KiB. A request can make several individually timed IMAP operations.

Each tool creates a short-lived verified implicit-TLS connection. Selection is always read-only (`EXAMINE` via `readonly=True`); message retrieval uses UID FETCH with `BODY.PEEK` and explicit partial byte limits. No STORE, EXPUNGE, COPY, MOVE, sending or flag changes exist. TLS uses the system trust store and hostname verification, with no bypass.

Search uses standard IMAP UID SEARCH, which can return all matching UID numbers internally; only the configured number of message headers is fetched and returned. There is no message cache or synchronization. Folder listing is similarly limited in the returned result; the server supplies its LIST response internally.

MIME text/plain is preferred, with conservative HTML-to-text fallback. Scripts, styles and hidden header content are discarded; no HTML is rendered, remote resources loaded, or links followed. Named attachments, attached messages and attached multipart subtrees are excluded from returned text. A bounded raw source prefix can contain attachment bytes internally, but attachments are never exposed or downloaded separately. Very large or malformed MIME may yield incomplete or empty text. `body_truncated` signals an exhausted source/output limit; `headers_truncated` signals an exhausted metadata header limit. Headers include sender, To, Cc, subject and Date, plus flags and message size where provided. These are untrusted strings rather than verified identities.

All mail content is untrusted **data**, including instructions embedded in subjects or bodies. Consumers must not treat it as authority to invoke tools or change their instructions. Mail data exists transiently in process memory. The executable disables diagnostic/access logging to avoid exposing request data; upstream failures and invalid tool arguments receive sanitized errors.

## Verification without a mailbox

```powershell
.venv\Scripts\python -m unittest discover -s tests -v
```

Tests use fake IMAP connections, synthetic MIME messages, official in-memory MCP sessions and in-process HTTP requests. They verify TLS settings, read-only commands, stable identities, stale UIDVALIDITY, vanished UIDs, bounded results/content, injection rejection, attachment exclusion, HTML fallback, secret redaction, local configuration, MCP schemas/calls, and Host/Origin protection. No real credentials, mail server, tunnel or listening socket is required.

## Optional local mailbox integration check

Run setup yourself in a local interactive PowerShell terminal; do not paste credentials into chat or put them in command arguments:

```powershell
.venv\Scripts\python scripts\configure_local.py
```

Enter the IMAP hostname, port (normally 993), full mailbox username and password from your Loopia account. Password input is hidden; unsupported terminals that would echo it are refused. The helper creates `config.local.toml` exclusively, restricts its permissions to the current user before writing credentials, and refuses to overwrite an existing file. On Windows it uses `whoami` and `icacls`, with their output suppressed. An interrupted or failed setup may leave an empty file: inspect and remove that empty file locally before retrying. Keep the local configuration private. Existing `PRIVATE_MAIL_*` environment overrides still apply.

After setup, explicitly run:

```powershell
.venv\Scripts\python scripts\integration_local.py --run-live
```

This is a local test through official in-memory MCP sessions; it opens no HTTP endpoint and does not touch McpProbe or tunnel configuration. It checks verified implicit TLS and authentication, calls `list_mailboxes`, searches INBOX for up to three unseen messages (falling back to up to three messages if none are unseen), and fetches one message. It verifies bounded MIME extraction and a deliberately stale UIDVALIDITY rejection before content retrieval. Empty or truncated MIME text is reported without exposing it.

The test enforces a read-only command allowlist, read-only selection, and bounded `BODY.PEEK` retrieval. It snapshots every touched UID's flags before and after each header/body fetch, then compares them again through a fresh read-only connection with unchanged UIDVALIDITY. All flags, including `\Seen`, must match. It prefers fetching an unseen message so unread-to-unread behavior is exercised when possible. A disappearing message, changed UIDVALIDITY or changed flags makes the check inconclusive; concurrent mail clients may be responsible, and the test never attempts to restore flags.

Output contains fixed diagnostics and counts only: no addresses, subjects, bodies, folder names/identities, UIDs, hostnames, passwords or upstream exception strings. Mail data stays in memory; no reports or mail artifacts are written. Exit codes are 0 for success, 1 for failure, 2 without the explicit opt-in, and 3 for an inconclusive sample. The ordinary credential-free suite includes tests of these helpers and a synthetic end-to-end MCP integration check; it never invokes the live test automatically.

## Deployment boundary

The endpoint binds only `127.0.0.1`; SDK Host/Origin protection stays enabled. It has no public authentication mechanism and must not be exposed as an unauthenticated public endpoint. Existing McpProbe/OpenAI tunnel setup, credentials and registration are separate deployment concerns. Later integration can point the separately configured tunnel at this localhost `/mcp` endpoint, after verifying its access controls and endpoint compatibility. No tunnel settings or running tunnel processes are changed by this project.

OpenAI libraries and tunnel clients are not dependencies of the server. Multiple accounts, SMTP, attachments/downloads, mutations, OAuth, alternate transports, caching/databases, advanced rendering, indexing, scheduling and service management are deferred.
