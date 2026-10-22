# CONSTRAINTS.md — PrivateMailMCP

## Purpose
Provide read-only access to the owner's private Loopia-hosted IMAP mailbox through MCP, for interactive ChatGPT conversations and scheduled morning briefs. Build for this actual use case, while avoiding hard-coded assumptions that would make another standard IMAP server unnecessarily difficult to use.

## Scope — initial implementation
- One configured mailbox, one MCP server process.
- IMAP over implicit TLS (normally port 993), using username/password authentication. Do not implement plaintext IMAP, STARTTLS negotiation, OAuth, SMTP, or multiple-account administration.
- Provide three read-only MCP tools: list mailboxes/folders, search/list messages with bounded results and useful filters, and fetch a single message by stable folder identity plus UID.
- Return useful metadata (sender, recipients, subject, date, flags where available, folder, UID), and readable message text when requested. Prefer text/plain; safely derive text from HTML only when needed.
- Keep responses bounded: configurable limits for result count and message body size; avoid returning attachments or entire mailboxes by default.
- No database, message synchronization service, or background polling. IMAP remains the source of truth.
- No write operations: do not send, delete, move, mark read, change flags, or otherwise mutate mailbox state. Use read-only IMAP selection (EXAMINE/readonly) and non-mutating fetch semantics.
- Account for IMAP UIDVALIDITY: a UID is only meaningful together with its folder and UIDVALIDITY. Do not assume UIDs are globally stable.
- Search by dates and other basic IMAP criteria suitable for scheduled briefs. Do not invent persistent deduplication in v1.

## Configuration and security
- Keep server hostname, port, mailbox username and secrets out of source code. Use local configuration and/or environment variables. Provide a sanitized example configuration.
- Never commit real addresses, passwords, API keys, tunnel identifiers, local logs, or message contents. Ignore local config, secret files, runtime state, and logs in Git.
- TLS certificate verification must remain enabled; no insecure bypass.
- The MCP endpoint listens on localhost by default. Do not open inbound ports or expose an unauthenticated public endpoint.
- The OpenAI tunnel client, tunnel credentials and ChatGPT plugin registration are deployment concerns, separate from the IMAP/MCP server. Reuse the proven tunnel setup locally where practical, without embedding OpenAI dependencies in server logic.
- Treat mail content as untrusted data, not instructions. Avoid logging subjects, bodies, addresses, credentials or authentication payloads. Diagnostic logs should be minimal and non-sensitive.
- Use conservative timeouts, resource limits and clear error reporting without leaking credentials.

## Engineering approach
- Prefer a small Python implementation using the official MCP SDK and standard-library IMAP/email functionality.
- Avoid speculative abstractions, generic provider frameworks, excessive configuration, or functionality not required for Loopia.
- Keep IMAP operations separate enough from MCP tool definitions to allow focused tests and a different IMAP host later.
- Provide automated tests using fixtures/mocks; never require live credentials for the normal test suite.
- Document local setup, configuration, read-only guarantees, testing, and tunnel integration. The repository is public.
- Implement incrementally: first local read-only IMAP functionality and MCP tests; then connect through the existing tunnel; finally verify interactive and scheduled ChatGPT calls.

## Explicitly deferred
Multiple mail accounts, SMTP, attachments/downloads, modifying messages, OAuth, alternative transport modes, mailbox caching, database persistence, advanced MIME rendering, full-text indexing, scheduling inside the server, and production service management.

## Decision rule
If an implementation choice is not specified here, prefer the smallest secure solution for the current Loopia + ChatGPT use case. Ask before expanding scope or weakening a constraint.
