"""Explicit opt-in live test. Prints only fixed diagnostics and aggregate counts."""
import argparse
import asyncio
from email import policy
from email.parser import BytesParser
import imaplib
import json
import logging
from pathlib import Path
import re
import ssl
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from mcp.shared.memory import create_connected_server_and_client_session
from private_mail_mcp.config import load_config
from private_mail_mcp.mail import MailClient, clean, folder_id, readable
from private_mail_mcp.server import create_server


class AuditFailure(Exception):
    pass


class Inconclusive(Exception):
    pass


class Audit:
    def __init__(self):
        self.baseline = {}
        self.content_fetches = 0
        self.raw_body = None
        self.changed = False
        self.inconclusive = False

    def observe(self, validity, uid, flags):
        key = (validity, uid)
        if flags is None:
            self.inconclusive = True
            raise Inconclusive
        if key in self.baseline and self.baseline[key] != flags:
            self.changed = True
        self.baseline.setdefault(key, flags)


class AuditedIMAP(imaplib.IMAP4_SSL):
    def __init__(self, *args, audit, **kwargs):
        self.audit = audit
        self.validity = None
        super().__init__(*args, **kwargs)
        self.debug = 0

    def _command(self, name, *args):
        # Enforce the read-only wire command boundary, including SDK/tool code.
        if name not in {"CAPABILITY", "LOGIN", "EXAMINE", "LIST", "UID", "LOGOUT"}:
            raise AuditFailure
        if name == "UID":
            if not args or str(args[0]).upper() not in {"SEARCH", "FETCH"}:
                raise AuditFailure
            if str(args[0]).upper() == "FETCH":
                query = str(args[-1])
                if query != "(UID FLAGS)" and not re.fullmatch(
                    r"\(UID FLAGS RFC822.SIZE BODY\.PEEK\[(?:HEADER)?\]<0\.[1-9][0-9]*>\)", query):
                    raise AuditFailure
        return super()._command(name, *args)

    def select(self, mailbox="INBOX", readonly=False):
        if not readonly:
            raise AuditFailure
        result = super().select(mailbox, readonly=True)
        if result[0] != "OK":
            raise AuditFailure
        values = self.untagged_responses.get("UIDVALIDITY", [])
        if not values or not re.fullmatch(rb"[1-9][0-9]{0,9}", values[0]):
            raise AuditFailure
        self.validity = int(values[0])
        return result

    def flags(self, uid):
        status, rows = super().uid("FETCH", str(uid), "(UID FLAGS)")
        if status != "OK":
            raise AuditFailure
        for row in rows or []:
            if isinstance(row, bytes):
                identity = re.search(rb"\bUID ([0-9]+)\b", row)
                flags = re.search(rb"\bFLAGS \(([^)]*)\)", row)
                if identity and int(identity[1]) == uid and flags:
                    return frozenset(flags[1].split())
        return None

    def uid(self, command, *args):
        content = str(command).upper() == "FETCH" and "BODY.PEEK[" in str(args[-1])
        if not content:
            return super().uid(command, *args)
        uid = int(args[0])
        if self.validity is None:
            raise AuditFailure
        self.audit.observe(self.validity, uid, self.flags(uid))
        result = super().uid(command, *args)
        self.audit.content_fetches += 1
        self.audit.observe(self.validity, uid, self.flags(uid))
        if "BODY.PEEK[]" in str(args[-1]):
            for row in result[1] or []:
                if isinstance(row, tuple) and len(row) == 2:
                    found = re.search(rb"\bUID ([0-9]+)\b", row[0])
                    if found and int(found[1]) == uid and isinstance(row[1], bytes):
                        self.audit.raw_body = row[1]
                        break
        return result


def result_data(result):
    if result.isError:
        raise AuditFailure
    value = result.structuredContent
    if value is None and len(result.content) == 1 and result.content[0].type == "text":
        value = json.loads(result.content[0].text)
    if not isinstance(value, dict):
        raise AuditFailure
    return value


async def exercise(config, mail, audit, report):
    server = create_server(config, mail)
    inbox = folder_id(b"INBOX")
    async with create_connected_server_and_client_session(server) as session:
        report("MCP list_mailboxes")
        folders = result_data(await session.call_tool("list_mailboxes", {}))
        if not isinstance(folders.get("folders"), list):
            raise AuditFailure
        print(f"PASS: list_mailboxes; returned {len(folders['folders'])} folders (names withheld).")
        report("MCP search_messages")
        search = result_data(await session.call_tool("search_messages", {"folder": inbox, "limit": min(3, config.max_results), "unseen_only": True}))
        if not search["messages"]:
            search = result_data(await session.call_tool("search_messages", {"folder": inbox, "limit": min(3, config.max_results)}))
        messages = search["messages"]
        if not messages:
            audit.inconclusive = True
            raise Inconclusive
        if len(messages) > min(3, config.max_results):
            raise AuditFailure
        print(f"PASS: search_messages; returned {len(messages)} messages (metadata withheld).")
        chosen = next((m for m in messages if "\\Seen" not in m["flags"]), messages[0])
        unseen = "\\Seen" not in chosen["flags"]
        identity = {"folder": inbox, "uidvalidity": search["uidvalidity"], "uid": chosen["uid"]}
        report("MCP fetch_message and MIME")
        fetched = result_data(await session.call_tool("fetch_message", {**identity, "include_body": True}))
        if any(fetched.get(k) != v for k, v in identity.items()):
            raise AuditFailure
        text = fetched.get("body")
        if not isinstance(text, str) or len(text) > config.max_body_chars or type(fetched.get("body_truncated")) is not bool:
            raise AuditFailure
        raw = audit.raw_body
        if raw is None or len(raw) > config.max_message_bytes:
            raise AuditFailure
        parsed = BytesParser(policy=policy.default).parsebytes(raw)
        if text != clean(readable(parsed))[:config.max_body_chars]:
            raise AuditFailure
        print("PASS: fetch_message identity, bounded MIME parsing and text extraction; content withheld.")
        print("INFO: extracted text " + ("present." if text.strip() else "empty; message may lack readable text."))
        print("INFO: body truncation " + ("reported." if fetched["body_truncated"] else "not reported."))
        report("stale UIDVALIDITY")
        before = audit.content_fetches
        stale_identity = {**identity, "uidvalidity": 1 if identity["uidvalidity"] != 1 else 2}
        stale = await session.call_tool("fetch_message", stale_identity)
        if not stale.isError or "UIDVALIDITY changed" not in str(stale) or audit.content_fetches != before:
            raise AuditFailure
        print("PASS: stale UIDVALIDITY rejected before content fetch.")
    report("final flags verification")
    with mail.connection() as connection:
        current = mail.select(connection, inbox)
        if any(validity != current for validity, _ in audit.baseline):
            raise Inconclusive
        for validity, uid in list(audit.baseline):
            audit.observe(validity, uid, connection.flags(uid))
    if audit.changed:
        raise Inconclusive
    print(f"PASS: all flags, including Seen, unchanged for {len(audit.baseline)} sampled messages before/after every content fetch and fresh final check.")
    print("INFO: selected body message was " + ("unseen and remained unseen." if unseen else "already seen; no sampled unseen body was available."))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-live", action="store_true", help="Explicitly authorize this invocation to contact configured mailbox")
    args = parser.parse_args()
    if not args.run_live:
        print("No connection made. Use --run-live only after local credentials are configured.")
        return 2
    logging.disable(logging.CRITICAL)
    imaplib.Debug = 0
    stage = "configuration"
    audit = None
    def report(value):
        nonlocal stage
        stage = value
    try:
        config = load_config(str(ROOT / "config.local.toml"))
        audit = Audit()
        mail = MailClient(config, lambda *a, **kw: AuditedIMAP(*a, audit=audit, **kw))
        report("verified TLS connectivity")
        connection = None
        try:
            context = ssl.create_default_context()
            if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
                raise AuditFailure
            connection = mail.factory(config.host, config.port, ssl_context=context, timeout=config.timeout)
            print("PASS: TLS certificate and hostname verification.")
            report("IMAP authentication")
            if connection.login(config.username, config.password)[0] != "OK":
                raise AuditFailure
            print("PASS: IMAP authentication.")
        finally:
            if connection is not None:
                try:
                    connection.logout()
                except BaseException:
                    pass
        asyncio.run(exercise(config, mail, audit, report))
        print("SUCCESS: local integration completed; no mailbox writes, private output or persistent mail artifacts.")
        return 0
    except Inconclusive:
        print(f"INCONCLUSIVE at {stage}: empty sample, vanished message, changed flags or UIDVALIDITY; concurrent mailbox activity may be responsible. No restoration attempted.")
        return 3
    except BaseException:
        if audit is not None and audit.inconclusive:
            print(f"INCONCLUSIVE at {stage}: sampled message vanished; no restoration attempted.")
            return 3
        print(f"FAIL at {stage}: operation could not be verified. Check local setup/connectivity; upstream details withheld.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
