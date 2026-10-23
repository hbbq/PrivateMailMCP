import asyncio
from email.message import EmailMessage
import imaplib
import os
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest.mock import patch

import httpx

from mcp.shared.memory import create_connected_server_and_client_session

from private_mail_mcp.config import Config, ConfigError, load_config
from private_mail_mcp.mail import MailClient, MailError, folder_id, folder_bytes, readable, display_folder
from private_mail_mcp.server import create_server


CONFIG = Config("imap.example.invalid", "user@example.invalid", "password-sentinel")
FOLDER = folder_id(b"INBOX")
RAW = b"From: sender@example.invalid\r\nTo: recipient@example.invalid\r\nSubject: =?utf-8?q?Hello_=C3=A5?=\r\nDate: Thu, 1 Jan 2026 12:00:00 +0000\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello body\r\n"


class FakeIMAP:
    def __init__(self):
        self.calls = []
        self.validity = b"42"
        self.rows = [b'(\\HasNoChildren) "/" "INBOX"']
        self.search = b"1 3 2"
        self.raw = RAW
        self.missing = False

    def login(self, *args):
        self.calls.append(("login",))
        return "OK", []

    def logout(self):
        self.calls.append(("logout",))
        return "BYE", []

    def list(self):
        self.calls.append(("list",))
        return "OK", self.rows

    def select(self, name, readonly=False):
        self.calls.append(("select", name, readonly))
        return "OK", [b"3"]

    def response(self, name):
        return name, [self.validity]

    def uid(self, operation, *args):
        self.calls.append((operation, *args))
        if operation == "SEARCH":
            return "OK", [self.search]
        if self.missing:
            return "OK", [None]
        uid, query = args
        cap = int(query.split("<0.")[1].split(">")[0])
        body = self.raw if "BODY.PEEK[]" in query else self.raw.split(b"\r\n\r\n")[0] + b"\r\n\r\n"
        return "OK", [(f"1 (UID {uid} FLAGS (\\Seen) RFC822.SIZE {len(self.raw)} BODY[]<0> {{{min(len(body), cap)}}}".encode(), body[:cap]), b")"]


class MailTests(unittest.TestCase):
    def setUp(self):
        self.fake = FakeIMAP()
        self.connections = []
        def factory(*args, **kwargs):
            self.connections.append((args, kwargs))
            return self.fake
        self.mail = MailClient(CONFIG, factory)

    def test_list_and_tls(self):
        result = self.mail.list_mailboxes()
        self.assertEqual(result["folders"][0]["folder"], FOLDER)
        args, kwargs = self.connections[0]
        self.assertEqual(args, (CONFIG.host, 993))
        self.assertEqual(kwargs["ssl_context"].verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(kwargs["ssl_context"].check_hostname)
        self.assertEqual(self.fake.calls[-1], ("logout",))

    def test_folder_identity_quotes_unicode_and_literal(self):
        self.fake.rows = [b'(\\Noselect) "/" "A\\\"B"', (b'(\\HasNoChildren) "/" {5}', b"Other"), b'', b'() "/" "&AOQ-"']
        folders = self.mail.list_mailboxes()["folders"]
        self.assertFalse(folders[0]["selectable"])
        self.assertEqual(folder_bytes(folders[0]["folder"]), b'A"B')
        self.assertEqual(folders[2]["name"], "ä")
        self.mail.fetch_message(folders[0]["folder"], 42, 1)
        self.assertIn(("select", b'"A\\\"B"', True), self.fake.calls)

    def test_search_filters_bounds_readonly(self):
        result = self.mail.search_messages(FOLDER, 2, "2026-01-01", "2026-01-03", 'a"b', "target", "subject", True)
        self.assertEqual([x["uid"] for x in result["messages"]], [3, 2])
        self.assertTrue(result["truncated"])
        self.assertEqual(result["uidvalidity"], 42)
        self.assertIn(("select", b'"INBOX"', True), self.fake.calls)
        search = next(x for x in self.fake.calls if x[0] == "SEARCH")
        self.assertIn(b"01-Jan-2026", search)
        self.assertIn(b'"a\\\"b"', search)
        fetches = [x for x in self.fake.calls if x[0] == "FETCH"]
        self.assertEqual(len(fetches), 2)
        self.assertTrue(all("BODY.PEEK[HEADER]<0.32768>" in x[2] for x in fetches))
        self.assertNotIn("body", result["messages"][0])

    def test_fetch_body_metadata(self):
        result = self.mail.fetch_message(FOLDER, 42, 2)
        self.assertEqual(result["subject"], "Hello å")
        self.assertEqual(result["flags"], ["\\Seen"])
        self.assertIn("Hello body", result["body"])
        self.assertFalse(result["body_truncated"])
        self.assertEqual(result["uid"], 2)
        self.assertTrue(any("BODY.PEEK[]<0.1048576>" in x[2] for x in self.fake.calls if x[0] == "FETCH"))

    def test_stale_validity_no_fetch(self):
        with self.assertRaisesRegex(MailError, "UIDVALIDITY changed"):
            self.mail.fetch_message(FOLDER, 41, 2)
        self.assertFalse(any(x[0] == "FETCH" for x in self.fake.calls))

    def test_missing_uid_and_invalid_uidvalidity(self):
        self.fake.missing = True
        with self.assertRaisesRegex(MailError, "no longer exists"):
            self.mail.fetch_message(FOLDER, 42, 1)
        for validity in (None, b"0", b"4294967296"):
            self.fake.validity = validity
            with self.assertRaises(MailError):
                self.mail.fetch_message(FOLDER, 42, 1)

    def test_reject_injection_and_invalid_limits_before_connect(self):
        for kwargs in ({"sender": "a\r\nDELETE INBOX"}, {"subject": "å"}, {"since": "2026-02-31"}, {"limit": 201}, {"limit": True}):
            with self.assertRaises(MailError):
                self.mail.search_messages(FOLDER, **kwargs)
        for raw in (b"INBOX\r\n", b"INBOX\0", b""):
            with self.assertRaises(MailError):
                self.mail.fetch_message(folder_id(raw), 42, 1)
        for uid in (0, -1, True, 4294967296):
            with self.assertRaises(MailError):
                self.mail.fetch_message(FOLDER, 42, uid)
        self.assertFalse(self.connections)

    def test_upstream_errors_sanitized_and_logout(self):
        def fail(*args):
            raise imaplib.IMAP4.error("password-sentinel address@example.invalid")
        self.fake.uid = fail
        with self.assertRaises(MailError) as raised:
            self.mail.fetch_message(FOLDER, 42, 1)
        self.assertNotIn("sentinel", str(raised.exception))
        self.assertEqual(self.fake.calls[-1], ("logout",))

    def test_mime_plain_preferred_attachment_subtrees_excluded(self):
        message = EmailMessage()
        message.set_content("Readable plain")
        message.add_alternative("<p>HTML alternative</p>", subtype="html")
        attached = EmailMessage()
        attached.set_content("secret attached mail")
        message.add_attachment(attached)
        message.add_attachment(b"secret binary", maintype="application", subtype="octet-stream", filename="secret.txt")
        self.fake.raw = message.as_bytes()
        result = self.mail.fetch_message(FOLDER, 42, 1)
        self.assertIn("Readable plain", result["body"])
        self.assertNotIn("HTML alternative", result["body"])
        self.assertNotIn("secret", result["body"])

    def test_html_unknown_charset_and_malformed_mime(self):
        self.fake.raw = b'Content-Type: text/html; charset=unknown-x\r\n\r\n<head>secret</head><script>evil()</script><p>Hello &amp; <b>world</b></p><img src="https://example.invalid/tracker">'
        text = self.mail.fetch_message(FOLDER, 42, 1)["body"]
        self.assertIn("Hello & world", text)
        self.assertNotIn("secret", text)
        self.assertNotIn("evil", text)
        self.assertNotIn("tracker", text)

    def test_partial_source_and_output_truncation(self):
        config = Config(CONFIG.host, CONFIG.username, CONFIG.password, max_message_bytes=1024, max_body_chars=5)
        self.mail.config = config
        self.fake.raw = b"Content-Type: text/plain\r\n\r\n" + b"a" * 2000
        result = self.mail.fetch_message(FOLDER, 42, 1)
        self.assertEqual(result["body"], "aaaaa")
        self.assertTrue(result["body_truncated"])
        self.fake.raw = b"Content-Type: application/octet-stream\r\nContent-Disposition: attachment\r\n\r\n" + b"secret" * 1000
        result = self.mail.fetch_message(FOLDER, 42, 1)
        self.assertEqual(result["body"], "")
        self.assertTrue(result["body_truncated"])

    def test_default_limit_respects_configuration(self):
        self.mail.config = Config(CONFIG.host, CONFIG.username, CONFIG.password, max_results=1)
        result = self.mail.search_messages(FOLDER)
        self.assertEqual(len(result["messages"]), 1)

    def test_folders_bounded_and_wrong_uid_ignored(self):
        self.mail.config = Config(CONFIG.host, CONFIG.username, CONFIG.password, max_folders=1)
        self.fake.rows *= 2
        self.assertTrue(self.mail.list_mailboxes()["truncated"])
        self.fake.uid = lambda *args: ("OK", [(b"1 (UID 99 FLAGS ())", RAW)])
        with self.assertRaisesRegex(MailError, "no longer exists"):
            self.mail.fetch_message(FOLDER, 42, 1)


class ConfigTests(unittest.TestCase):
    def test_environment_override_and_repr(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "local.toml"
            path.write_text('host="imap.example.invalid"\nusername="user@example.invalid"\npassword="file-secret"\n', encoding="utf-8")
            with patch.dict(os.environ, {"PRIVATE_MAIL_PASSWORD": "env-secret", "PRIVATE_MAIL_MAX_RESULTS": "10"}, clear=True):
                config = load_config(str(path))
            self.assertEqual(config.password, "env-secret")
            self.assertEqual(config.max_results, 10)
            self.assertNotIn("env-secret", repr(config))
            self.assertNotIn("user@", repr(config))

    def test_bad_config_sanitized(self):
        with patch.dict(os.environ, {"PRIVATE_MAIL_PORT": "sensitive-input"}, clear=True):
            with self.assertRaises(ConfigError) as raised:
                load_config("nonexistent-config.local.toml")
        self.assertNotIn("sensitive", str(raised.exception))
        with self.assertRaises(ConfigError):
            Config(CONFIG.host, CONFIG.username, CONFIG.password, max_body_chars=0)


class MCPTests(unittest.IsolatedAsyncioTestCase):
    async def test_http_loopback_and_dns_rebinding_protection(self):
        server = create_server(CONFIG)
        app = server.streamable_http_app()
        headers = {"Accept": "application/json, text/event-stream"}
        request = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}}}
        async with server.session_manager.run():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://127.0.0.1:8000") as client:
                response = await client.post("/mcp", json=request, headers=headers)
                self.assertEqual(response.status_code, 200)
                self.assertIn("result", response.json())
                response = await client.post("/mcp", json=request, headers={**headers, "Host": "evil.example.invalid"})
                self.assertEqual(response.status_code, 421)
                response = await client.post("/mcp", json=request, headers={**headers, "Origin": "https://evil.example.invalid"})
                self.assertEqual(response.status_code, 403)

    async def test_official_protocol_three_tools_and_calls(self):
        fake = FakeIMAP()
        server = create_server(CONFIG, MailClient(CONFIG, lambda *a, **kw: fake))
        async with create_connected_server_and_client_session(server) as session:
            tools = await session.list_tools()
            self.assertEqual({tool.name for tool in tools.tools}, {"list_mailboxes", "search_messages", "fetch_message"})
            folders = await session.call_tool("list_mailboxes", {})
            self.assertFalse(folders.isError)
            searched = await session.call_tool("search_messages", {"folder": FOLDER, "limit": 1})
            self.assertFalse(searched.isError)
            fetched = await session.call_tool("fetch_message", {"folder": FOLDER, "uidvalidity": 42, "uid": 3})
            self.assertFalse(fetched.isError)
            self.assertIn("Hello body", str(fetched))
            invalid = await session.call_tool("fetch_message", {"folder": FOLDER, "uidvalidity": 42, "uid": "password-sentinel"})
            self.assertTrue(invalid.isError)
            self.assertNotIn("password-sentinel", str(invalid))
            stale = await session.call_tool("fetch_message", {"folder": FOLDER, "uidvalidity": 43, "uid": 3})
            self.assertTrue(stale.isError)
            self.assertIn("UIDVALIDITY changed", str(stale))


if __name__ == "__main__":
    unittest.main()
