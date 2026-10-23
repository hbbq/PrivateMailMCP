"""Safety checks for optional local helpers. No network or real credentials."""
import asyncio
import contextlib
import getpass
import io
import os
from pathlib import Path
import tempfile
import tomllib
import unittest
from unittest.mock import patch

from private_mail_mcp.config import Config
from scripts import configure_local as setup
from scripts import integration_local as live
from test_private_mail import CONFIG, FakeIMAP


class SetupTests(unittest.TestCase):
    def test_roundtrip_strings_and_permissions_before_secrets(self):
        secret = 'fake-"\\-Ã¥-ðŸ˜€-' + chr(127) + '\t'
        config = Config("imap.example.invalid", 'fake-"\\-Ã¥-ðŸ˜€@example.invalid', secret)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.local.toml"
            def restrict(target):
                self.assertEqual(target.read_bytes(), b"")
            with patch.object(setup, "restrict_file", side_effect=restrict):
                setup.write_config(path, config)
            values = tomllib.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(values["password"], secret)
            self.assertEqual(values["username"], config.username)
            with self.assertRaises(FileExistsError):
                setup.write_config(path, config)
            self.assertEqual(tomllib.loads(path.read_text(encoding="utf-8")), values)

    def test_permission_failure_writes_no_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "local.toml"
            with patch.object(setup, "restrict_file", side_effect=PermissionError("fake-secret")):
                with self.assertRaises(PermissionError):
                    setup.write_config(path, Config("imap.example.invalid", "fake", "fake-secret"))
            self.assertEqual(path.read_bytes(), b"")

    def test_getpass_fallback_refused_without_echo(self):
        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            def fallback(*args):
                import warnings
                warnings.warn("echo fallback", getpass.GetPassWarning)
                self.fail("fallback must be aborted before echoed input")
            with patch.object(setup, "ROOT", Path(directory)), patch("builtins.input", side_effect=["imap.example.invalid", "", "fake"]), patch.object(setup.getpass, "getpass", side_effect=fallback), contextlib.redirect_stdout(output):
                self.assertEqual(setup.main(), 1)
            self.assertNotIn("echo fallback", output.getvalue())
            self.assertFalse((Path(directory) / "config.local.toml").exists())

    def test_existing_file_never_read_or_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.local.toml"
            path.write_text("fake-secret", encoding="utf-8")
            with patch.object(setup, "ROOT", Path(directory)), patch("builtins.input", side_effect=AssertionError), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(setup.main(), 1)
            self.assertEqual(path.read_text(), "fake-secret")

    def test_windows_acl_uses_current_sid_and_hides_output(self):
        sid = "S-1-5-21-123-1001"
        class Result:
            stdout = f'"FAKE\\User","{sid}"\n'
        with patch.object(setup.os, "name", "nt"), patch.object(setup.subprocess, "CREATE_NO_WINDOW", 0x08000000, create=True), patch.object(setup.subprocess, "run", return_value=Result()) as run:
            setup.restrict_file("fake-local-file")
        self.assertEqual(run.call_args_list[1].args[0], ["icacls", "fake-local-file", "/inheritance:r", "/grant:r", f"*{sid}:F"])
        self.assertTrue(all(c.kwargs["capture_output"] and c.kwargs["check"] for c in run.call_args_list))


class IntegrationSafetyTests(unittest.TestCase):
    def client(self):
        client = live.AuditedIMAP.__new__(live.AuditedIMAP)
        client.audit = live.Audit()
        client.validity = 42
        return client

    def test_optin_required_before_configuration_or_network(self):
        with patch("sys.argv", ["integration_local.py"]), patch.object(live, "load_config", side_effect=AssertionError), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(live.main(), 2)

    def test_failure_output_never_includes_exception_or_configuration(self):
        output = io.StringIO()
        with patch("sys.argv", ["integration_local.py", "--run-live"]), patch.object(live, "load_config", side_effect=RuntimeError("fake-private-password address@example.invalid")), contextlib.redirect_stdout(output):
            self.assertEqual(live.main(), 1)
        self.assertNotIn("fake-private", output.getvalue())
        self.assertNotIn("address@", output.getvalue())
        self.assertIn("configuration", output.getvalue())

    def test_forbidden_wire_commands_blocked(self):
        client = self.client()
        with patch.object(live.imaplib.IMAP4_SSL, "_command", return_value="allowed"):
            for name, args in [("SELECT", ("INBOX",)), ("STORE", ()), ("EXPUNGE", ()), ("UID", ("STORE", "1", "FLAGS")), ("UID", ("FETCH", "1", "(BODY[])")), ("UID", ("FETCH", "1", "(RFC822)"))]:
                with self.subTest(name=name, args=args), self.assertRaises(live.AuditFailure):
                    client._command(name, *args)
            for name, args in [("EXAMINE", ("INBOX",)), ("UID", ("FETCH", "1", "(UID FLAGS)")), ("UID", ("FETCH", "1", "(UID FLAGS RFC822.SIZE BODY.PEEK[HEADER]<0.32768>)")), ("UID", ("SEARCH", None, "ALL"))]:
                self.assertEqual(client._command(name, *args), "allowed")
        with self.assertRaises(live.AuditFailure):
            client.select("INBOX", readonly=False)

    def test_flags_parsing_and_uid_identity(self):
        client = self.client()
        with patch.object(live.imaplib.IMAP4_SSL, "uid", return_value=("OK", [b"1 (UID 9 FLAGS (\\Seen Custom))", b"2 (UID 8 FLAGS ())"])):
            self.assertEqual(client.flags(8), frozenset())
            self.assertEqual(client.flags(9), frozenset([b"\\Seen", b"Custom"]))
            self.assertIsNone(client.flags(7))

    def test_content_fetch_checks_flags_before_and_after(self):
        client = self.client()
        result = ("OK", [(b"1 (UID 9 FLAGS () BODY[]<0> {4}", b"fake"), b")"])
        with patch.object(live.AuditedIMAP, "flags", side_effect=[frozenset(), frozenset([b"\\Seen"])]), patch.object(live.imaplib.IMAP4_SSL, "uid", return_value=result) as parent:
            self.assertEqual(client.uid("FETCH", "9", "(UID FLAGS RFC822.SIZE BODY.PEEK[]<0.1024>)"), result)
        self.assertEqual(parent.call_count, 1)
        self.assertTrue(client.audit.changed)
        self.assertEqual(client.audit.content_fetches, 1)
        self.assertEqual(client.audit.raw_body, b"fake")
        self.assertEqual(client.audit.baseline, {(42, 9): frozenset()})

    def test_vanished_message_inconclusive(self):
        with self.assertRaises(live.Inconclusive):
            live.Audit().observe(42, 9, None)


class FullSyntheticIntegrationTests(unittest.TestCase):
    def exercise(self, unread=True, empty=False, changed=False):
        audit = live.Audit()
        class Synthetic(FakeIMAP):
            def flags(self, uid):
                return frozenset() if unread else frozenset([b"\\Seen"])

            def uid(self, operation, *args):
                if operation == "SEARCH" and (empty or (not unread and b"UNSEEN" in args)):
                    return "OK", [b""]
                content = operation == "FETCH" and "BODY.PEEK[" in args[-1]
                if content:
                    uid = int(args[0])
                    audit.observe(42, uid, self.flags(uid))
                result = super().uid(operation, *args)
                if content:
                    audit.content_fetches += 1
                    audit.observe(42, uid, self.flags(uid))
                    if unread:
                        result = result[0], [(row[0].replace(b"\\Seen", b""), row[1]) if isinstance(row, tuple) else row for row in result[1]]
                    if "BODY.PEEK[]" in args[-1]:
                        audit.raw_body = result[1][0][1]
                return result
        mail = live.MailClient(CONFIG, lambda *a, **kw: Synthetic())
        output = io.StringIO()
        audit.changed = changed
        with contextlib.redirect_stdout(output):
            asyncio.run(live.exercise(CONFIG, mail, audit, lambda value: None))
        return output.getvalue(), audit

    def test_full_official_mcp_unread_sample(self):
        output, audit = self.exercise()
        self.assertEqual(audit.content_fetches, 4)
        self.assertEqual(len(audit.baseline), 3)
        self.assertIn("unseen and remained unseen", output)
        self.assertIn("stale UIDVALIDITY rejected", output)
        self.assertNotIn("sender@", output)
        self.assertNotIn("Hello body", output)
        self.assertNotIn("Hello", output)

    def test_full_official_mcp_seen_fallback(self):
        output, audit = self.exercise(unread=False)
        self.assertIn("already seen", output)
        self.assertEqual(audit.content_fetches, 4)

    def test_empty_or_changing_sample_not_success(self):
        with self.assertRaises(BaseExceptionGroup) as raised:
            self.exercise(empty=True)
        self.assertIsNotNone(raised.exception.subgroup(live.Inconclusive))
        with self.assertRaises(live.Inconclusive):
            self.exercise(changed=True)


if __name__ == "__main__":
    unittest.main()
