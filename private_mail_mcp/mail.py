"""Small, read-only IMAP operations. Mail content is always untrusted data."""
import base64
from contextlib import contextmanager
from datetime import date
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
import imaplib
import re
import ssl

from .config import Config


class MailError(Exception):
    """A fixed public diagnostic, never an upstream error string."""


def folder_id(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii")


def folder_bytes(value: str) -> bytes:
    try:
        raw = base64.b64decode(value, altchars=b"-_", validate=True)
        if not raw or len(raw) > 1024 or any(c < 32 or c == 127 for c in raw) or folder_id(raw) != value:
            raise ValueError
        return raw
    except Exception:
        raise MailError("Invalid folder identity.") from None


def quoted(raw: bytes) -> bytes:
    return b'"' + raw.replace(b"\\", b"\\\\").replace(b'"', b'\\"') + b'"'


def display_folder(raw: bytes) -> str:
    # Modified UTF-7 is for display only; identity retains exact wire bytes.
    try:
        def decode(match):
            part = match[1]
            value = "&" if not part else base64.b64decode(
                part.replace(b",", b"/") + b"=" * (-len(part) % 4)
            ).decode("utf-16-be")
            return value.encode("utf-8")
        return clean(re.sub(rb"&([^-]*)-", decode, raw).decode("utf-8"))
    except Exception:
        return clean(raw.decode("ascii", errors="replace"))


class HTMLText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "head", "template"):
            self.hidden += 1
        if not self.hidden and tag in ("p", "br", "div", "li", "tr", "hr"):
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style", "head", "template") and self.hidden:
            self.hidden -= 1
        if not self.hidden and tag in ("p", "div", "li", "tr"):
            self.parts.append("\n")

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def readable(message):
    """Do not traverse attached messages, named attachments or attached multipart trees."""
    plain, html = [], []
    def visit(part, depth=0):
        if depth > 30 or part.get_content_disposition() == "attachment" or part.get_filename() or part.get_content_maintype() == "message":
            return
        if part.is_multipart():
            for child in part.iter_parts():
                visit(child, depth + 1)
        elif part.get_content_type() in ("text/plain", "text/html"):
            data = part.get_payload(decode=True) or b""
            try:
                text = data.decode(part.get_content_charset() or "utf-8", errors="replace")
            except LookupError:
                text = data.decode("utf-8", errors="replace")
            (plain if part.get_content_type() == "text/plain" else html).append(text)
    visit(message)
    if plain:
        return "\n".join(plain)
    parser = HTMLText()
    parser.feed("\n".join(html))
    return "".join(parser.parts)


def clean(value: str) -> str:
    return "".join(c for c in value if c in "\n\t" or (ord(c) >= 32 and ord(c) != 127))


class MailClient:
    def __init__(self, config: Config, factory=None):
        self.config = config
        self.factory = factory or imaplib.IMAP4_SSL

    @contextmanager
    def connection(self):
        client = None
        try:
            client = self.factory(self.config.host, self.config.port, ssl_context=ssl.create_default_context(), timeout=self.config.timeout)
            client.login(self.config.username, self.config.password)
            yield client
        except MailError:
            raise
        except Exception:
            raise MailError("IMAP operation failed; check local configuration and connectivity.") from None
        finally:
            if client is not None:
                try:
                    client.logout()
                except Exception:
                    pass

    @staticmethod
    def ok(result):
        status, data = result
        if status != "OK":
            raise MailError("IMAP server could not complete the read operation.")
        return data

    def select(self, client, folder):
        raw = folder_bytes(folder)
        self.ok(client.select(quoted(raw), readonly=True))
        _, values = client.response("UIDVALIDITY")
        if not values or not values[0] or not re.fullmatch(rb"[1-9][0-9]{0,9}", values[0]) or int(values[0]) > 4294967295:
            raise MailError("IMAP server did not provide valid UIDVALIDITY.")
        return int(values[0])

    def list_mailboxes(self):
        with self.connection() as client:
            lines = [line for line in (self.ok(client.list()) or []) if line]
            folders = []
            for line in lines:
                if not line:
                    continue
                prefix, literal = line if isinstance(line, tuple) else (line, None)
                match = re.fullmatch(rb'\(([^)]*)\) (?:NIL|"(?:[^"\\]|\\.)*") (.+)', prefix)
                if not match:
                    raise MailError("Unsupported IMAP folder response.")
                flags, name = match.groups()
                if literal is not None:
                    name = literal
                elif name.startswith(b'"') and name.endswith(b'"'):
                    name = re.sub(rb"\\(.)", rb"\1", name[1:-1])
                elif name.startswith(b"{"):
                    raise MailError("Unsupported IMAP folder response.")
                identity = folder_id(name)
                folder_bytes(identity)
                folders.append({"folder": identity, "name": display_folder(name), "selectable": b"\\noselect" not in flags.lower().split(), "flags": flags.decode("ascii", "replace").split()})
                if len(folders) >= self.config.max_folders:
                    break
            return {"folders": folders, "truncated": len(lines) > len(folders)}

    def metadata(self, client, folder, validity, uid, include_body=False):
        cap = self.config.max_message_bytes if include_body else self.config.max_header_bytes
        section = "" if include_body else "HEADER"
        query = f"(UID FLAGS RFC822.SIZE BODY.PEEK[{section}]<0.{cap}>)"
        rows = self.ok(client.uid("FETCH", str(uid), query)) or []
        record = None
        for row in rows:
            if isinstance(row, tuple) and len(row) == 2:
                info, content = row
                found = re.search(rb"\bUID ([0-9]+)\b", info)
                if found and int(found[1]) == uid:
                    record = info, content
                    break
        if record is None:
            raise MailError("Message no longer exists in this folder.")
        info, content = record
        if not isinstance(content, bytes) or len(content) > cap:
            raise MailError("IMAP server exceeded the requested message limit.")
        msg = BytesParser(policy=policy.default).parsebytes(content)
        flags = re.search(rb"\bFLAGS \(([^)]*)\)", info)
        size = re.search(rb"\bRFC822.SIZE ([0-9]+)", info)
        result = {"folder": folder, "uidvalidity": validity, "uid": uid,
                  "sender": clean(str(msg.get("From", ""))),
                  "to": clean(str(msg.get("To", ""))), "cc": clean(str(msg.get("Cc", ""))),
                  "subject": clean(str(msg.get("Subject", ""))), "date": clean(str(msg.get("Date", ""))),
                  "flags": flags[1].decode("ascii", "replace").split() if flags else [],
                  "size_bytes": int(size[1]) if size else None}
        if include_body:
            text = clean(readable(msg))
            result["body"] = text[:self.config.max_body_chars]
            result["body_truncated"] = len(text) > self.config.max_body_chars or len(content) >= cap or (size is not None and int(size[1]) > len(content))
        else:
            result["headers_truncated"] = len(content) >= cap
        return result

    def search_messages(self, folder: str, limit: int | None = None, since: str | None = None, before: str | None = None,
                        sender: str | None = None, recipient: str | None = None, subject: str | None = None,
                        unseen_only: bool = False):
        folder_bytes(folder)
        if limit is None:
            limit = min(20, self.config.max_results)
        if type(limit) is not int or not 1 <= limit <= self.config.max_results or type(unseen_only) is not bool:
            raise MailError("Invalid search limit or filter.")
        criteria = []
        months = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
        for key, value in (("SINCE", since), ("BEFORE", before)):
            if value is not None:
                try:
                    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
                        raise ValueError
                    day = date.fromisoformat(value)
                    criteria += [key.encode(), f"{day.day:02}-{months[day.month - 1]}-{day.year:04}".encode()]
                except Exception:
                    raise MailError("Dates must be valid YYYY-MM-DD values.") from None
        for key, value in (("FROM", sender), ("TO", recipient), ("SUBJECT", subject)):
            if value is not None:
                if not isinstance(value, str) or not value or len(value) > 256 or any(ord(c) < 32 or ord(c) > 126 for c in value):
                    raise MailError("Text filters must contain 1 to 256 printable ASCII characters.")
                criteria += [key.encode(), quoted(value.encode("ascii"))]
        if unseen_only:
            criteria.append(b"UNSEEN")
        with self.connection() as client:
            validity = self.select(client, folder)
            data = self.ok(client.uid("SEARCH", None, *(criteria or [b"ALL"])))
            raw = b" ".join(item for item in data if isinstance(item, bytes))
            if raw and not re.fullmatch(rb"[0-9 ]+", raw):
                raise MailError("Invalid IMAP search response.")
            uids = sorted({int(v) for v in raw.split()}, reverse=True)
            if any(not 1 <= uid <= 4294967295 for uid in uids):
                raise MailError("Invalid IMAP search response.")
            messages = []
            for uid in uids[:limit]:
                try:
                    messages.append(self.metadata(client, folder, validity, uid))
                except MailError as error:
                    if str(error) != "Message no longer exists in this folder.":
                        raise
            return {"folder": folder, "uidvalidity": validity, "messages": messages, "matched": len(uids), "truncated": len(uids) > limit}

    def fetch_message(self, folder: str, uidvalidity: int, uid: int, include_body: bool = True):
        folder_bytes(folder)
        if any(type(v) is not int or not 1 <= v <= 4294967295 for v in (uidvalidity, uid)) or type(include_body) is not bool:
            raise MailError("UID and UIDVALIDITY must be positive 32-bit integers.")
        with self.connection() as client:
            current = self.select(client, folder)
            if current != uidvalidity:
                raise MailError("UIDVALIDITY changed; search this folder again before fetching.")
            return self.metadata(client, folder, current, uid, include_body)
