"""Interactive, local-only credential setup. Never pass credentials as arguments."""
import csv
import getpass
import json
import os
from pathlib import Path
import subprocess
import sys
import warnings

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from private_mail_mcp.config import Config


def restrict_file(path):
    """Restrict a newly created, still empty file before writing any secrets."""
    if os.name == "nt":
        options = {"capture_output": True, "text": True, "check": True,
                   "creationflags": subprocess.CREATE_NO_WINDOW}
        row = next(csv.reader(subprocess.run(
            ["whoami", "/user", "/fo", "csv", "/nh"], **options).stdout.splitlines()))
        sid = row[1]
        if not sid.startswith("S-1-") or any(c not in "S-0123456789" for c in sid):
            raise ValueError
        subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", f"*{sid}:F"], **options)
    else:
        path.chmod(0o600)


def write_config(path, config):
    # Exclusive creation also prevents accidentally replacing an existing config.
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        restrict_file(path)
        values = {"host": config.host, "port": config.port,
                  "username": config.username, "password": config.password}
        stream.write("# Local credentials. Do not share or commit this file.\n")
        for key, value in values.items():
            serialized = json.dumps(value, ensure_ascii=False).replace(chr(127), "\\u007f")
            stream.write(f"{key} = {serialized}\n")


def main():
    path = ROOT / "config.local.toml"
    try:
        if path.exists():
            print("Configuration already exists; left unchanged. Edit it locally if needed.")
            return 1
        print("Enter the IMAP host and mailbox username provided by your Loopia account.")
        print("Credentials stay on this computer. Password input is hidden.")
        host = input("IMAP hostname: ").strip()
        port = int(input("Implicit TLS port [993]: ").strip() or "993")
        username = input("Mailbox username: ").strip()
        # Refuse getpass's unsafe echoed fallback on unsupported terminals.
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            password = getpass.getpass("Mailbox password (hidden): ")
        config = Config(host, username, password, port=port)
        write_config(path, config)
        print("Created ignored config.local.toml with restricted file permissions.")
        return 0
    except (KeyboardInterrupt, EOFError):
        print("Setup cancelled; no credentials displayed.")
        return 1
    except BaseException:
        print("Setup failed. Check input, terminal support and local file permissions; no credentials displayed.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
