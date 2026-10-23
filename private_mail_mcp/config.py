"""Local configuration; secrets are never included in diagnostics or repr."""
from dataclasses import dataclass, field
import os
from pathlib import Path
import tomllib


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Config:
    host: str
    username: str = field(repr=False)
    password: str = field(repr=False)
    port: int = 993
    listen_port: int = 8000
    timeout: int = 20
    max_results: int = 50
    max_body_chars: int = 32000
    max_message_bytes: int = 1048576
    max_header_bytes: int = 32768
    max_folders: int = 200

    def __post_init__(self):
        for name in ("host", "username", "password"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value or any(c in value for c in "\r\n\x00"):
                raise ConfigError("Invalid or missing IMAP configuration.")
        bounds = {"port": (1, 65535), "listen_port": (1, 65535), "timeout": (1, 120),
                  "max_results": (1, 200), "max_body_chars": (1, 200000),
                  "max_message_bytes": (1024, 4194304), "max_header_bytes": (1024, 65536),
                  "max_folders": (1, 1000)}
        for name, (low, high) in bounds.items():
            value = getattr(self, name)
            if type(value) is not int or not low <= value <= high:
                raise ConfigError("Invalid configuration limit.")


def load_config(path: str | None = None) -> Config:
    """Environment PRIVATE_MAIL_<FIELD> overrides the optional local TOML file."""
    selected = path or os.environ.get("PRIVATE_MAIL_CONFIG", "config.local.toml")
    try:
        source = Path(selected)
        values = tomllib.loads(source.read_text(encoding="utf-8-sig")) if source.exists() else {}
        if not isinstance(values, dict) or set(values) - set(Config.__dataclass_fields__):
            raise ConfigError("Unknown configuration option.")
        for name in Config.__dataclass_fields__:
            env = os.environ.get("PRIVATE_MAIL_" + name.upper())
            if env is not None:
                values[name] = env if name in ("host", "username", "password") else int(env)
        return Config(**values)
    except ConfigError:
        raise
    except Exception:
        raise ConfigError("Cannot load local configuration.") from None
