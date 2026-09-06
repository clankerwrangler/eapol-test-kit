from dataclasses import dataclass, field
import ipaddress
import os
from pathlib import Path


def default_allowed_hosts() -> tuple[str, ...]:
    configured = os.environ.get("EAPOLKIT_ALLOWED_HOSTS", "")
    if configured:
        return tuple(host.strip().lower() for host in configured.split(",") if host.strip())
    hosts = ("localhost", "127.0.0.1", "::1")
    bind = os.environ.get("EAPOLKIT_BIND_ADDRESS", "").strip().lower()
    try:
        address = ipaddress.ip_address(bind)
    except ValueError:
        return hosts
    if address.is_unspecified or bind in hosts:
        return hosts
    return (*hosts, bind)


@dataclass(frozen=True)
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(os.environ.get("EAPOLKIT_DATA_DIR", "/data")))
    binary: str = field(default_factory=lambda: os.environ.get("EAPOLKIT_BINARY", "/usr/local/bin/eapol_test"))
    allowed_hosts: tuple[str, ...] = field(default_factory=default_allowed_hosts)
    secure_cookies: bool = field(default_factory=lambda: os.environ.get("EAPOLKIT_SECURE_COOKIES", "0") == "1")
    session_seconds: int = 43200
    upload_limit: int = 2 * 1024 * 1024
    request_limit: int = 8 * 1024 * 1024
    history_limit: int = 200
    max_log_lines: int = 2000
    max_log_bytes: int = 512 * 1024
    max_line_bytes: int = 4096
