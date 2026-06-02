from __future__ import annotations

import hashlib
import re
from pathlib import PurePosixPath, PureWindowsPath
from typing import Callable, TypeVar
from urllib.parse import urlparse

from tokenverify.security import REDACTED, sanitize_public_text


class RelayAuditSecurityViolation(RuntimeError):
    pass


T = TypeVar("T")


def sanitize_to_fqdn(value: object) -> str:
    text = str(value).strip()
    parsed = urlparse(text)
    host = parsed.hostname
    if host:
        return host
    without_scheme = text.removeprefix("https://").removeprefix("http://")
    authority = without_scheme.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in authority:
        authority = authority.rsplit("@", 1)[1]
    if ":" in authority and not authority.startswith("["):
        authority = authority.split(":", 1)[0]
    return authority or "[redacted-endpoint]"


def basename_only(value: object) -> str:
    text = str(value).strip()
    if not text:
        return "[redacted-path]"
    windows_name = PureWindowsPath(text).name
    posix_name = PurePosixPath(windows_name).name
    return posix_name or "[redacted-path]"


def hash_relay_endpoint(value: object) -> str:
    return hashlib.sha256(str(value).strip().rstrip("/").encode("utf-8")).hexdigest()[:16]


def sanitize_public_relay_text(value: object) -> str:
    text = str(value)
    text = re.sub(r"https?://[^\s`'\"<>]+", lambda match: sanitize_to_fqdn(match.group(0)), text)
    text = re.sub(
        r"(?<!\w)(?:~|/[A-Za-z0-9_.-]+|[A-Za-z]:\\)[^\s`'\"<>]*",
        lambda match: basename_only(match.group(0)),
        text,
    )
    text = sanitize_public_text(text)
    text = re.sub(r"Bearer\s+[A-Za-z0-9._~+/=-]+", f"Bearer {REDACTED}", text, flags=re.IGNORECASE)
    text = re.sub(r"\bsk-[A-Za-z0-9._-]+", REDACTED, text)
    return text


def enforce_relay_live_gate(
    *,
    live_mode: bool,
    transport_factory: Callable[[], T] | None = None,
) -> T | None:
    if not live_mode:
        raise RelayAuditSecurityViolation("Network execution blocked: --live flag missing.")
    raise RelayAuditSecurityViolation("Network execution blocked: relay live probes are not implemented in this milestone.")
