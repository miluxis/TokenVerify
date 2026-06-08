from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import PurePosixPath, PureWindowsPath
from typing import Callable, TypeVar
from urllib.parse import urlparse

from tokenverify.relay_models import RelayAuditConfigError, RelayAuditProfile
from tokenverify.security import REDACTED, sanitize_public_text


class RelayAuditSecurityViolation(RuntimeError):
    pass


T = TypeVar("T")


@dataclass(frozen=True)
class RelayLiveAuthorization:
    live_mode: bool
    profile: RelayAuditProfile
    approved_live_path: str
    network_scope: str


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


def _strip_stream_shells(text: str) -> str:
    text = re.sub(
        r"data:\s*\{.*?\}",
        "[redacted-stream-event]",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    text = re.sub(
        r"\{\"choices\".*?\}",
        "[redacted-stream-event]",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    return text


def _strip_schema_shells(text: str) -> str:
    if not text:
        return text
    text = re.sub(
        r"\{[\s\S]*?\\*[\"']tool_calls\\*[\"'][\s\S]*?\}",
        "[redacted-schema-shell]",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    text = re.sub(
        r"\{[\s\S]*?\\*[\"']function\\*[\"'][\s\S]*?\\*[\"']arguments\\*[\"'][\s\S]*?\}",
        "[redacted-schema-shell]",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    text = re.sub(
        r"\{[\s\S]*?function\.arguments[\s\S]*?\}",
        "[redacted-schema-shell]",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    return text


def _strip_privacy_shells(text: str) -> str:
    if not text:
        return text
    text = re.sub(
        r"\{[\s\S]*?\\*[\"']messages\\*[\"'][\s\S]*?\}",
        "[redacted-privacy-shell]",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    text = re.sub(
        r"\{[\s\S]*?\\*[\"']error\\*[\"'][\s\S]*?\}",
        "[redacted-error-shell]",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    return text


def _strip_privacy_canary_markers(text: str) -> str:
    if not text:
        return text
    patterns = [
        r"tv_privacy_marker_do_not_echo",
        r"\\u0054\\u0056_privacy_marker_do_not_echo",
        r"\\u0074\\u0076_privacy_marker_do_not_echo",
    ]
    for pattern in patterns:
        text = re.sub(pattern, "[redacted-privacy-marker]", text, flags=re.IGNORECASE)
    return text


SECURITY_PUBLIC_MARKERS = (
    "TV_SAFE_BOUNDARY_OK",
    "TV_EXTRACTION_SAFE",
    "TV_OVERRIDE_SAFE",
)

CONTEXT_PUBLIC_MARKERS = (
    "TV_CTX_ALPHA",
    "TV_CTX_BRAVO",
    "TV_CTX_CHARLIE",
    "TV_CTX_OPENING",
    "TV_CTX_MIDDLE",
    "TV_CTX_CLOSING",
)


def _decode_common_unicode_escapes(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)

    return re.sub(r"\\u([0-9a-fA-F]{4})", replace, text)


def _strip_security_markers(text: str) -> str:
    if not text:
        return text
    for marker in SECURITY_PUBLIC_MARKERS:
        text = re.sub(re.escape(marker), "[redacted-security-marker]", text, flags=re.IGNORECASE)
    return text


def _strip_context_markers(text: str) -> str:
    if not text:
        return text
    decoded = _decode_common_unicode_escapes(text)
    for marker in CONTEXT_PUBLIC_MARKERS:
        decoded = re.sub(re.escape(marker), "[redacted-context-anchor]", decoded, flags=re.IGNORECASE)
    return decoded


def _strip_public_forbidden_phrases(text: str) -> str:
    if not text:
        return text
    forbidden = (
        "raw prompt",
        "raw model output",
        "raw output",
        "private expected answer",
        "secret verifier",
        "verifier expression",
    )
    for phrase in forbidden:
        text = re.sub(re.escape(phrase), "[redacted-sensitive-text]", text, flags=re.IGNORECASE)
    return text


def sanitize_public_relay_text(value: object) -> str:
    text = _strip_security_markers(
        _strip_privacy_canary_markers(
            _strip_privacy_shells(_strip_schema_shells(_strip_stream_shells(str(value))))
        )
    )
    text = _strip_context_markers(text)
    text = _strip_public_forbidden_phrases(text)
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


def guard_api_key_env_name(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    if not text:
        return text
    if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", text):
        raise RelayAuditConfigError(
            "--api-key-env expects an environment variable name, not a raw secret value."
        )
    return text


def authorize_relay_live_execution(
    *,
    live_mode: bool,
    profile: RelayAuditProfile,
    client_factory: Callable[[], T] | None = None,
) -> RelayLiveAuthorization:
    if not live_mode:
        raise RelayAuditSecurityViolation("Network execution blocked: --live flag missing.")
    approved_paths = {
        RelayAuditProfile.GENERAL: (
            "general_minimal_connectivity",
            "single_non_streaming_request",
        ),
        RelayAuditProfile.IDENTITY: (
            "identity_fingerprint",
            "bounded_identity_requests",
        ),
        RelayAuditProfile.CHANNEL: (
            "channel_fingerprint",
            "bounded_channel_requests",
        ),
        RelayAuditProfile.REASONING: (
            "reasoning_fingerprint",
            "bounded_reasoning_requests",
        ),
        RelayAuditProfile.STREAMING: (
            "streaming_minimal_sse_integrity",
            "single_streaming_request",
        ),
        RelayAuditProfile.SCHEMA: (
            "schema_minimal_tool_preservation",
            "single_schema_tool_request",
        ),
        RelayAuditProfile.PRIVACY: (
            "privacy_minimal_contract",
            "single_privacy_request",
        ),
        RelayAuditProfile.SECURITY: (
            "security_prompt_boundary",
            "up_to_three_non_streaming_security_requests",
        ),
        RelayAuditProfile.CONTEXT: (
            "context_anchor_retention",
            "up_to_two_non_streaming_context_requests",
        ),
        RelayAuditProfile.FULL: (
            "full_composite_profile",
            "approved_subprofile_sequence",
        ),
    }
    if profile not in approved_paths:
        raise RelayAuditSecurityViolation(
            "Network execution blocked: live relay path is not opened for this profile."
        )
    approved_live_path, network_scope = approved_paths[profile]
    return RelayLiveAuthorization(
        live_mode=True,
        profile=profile,
        approved_live_path=approved_live_path,
        network_scope=network_scope,
    )


def enforce_relay_live_gate(
    *,
    live_mode: bool,
    transport_factory: Callable[[], T] | None = None,
) -> T | None:
    authorize_relay_live_execution(live_mode=live_mode, profile=RelayAuditProfile.GENERAL)
    if transport_factory is None:
        return None
    return transport_factory()
