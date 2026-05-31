from __future__ import annotations

import hashlib
import re
from urllib.parse import urlparse


REDACTED = "***REDACTED***"
PRIVATE_OBSERVATION_FIELDS = {
    "system_fingerprint",
    "raw_response_timestamp",
    "raw_response_timestamps",
    "absolute_arrival_time",
    "absolute_arrival_times",
    "raw_timing_array",
    "raw_timing_arrays",
}


def hash_endpoint_url(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]


def endpoint_host(url: str) -> str:
    parsed = urlparse(url)
    if parsed.hostname:
        return parsed.hostname
    return url.removeprefix("https://").removeprefix("http://").split("/")[0]


def sanitize_public_text(value: object) -> str:
    text = str(value)
    text = re.sub(r"https?://[^\s`'\"<>]+", "[redacted-endpoint]", text)
    text = re.sub(r"Bearer\s+[A-Za-z0-9._~+/=-]+", f"Bearer {REDACTED}", text, flags=re.IGNORECASE)
    text = re.sub(r"\bsk-[A-Za-z0-9._-]+", REDACTED, text)
    text = re.sub(r"\bTOKEN_[A-Z0-9_]*\b", REDACTED, text)
    text = re.sub(r"\b[A-Z0-9_]*TOKEN[A-Z0-9_]*\b", REDACTED, text)
    text = re.sub(r"\bfp_[A-Za-z0-9._-]+\b", "[redacted-fingerprint]", text)
    text = re.sub(r"raw provider error text", "provider error", text, flags=re.IGNORECASE)
    for field in PRIVATE_OBSERVATION_FIELDS:
        text = re.sub(re.escape(field), "[private-observation-field]", text, flags=re.IGNORECASE)
    return text


def public_error_summary(value: object) -> str:
    text = sanitize_public_text(value).lower()
    if any(marker in text for marker in ("authentication", "authorization", "auth_error", "401", "403")):
        return "Provider authentication or authorization error."
    if any(marker in text for marker in ("timeout", "timed out")):
        return "Provider timeout before a conclusive result."
    if any(marker in text for marker in ("network", "disconnect", "connection reset")):
        return "Provider network error before a conclusive result."
    if "quota" in text or "rate limit" in text or "too many requests" in text:
        return "Provider quota or rate-limit error."
    return "Provider runtime error before a conclusive result."
