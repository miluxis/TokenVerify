from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from tokenverify.relay_models import RelayAuditConfigError, RelayAuditProfile, RelayPackSummary, RelayRiskCategory
from tokenverify.relay_safety import basename_only, sanitize_public_relay_text


MAX_RELAY_PACK_BYTES = 5 * 1024 * 1024
MAX_PUBLIC_METADATA_LENGTH = 160
MAX_PUBLIC_INTENTS = 5


def load_relay_pack_summary(path: Path | str) -> RelayPackSummary:
    basename = basename_only(path)
    _reject_remote_pack_path(path, basename)
    pack_path = Path(path).expanduser()
    if not pack_path.exists():
        raise RelayAuditConfigError(f"Relay pack file not found: {basename}.") from None
    if pack_path.is_dir():
        raise RelayAuditConfigError(f"Relay pack path is a directory: {basename}.") from None
    try:
        size = pack_path.stat().st_size
    except OSError:
        raise RelayAuditConfigError(f"Relay pack file is not readable: {basename}.") from None
    if size > MAX_RELAY_PACK_BYTES:
        raise RelayAuditConfigError(f"Relay pack file is too large: {basename}.") from None
    try:
        raw_text = pack_path.read_text(encoding="utf-8")
    except OSError:
        raise RelayAuditConfigError(f"Relay pack file is not readable: {basename}.") from None
    try:
        data = yaml.safe_load(raw_text) or {}
    except yaml.YAMLError:
        raise RelayAuditConfigError(f"Relay pack metadata is invalid: {basename}.") from None
    if not isinstance(data, dict):
        raise RelayAuditConfigError(f"Relay pack metadata must be a mapping: {basename}.") from None
    return _summary_from_mapping(data, raw_text=raw_text, basename=basename)


def _reject_remote_pack_path(path: Path | str, basename: str) -> None:
    parsed = urlparse(str(path).strip())
    if parsed.scheme in {"http", "https"}:
        safe_name = basename_only(parsed.path) if parsed.path else basename
        raise RelayAuditConfigError(f"Relay pack path must be a local file: {safe_name}.") from None


def _summary_from_mapping(data: dict[str, Any], *, raw_text: str, basename: str) -> RelayPackSummary:
    pack_id = _optional_public_scalar(data.get("id"), "id", basename)
    version = _optional_public_scalar(data.get("version"), "version", basename)
    profiles = _safe_profiles(data.get("profiles"), basename)
    categories = _safe_categories(data.get("categories"), basename)
    challenges = _challenge_maps(data.get("challenges"), basename)
    challenge_profiles = _challenge_profile_values(challenges, basename)
    challenge_categories = _challenge_category_values(challenges, basename)
    public_intents = _public_intents(challenges)
    return RelayPackSummary(
        label="Local Private Pack",
        pack_hash=hashlib.sha256(raw_text.encode("utf-8")).hexdigest()[:16],
        pack_id=pack_id,
        version=version,
        basename=basename,
        profiles=_dedupe_preserve_order([*profiles, *challenge_profiles]),
        categories=_dedupe_preserve_order([*categories, *challenge_categories]),
        challenge_count=len(challenges),
        public_intents=public_intents,
    )


def _optional_public_scalar(value: Any, field_name: str, basename: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str | int | float | bool):
        raise RelayAuditConfigError(f"Relay pack field {field_name} must be a scalar value: {basename}.") from None
    text = sanitize_public_relay_text(value).strip()
    if not text:
        return None
    return text[:MAX_PUBLIC_METADATA_LENGTH]


def _safe_profiles(value: Any, basename: str) -> list[str]:
    return _safe_enum_list(value, RelayAuditProfile, "profiles", basename)


def _safe_categories(value: Any, basename: str) -> list[str]:
    return _safe_enum_list(value, RelayRiskCategory, "categories", basename)


def _safe_enum_list(value: Any, enum_type, field_name: str, basename: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise RelayAuditConfigError(f"Relay pack field {field_name} must be a list: {basename}.") from None
    output: list[str] = []
    accepted = {item.value for item in enum_type}
    for item in value:
        if not isinstance(item, str):
            raise RelayAuditConfigError(f"Relay pack field {field_name} must contain strings: {basename}.") from None
        normalized = item.strip().lower()
        if normalized not in accepted:
            raise RelayAuditConfigError(f"Relay pack field {field_name} contains unsupported value: {basename}.") from None
        output.append(normalized)
    return _dedupe_preserve_order(output)


def _challenge_maps(value: Any, basename: str) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise RelayAuditConfigError(f"Relay pack field challenges must be a list: {basename}.") from None
    output: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            raise RelayAuditConfigError(f"Relay pack challenge metadata must be a mapping: {basename}.") from None
        output.append(item)
    return output


def _challenge_profile_values(challenges: list[dict[str, Any]], basename: str) -> list[str]:
    values = []
    accepted = {item.value for item in RelayAuditProfile}
    for challenge in challenges:
        value = challenge.get("profile")
        if value is None:
            continue
        if not isinstance(value, str):
            raise RelayAuditConfigError(f"Relay pack challenge profile must be a string: {basename}.") from None
        normalized = value.strip().lower()
        if normalized not in accepted:
            raise RelayAuditConfigError(f"Relay pack challenge profile contains unsupported value: {basename}.") from None
        values.append(normalized)
    return _dedupe_preserve_order(values)


def _challenge_category_values(challenges: list[dict[str, Any]], basename: str) -> list[str]:
    values = []
    accepted = {item.value for item in RelayRiskCategory}
    for challenge in challenges:
        value = challenge.get("category")
        if value is None:
            continue
        if not isinstance(value, str):
            raise RelayAuditConfigError(f"Relay pack challenge category must be a string: {basename}.") from None
        normalized = value.strip().lower()
        if normalized not in accepted:
            raise RelayAuditConfigError(f"Relay pack challenge category contains unsupported value: {basename}.") from None
        values.append(normalized)
    return _dedupe_preserve_order(values)


def _public_intents(challenges: list[dict[str, Any]]) -> list[str]:
    output: list[str] = []
    for challenge in challenges:
        value = challenge.get("public_intent")
        if value is None:
            continue
        if not isinstance(value, str):
            continue
        cleaned = sanitize_public_relay_text(value).strip()
        if cleaned:
            output.append(cleaned[:MAX_PUBLIC_METADATA_LENGTH])
        if len(output) >= MAX_PUBLIC_INTENTS:
            break
    return output


def _dedupe_preserve_order(values: list[str]) -> list[str]:
    seen = set()
    output = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output
