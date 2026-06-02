from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import yaml

from tokenverify.relay_fake import build_fake_relay_result
from tokenverify.relay_live import RelayLiveTransport, run_minimal_general_live_check
from tokenverify.relay_models import (
    RelayAuditConfigError,
    RelayAuditProfile,
    RelayPackSummary,
    RelayResult,
    RelayVerdict,
)
from tokenverify.relay_safety import authorize_relay_live_execution, basename_only


@dataclass(frozen=True)
class RelayAuditRequest:
    base_url: str
    model: str
    profile: RelayAuditProfile
    fake_scenario: RelayVerdict | None
    pack_path: Path | None
    live: bool = False
    api_key: str | None = None
    live_transport_factory: Callable[[], RelayLiveTransport | None] | None = None


def run_relay_audit(request: RelayAuditRequest) -> RelayResult:
    pack_summary = (
        load_relay_pack_summary(request.pack_path)
        if request.pack_path
        else RelayPackSummary(
            label="No Pack",
            pack_hash=None,
        )
    )
    if request.fake_scenario is not None:
        return build_fake_relay_result(
            profile=request.profile,
            scenario=request.fake_scenario,
            endpoint=request.base_url,
            model=request.model,
            pack_summary=pack_summary,
        )
    authorization = authorize_relay_live_execution(live_mode=request.live, profile=request.profile)
    live_transport = request.live_transport_factory() if request.live_transport_factory else None
    return run_minimal_general_live_check(
        authorization=authorization,
        endpoint=request.base_url,
        model=request.model,
        api_key=request.api_key,
        pack_summary=pack_summary,
        transport=live_transport,
    )


def load_relay_pack_summary(path: Path | str) -> RelayPackSummary:
    pack_path = Path(path).expanduser()
    basename = basename_only(path)
    if not pack_path.exists():
        raise RelayAuditConfigError(f"Relay pack file not found: {basename}.")
    try:
        raw_text = pack_path.read_text(encoding="utf-8")
        data = yaml.safe_load(raw_text) or {}
    except yaml.YAMLError as exc:
        raise RelayAuditConfigError(f"Relay pack metadata is invalid: {basename}.") from exc
    if not isinstance(data, dict):
        raise RelayAuditConfigError(f"Relay pack metadata must be a mapping: {basename}.")
    pack_id = _optional_scalar(data.get("id"), "id", basename)
    version = _optional_scalar(data.get("version"), "version", basename)
    pack_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()[:16]
    return RelayPackSummary(
        label="Local Private Pack",
        pack_hash=pack_hash,
        pack_id=pack_id,
        version=version,
        basename=basename,
    )


def exit_code_for_relay_verdict(verdict: RelayVerdict) -> int:
    if verdict == RelayVerdict.FAIL:
        return 1
    if verdict == RelayVerdict.INCONCLUSIVE:
        return 3
    return 0


def _optional_scalar(value: Any, field_name: str, basename: str) -> str | None:
    if value is None:
        return None
    if isinstance(value, str | int | float | bool):
        return str(value)
    raise RelayAuditConfigError(f"Relay pack field {field_name} must be a scalar value: {basename}.")
