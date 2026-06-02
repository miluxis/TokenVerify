from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from tokenverify.relay_fake import build_fake_relay_result
from tokenverify.relay_live import RelayLiveTransport, run_minimal_general_live_check
from tokenverify.relay_models import (
    RelayAuditConfigError,
    RelayAuditProfile,
    RelayPackSummary,
    RelayResult,
    RelayVerdict,
)
from tokenverify.relay_pack import load_relay_pack_summary
from tokenverify.relay_safety import authorize_relay_live_execution
from tokenverify.relay_streaming import RelayStreamingTransport, run_minimal_streaming_live_check


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
    stream_transport_factory: Callable[[], RelayStreamingTransport | None] | None = None


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
    if request.profile == RelayAuditProfile.STREAMING:
        stream_transport = request.stream_transport_factory() if request.stream_transport_factory else None
        return run_minimal_streaming_live_check(
            authorization=authorization,
            endpoint=request.base_url,
            model=request.model,
            api_key=request.api_key,
            pack_summary=pack_summary,
            transport=stream_transport,
        )
    live_transport = request.live_transport_factory() if request.live_transport_factory else None
    return run_minimal_general_live_check(
        authorization=authorization,
        endpoint=request.base_url,
        model=request.model,
        api_key=request.api_key,
        pack_summary=pack_summary,
        transport=live_transport,
    )


def exit_code_for_relay_verdict(verdict: RelayVerdict) -> int:
    if verdict == RelayVerdict.FAIL:
        return 1
    if verdict == RelayVerdict.INCONCLUSIVE:
        return 3
    return 0
