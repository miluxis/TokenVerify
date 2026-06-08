from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from tokenverify.relay_context import RelayContextTransport, run_minimal_context_live_check
from tokenverify.relay_channel import RelayChannelTransport, run_channel_live_check
from tokenverify.relay_fake import build_fake_relay_result
from tokenverify.relay_full import run_full_live_check
from tokenverify.relay_identity import RelayIdentityTransport, run_identity_live_check
from tokenverify.relay_live import RelayLiveTransport, run_minimal_general_live_check
from tokenverify.relay_models import (
    RelayAuditConfigError,
    RelayChannelClaim,
    RelayAuditProfile,
    RelayPackSummary,
    RelayResult,
    RelayVerdict,
)
from tokenverify.relay_pack import load_relay_pack_summary
from tokenverify.relay_privacy import RelayPrivacyTransport, run_minimal_privacy_live_check
from tokenverify.relay_reasoning import RelayReasoningTransport, run_reasoning_live_check
from tokenverify.relay_safety import authorize_relay_live_execution
from tokenverify.relay_schema import RelaySchemaTransport, run_minimal_schema_live_check
from tokenverify.relay_security import RelaySecurityTransport, run_minimal_security_live_check
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
    drift_check: bool = False
    claim_channel: RelayChannelClaim = RelayChannelClaim.UNKNOWN
    live_transport_factory: Callable[[], RelayLiveTransport | None] | None = None
    identity_transport_factory: Callable[[], RelayIdentityTransport | None] | None = None
    channel_transport_factory: Callable[[], RelayChannelTransport | None] | None = None
    reasoning_transport_factory: Callable[[], RelayReasoningTransport | None] | None = None
    stream_transport_factory: Callable[[], RelayStreamingTransport | None] | None = None
    schema_transport_factory: Callable[[], RelaySchemaTransport | None] | None = None
    privacy_transport_factory: Callable[[], RelayPrivacyTransport | None] | None = None
    security_transport_factory: Callable[[], RelaySecurityTransport | None] | None = None
    context_transport_factory: Callable[[], RelayContextTransport | None] | None = None


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
            drift_check=request.drift_check,
            claim_channel=request.claim_channel.value,
        )
    authorization = authorize_relay_live_execution(live_mode=request.live, profile=request.profile)
    if request.profile == RelayAuditProfile.FULL:
        def run_subprofile(profile: RelayAuditProfile) -> RelayResult:
            sub_authorization = authorize_relay_live_execution(live_mode=request.live, profile=profile)
            if profile == RelayAuditProfile.GENERAL:
                live_transport = request.live_transport_factory() if request.live_transport_factory else None
                return run_minimal_general_live_check(
                    authorization=sub_authorization,
                    endpoint=request.base_url,
                    model=request.model,
                    api_key=request.api_key,
                    pack_summary=pack_summary,
                    transport=live_transport,
                )
            if profile == RelayAuditProfile.IDENTITY:
                identity_transport = (
                    request.identity_transport_factory()
                    if request.identity_transport_factory
                    else request.live_transport_factory() if request.live_transport_factory else None
                )
                return run_identity_live_check(
                    authorization=sub_authorization,
                    endpoint=request.base_url,
                    model=request.model,
                    api_key=request.api_key,
                    pack_summary=pack_summary,
                    claim_channel=request.claim_channel.value,
                    transport=identity_transport,
                )
            if profile == RelayAuditProfile.CHANNEL:
                channel_transport = (
                    request.channel_transport_factory()
                    if request.channel_transport_factory
                    else request.live_transport_factory() if request.live_transport_factory else None
                )
                return run_channel_live_check(
                    authorization=sub_authorization,
                    endpoint=request.base_url,
                    model=request.model,
                    api_key=request.api_key,
                    pack_summary=pack_summary,
                    claim_channel=request.claim_channel,
                    transport=channel_transport,
                )
            if profile == RelayAuditProfile.REASONING:
                reasoning_transport = (
                    request.reasoning_transport_factory()
                    if request.reasoning_transport_factory
                    else request.live_transport_factory() if request.live_transport_factory else None
                )
                return run_reasoning_live_check(
                    authorization=sub_authorization,
                    endpoint=request.base_url,
                    model=request.model,
                    api_key=request.api_key,
                    pack_summary=pack_summary,
                    transport=reasoning_transport,
                )
            if profile == RelayAuditProfile.STREAMING:
                stream_transport = request.stream_transport_factory() if request.stream_transport_factory else None
                return run_minimal_streaming_live_check(
                    authorization=sub_authorization,
                    endpoint=request.base_url,
                    model=request.model,
                    api_key=request.api_key,
                    pack_summary=pack_summary,
                    transport=stream_transport,
                )
            if profile == RelayAuditProfile.SCHEMA:
                schema_transport = request.schema_transport_factory() if request.schema_transport_factory else None
                return run_minimal_schema_live_check(
                    authorization=sub_authorization,
                    endpoint=request.base_url,
                    model=request.model,
                    api_key=request.api_key,
                    pack_summary=pack_summary,
                    transport=schema_transport,
                )
            if profile == RelayAuditProfile.PRIVACY:
                privacy_transport = request.privacy_transport_factory() if request.privacy_transport_factory else None
                return run_minimal_privacy_live_check(
                    authorization=sub_authorization,
                    endpoint=request.base_url,
                    model=request.model,
                    api_key=request.api_key,
                    pack_summary=pack_summary,
                    transport=privacy_transport,
                )
            if profile == RelayAuditProfile.SECURITY:
                security_transport = request.security_transport_factory() if request.security_transport_factory else None
                return run_minimal_security_live_check(
                    authorization=sub_authorization,
                    endpoint=request.base_url,
                    model=request.model,
                    api_key=request.api_key,
                    pack_summary=pack_summary,
                    transport=security_transport,
                )
            if profile == RelayAuditProfile.CONTEXT:
                context_transport = request.context_transport_factory() if request.context_transport_factory else None
                return run_minimal_context_live_check(
                    authorization=sub_authorization,
                    endpoint=request.base_url,
                    model=request.model,
                    api_key=request.api_key,
                    pack_summary=pack_summary,
                    transport=context_transport,
                )
            raise RelayAuditConfigError("Unsupported full-profile subprofile.")

        drift_samples: list[RelayResult] = []
        if request.drift_check:
            for _ in range(8):
                sub_authorization = authorize_relay_live_execution(live_mode=request.live, profile=RelayAuditProfile.GENERAL)
                live_transport = request.live_transport_factory() if request.live_transport_factory else None
                drift_samples.append(
                    run_minimal_general_live_check(
                        authorization=sub_authorization,
                        endpoint=request.base_url,
                        model=request.model,
                        api_key=request.api_key,
                        pack_summary=pack_summary,
                        transport=live_transport,
                    )
                )
        return run_full_live_check(
            authorization=authorization,
            endpoint=request.base_url,
            model=request.model,
            pack_summary=pack_summary,
            subprofile_runner=run_subprofile,
            drift_check=request.drift_check,
            drift_samples=drift_samples,
        )
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
    if request.profile == RelayAuditProfile.IDENTITY:
        identity_transport = request.identity_transport_factory() if request.identity_transport_factory else None
        return run_identity_live_check(
            authorization=authorization,
            endpoint=request.base_url,
            model=request.model,
            api_key=request.api_key,
            pack_summary=pack_summary,
            claim_channel=request.claim_channel.value,
            transport=identity_transport,
        )
    if request.profile == RelayAuditProfile.CHANNEL:
        channel_transport = request.channel_transport_factory() if request.channel_transport_factory else None
        return run_channel_live_check(
            authorization=authorization,
            endpoint=request.base_url,
            model=request.model,
            api_key=request.api_key,
            pack_summary=pack_summary,
            claim_channel=request.claim_channel,
            transport=channel_transport,
        )
    if request.profile == RelayAuditProfile.REASONING:
        reasoning_transport = request.reasoning_transport_factory() if request.reasoning_transport_factory else None
        return run_reasoning_live_check(
            authorization=authorization,
            endpoint=request.base_url,
            model=request.model,
            api_key=request.api_key,
            pack_summary=pack_summary,
            transport=reasoning_transport,
        )
    if request.profile == RelayAuditProfile.SCHEMA:
        schema_transport = request.schema_transport_factory() if request.schema_transport_factory else None
        return run_minimal_schema_live_check(
            authorization=authorization,
            endpoint=request.base_url,
            model=request.model,
            api_key=request.api_key,
            pack_summary=pack_summary,
            transport=schema_transport,
        )
    if request.profile == RelayAuditProfile.PRIVACY:
        privacy_transport = request.privacy_transport_factory() if request.privacy_transport_factory else None
        return run_minimal_privacy_live_check(
            authorization=authorization,
            endpoint=request.base_url,
            model=request.model,
            api_key=request.api_key,
            pack_summary=pack_summary,
            transport=privacy_transport,
        )
    if request.profile == RelayAuditProfile.SECURITY:
        security_transport = request.security_transport_factory() if request.security_transport_factory else None
        return run_minimal_security_live_check(
            authorization=authorization,
            endpoint=request.base_url,
            model=request.model,
            api_key=request.api_key,
            pack_summary=pack_summary,
            transport=security_transport,
        )
    if request.profile == RelayAuditProfile.CONTEXT:
        context_transport = request.context_transport_factory() if request.context_transport_factory else None
        return run_minimal_context_live_check(
            authorization=authorization,
            endpoint=request.base_url,
            model=request.model,
            api_key=request.api_key,
            pack_summary=pack_summary,
            transport=context_transport,
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
