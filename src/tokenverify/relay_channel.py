from __future__ import annotations

import hashlib
from typing import Any, Protocol

from tokenverify.relay_fingerprint import RelayResponseEnvelope, extract_relay_response_envelope
from tokenverify.relay_live import RelayLiveTransportResponse, normalize_live_runtime_error
from tokenverify.relay_models import (
    RelayAuditMode,
    RelayAuditProfile,
    RelayChannelClaim,
    RelayEvidence,
    RelayPackSummary,
    RelayResult,
    RelayRiskCategory,
    RelayRiskLevel,
    RelayRuntimeCategory,
    RelayVerdict,
)
from tokenverify.relay_safety import hash_relay_endpoint, sanitize_public_relay_text, sanitize_to_fqdn


class RelayChannelTransport(Protocol):
    def __call__(self, payload: dict[str, Any]) -> RelayLiveTransportResponse:
        ...


def build_channel_payload(model: str) -> dict[str, Any]:
    return {
        "model": sanitize_public_relay_text(model),
        "messages": [{"role": "user", "content": "Return only: ok"}],
        "max_tokens": 8,
        "stream": False,
    }


def classify_channel_observation(*, claim: RelayChannelClaim, envelope: RelayResponseEnvelope) -> RelayResult:
    marker = envelope.provider_marker_family
    marker_detected = bool(marker)
    compatible = _claim_matches_marker(claim, marker)
    official_contradicted = claim == RelayChannelClaim.OFFICIAL and marker_detected and marker not in {"official"}
    suspicious_unknown = claim == RelayChannelClaim.UNKNOWN and marker_detected

    evidence = [
        RelayEvidence(
            key="channel_response_markers",
            category=RelayRiskCategory.INFRASTRUCTURE_FINGERPRINT,
            status="observed" if marker_detected else "pass",
            summary="Sanitized channel marker extraction completed.",
            metrics={
                "provider_marker_detected": marker_detected,
                "provider_marker_family": marker,
                "response_id_pattern": envelope.response_id_pattern,
            },
        ),
        RelayEvidence(
            key="channel_header_marker_family",
            category=RelayRiskCategory.INFRASTRUCTURE_FINGERPRINT,
            status="observed" if envelope.header_marker_families else "pass",
            summary="Header marker families were reduced to public labels.",
            metrics={"header_marker_families": list(envelope.header_marker_families)},
        ),
        RelayEvidence(
            key="channel_claim_consistency",
            category=RelayRiskCategory.INFRASTRUCTURE_FINGERPRINT,
            status="fail" if official_contradicted else "pass" if compatible or not suspicious_unknown else "suspicious",
            summary=_claim_summary(claim, marker, official_contradicted, compatible, suspicious_unknown),
            metrics={
                "claim_channel": claim.value,
                "observed_channel_family": marker,
                "official_claim_contradicted": official_contradicted,
                "compatible_gateway_claim": compatible,
            },
        ),
        RelayEvidence(
            key="channel_infrastructure_fingerprint",
            category=RelayRiskCategory.INFRASTRUCTURE_FINGERPRINT,
            status="observed" if marker_detected else "pass",
            summary="Infrastructure fingerprint was rendered as sanitized marker-family evidence.",
            metrics={"provider_marker_family": marker},
        ),
    ]

    verdict = RelayVerdict.PASS
    risk = RelayRiskLevel.LOW
    if official_contradicted:
        verdict = RelayVerdict.FAIL
        risk = RelayRiskLevel.HIGH
    elif suspicious_unknown or (marker_detected and not compatible and claim != RelayChannelClaim.UNKNOWN):
        verdict = RelayVerdict.SUSPICIOUS
        risk = RelayRiskLevel.MEDIUM
    return _channel_result(verdict=verdict, risk=risk, evidence=evidence)


def run_channel_live_check(
    *,
    authorization,
    endpoint: str,
    model: str,
    api_key: str | None,
    pack_summary: RelayPackSummary,
    claim_channel: RelayChannelClaim,
    transport: RelayChannelTransport | None,
) -> RelayResult:
    if transport is None:
        return _inconclusive(endpoint, model, pack_summary, "Relay channel live transport is not configured.")
    try:
        response = transport(build_channel_payload(model))
        if response.status_code != 200:
            normalized = normalize_live_runtime_error(RuntimeError(str(response.status_code)))
            return _inconclusive(endpoint, model, pack_summary, normalized.public_message)
        envelope = extract_relay_response_envelope(
            status_code=response.status_code,
            body=response.body,
            headers=response.headers or {},
        )
        result = classify_channel_observation(claim=claim_channel, envelope=envelope)
        return _replace_target_fields(result, endpoint, model, pack_summary)
    except BaseException as exc:
        normalized = normalize_live_runtime_error(RuntimeError(sanitize_public_relay_text(str(exc))))
        return _inconclusive(endpoint, model, pack_summary, normalized.public_message)


def _claim_matches_marker(claim: RelayChannelClaim, marker: str | None) -> bool:
    if marker is None:
        return False
    if claim == RelayChannelClaim.BEDROCK and marker == "bedrock":
        return True
    if claim == RelayChannelClaim.AZURE and marker == "azure":
        return True
    if claim == RelayChannelClaim.OPENROUTER and marker == "openrouter":
        return True
    if claim == RelayChannelClaim.PROXY and marker in {"proxy", "nginx", "cloudflare", "oneapi", "newapi"}:
        return True
    return False


def _claim_summary(
    claim: RelayChannelClaim,
    marker: str | None,
    official_contradicted: bool,
    compatible: bool,
    suspicious_unknown: bool,
) -> str:
    if official_contradicted:
        return "Official channel claim is contradicted by a sanitized non-official marker."
    if compatible:
        return "Observed channel marker is compatible with the user's channel claim."
    if suspicious_unknown:
        return "Channel marker was observed without a compatible explicit channel claim."
    return "No channel-claim contradiction was observed."


def _channel_result(*, verdict: RelayVerdict, risk: RelayRiskLevel, evidence: list[RelayEvidence]) -> RelayResult:
    return RelayResult(
        run_id="relay-channel-" + hashlib.sha256(verdict.value.encode()).hexdigest()[:16],
        profile=RelayAuditProfile.CHANNEL,
        scenario=verdict,
        mode=RelayAuditMode.LIVE,
        model="example-model",
        endpoint_host="relay.example",
        endpoint_hash="0000000000000000",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=verdict,
        risk_level=risk,
        risk_categories=[RelayRiskCategory.INFRASTRUCTURE_FINGERPRINT],
        evidence=evidence,
        retest_guidance="Rerun channel checks after relay route or channel-claim changes.",
    )


def _replace_target_fields(result: RelayResult, endpoint: str, model: str, pack_summary: RelayPackSummary) -> RelayResult:
    return RelayResult(
        run_id=result.run_id,
        profile=result.profile,
        scenario=result.scenario,
        mode=result.mode,
        model=sanitize_public_relay_text(model),
        endpoint_host=sanitize_to_fqdn(endpoint),
        endpoint_hash=hash_relay_endpoint(endpoint),
        pack_summary=pack_summary,
        verdict=result.verdict,
        risk_level=result.risk_level,
        risk_categories=result.risk_categories,
        evidence=result.evidence,
        retest_guidance=result.retest_guidance,
        inconclusive_reason=result.inconclusive_reason,
        runtime_category=result.runtime_category,
    )


def _inconclusive(endpoint: str, model: str, pack_summary: RelayPackSummary, message: str) -> RelayResult:
    return RelayResult(
        run_id="relay-channel-" + hash_relay_endpoint(endpoint + model + "inconclusive"),
        profile=RelayAuditProfile.CHANNEL,
        scenario=RelayVerdict.INCONCLUSIVE,
        mode=RelayAuditMode.LIVE,
        model=sanitize_public_relay_text(model),
        endpoint_host=sanitize_to_fqdn(endpoint),
        endpoint_hash=hash_relay_endpoint(endpoint),
        pack_summary=pack_summary,
        verdict=RelayVerdict.INCONCLUSIVE,
        risk_level=RelayRiskLevel.UNKNOWN,
        risk_categories=[RelayRiskCategory.UPSTREAM_ERROR_LEAKAGE],
        evidence=[
            RelayEvidence(
                key="channel_envelope_unavailable",
                category=RelayRiskCategory.UPSTREAM_ERROR_LEAKAGE,
                status="inconclusive",
                summary=sanitize_public_relay_text(message),
            )
        ],
        retest_guidance="Resolve channel runtime conditions, then rerun with explicit --live.",
        inconclusive_reason=sanitize_public_relay_text(message),
        runtime_category=RelayRuntimeCategory.UNKNOWN_RUNTIME_ERROR,
    )
