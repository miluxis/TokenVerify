from __future__ import annotations

import hashlib
import re
from typing import Any, Protocol

from tokenverify.relay_fingerprint import RelayResponseEnvelope, claimed_model_family, extract_relay_response_envelope
from tokenverify.relay_live import RelayLiveTransportResponse, normalize_live_runtime_error
from tokenverify.relay_models import (
    RelayAuditMode,
    RelayAuditProfile,
    RelayEvidence,
    RelayPackSummary,
    RelayResult,
    RelayRiskCategory,
    RelayRiskLevel,
    RelayRuntimeCategory,
    RelayVerdict,
)
from tokenverify.relay_safety import hash_relay_endpoint, sanitize_public_relay_text, sanitize_to_fqdn


class RelayReasoningTransport(Protocol):
    def __call__(self, payload: dict[str, Any]) -> RelayLiveTransportResponse:
        ...


def build_reasoning_payload(model: str) -> dict[str, Any]:
    return {
        "model": sanitize_public_relay_text(model),
        "messages": [{"role": "user", "content": "Solve 17 + 28. Return only the final number."}],
        "max_tokens": 48,
        "stream": False,
    }


def claimed_reasoning_family(model: str) -> str:
    text = model.strip().lower()
    if "deepseek" in text and (re.search(r"\br\d+\b", text) or "reasoner" in text or "reasoning" in text):
        return "deepseek_reasoning"
    if re.search(r"(?:^|[-_/])o\d+(?:$|[-_/])", text) or ("reasoning" in text and "openai" in text):
        return "openai_reasoning"
    if "claude" in text and any(marker in text for marker in ("thinking", "reasoning")):
        return "claude_reasoning"
    if claimed_model_family(model) == "unknown":
        return "unknown"
    return "generic"


def classify_reasoning_observation(
    *,
    claimed_model: str,
    envelope: RelayResponseEnvelope,
    content_text: str | None,
) -> RelayResult:
    family = claimed_reasoning_family(claimed_model)
    fake_thinking = _fake_thinking_observed(content_text)
    native_observed = _native_reasoning_observed(envelope)
    required_missing = _required_signal_missing(family, envelope)
    cross_provider = _cross_provider_reasoning_metadata(family, envelope)

    evidence = [
        RelayEvidence(
            key="reasoning_family_expectation",
            category=RelayRiskCategory.MODEL_SUBSTITUTION,
            status="observed",
            summary="Claimed model was mapped to a public reasoning-family expectation.",
            metrics={"claimed_reasoning_family": family},
        ),
        RelayEvidence(
            key="reasoning_native_signal",
            category=RelayRiskCategory.MODEL_SUBSTITUTION,
            status="fail" if required_missing else "pass",
            summary=(
                "Required native reasoning signal was not observed."
                if required_missing
                else "Native reasoning signal check did not find a contradiction."
            ),
            metrics={
                "expected_reasoning_family": family,
                "native_reasoning_field_observed": native_observed,
                "reasoning_content_observed": envelope.reasoning_content_observed,
                "thinking_block_observed": envelope.thinking_block_observed,
            },
        ),
        RelayEvidence(
            key="reasoning_usage_signal",
            category=RelayRiskCategory.MODEL_SUBSTITUTION,
            status="pass" if envelope.reasoning_usage_observed or family != "openai_reasoning" else "fail",
            summary="Reasoning usage metadata was checked using public-safe booleans.",
            metrics={"reasoning_usage_observed": envelope.reasoning_usage_observed},
        ),
        RelayEvidence(
            key="reasoning_cross_provider_signal",
            category=RelayRiskCategory.MODEL_SUBSTITUTION,
            status="fail" if cross_provider else "pass",
            summary=(
                "Cross-provider reasoning metadata was observed under an incompatible claim."
                if cross_provider
                else "No incompatible cross-provider reasoning metadata was observed."
            ),
            metrics={"cross_provider_reasoning_metadata_detected": cross_provider},
        ),
        RelayEvidence(
            key="reasoning_fake_thinking_signal",
            category=RelayRiskCategory.MODEL_SUBSTITUTION,
            status="suspicious" if fake_thinking else "pass",
            summary=(
                "Fake-thinking text marker was observed in ordinary content."
                if fake_thinking
                else "No fake-thinking ordinary-content marker was observed."
            ),
            metrics={"fake_thinking_text_observed": fake_thinking},
        ),
    ]

    verdict = RelayVerdict.PASS
    risk = RelayRiskLevel.LOW
    if required_missing or cross_provider:
        verdict = RelayVerdict.FAIL
        risk = RelayRiskLevel.HIGH
    elif fake_thinking:
        verdict = RelayVerdict.SUSPICIOUS
        risk = RelayRiskLevel.MEDIUM
    return _reasoning_result(verdict=verdict, risk=risk, model=claimed_model, evidence=evidence)


def run_reasoning_live_check(
    *,
    authorization,
    endpoint: str,
    model: str,
    api_key: str | None,
    pack_summary: RelayPackSummary,
    transport: RelayReasoningTransport | None,
) -> RelayResult:
    if transport is None:
        return _inconclusive(endpoint, model, pack_summary, "Relay reasoning live transport is not configured.")
    try:
        response = transport(build_reasoning_payload(model))
        if response.status_code != 200:
            normalized = normalize_live_runtime_error(RuntimeError(str(response.status_code)))
            return _inconclusive(endpoint, model, pack_summary, normalized.public_message)
        envelope = extract_relay_response_envelope(
            status_code=response.status_code,
            body=response.body,
            headers=response.headers or {},
        )
        result = classify_reasoning_observation(
            claimed_model=model,
            envelope=envelope,
            content_text=_first_content(response.body),
        )
        return _replace_target_fields(result, endpoint, model, pack_summary)
    except BaseException as exc:
        normalized = normalize_live_runtime_error(RuntimeError(sanitize_public_relay_text(str(exc))))
        return _inconclusive(endpoint, model, pack_summary, normalized.public_message)


def _native_reasoning_observed(envelope: RelayResponseEnvelope) -> bool:
    return envelope.reasoning_content_observed or envelope.thinking_block_observed or envelope.reasoning_usage_observed


def _required_signal_missing(family: str, envelope: RelayResponseEnvelope) -> bool:
    if family == "deepseek_reasoning":
        return not envelope.reasoning_content_observed
    if family == "openai_reasoning":
        return not envelope.reasoning_usage_observed
    if family == "claude_reasoning":
        return not envelope.thinking_block_observed and not envelope.reasoning_usage_observed
    return False


def _cross_provider_reasoning_metadata(family: str, envelope: RelayResponseEnvelope) -> bool:
    if family != "deepseek_reasoning" and envelope.reasoning_content_observed:
        return True
    if family != "openai_reasoning" and envelope.reasoning_usage_observed and family != "claude_reasoning":
        return True
    return False


def _fake_thinking_observed(value: str | None) -> bool:
    text = sanitize_public_relay_text(value or "").lower()
    return bool(re.search(r"<\s*think\s*>|thinking process:|\[thinking\]", text, flags=re.IGNORECASE))


def _first_content(body: dict[str, Any]) -> str | None:
    choices = body.get("choices") if isinstance(body, dict) else None
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        message = choices[0].get("message")
        if isinstance(message, dict) and isinstance(message.get("content"), str):
            return message["content"]
    return None


def _reasoning_result(
    *,
    verdict: RelayVerdict,
    risk: RelayRiskLevel,
    model: str,
    evidence: list[RelayEvidence],
) -> RelayResult:
    return RelayResult(
        run_id="relay-reasoning-" + hashlib.sha256(f"{model}|{verdict.value}".encode()).hexdigest()[:16],
        profile=RelayAuditProfile.REASONING,
        scenario=verdict,
        mode=RelayAuditMode.LIVE,
        model=sanitize_public_relay_text(model),
        endpoint_host="relay.example",
        endpoint_hash="0000000000000000",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=verdict,
        risk_level=risk,
        risk_categories=[RelayRiskCategory.MODEL_SUBSTITUTION],
        evidence=evidence,
        retest_guidance="Rerun reasoning checks after model or relay configuration changes.",
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
        run_id="relay-reasoning-" + hash_relay_endpoint(endpoint + model + "inconclusive"),
        profile=RelayAuditProfile.REASONING,
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
                key="reasoning_envelope_unavailable",
                category=RelayRiskCategory.UPSTREAM_ERROR_LEAKAGE,
                status="inconclusive",
                summary=sanitize_public_relay_text(message),
            )
        ],
        retest_guidance="Resolve reasoning runtime conditions, then rerun with explicit --live.",
        inconclusive_reason=sanitize_public_relay_text(message),
        runtime_category=RelayRuntimeCategory.UNKNOWN_RUNTIME_ERROR,
    )
