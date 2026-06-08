from __future__ import annotations

import hashlib
from typing import Any, Protocol

from tokenverify.relay_fingerprint import (
    RelayResponseEnvelope,
    claimed_model_family,
    extract_relay_response_envelope,
    family_from_self_report,
)
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
from tokenverify.relay_safety import RelayLiveAuthorization, hash_relay_endpoint, sanitize_public_relay_text, sanitize_to_fqdn


class RelayIdentityTransport(Protocol):
    def __call__(self, payload: dict[str, Any]) -> RelayLiveTransportResponse:
        ...


def build_identity_payload(model: str) -> dict[str, Any]:
    return {
        "model": sanitize_public_relay_text(model),
        "messages": [{"role": "user", "content": "Return only a brief public model family label."}],
        "max_tokens": 16,
        "stream": False,
    }


def classify_identity_observation(
    *,
    claimed_model: str,
    envelope: RelayResponseEnvelope,
    self_report_text: str | None,
) -> RelayResult:
    claimed_family = claimed_model_family(claimed_model)
    observed_family = envelope.observed_model_family
    self_report_family = family_from_self_report(self_report_text)
    strong_mismatch = (
        observed_family != "unknown"
        and claimed_family != "unknown"
        and observed_family != claimed_family
    )
    cross_provider = (
        envelope.system_fingerprint_observed
        and claimed_family not in {"openai", "unknown"}
    )
    self_report_mismatch = (
        self_report_family != "unknown"
        and claimed_family != "unknown"
        and self_report_family != claimed_family
    )

    evidence = [
        RelayEvidence(
            key="identity_response_envelope",
            category=RelayRiskCategory.MODEL_SUBSTITUTION,
            status="observed",
            summary="Sanitized response envelope metadata was extracted for identity checks.",
            metrics={
                "claimed_model_family": claimed_family,
                "observed_model_family": observed_family,
                "response_shape_family": envelope.response_shape_family,
                "response_id_pattern": envelope.response_id_pattern,
            },
        ),
        RelayEvidence(
            key="identity_model_field_consistency",
            category=RelayRiskCategory.MODEL_SUBSTITUTION,
            status="fail" if strong_mismatch else "pass",
            summary=(
                "Observed model-family metadata contradicts the claimed model family."
                if strong_mismatch
                else "No model-family field contradiction was observed."
            ),
            metrics={
                "claimed_model_family": claimed_family,
                "observed_model_family": observed_family,
                "model_family_contradiction": strong_mismatch,
            },
        ),
        RelayEvidence(
            key="identity_cross_provider_metadata",
            category=RelayRiskCategory.MODEL_SUBSTITUTION,
            status="fail" if cross_provider else "pass",
            summary=(
                "Cross-provider metadata was observed under an incompatible model claim."
                if cross_provider
                else "No incompatible cross-provider metadata was observed."
            ),
            metrics={"cross_provider_metadata_detected": cross_provider},
        ),
    ]
    if self_report_family != "unknown":
        evidence.append(
            RelayEvidence(
                key="identity_self_report_consistency",
                category=RelayRiskCategory.MODEL_SUBSTITUTION,
                status="suspicious" if self_report_mismatch else "pass",
                summary=(
                    "Auxiliary self-identification text conflicts with the claimed family."
                    if self_report_mismatch
                    else "Auxiliary self-identification text does not conflict with the claimed family."
                ),
                metrics={
                    "self_report_family": self_report_family,
                    "self_report_mismatch": self_report_mismatch,
                },
            )
        )
    if self_report_mismatch or strong_mismatch or cross_provider:
        candidate = observed_family if observed_family != "unknown" else self_report_family
        evidence.append(
            RelayEvidence(
                key="identity_candidate_family_scores",
                category=RelayRiskCategory.MODEL_SUBSTITUTION,
                status="suspicious",
                summary="Candidate upstream-family signal was derived from sanitized identity features.",
                metrics={
                    "candidate_family_top": candidate,
                    "candidate_family_confidence": "high" if strong_mismatch or cross_provider else "medium",
                },
            )
        )

    verdict = RelayVerdict.PASS
    risk = RelayRiskLevel.LOW
    if strong_mismatch or cross_provider:
        verdict = RelayVerdict.FAIL
        risk = RelayRiskLevel.HIGH
    elif self_report_mismatch:
        verdict = RelayVerdict.SUSPICIOUS
        risk = RelayRiskLevel.MEDIUM
    return _identity_result(verdict=verdict, risk=risk, model=claimed_model, evidence=evidence)


def run_identity_live_check(
    *,
    authorization: RelayLiveAuthorization,
    endpoint: str,
    model: str,
    api_key: str | None,
    pack_summary: RelayPackSummary,
    claim_channel: str = "unknown",
    transport: RelayIdentityTransport | None,
) -> RelayResult:
    if transport is None:
        return _inconclusive(endpoint, model, pack_summary, "Relay identity live transport is not configured.")
    try:
        response = transport(build_identity_payload(model))
        if response.status_code != 200:
            normalized = normalize_live_runtime_error(RuntimeError(str(response.status_code)))
            return _inconclusive(endpoint, model, pack_summary, normalized.public_message)
        envelope = extract_relay_response_envelope(
            status_code=response.status_code,
            body=response.body,
            headers=response.headers or {},
        )
        content = _first_content(response.body)
        result = classify_identity_observation(claimed_model=model, envelope=envelope, self_report_text=content)
        return _replace_target_fields(result, endpoint, model, pack_summary)
    except BaseException as exc:
        normalized = normalize_live_runtime_error(RuntimeError(sanitize_public_relay_text(str(exc))))
        return _inconclusive(endpoint, model, pack_summary, normalized.public_message)


def _first_content(body: dict[str, Any]) -> str | None:
    choices = body.get("choices") if isinstance(body, dict) else None
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        message = choices[0].get("message")
        if isinstance(message, dict) and isinstance(message.get("content"), str):
            return message["content"]
    return None


def _identity_result(
    *,
    verdict: RelayVerdict,
    risk: RelayRiskLevel,
    model: str,
    evidence: list[RelayEvidence],
) -> RelayResult:
    return RelayResult(
        run_id="relay-identity-" + hashlib.sha256(f"{model}|{verdict.value}".encode()).hexdigest()[:16],
        profile=RelayAuditProfile.IDENTITY,
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
        retest_guidance="Rerun identity checks after relay or model configuration changes.",
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
        run_id="relay-identity-" + hash_relay_endpoint(endpoint + model + "inconclusive"),
        profile=RelayAuditProfile.IDENTITY,
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
                key="identity_envelope_unavailable",
                category=RelayRiskCategory.UPSTREAM_ERROR_LEAKAGE,
                status="inconclusive",
                summary=sanitize_public_relay_text(message),
            )
        ],
        retest_guidance="Resolve identity runtime conditions, then rerun with explicit --live.",
        inconclusive_reason=sanitize_public_relay_text(message),
        runtime_category=RelayRuntimeCategory.UNKNOWN_RUNTIME_ERROR,
    )
