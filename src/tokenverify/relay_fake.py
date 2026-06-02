from __future__ import annotations

import hashlib

from tokenverify.relay_models import (
    RelayAuditMode,
    RelayAuditProfile,
    RelayEvidence,
    RelayPackSummary,
    RelayResult,
    RelayRiskCategory,
    RelayRiskLevel,
    RelayVerdict,
)
from tokenverify.relay_safety import hash_relay_endpoint, sanitize_public_relay_text, sanitize_to_fqdn


def build_fake_relay_result(
    *,
    profile: RelayAuditProfile,
    scenario: RelayVerdict,
    endpoint: str,
    model: str,
    pack_summary: RelayPackSummary,
) -> RelayResult:
    endpoint_host = sanitize_to_fqdn(endpoint)
    endpoint_hash = hash_relay_endpoint(endpoint)
    evidence = list(_scenario_evidence(scenario))
    if profile != RelayAuditProfile.GENERAL:
        evidence.append(
            RelayEvidence(
                key=f"{profile.value}_profile_not_implemented",
                category=_profile_category(profile),
                status="skipped",
                summary=f"The {profile.value} profile is defined but its live checks are not implemented in this milestone.",
                metrics={"profile_contract_defined": True},
            )
        )
    run_id = _run_id(profile, scenario, endpoint_hash, model, pack_summary.pack_hash)
    risk_level = _risk_level_for(scenario)
    risk_categories = sorted({item.category for item in evidence}, key=lambda item: item.value)
    inconclusive_reason = None
    if scenario == RelayVerdict.INCONCLUSIVE:
        inconclusive_reason = (
            "The fake observation set represents an auth or network-style runtime condition, "
            "not a relay misconduct finding."
        )
    return RelayResult(
        run_id=run_id,
        profile=profile,
        scenario=scenario,
        mode=RelayAuditMode.FAKE,
        model=sanitize_public_relay_text(model),
        endpoint_host=endpoint_host,
        endpoint_hash=endpoint_hash,
        pack_summary=pack_summary,
        verdict=scenario,
        risk_level=risk_level,
        risk_categories=risk_categories,
        evidence=evidence,
        retest_guidance=_retest_guidance(scenario),
        inconclusive_reason=inconclusive_reason,
    )


def _scenario_evidence(scenario: RelayVerdict) -> list[RelayEvidence]:
    if scenario == RelayVerdict.PASS:
        return [
            RelayEvidence(
                key="relay_contract_consistency",
                category=RelayRiskCategory.MODEL_SUBSTITUTION,
                status="pass",
                summary="Deterministic fake observation shows stable model identity and compatible response structure.",
                metrics={"model_identity_stable": True, "structure_consistency": 0.98},
            )
        ]
    if scenario == RelayVerdict.SUSPICIOUS:
        return [
            RelayEvidence(
                key="context_retention_signal",
                category=RelayRiskCategory.CONTEXT_TRUNCATION,
                status="warning",
                summary=(
                    "Deterministic fake observation shows a medium context-retention warning "
                    "with sanitized aggregate metrics."
                ),
                metrics={"token_loss_ratio": 0.37, "sample_count": 4},
            )
        ]
    if scenario == RelayVerdict.FAIL:
        return [
            RelayEvidence(
                key="schema_preservation_failure",
                category=RelayRiskCategory.SCHEMA_TOOL_REWRITE,
                status="fail",
                summary="Deterministic fake observation shows required structured fields were rewritten before verification.",
                metrics={"schema_field_preservation": "failed", "required_fields_missing": 2},
            ),
            RelayEvidence(
                key="model_identity_mismatch",
                category=RelayRiskCategory.MODEL_SUBSTITUTION,
                status="fail",
                summary="Deterministic fake observation shows a sanitized model identity mismatch signal.",
                metrics={"identity_match": False},
            ),
        ]
    return [
        RelayEvidence(
            key="runtime_not_conclusive",
            category=RelayRiskCategory.UPSTREAM_ERROR_LEAKAGE,
            status="inconclusive",
            summary=(
                "Deterministic fake observation represents an authentication, quota, timeout, "
                "or network-style condition before a relay judgment could be made."
            ),
            metrics={"runtime_condition": "sanitized_unavailable"},
        )
    ]


def _risk_level_for(scenario: RelayVerdict) -> RelayRiskLevel:
    return {
        RelayVerdict.PASS: RelayRiskLevel.LOW,
        RelayVerdict.SUSPICIOUS: RelayRiskLevel.MEDIUM,
        RelayVerdict.FAIL: RelayRiskLevel.HIGH,
        RelayVerdict.INCONCLUSIVE: RelayRiskLevel.UNKNOWN,
    }[scenario]


def _profile_category(profile: RelayAuditProfile) -> RelayRiskCategory:
    return {
        RelayAuditProfile.STREAMING: RelayRiskCategory.STREAMING_INTEGRITY,
        RelayAuditProfile.SCHEMA: RelayRiskCategory.SCHEMA_TOOL_REWRITE,
        RelayAuditProfile.PRIVACY: RelayRiskCategory.PROMPT_INSTRUCTION_LEAKAGE,
        RelayAuditProfile.FULL: RelayRiskCategory.LATENCY_OR_INSTABILITY,
        RelayAuditProfile.GENERAL: RelayRiskCategory.MODEL_SUBSTITUTION,
    }[profile]


def _retest_guidance(scenario: RelayVerdict) -> str:
    if scenario == RelayVerdict.FAIL:
        return "Retest with an approved live plan before making operational decisions."
    if scenario == RelayVerdict.INCONCLUSIVE:
        return "Resolve auth, quota, timeout, or network conditions, then rerun the audit."
    return "Repeat with live mode only after an approved live-probe milestone."


def _run_id(
    profile: RelayAuditProfile,
    scenario: RelayVerdict,
    endpoint_hash: str,
    model: str,
    pack_hash: str | None,
) -> str:
    material = "|".join([profile.value, scenario.value, endpoint_hash, model, pack_hash or "no-pack"])
    return "relay-fake-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]
