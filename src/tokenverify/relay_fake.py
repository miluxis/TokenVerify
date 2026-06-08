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
    RelayRuntimeCategory,
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
    drift_check: bool = False,
    claim_channel: str = "unknown",
) -> RelayResult:
    endpoint_host = sanitize_to_fqdn(endpoint)
    endpoint_hash = hash_relay_endpoint(endpoint)
    if profile == RelayAuditProfile.FULL:
        return _build_full_fake_result(
            scenario=scenario,
            endpoint_host=endpoint_host,
            endpoint_hash=endpoint_hash,
            model=model,
            pack_summary=pack_summary,
            drift_check=drift_check,
            claim_channel=claim_channel,
        )
    if profile in {RelayAuditProfile.IDENTITY, RelayAuditProfile.CHANNEL, RelayAuditProfile.REASONING}:
        return _build_fingerprint_fake_result(
            scenario=scenario,
            profile=profile,
            endpoint_host=endpoint_host,
            endpoint_hash=endpoint_hash,
            model=model,
            pack_summary=pack_summary,
            claim_channel=claim_channel,
        )
    if profile == RelayAuditProfile.SECURITY:
        return _build_security_fake_result(
            scenario=scenario,
            endpoint_host=endpoint_host,
            endpoint_hash=endpoint_hash,
            model=model,
            pack_summary=pack_summary,
        )
    if profile == RelayAuditProfile.CONTEXT:
        return _build_context_fake_result(
            scenario=scenario,
            endpoint_host=endpoint_host,
            endpoint_hash=endpoint_hash,
            model=model,
            pack_summary=pack_summary,
        )
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


def _build_full_fake_result(
    *,
    scenario: RelayVerdict,
    endpoint_host: str,
    endpoint_hash: str,
    model: str,
    pack_summary: RelayPackSummary,
    drift_check: bool,
    claim_channel: str,
) -> RelayResult:
    evidence = _full_fake_evidence(scenario, model, drift_check=drift_check, claim_channel=claim_channel)
    risk_categories = sorted({item.category for item in evidence}, key=lambda item: item.value)
    inconclusive_reason = None
    runtime_category = None
    if scenario == RelayVerdict.INCONCLUSIVE:
        runtime_category = RelayRuntimeCategory.TIMEOUT
        inconclusive_reason = "The fake full-profile scenario represents a sanitized runtime interruption."
    return RelayResult(
        run_id=_run_id(RelayAuditProfile.FULL, scenario, endpoint_hash, model, pack_summary.pack_hash),
        profile=RelayAuditProfile.FULL,
        scenario=scenario,
        mode=RelayAuditMode.FAKE,
        model=sanitize_public_relay_text(model),
        endpoint_host=endpoint_host,
        endpoint_hash=endpoint_hash,
        pack_summary=pack_summary,
        verdict=scenario,
        risk_level=_risk_level_for(scenario),
        risk_categories=risk_categories,
        evidence=evidence,
        retest_guidance="Use live mode for bounded full-profile relay evidence.",
        inconclusive_reason=inconclusive_reason,
        runtime_category=runtime_category,
    )


def _build_fingerprint_fake_result(
    *,
    scenario: RelayVerdict,
    profile: RelayAuditProfile,
    endpoint_host: str,
    endpoint_hash: str,
    model: str,
    pack_summary: RelayPackSummary,
    claim_channel: str,
) -> RelayResult:
    evidence = _fingerprint_fake_evidence(profile, scenario, model=model, claim_channel=claim_channel)
    risk_categories = sorted({item.category for item in evidence}, key=lambda item: item.value)
    inconclusive_reason = None
    runtime_category = None
    if scenario == RelayVerdict.INCONCLUSIVE:
        runtime_category = RelayRuntimeCategory.TIMEOUT
        inconclusive_reason = f"The fake {profile.value} fingerprint scenario represents a sanitized runtime interruption."
    return RelayResult(
        run_id=_run_id(profile, scenario, endpoint_hash, model, pack_summary.pack_hash),
        profile=profile,
        scenario=scenario,
        mode=RelayAuditMode.FAKE,
        model=sanitize_public_relay_text(model),
        endpoint_host=endpoint_host,
        endpoint_hash=endpoint_hash,
        pack_summary=pack_summary,
        verdict=scenario,
        risk_level=_risk_level_for(scenario),
        risk_categories=risk_categories,
        evidence=evidence,
        retest_guidance=f"Use live {profile.value} profile only when you intentionally want bounded fingerprint evidence.",
        inconclusive_reason=inconclusive_reason,
        runtime_category=runtime_category,
    )


def _fingerprint_fake_evidence(
    profile: RelayAuditProfile,
    scenario: RelayVerdict,
    *,
    model: str,
    claim_channel: str,
) -> list[RelayEvidence]:
    if profile == RelayAuditProfile.IDENTITY:
        return _identity_fake_evidence(scenario, model)
    if profile == RelayAuditProfile.CHANNEL:
        return _channel_fake_evidence(scenario, claim_channel)
    return _reasoning_fake_evidence(scenario)


def _identity_fake_evidence(scenario: RelayVerdict, model: str) -> list[RelayEvidence]:
    safe_model = sanitize_public_relay_text(model)
    if scenario == RelayVerdict.PASS:
        return [
            RelayEvidence(
                key="identity_response_envelope",
                category=RelayRiskCategory.MODEL_SUBSTITUTION,
                status="pass",
                summary="The fake identity fingerprint observed a compatible sanitized response envelope.",
                metrics={
                    "claimed_model_family": "claude" if "claude" in safe_model.lower() else "unknown",
                    "observed_model_family": "claude" if "claude" in safe_model.lower() else "unknown",
                    "response_id_pattern": "msg_...",
                },
            )
        ]
    if scenario == RelayVerdict.FAIL:
        return [
            RelayEvidence(
                key="identity_model_field_consistency",
                category=RelayRiskCategory.MODEL_SUBSTITUTION,
                status="fail",
                summary="The fake identity fingerprint observed a model-family contradiction.",
                metrics={
                    "claimed_model_family": "claude",
                    "observed_model_family": "qwen",
                    "model_family_contradiction": True,
                },
            )
        ]
    if scenario == RelayVerdict.INCONCLUSIVE:
        return [
            RelayEvidence(
                key="identity_runtime_inconclusive",
                category=RelayRiskCategory.UPSTREAM_ERROR_LEAKAGE,
                status="inconclusive",
                summary="The fake identity fingerprint simulates a sanitized runtime interruption.",
                metrics={"runtime_category": RelayRuntimeCategory.TIMEOUT.value},
            )
        ]
    return [
        RelayEvidence(
            key="identity_candidate_family_scores",
            category=RelayRiskCategory.MODEL_SUBSTITUTION,
            status="suspicious",
            summary="The fake identity fingerprint observed a candidate upstream-family signal.",
            metrics={"top_candidate": "qwen", "confidence": "medium"},
        )
    ]


def _channel_fake_evidence(scenario: RelayVerdict, claim_channel: str) -> list[RelayEvidence]:
    safe_claim = sanitize_public_relay_text(claim_channel)
    if scenario == RelayVerdict.PASS:
        return [
            RelayEvidence(
                key="channel_claim_consistency",
                category=RelayRiskCategory.INFRASTRUCTURE_FINGERPRINT,
                status="pass",
                summary="The fake channel fingerprint observed no channel-claim contradiction.",
                metrics={
                    "claim_channel": safe_claim,
                    "observed_channel_family": None,
                    "official_claim_contradicted": False,
                },
            )
        ]
    if scenario == RelayVerdict.FAIL:
        return [
            RelayEvidence(
                key="channel_claim_consistency",
                category=RelayRiskCategory.INFRASTRUCTURE_FINGERPRINT,
                status="fail",
                summary="The fake channel fingerprint observed a channel-claim contradiction.",
                metrics={
                    "claim_channel": "official",
                    "observed_channel_family": "bedrock",
                    "official_claim_contradicted": True,
                },
            )
        ]
    if scenario == RelayVerdict.INCONCLUSIVE:
        return [
            RelayEvidence(
                key="channel_runtime_inconclusive",
                category=RelayRiskCategory.UPSTREAM_ERROR_LEAKAGE,
                status="inconclusive",
                summary="The fake channel fingerprint simulates a sanitized runtime interruption.",
                metrics={"runtime_category": RelayRuntimeCategory.TIMEOUT.value},
            )
        ]
    return [
        RelayEvidence(
            key="channel_response_markers",
            category=RelayRiskCategory.INFRASTRUCTURE_FINGERPRINT,
            status="suspicious",
            summary="The fake channel fingerprint observed a provider marker without an official claim.",
            metrics={"observed_channel_family": "proxy", "provider_marker_detected": True},
        )
    ]


def _reasoning_fake_evidence(scenario: RelayVerdict) -> list[RelayEvidence]:
    if scenario == RelayVerdict.PASS:
        return [
            RelayEvidence(
                key="reasoning_native_signal",
                category=RelayRiskCategory.MODEL_SUBSTITUTION,
                status="pass",
                summary="The fake reasoning fingerprint observed compatible native reasoning evidence.",
                metrics={
                    "native_reasoning_field_observed": True,
                    "fake_think_tag_observed": False,
                },
            )
        ]
    if scenario == RelayVerdict.FAIL:
        return [
            RelayEvidence(
                key="reasoning_native_signal",
                category=RelayRiskCategory.MODEL_SUBSTITUTION,
                status="fail",
                summary="The fake reasoning fingerprint observed missing required native reasoning evidence.",
                metrics={
                    "expected_reasoning_family": "deepseek",
                    "native_reasoning_field_observed": False,
                },
            )
        ]
    if scenario == RelayVerdict.INCONCLUSIVE:
        return [
            RelayEvidence(
                key="reasoning_runtime_inconclusive",
                category=RelayRiskCategory.UPSTREAM_ERROR_LEAKAGE,
                status="inconclusive",
                summary="The fake reasoning fingerprint simulates a sanitized runtime interruption.",
                metrics={"runtime_category": RelayRuntimeCategory.TIMEOUT.value},
            )
        ]
    return [
        RelayEvidence(
            key="reasoning_fake_thinking_signal",
            category=RelayRiskCategory.MODEL_SUBSTITUTION,
            status="suspicious",
            summary="The fake reasoning fingerprint observed public fake-thinking text rather than native reasoning API output.",
            metrics={"fake_think_tag_observed": True},
        )
    ]


def _full_fake_evidence(
    scenario: RelayVerdict,
    model: str,
    *,
    drift_check: bool,
    claim_channel: str,
) -> list[RelayEvidence]:
    base = [
        RelayEvidence(
            key="full_profile_composite_verdict",
            category=RelayRiskCategory.LATENCY_OR_INSTABILITY,
            status="observed",
            summary="Composite verdict was derived from sanitized subprofile verdicts.",
            metrics={
                "general": {"verdict": "pass", "risk_level": "low", "evidence_keys": ["minimal_live_connectivity"]},
                "identity": {"verdict": "pass", "risk_level": "low", "evidence_keys": ["identity_response_envelope"]},
                "channel": {"verdict": "pass", "risk_level": "low", "evidence_keys": ["channel_claim_consistency"]},
                "reasoning": (
                    {"verdict": "pass", "risk_level": "low", "evidence_keys": ["reasoning_native_signal"]}
                    if scenario == RelayVerdict.PASS
                    else {
                        "verdict": "fail",
                        "risk_level": "high",
                        "evidence_keys": ["reasoning_native_signal", "reasoning_fake_thinking_signal"],
                    }
                ),
                "streaming": {"verdict": "pass", "risk_level": "low", "evidence_keys": ["stream_content_delta", "stream_terminal_finish"]},
                "schema": {"verdict": "pass", "risk_level": "low", "evidence_keys": ["schema_tool_envelope", "schema_arguments_json"]},
                "privacy": {"verdict": "pass", "risk_level": "low", "evidence_keys": ["privacy_marker_leakage"]},
                "security": {"verdict": "pass", "risk_level": "low", "evidence_keys": ["security_prompt_extraction", "security_override_resistance"]},
                "context": {"verdict": "pass", "risk_level": "low", "evidence_keys": ["context_anchor_retention"]},
            },
        ),
        RelayEvidence(
            key="identity_response_envelope",
            category=RelayRiskCategory.MODEL_SUBSTITUTION,
            status="pass",
            summary="Deterministic fake identity fingerprint observed no model-family contradiction.",
            metrics={
                "claimed_model_family": "claude" if "claude" in sanitize_public_relay_text(model).lower() else "unknown",
                "observed_model_family": "claude" if "claude" in sanitize_public_relay_text(model).lower() else "unknown",
                "response_shape_family": "openai_chat_completions",
                "response_id_pattern": "msg_...",
            },
        ),
        RelayEvidence(
            key="channel_claim_consistency",
            category=RelayRiskCategory.INFRASTRUCTURE_FINGERPRINT,
            status="pass",
            summary="Deterministic fake channel fingerprint observed no channel-claim contradiction.",
            metrics={
                "claim_channel": sanitize_public_relay_text(claim_channel),
                "observed_channel_family": None,
                "official_claim_contradicted": False,
                "compatible_gateway_claim": False,
            },
        ),
        RelayEvidence(
            key="reasoning_native_signal",
            category=RelayRiskCategory.MODEL_SUBSTITUTION,
            status="pass" if scenario == RelayVerdict.PASS else "fail",
            summary=(
                "Deterministic fake reasoning fingerprint observed no native reasoning contradiction."
                if scenario == RelayVerdict.PASS
                else "Deterministic fake reasoning fingerprint observed missing expected native reasoning evidence."
            ),
            metrics={
                "expected_reasoning_family": None if scenario == RelayVerdict.PASS else "claude_reasoning",
                "native_reasoning_field_observed": True if scenario == RelayVerdict.PASS else False,
                "reasoning_content_observed": False,
                "thinking_block_observed": True if scenario == RelayVerdict.PASS else False,
            },
        ),
        RelayEvidence(
            key="drift_check_summary",
            category=RelayRiskCategory.LATENCY_OR_INSTABILITY,
            status="pass" if drift_check else "insufficient_evidence",
            summary=(
                "Deterministic fake drift-check sampling completed."
                if drift_check
                else "Drift check was not enabled for this run."
            ),
            metrics=(
                {
                    "drift_check_enabled": True,
                    "sample_count": 8,
                    "suspicious_sample_count": 0,
                    "failed_sample_count": 0,
                    "inconclusive_sample_count": 0,
                }
                if drift_check
                else {"drift_check_enabled": False, "sample_count": 0, "recommended_action": "--drift-check yes"}
            ),
        ),
    ]
    if scenario == RelayVerdict.SUSPICIOUS:
        base.append(
            RelayEvidence(
                key="relay_identity_candidate_signals",
                category=RelayRiskCategory.MODEL_SUBSTITUTION,
                status="suspicious",
                summary="Claimed model behavior diverged from Claude-like expectations.",
                metrics={
                    "claimed_model": sanitize_public_relay_text(model),
                    "claude_reasoning_signal": "missing",
                    "candidate_signals": [
                        {"label": "GLM-like", "confidence": "medium"},
                        {"label": "Qwen-like", "confidence": "low-to-medium"},
                        {"label": "Claude Opus-like", "confidence": "low"},
                    ],
                },
            )
        )
        base.append(
            RelayEvidence(
                key="reasoning_fake_thinking_signal",
                category=RelayRiskCategory.MODEL_SUBSTITUTION,
                status="suspicious",
                summary="Deterministic fake observation shows a sanitized fake-thinking marker in ordinary content.",
                metrics={"fake_thinking_text_observed": True},
            )
        )
    if scenario == RelayVerdict.FAIL:
        base.append(
            RelayEvidence(
                key="identity_model_field_consistency",
                category=RelayRiskCategory.MODEL_SUBSTITUTION,
                status="fail",
                summary="Deterministic fake observation shows a strong model-family contradiction.",
                metrics={
                    "claimed_model_family": "claude",
                    "observed_model_family": "deepseek",
                    "model_family_contradiction": True,
                },
            )
        )
    if scenario == RelayVerdict.INCONCLUSIVE:
        base.append(
            RelayEvidence(
                key="runtime_not_conclusive",
                category=RelayRiskCategory.UPSTREAM_ERROR_LEAKAGE,
                status="inconclusive",
                summary="Deterministic fake observation represents a timeout before a relay judgment could be made.",
                metrics={"runtime_condition": "sanitized_unavailable"},
            )
        )
    return base


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
        RelayAuditProfile.IDENTITY: RelayRiskCategory.MODEL_SUBSTITUTION,
        RelayAuditProfile.CHANNEL: RelayRiskCategory.INFRASTRUCTURE_FINGERPRINT,
        RelayAuditProfile.REASONING: RelayRiskCategory.MODEL_SUBSTITUTION,
        RelayAuditProfile.STREAMING: RelayRiskCategory.STREAMING_INTEGRITY,
        RelayAuditProfile.SCHEMA: RelayRiskCategory.SCHEMA_TOOL_REWRITE,
        RelayAuditProfile.PRIVACY: RelayRiskCategory.PROMPT_INSTRUCTION_LEAKAGE,
        RelayAuditProfile.SECURITY: RelayRiskCategory.PROMPT_INSTRUCTION_LEAKAGE,
        RelayAuditProfile.CONTEXT: RelayRiskCategory.CONTEXT_TRUNCATION,
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


def _build_security_fake_result(
    *,
    scenario: RelayVerdict,
    endpoint_host: str,
    endpoint_hash: str,
    model: str,
    pack_summary: RelayPackSummary,
) -> RelayResult:
    evidence = _security_fake_evidence(scenario)
    risk_categories = sorted({item.category for item in evidence}, key=lambda item: item.value)
    inconclusive_reason = None
    runtime_category = None
    if scenario == RelayVerdict.INCONCLUSIVE:
        runtime_category = RelayRuntimeCategory.TIMEOUT
        inconclusive_reason = "The fake prompt-security scenario represents a sanitized runtime interruption."
    return RelayResult(
        run_id=_run_id(RelayAuditProfile.SECURITY, scenario, endpoint_hash, model, pack_summary.pack_hash),
        profile=RelayAuditProfile.SECURITY,
        scenario=scenario,
        mode=RelayAuditMode.FAKE,
        model=sanitize_public_relay_text(model),
        endpoint_host=endpoint_host,
        endpoint_hash=endpoint_hash,
        pack_summary=pack_summary,
        verdict=scenario,
        risk_level=_risk_level_for(scenario),
        risk_categories=risk_categories,
        evidence=evidence,
        retest_guidance=(
            "Use live security profile only when you intentionally want bounded prompt-boundary evidence."
        ),
        inconclusive_reason=inconclusive_reason,
        runtime_category=runtime_category,
    )


def _security_fake_evidence(scenario: RelayVerdict) -> list[RelayEvidence]:
    if scenario == RelayVerdict.PASS:
        return [
            RelayEvidence(
                key="security_boundary_control",
                category=RelayRiskCategory.MESSAGE_REWRITE,
                status="pass",
                summary="The fake prompt-security scenario preserved all expected public boundary contracts.",
                metrics={
                    "security_probe_count": 3,
                    "security_probe_completed_count": 3,
                    "boundary_exact_answer_observed": True,
                    "extraction_safe_answer_observed": True,
                    "override_safe_answer_observed": True,
                },
            )
        ]
    if scenario == RelayVerdict.FAIL:
        return [
            RelayEvidence(
                key="security_hidden_instruction_echo",
                category=RelayRiskCategory.PROMPT_INSTRUCTION_LEAKAGE,
                status="fail",
                summary=(
                    "The fake prompt-security scenario simulates hidden-instruction echo and override leakage "
                    "without exposing raw probe text."
                ),
                metrics={
                    "security_probe_count": 3,
                    "security_probe_completed_count": 3,
                    "hidden_instruction_echo_detected": True,
                    "prompt_extraction_signal_detected": True,
                    "override_success_signal_detected": True,
                },
            )
        ]
    if scenario == RelayVerdict.INCONCLUSIVE:
        return [
            RelayEvidence(
                key="security_runtime_inconclusive",
                category=RelayRiskCategory.UPSTREAM_ERROR_LEAKAGE,
                status="inconclusive",
                summary="The fake prompt-security scenario simulates a sanitized runtime interruption.",
                metrics={
                    "security_probe_count": 3,
                    "security_probe_completed_count": 1,
                    "runtime_category": RelayRuntimeCategory.TIMEOUT.value,
                },
            )
        ]
    return [
        RelayEvidence(
            key="security_role_boundary_rewrite",
            category=RelayRiskCategory.MESSAGE_REWRITE,
            status="suspicious",
            summary="The fake prompt-security scenario simulates non-exact but non-leaking public behavior.",
            metrics={"security_probe_count": 3, "security_probe_completed_count": 3},
        )
    ]


def _build_context_fake_result(
    *,
    scenario: RelayVerdict,
    endpoint_host: str,
    endpoint_hash: str,
    model: str,
    pack_summary: RelayPackSummary,
) -> RelayResult:
    evidence = _context_fake_evidence(scenario)
    inconclusive_reason = None
    runtime_category = None
    if scenario == RelayVerdict.INCONCLUSIVE:
        runtime_category = RelayRuntimeCategory.TIMEOUT
        inconclusive_reason = "The fake context-retention scenario represents a sanitized runtime interruption."
    return RelayResult(
        run_id=_run_id(RelayAuditProfile.CONTEXT, scenario, endpoint_hash, model, pack_summary.pack_hash),
        profile=RelayAuditProfile.CONTEXT,
        scenario=scenario,
        mode=RelayAuditMode.FAKE,
        model=sanitize_public_relay_text(model),
        endpoint_host=endpoint_host,
        endpoint_hash=endpoint_hash,
        pack_summary=pack_summary,
        verdict=scenario,
        risk_level=_risk_level_for(scenario),
        risk_categories=[RelayRiskCategory.CONTEXT_TRUNCATION],
        evidence=evidence,
        retest_guidance="Use live context profile only when you intentionally want bounded anchor-retention evidence.",
        inconclusive_reason=inconclusive_reason,
        runtime_category=runtime_category,
    )


def _context_fake_evidence(scenario: RelayVerdict) -> list[RelayEvidence]:
    if scenario == RelayVerdict.PASS:
        return [
            RelayEvidence(
                key="context_anchor_retention",
                category=RelayRiskCategory.CONTEXT_TRUNCATION,
                status="pass",
                summary="The fake context-retention scenario preserved all expected public anchors.",
                metrics={
                    "context_probe_count": 2,
                    "context_probe_completed_count": 2,
                    "anchor_missing_count": 0,
                    "anchor_order_preserved": True,
                },
            )
        ]
    if scenario == RelayVerdict.SUSPICIOUS:
        return [
            RelayEvidence(
                key="context_anchor_rewrite",
                category=RelayRiskCategory.CONTEXT_TRUNCATION,
                status="suspicious",
                summary="The fake context-retention scenario kept anchors but degraded the exact separator contract.",
                metrics={
                    "context_probe_count": 2,
                    "context_probe_completed_count": 2,
                    "separator_degradation_detected": True,
                    "anchor_missing_count": 0,
                },
            )
        ]
    if scenario == RelayVerdict.FAIL:
        return [
            RelayEvidence(
                key="context_anchor_missing",
                category=RelayRiskCategory.CONTEXT_TRUNCATION,
                status="fail",
                summary="The fake context-retention scenario simulates missing or wrong public anchor evidence.",
                metrics={
                    "context_probe_count": 2,
                    "context_probe_completed_count": 2,
                    "anchor_missing_count": 1,
                    "closing_anchor_wrongly_selected": True,
                },
            )
        ]
    return [
        RelayEvidence(
            key="context_runtime_inconclusive",
            category=RelayRiskCategory.CONTEXT_TRUNCATION,
            status="inconclusive",
            summary="The fake context-retention scenario simulates a sanitized runtime interruption.",
            metrics={
                "context_probe_count": 2,
                "context_probe_completed_count": 1,
                "runtime_category": RelayRuntimeCategory.TIMEOUT.value,
            },
        )
    ]
