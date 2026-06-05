from tokenverify.relay_fraud import (
    FraudEvidence,
    FraudEvidenceTag,
    FraudScenarioDefinition,
    FraudScenarioStatus,
    collect_relay_fraud_evidence,
    evaluate_fraud_scenarios,
    fraud_scenario_registry,
    render_fraud_scenario_summary,
)
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


def test_fraud_registry_has_initial_ten_unique_scenarios_with_languages():
    registry = fraud_scenario_registry()

    assert len(registry) == 10
    assert len({scenario.scenario_id for scenario in registry}) == 10
    assert {scenario.scenario_id for scenario in registry} == {
        "model_identity_and_capability_substitution",
        "channel_source_and_compliance_misrepresentation",
        "account_pool_reverse_resource_and_mixed_routing_drift",
        "prompt_context_integrity_manipulation",
        "cached_answers_masquerading_as_live_inference",
        "fake_or_degraded_streaming",
        "schema_tool_calling_contract_breakage",
        "privacy_and_prompt_leakage",
        "capacity_quota_and_error_masking",
        "billing_and_usage_opacity",
    }
    for scenario in registry:
        assert scenario.title_en
        assert scenario.title_zh
        assert scenario.classification in {"open_source", "commercial_backend"}
        assert scenario.boundary_en
        assert scenario.boundary_zh


def test_required_evidence_maps_to_detected_and_optional_only_maps_to_suspicious():
    results = evaluate_fraud_scenarios(
        [
            FraudEvidence(
                tag=FraudEvidenceTag.PROMPT_BOUNDARY_FAILED,
                public_label="PROMPT_BOUNDARY_FAILED",
                source="security",
            )
        ],
        available_sources={"security"},
    )

    integrity = results.by_id["prompt_context_integrity_manipulation"]
    leakage = results.by_id["privacy_and_prompt_leakage"]

    assert integrity.status == FraudScenarioStatus.DETECTED
    assert leakage.status == FraudScenarioStatus.SUSPICIOUS
    assert "PROMPT_BOUNDARY_FAILED" in integrity.triggered_evidence


def test_missing_required_sources_are_not_evaluated_not_passed():
    results = evaluate_fraud_scenarios([], available_sources=set())

    assert results.by_id["schema_tool_calling_contract_breakage"].status == FraudScenarioStatus.NOT_EVALUATED
    assert results.by_id["billing_and_usage_opacity"].status == FraudScenarioStatus.NOT_EVALUATED


def test_scenario_evaluator_failure_is_isolated_and_sanitized():
    broken = FraudScenarioDefinition(
        scenario_id="broken",
        title_en="Broken",
        title_zh="损坏场景",
        classification="open_source",
        required_sources=frozenset({"security"}),
        required_tags=frozenset({FraudEvidenceTag.PROMPT_BOUNDARY_FAILED}),
        boundary_en="Boundary",
        boundary_zh="边界",
    )

    class ExplodingEvidence(dict):
        def get(self, key, default=None):
            raise RuntimeError("raw traceback https://relay.example/v1 Authorization: Bearer sk-secret /Users/Teng/private")

    summary = evaluate_fraud_scenarios(
        [],
        available_sources={"security"},
        registry=(broken,),
        evidence_by_tag_override=ExplodingEvidence(),
    )

    result = summary.by_id["broken"]
    assert result.status == FraudScenarioStatus.NOT_EVALUATED
    assert result.safe_note == "Scenario evaluator failed safely."
    assert "https://" not in (result.safe_note or "")
    assert "sk-secret" not in (result.safe_note or "")
    assert "/Users" not in (result.safe_note or "")


def test_triggered_evidence_breadcrumbs_are_public_aliases_only():
    summary = evaluate_fraud_scenarios(
        [
            FraudEvidence(
                tag=FraudEvidenceTag.STREAM_DELTA_MISSING,
                public_label="STREAM_DELTA_MISSING https://relay.example/v1 Authorization: Bearer sk-secret",
                source="streaming",
            )
        ],
        available_sources={"streaming"},
    )

    result = summary.by_id["fake_or_degraded_streaming"]
    assert result.status == FraudScenarioStatus.DETECTED
    assert result.triggered_evidence == ("STREAM_DELTA_MISSING",)


def _relay_result(profile, evidence, *, verdict=RelayVerdict.FAIL, runtime_category=None):
    return RelayResult(
        run_id="relay-test",
        profile=profile,
        scenario=verdict,
        mode=RelayAuditMode.LIVE,
        model="claimed-model",
        endpoint_host="relay.example",
        endpoint_hash="abcdef1234567890",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=verdict,
        risk_level=RelayRiskLevel.HIGH if verdict == RelayVerdict.FAIL else RelayRiskLevel.LOW,
        risk_categories=[item.category for item in evidence],
        evidence=evidence,
        retest_guidance="Retest.",
        runtime_category=runtime_category,
    )


def test_collect_relay_fraud_evidence_maps_security_context_schema_streaming_and_runtime():
    result = _relay_result(
        RelayAuditProfile.SECURITY,
        [
            RelayEvidence(
                key="security_prompt_extraction",
                category=RelayRiskCategory.PROMPT_INSTRUCTION_LEAKAGE,
                status="fail",
                summary="sanitized",
                metrics={"sensitive_core_echo_detected": True},
            )
        ],
    )
    evidence, sources = collect_relay_fraud_evidence(result)

    assert FraudEvidenceTag.PROMPT_BOUNDARY_FAILED in {item.tag for item in evidence}
    assert FraudEvidenceTag.SENSITIVE_CORE_ECHO_DETECTED in {item.tag for item in evidence}
    assert "security" in sources

    schema_result = _relay_result(
        RelayAuditProfile.SCHEMA,
        [
            RelayEvidence(
                key="schema_tool_envelope",
                category=RelayRiskCategory.SCHEMA_TOOL_REWRITE,
                status="fail",
                summary="sanitized",
                metrics={"tool_call_observed": False},
            )
        ],
    )
    schema_evidence, schema_sources = collect_relay_fraud_evidence(schema_result)
    assert FraudEvidenceTag.SCHEMA_TOOL_DROPPED in {item.tag for item in schema_evidence}
    assert "schema" in schema_sources

    streaming_result = _relay_result(
        RelayAuditProfile.STREAMING,
        [
            RelayEvidence(
                key="stream_content_delta",
                category=RelayRiskCategory.STREAMING_INTEGRITY,
                status="fail",
                summary="sanitized",
                metrics={"content_delta_count": 0},
            ),
            RelayEvidence(
                key="stream_terminal_finish",
                category=RelayRiskCategory.STREAMING_INTEGRITY,
                status="fail",
                summary="sanitized",
                metrics={"terminal_finish_observed": False},
            ),
        ],
    )
    streaming_evidence, streaming_sources = collect_relay_fraud_evidence(streaming_result)
    assert FraudEvidenceTag.STREAM_DELTA_MISSING in {item.tag for item in streaming_evidence}
    assert FraudEvidenceTag.STREAM_FINISH_MISSING in {item.tag for item in streaming_evidence}
    assert "streaming" in streaming_sources

    context_result = _relay_result(
        RelayAuditProfile.CONTEXT,
        [
            RelayEvidence(
                key="context_anchor_retention",
                category=RelayRiskCategory.CONTEXT_TRUNCATION,
                status="fail",
                summary="sanitized",
                metrics={"anchor_missing_count": 1},
            )
        ],
    )
    context_evidence, context_sources = collect_relay_fraud_evidence(context_result)
    assert FraudEvidenceTag.CONTEXT_ANCHOR_MISSING in {item.tag for item in context_evidence}
    assert "context" in context_sources

    runtime_result = _relay_result(
        RelayAuditProfile.GENERAL,
        [],
        verdict=RelayVerdict.INCONCLUSIVE,
        runtime_category=RelayRuntimeCategory.QUOTA_OR_RATE_LIMIT,
    )
    runtime_evidence, runtime_sources = collect_relay_fraud_evidence(runtime_result)
    assert FraudEvidenceTag.QUOTA_OR_RATE_LIMIT_OBSERVED in {item.tag for item in runtime_evidence}
    assert "runtime" in runtime_sources


def test_fraud_summary_sanitizes_adversarial_scenario_text():
    summary = evaluate_fraud_scenarios(
        [
            FraudEvidence(
                tag=FraudEvidenceTag.PROMPT_BOUNDARY_FAILED,
                public_label="PROMPT_BOUNDARY_FAILED",
                source="security",
                detail="https://relay.example/v1 Authorization: Bearer sk-secret /Users/Teng/private raw model output",
            )
        ],
        available_sources={"security"},
    )
    rendered = "\n".join(render_fraud_scenario_summary(summary))

    assert "PROMPT_BOUNDARY_FAILED" in rendered
    assert "https://" not in rendered
    assert "sk-secret" not in rendered
    assert "/Users" not in rendered
    assert "raw model output" not in rendered
