from tokenverify.models import AuditResult, Rating, Verdict
from tokenverify.relay_fraud import (
    FraudEvidence,
    FraudEvidenceTag,
    FraudScenarioDefinition,
    FraudScenarioStatus,
    collect_relay_fraud_evidence,
    collect_provider_fraud_evidence,
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

    assert len(registry) == 12
    assert len({scenario.scenario_id for scenario in registry}) == 12
    assert {scenario.scenario_id for scenario in registry} == {
        "model_identity_and_capability_substitution",
        "channel_source_and_compliance_misrepresentation",
        "account_pool_reverse_resource_and_mixed_routing_drift",
        "prompt_context_integrity_manipulation",
        "thinking_reasoning_capability_forgery",
        "cached_answers_masquerading_as_live_inference",
        "fake_or_degraded_streaming",
        "schema_tool_calling_contract_breakage",
        "privacy_and_prompt_leakage",
        "capacity_quota_and_error_masking",
        "billing_and_usage_opacity",
        "unmapped_technical_risk_signal",
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


def test_render_not_evaluated_does_not_print_triggered_conclusion():
    summary = evaluate_fraud_scenarios([], available_sources=set())

    rendered = "\n".join(render_fraud_scenario_summary(summary, language="zh", report_kind="full"))

    assert "not_evaluated" not in rendered
    assert "已观察到与声明模型或能力存在强矛盾" not in rendered
    assert "insufficient_evidence" in rendered


def test_render_not_detected_uses_non_triggered_conclusion():
    summary = evaluate_fraud_scenarios([], available_sources={"schema"})

    rendered = "\n".join(render_fraud_scenario_summary(summary))

    assert "### Schema / Tool-Calling Contract Breakage" in rendered
    assert "- Status: not_detected" in rendered
    assert "Schema or tool-calling contract breakage observed." not in rendered
    assert "No tool_calls loss or function-arguments JSON breakage was observed." in rendered


def test_insufficient_evidence_uses_actionable_drift_check_text():
    summary = evaluate_fraud_scenarios(
        [],
        available_sources={"general", "streaming", "schema", "privacy", "security", "context"},
    )

    rendered_zh = "\n".join(render_fraud_scenario_summary(summary, language="zh", report_kind="full"))
    rendered_en = "\n".join(render_fraud_scenario_summary(summary, language="en", report_kind="full"))

    assert "- 状态：**insufficient_evidence**" in rendered_zh
    assert "- Status: **insufficient_evidence**" in rendered_en
    assert "--drift-check yes" in rendered_zh
    assert "--drift-check yes" in rendered_en
    assert "--repeat 8" not in rendered_zh
    assert "--repeat 8" not in rendered_en


def test_enabled_drift_check_without_drift_renders_not_detected():
    summary = evaluate_fraud_scenarios(
        [],
        available_sources={"general", "streaming", "schema", "privacy", "security", "context", "drift"},
    )

    rendered_zh = "\n".join(render_fraud_scenario_summary(summary, language="zh", report_kind="full"))
    rendered_en = "\n".join(render_fraud_scenario_summary(summary, language="en", report_kind="full"))

    assert "### 3. 号池、逆向与混池漂移" in rendered_zh
    assert "- 状态：**not_detected**" in rendered_zh
    assert "已启用漂移检测" in rendered_zh
    assert "--drift-check yes" not in rendered_zh
    assert "### 3. Account-Pool, Reverse-Resource, And Mixed-Routing Drift" in rendered_en
    assert "- Status: **not_detected**" in rendered_en
    assert "Drift checking ran" in rendered_en
    assert "--drift-check yes" not in rendered_en


def test_drift_missing_insufficient_evidence_recommends_drift_check_yes():
    summary = evaluate_fraud_scenarios(
        [],
        available_sources={"general", "identity", "channel", "reasoning", "streaming", "schema", "privacy", "security", "context"},
    )

    drift = summary.by_id["account_pool_reverse_resource_and_mixed_routing_drift"]

    assert drift.status == FraudScenarioStatus.NOT_EVALUATED

    rendered = "\n".join(render_fraud_scenario_summary(summary, language="zh", report_kind="full"))

    assert "insufficient_evidence" in rendered
    assert "--drift-check yes" in rendered
    assert "有界重复采样" in rendered


def test_identity_channel_reasoning_sources_make_core_scenarios_evaluated():
    summary = evaluate_fraud_scenarios(
        [],
        available_sources={"general", "identity", "channel", "reasoning"},
    )

    assert (
        summary.by_id["model_identity_and_capability_substitution"].status
        == FraudScenarioStatus.NOT_DETECTED
    )
    assert (
        summary.by_id["channel_source_and_compliance_misrepresentation"].status
        == FraudScenarioStatus.NOT_DETECTED
    )
    assert (
        summary.by_id["thinking_reasoning_capability_forgery"].status
        == FraudScenarioStatus.NOT_DETECTED
    )


def test_observed_channel_marker_maps_to_detected_channel_scenario():
    summary = evaluate_fraud_scenarios(
        [
            FraudEvidence(
                tag=FraudEvidenceTag.CHANNEL_MARKER_OBSERVED,
                public_label="Channel marker observed: observed_channel_family=bedrock",
                source="channel",
            )
        ],
        available_sources={"channel"},
    )

    channel = summary.by_id["channel_source_and_compliance_misrepresentation"]

    assert channel.status == FraudScenarioStatus.DETECTED
    assert channel.triggered_evidence == ("Channel marker observed: observed_channel_family=bedrock",)


def test_not_detected_scenario_contains_absent_signal_explanation():
    summary = evaluate_fraud_scenarios([], available_sources={"channel"})

    channel = summary.by_id["channel_source_and_compliance_misrepresentation"]

    assert channel.status == FraudScenarioStatus.NOT_DETECTED
    assert any("Bedrock" in item or "bedrock" in item for item in channel.absent_signals)
    assert channel.explanation


def test_detected_scenario_contains_observed_signal_explanation():
    summary = evaluate_fraud_scenarios(
        [
            FraudEvidence(
                tag=FraudEvidenceTag.CHANNEL_MARKER_OBSERVED,
                public_label="observed channel family: bedrock",
                source="channel",
            )
        ],
        available_sources={"channel"},
    )

    channel = summary.by_id["channel_source_and_compliance_misrepresentation"]

    assert channel.status == FraudScenarioStatus.DETECTED
    assert "observed channel family: bedrock" in channel.observed_signals
    assert channel.explanation


def test_identity_channel_reasoning_evidence_maps_to_core_scenarios():
    summary = evaluate_fraud_scenarios(
        [
            FraudEvidence(
                tag=FraudEvidenceTag.IDENTITY_MODEL_FIELD_CONTRADICTION,
                public_label="Identity model-field contradiction: claimed=claude observed=qwen",
                source="identity",
            ),
            FraudEvidence(
                tag=FraudEvidenceTag.CHANNEL_OFFICIAL_CLAIM_CONTRADICTED,
                public_label="Official-channel claim contradicted: observed=bedrock",
                source="channel",
            ),
            FraudEvidence(
                tag=FraudEvidenceTag.REASONING_REQUIRED_SIGNAL_MISSING,
                public_label="Reasoning required signal missing: family=deepseek",
                source="reasoning",
            ),
        ],
        available_sources={"identity", "channel", "reasoning"},
    )

    assert (
        summary.by_id["model_identity_and_capability_substitution"].status
        == FraudScenarioStatus.DETECTED
    )
    assert (
        summary.by_id["channel_source_and_compliance_misrepresentation"].status
        == FraudScenarioStatus.DETECTED
    )
    assert (
        summary.by_id["thinking_reasoning_capability_forgery"].status
        == FraudScenarioStatus.DETECTED
    )
    rendered = "\n".join(render_fraud_scenario_summary(summary, language="zh", report_kind="full"))
    assert "Identity model-field contradiction" in rendered
    assert "Official-channel claim contradicted" in rendered
    assert "Reasoning required signal missing" in rendered
    assert "claimed=claude" in rendered


def test_collect_relay_fraud_evidence_maps_identity_channel_reasoning_profiles():
    identity_result = _relay_result(
        RelayAuditProfile.IDENTITY,
        [
            RelayEvidence(
                key="identity_model_field_consistency",
                category=RelayRiskCategory.MODEL_SUBSTITUTION,
                status="fail",
                summary="sanitized",
                metrics={
                    "claimed_model_family": "claude",
                    "observed_model_family": "qwen",
                    "model_family_contradiction": True,
                },
            ),
            RelayEvidence(
                key="identity_candidate_family_scores",
                category=RelayRiskCategory.MODEL_SUBSTITUTION,
                status="suspicious",
                summary="sanitized",
                metrics={"top_candidate": "qwen", "confidence": "medium"},
            ),
        ],
    )
    identity_evidence, identity_sources = collect_relay_fraud_evidence(identity_result)
    assert FraudEvidenceTag.IDENTITY_MODEL_FIELD_CONTRADICTION in {item.tag for item in identity_evidence}
    assert FraudEvidenceTag.IDENTITY_CANDIDATE_UPSTREAM_SIGNAL in {item.tag for item in identity_evidence}
    assert "identity" in identity_sources
    assert any("qwen" in item.public_label for item in identity_evidence)

    channel_result = _relay_result(
        RelayAuditProfile.CHANNEL,
        [
            RelayEvidence(
                key="channel_claim_consistency",
                category=RelayRiskCategory.INFRASTRUCTURE_FINGERPRINT,
                status="fail",
                summary="sanitized",
                metrics={
                    "claim_channel": "official",
                    "observed_channel_family": "bedrock",
                    "official_claim_contradicted": True,
                },
            )
        ],
    )
    channel_evidence, channel_sources = collect_relay_fraud_evidence(channel_result)
    assert FraudEvidenceTag.CHANNEL_OFFICIAL_CLAIM_CONTRADICTED in {item.tag for item in channel_evidence}
    assert "channel" in channel_sources

    reasoning_result = _relay_result(
        RelayAuditProfile.REASONING,
        [
            RelayEvidence(
                key="reasoning_native_signal",
                category=RelayRiskCategory.MODEL_SUBSTITUTION,
                status="fail",
                summary="sanitized",
                metrics={"expected_reasoning_family": "deepseek", "native_reasoning_field_observed": False},
            ),
            RelayEvidence(
                key="reasoning_fake_thinking_signal",
                category=RelayRiskCategory.MODEL_SUBSTITUTION,
                status="suspicious",
                summary="sanitized",
                metrics={"fake_think_tag_observed": True},
            ),
        ],
    )
    reasoning_evidence, reasoning_sources = collect_relay_fraud_evidence(reasoning_result)
    assert FraudEvidenceTag.REASONING_REQUIRED_SIGNAL_MISSING in {item.tag for item in reasoning_evidence}
    assert FraudEvidenceTag.REASONING_FAKE_THINKING_TEXT in {item.tag for item in reasoning_evidence}
    assert "reasoning" in reasoning_sources


def test_identity_evidence_renders_only_model_identity_facts():
    result = _relay_result(
        RelayAuditProfile.IDENTITY,
        [
            RelayEvidence(
                key="identity_response_envelope",
                category=RelayRiskCategory.MODEL_SUBSTITUTION,
                status="pass",
                summary="sanitized",
                metrics={
                    "claimed_model_family": "claude",
                    "observed_model_family": "claude",
                    "response_id_pattern": "msg_bdrk...",
                    "response_shape_family": "openai_chat_completions",
                },
            )
        ],
        verdict=RelayVerdict.PASS,
    )
    evidence, sources = collect_relay_fraud_evidence(result)
    summary = evaluate_fraud_scenarios(evidence, available_sources=sources)

    identity = summary.by_id["model_identity_and_capability_substitution"]

    assert identity.status == FraudScenarioStatus.NOT_DETECTED
    rendered = " ".join(identity.observed_signals + identity.absent_signals)
    assert "claimed_model_family=claude" in rendered
    assert "observed_model_family=claude" in rendered
    assert "response_id_pattern" not in rendered
    assert "response_shape_family" not in rendered


def test_bedrock_response_id_from_identity_envelope_routes_to_channel_not_identity():
    result = _relay_result(
        RelayAuditProfile.IDENTITY,
        [
            RelayEvidence(
                key="identity_response_envelope",
                category=RelayRiskCategory.MODEL_SUBSTITUTION,
                status="observed",
                summary="sanitized",
                metrics={
                    "claimed_model_family": "claude",
                    "observed_model_family": "claude",
                    "response_id_pattern": "msg_bdrk...",
                    "response_shape_family": "openai_chat_completions",
                },
            )
        ],
        verdict=RelayVerdict.PASS,
    )
    evidence, sources = collect_relay_fraud_evidence(result)
    summary = evaluate_fraud_scenarios(evidence, available_sources=sources | {"channel"})

    identity = summary.by_id["model_identity_and_capability_substitution"]
    channel = summary.by_id["channel_source_and_compliance_misrepresentation"]

    assert identity.status == FraudScenarioStatus.NOT_DETECTED
    assert channel.status == FraudScenarioStatus.DETECTED
    assert "response_id_pattern=msg_bdrk..." not in " ".join(identity.observed_signals)
    assert "response_shape_family=openai_chat_completions" not in " ".join(identity.observed_signals)
    channel_text = " ".join(channel.observed_signals)
    assert "response_id_pattern=msg_bdrk..." in channel_text
    assert "response_shape_family=openai_chat_completions" in channel_text


def test_channel_evidence_renders_detected_channel_marker_facts():
    result = _relay_result(
        RelayAuditProfile.CHANNEL,
        [
            RelayEvidence(
                key="channel_response_markers",
                category=RelayRiskCategory.INFRASTRUCTURE_FINGERPRINT,
                status="observed",
                summary="sanitized",
                metrics={
                    "observed_channel_family": "bedrock",
                    "response_id_pattern": "msg_bdrk...",
                    "provider_marker_detected": True,
                },
            ),
            RelayEvidence(
                key="channel_header_marker_family",
                category=RelayRiskCategory.INFRASTRUCTURE_FINGERPRINT,
                status="observed",
                summary="sanitized",
                metrics={"header_marker_family": "x-amzn-*"},
            ),
        ],
        verdict=RelayVerdict.SUSPICIOUS,
    )
    evidence, sources = collect_relay_fraud_evidence(result)
    summary = evaluate_fraud_scenarios(evidence, available_sources=sources)

    channel = summary.by_id["channel_source_and_compliance_misrepresentation"]

    assert channel.status == FraudScenarioStatus.DETECTED
    rendered = " ".join(channel.observed_signals)
    assert "observed_channel_family=bedrock" in rendered
    assert "response_id_pattern=msg_bdrk..." in rendered
    assert "header_marker_family=x-amzn-*" in rendered


def test_reasoning_expected_native_field_missing_maps_to_detected():
    result = _relay_result(
        RelayAuditProfile.REASONING,
        [
            RelayEvidence(
                key="reasoning_native_signal",
                category=RelayRiskCategory.MODEL_SUBSTITUTION,
                status="fail",
                summary="sanitized",
                metrics={
                    "expected_reasoning_family": "deepseek_r1",
                    "native_reasoning_field_observed": False,
                    "reasoning_content_observed": False,
                },
            )
        ],
    )
    evidence, sources = collect_relay_fraud_evidence(result)
    summary = evaluate_fraud_scenarios(evidence, available_sources=sources)

    reasoning = summary.by_id["thinking_reasoning_capability_forgery"]

    assert reasoning.status == FraudScenarioStatus.DETECTED
    rendered = " ".join(reasoning.observed_signals)
    assert "expected_reasoning_family=deepseek_r1" in rendered
    assert "native_reasoning_field_observed=False" in rendered


def test_generic_reasoning_native_absence_does_not_map_to_identity_or_reasoning_risk():
    result = _relay_result(
        RelayAuditProfile.REASONING,
        [
            RelayEvidence(
                key="reasoning_native_signal",
                category=RelayRiskCategory.MODEL_SUBSTITUTION,
                status="pass",
                summary="Native reasoning signal check did not find a contradiction.",
                metrics={
                    "expected_reasoning_family": "generic",
                    "native_reasoning_field_observed": False,
                    "reasoning_content_observed": False,
                },
            )
        ],
        verdict=RelayVerdict.PASS,
    )
    evidence, sources = collect_relay_fraud_evidence(result)
    summary = evaluate_fraud_scenarios(evidence, available_sources=sources | {"identity"})

    assert summary.by_id["thinking_reasoning_capability_forgery"].status == FraudScenarioStatus.NOT_DETECTED
    assert summary.by_id["model_identity_and_capability_substitution"].status == FraudScenarioStatus.NOT_DETECTED
    rendered = " ".join(
        summary.by_id["thinking_reasoning_capability_forgery"].observed_signals
        + summary.by_id["model_identity_and_capability_substitution"].observed_signals
    )
    assert "reasoning native signal missing" not in rendered


def test_fake_think_text_plus_missing_reasoning_content_maps_to_detected():
    result = _relay_result(
        RelayAuditProfile.REASONING,
        [
            RelayEvidence(
                key="reasoning_native_signal",
                category=RelayRiskCategory.MODEL_SUBSTITUTION,
                status="fail",
                summary="sanitized",
                metrics={
                    "expected_reasoning_family": "deepseek_r1",
                    "native_reasoning_field_observed": False,
                    "reasoning_content_observed": False,
                },
            ),
            RelayEvidence(
                key="reasoning_fake_thinking_signal",
                category=RelayRiskCategory.MODEL_SUBSTITUTION,
                status="fail",
                summary="sanitized",
                metrics={"fake_think_tag_observed": True, "public_think_text_observed": True},
            ),
        ],
    )
    evidence, sources = collect_relay_fraud_evidence(result)
    summary = evaluate_fraud_scenarios(evidence, available_sources=sources)

    reasoning = summary.by_id["thinking_reasoning_capability_forgery"]

    assert reasoning.status == FraudScenarioStatus.DETECTED
    rendered = " ".join(reasoning.observed_signals + (reasoning.explanation,))
    assert "fake" in rendered.lower()
    assert "native reasoning" in rendered.lower() or "reasoning_content" in rendered


def test_security_prompt_extraction_broadcasts_to_integrity_and_privacy_scenarios():
    result = _relay_result(
        RelayAuditProfile.SECURITY,
        [
            RelayEvidence(
                key="security_prompt_extraction",
                category=RelayRiskCategory.PROMPT_INSTRUCTION_LEAKAGE,
                status="fail",
                summary="sanitized",
                metrics={"prompt_extraction_signal_detected": True, "sensitive_core_echo_detected": True},
            )
        ],
    )
    evidence, sources = collect_relay_fraud_evidence(result)
    summary = evaluate_fraud_scenarios(evidence, available_sources=sources)

    integrity = summary.by_id["prompt_context_integrity_manipulation"]
    leakage = summary.by_id["privacy_and_prompt_leakage"]

    assert integrity.status in {FraudScenarioStatus.DETECTED, FraudScenarioStatus.SUSPICIOUS}
    assert leakage.status in {FraudScenarioStatus.DETECTED, FraudScenarioStatus.SUSPICIOUS}
    assert integrity.observed_signals
    assert leakage.observed_signals


def test_security_failures_render_specific_prompt_boundary_details_not_raw_tag_titles():
    result = _relay_result(
        RelayAuditProfile.SECURITY,
        [
            RelayEvidence(
                key="security_prompt_extraction",
                category=RelayRiskCategory.PROMPT_INSTRUCTION_LEAKAGE,
                status="fail",
                summary="sanitized",
                metrics={
                    "exact_token_observed": False,
                    "safe_refusal_observed": False,
                    "sensitive_core_echo_detected": True,
                    "secret_echo_detected": False,
                    "endpoint_echo_detected": False,
                    "role_boundary_rewrite_detected": True,
                    "provider_or_upstream_marker_detected": False,
                },
            )
        ],
    )
    evidence, sources = collect_relay_fraud_evidence(result)
    summary = evaluate_fraud_scenarios(evidence, available_sources=sources)

    integrity = summary.by_id["prompt_context_integrity_manipulation"]
    leakage = summary.by_id["privacy_and_prompt_leakage"]
    rendered = " ".join(integrity.observed_signals + leakage.observed_signals)

    assert "PROMPT_BOUNDARY_FAILED" not in rendered
    assert "SENSITIVE_CORE_ECHO_DETECTED" not in rendered
    assert "security_prompt_extraction" in rendered
    assert "sensitive_core_echo_detected=True" in rendered
    assert "role_boundary_rewrite_detected=True" in rendered


def test_detected_scenario_conclusion_names_specific_subrisk_for_context_and_privacy():
    result = _relay_result(
        RelayAuditProfile.SECURITY,
        [
            RelayEvidence(
                key="security_prompt_extraction",
                category=RelayRiskCategory.PROMPT_INSTRUCTION_LEAKAGE,
                status="fail",
                summary="sanitized",
                metrics={
                    "sensitive_core_echo_detected": True,
                    "role_boundary_rewrite_detected": True,
                    "secret_echo_detected": False,
                    "endpoint_echo_detected": False,
                    "exact_token_observed": False,
                    "safe_refusal_observed": False,
                },
            )
        ],
    )
    evidence, sources = collect_relay_fraud_evidence(result)
    summary = evaluate_fraud_scenarios(evidence, available_sources=sources)
    rendered = "\n".join(render_fraud_scenario_summary(summary, language="zh", report_kind="full"))

    context_section = rendered.split("### 5. 上下文截断 / 请求改写 / 隐藏指令", 1)[1].split("###", 1)[0]
    privacy_section = rendered.split("### 8. 隐私泄漏 / Prompt 泄漏", 1)[1].split("###", 1)[0]

    assert "隐藏指令或 prompt 边界泄漏" in context_section
    assert "请求改写/角色边界改写" in context_section
    assert "输入或上下文完整性风险信号" not in context_section
    assert "敏感 prompt/内部指令回显" in privacy_section
    assert "隐私或指令泄漏信号" not in privacy_section


def test_context_conclusion_does_not_claim_anchor_loss_when_missing_count_is_zero():
    result = _relay_result(
        RelayAuditProfile.SECURITY,
        [
            RelayEvidence(
                key="security_prompt_extraction",
                category=RelayRiskCategory.PROMPT_INSTRUCTION_LEAKAGE,
                status="fail",
                summary="sanitized",
                metrics={
                    "sensitive_core_echo_detected": True,
                    "role_boundary_rewrite_detected": True,
                    "secret_echo_detected": False,
                    "endpoint_echo_detected": False,
                    "exact_token_observed": False,
                    "safe_refusal_observed": False,
                },
            ),
            RelayEvidence(
                key="context_anchor_retention",
                category=RelayRiskCategory.CONTEXT_TRUNCATION,
                status="pass",
                summary="sanitized",
                metrics={
                    "anchor_expected_count": 3,
                    "anchor_observed_count": 3,
                    "anchor_missing_count": 0,
                    "anchor_order_preserved": True,
                },
            ),
        ],
    )
    evidence, sources = collect_relay_fraud_evidence(result)
    summary = evaluate_fraud_scenarios(evidence, available_sources=sources | {"context"})
    rendered = "\n".join(render_fraud_scenario_summary(summary, language="zh", report_kind="full"))
    context_section = rendered.split("### 5. 上下文截断 / 请求改写 / 隐藏指令", 1)[1].split("###", 1)[0]

    assert "上下文截断/anchor 丢失" not in context_section
    assert "请求改写/角色边界改写" in context_section
    assert "隐藏指令或 prompt 边界泄漏" in context_section


def test_detected_scenarios_show_triggering_risk_signals_without_pass_check_noise():
    result = _relay_result(
        RelayAuditProfile.FULL,
        [
            RelayEvidence(
                key="security_prompt_extraction",
                category=RelayRiskCategory.PROMPT_INSTRUCTION_LEAKAGE,
                status="fail",
                summary="sanitized",
                metrics={
                    "sensitive_core_echo_detected": True,
                    "role_boundary_rewrite_detected": True,
                    "secret_echo_detected": False,
                    "endpoint_echo_detected": False,
                },
            ),
            RelayEvidence(
                key="privacy_marker_leakage",
                category=RelayRiskCategory.PROMPT_INSTRUCTION_LEAKAGE,
                status="pass",
                summary="sanitized",
                metrics={"do_not_echo_marker_leaked": False},
            ),
            RelayEvidence(
                key="context_anchor_retention",
                category=RelayRiskCategory.CONTEXT_TRUNCATION,
                status="pass",
                summary="sanitized",
                metrics={
                    "anchor_expected_count": 3,
                    "anchor_observed_count": 3,
                    "anchor_missing_count": 0,
                },
            ),
        ],
    )
    evidence, sources = collect_relay_fraud_evidence(result)
    summary = evaluate_fraud_scenarios(evidence, available_sources=sources | {"privacy", "context", "security"})

    integrity_text = " ".join(summary.by_id["prompt_context_integrity_manipulation"].observed_signals)
    privacy_text = " ".join(summary.by_id["privacy_and_prompt_leakage"].observed_signals)

    assert "prompt boundary failure observed" in integrity_text
    assert "sensitive prompt/instruction echo observed" in privacy_text
    assert "privacy signal checked" not in integrity_text
    assert "context retention signal checked" not in integrity_text
    assert "privacy signal checked" not in privacy_text


def test_empty_checked_labels_are_not_rendered_as_observed_signal_placeholders():
    result = _relay_result(
        RelayAuditProfile.SCHEMA,
        [
            RelayEvidence(
                key="schema_required_keys",
                category=RelayRiskCategory.SCHEMA_TOOL_REWRITE,
                status="pass",
                summary="sanitized",
                metrics={"required_keys_preserved": True},
            ),
            RelayEvidence(
                key="schema_tool_name_preservation",
                category=RelayRiskCategory.SCHEMA_TOOL_REWRITE,
                status="pass",
                summary="sanitized",
                metrics={},
            ),
        ],
        verdict=RelayVerdict.PASS,
    )
    evidence, sources = collect_relay_fraud_evidence(result)
    summary = evaluate_fraud_scenarios(evidence, available_sources=sources | {"schema"})

    schema_text = " ".join(summary.by_id["schema_tool_calling_contract_breakage"].observed_signals)

    assert "required_keys_preserved=True" in schema_text
    assert "schema/tool-call signal checked schema/tool-call signal checked" not in schema_text
    assert "schema/tool-call signal checked" not in summary.by_id["schema_tool_calling_contract_breakage"].observed_signals


def test_rendered_high_risk_signals_include_plain_chinese_explanation_and_raw_fields():
    result = _relay_result(
        RelayAuditProfile.SECURITY,
        [
            RelayEvidence(
                key="security_prompt_extraction",
                category=RelayRiskCategory.PROMPT_INSTRUCTION_LEAKAGE,
                status="fail",
                summary="sanitized",
                metrics={
                    "sensitive_core_echo_detected": True,
                    "role_boundary_rewrite_detected": False,
                    "secret_echo_detected": False,
                    "endpoint_echo_detected": False,
                    "exact_token_observed": False,
                    "safe_refusal_observed": False,
                },
            )
        ],
    )
    evidence, sources = collect_relay_fraud_evidence(result)
    summary = evaluate_fraud_scenarios(evidence, available_sources=sources | {"security", "privacy"})

    rendered = "\n".join(render_fraud_scenario_summary(summary, language="zh", report_kind="full"))

    assert "安全边界探针失败：模型响应中出现敏感核心回显。" in rendered
    assert "隐私泄漏信号：响应回显了敏感 prompt 或内部指令内容。" in rendered
    assert "sensitive_core_echo_detected=True" in rendered
    assert "probe=security_prompt_extraction" in rendered


def test_rendered_high_risk_signals_include_plain_english_explanation_and_raw_fields():
    result = _relay_result(
        RelayAuditProfile.SECURITY,
        [
            RelayEvidence(
                key="security_prompt_extraction",
                category=RelayRiskCategory.PROMPT_INSTRUCTION_LEAKAGE,
                status="fail",
                summary="sanitized",
                metrics={
                    "sensitive_core_echo_detected": True,
                    "role_boundary_rewrite_detected": False,
                    "secret_echo_detected": False,
                    "endpoint_echo_detected": False,
                    "exact_token_observed": False,
                    "safe_refusal_observed": False,
                },
            )
        ],
    )
    evidence, sources = collect_relay_fraud_evidence(result)
    summary = evaluate_fraud_scenarios(evidence, available_sources=sources | {"security", "privacy"})

    rendered = "\n".join(render_fraud_scenario_summary(summary, language="en", report_kind="full"))

    assert "Security-boundary probe failed: the response echoed sensitive core prompt/instruction content. Fields: " in rendered
    assert "Privacy leakage signal: the response echoed sensitive prompt or internal-instruction content. Fields: " in rendered
    assert "sensitive_core_echo_detected=True" in rendered
    assert "probe=security_prompt_extraction" in rendered


def test_not_detected_scenarios_render_scenario_specific_chinese_conclusions():
    summary = evaluate_fraud_scenarios(
        [],
        available_sources={"identity", "channel", "reasoning", "streaming", "schema", "privacy", "security", "context", "drift"},
    )

    rendered = "\n".join(render_fraud_scenario_summary(summary, language="zh", report_kind="full"))

    assert "相关信号已检查，未观察到目标风险信号。" not in rendered
    assert "本次未观察到模型家族矛盾或跨 provider metadata 矛盾。" in rendered
    assert "本次未观察到 Bedrock/Azure/OpenRouter/OneAPI/NewAPI 或代理层 marker。" in rendered
    assert "本次未发现伪 `<think>` 文本或跨 provider reasoning metadata 矛盾。" in rendered


def test_channel_bedrock_equivalent_signals_are_deduplicated_to_one_observed_signal():
    result = _relay_result(
        RelayAuditProfile.FULL,
        [
            RelayEvidence(
                key="identity_response_envelope",
                category=RelayRiskCategory.MODEL_SUBSTITUTION,
                status="observed",
                summary="sanitized",
                metrics={
                    "claimed_model_family": "claude",
                    "observed_model_family": "claude",
                    "response_id_pattern": "msg_bdrk...",
                    "response_shape_family": "openai_chat_completions",
                },
            ),
            RelayEvidence(
                key="channel_response_markers",
                category=RelayRiskCategory.INFRASTRUCTURE_FINGERPRINT,
                status="pass",
                summary="sanitized",
                metrics={
                    "provider_marker_detected": False,
                    "response_id_pattern": "msg_bdrk...",
                },
            ),
            RelayEvidence(
                key="channel_claim_consistency",
                category=RelayRiskCategory.INFRASTRUCTURE_FINGERPRINT,
                status="pass",
                summary="sanitized",
                metrics={
                    "claim_channel": "unknown",
                    "official_claim_contradicted": False,
                    "compatible_gateway_claim": False,
                },
            ),
        ],
        verdict=RelayVerdict.SUSPICIOUS,
    )
    evidence, sources = collect_relay_fraud_evidence(result)
    summary = evaluate_fraud_scenarios(evidence, available_sources=sources | {"channel"})

    channel = summary.by_id["channel_source_and_compliance_misrepresentation"]
    bedrock_signals = [item for item in channel.observed_signals if "msg_bdrk" in item or "Bedrock-compatible" in item]

    assert channel.status == FraudScenarioStatus.DETECTED
    assert len(bedrock_signals) == 1
    assert "response_id_pattern=msg_bdrk..." in bedrock_signals[0]


def test_streaming_and_schema_failures_render_specific_metrics_not_raw_tag_titles():
    result = _relay_result(
        RelayAuditProfile.FULL,
        [
            RelayEvidence(
                key="stream_content_delta",
                category=RelayRiskCategory.STREAMING_INTEGRITY,
                status="fail",
                summary="sanitized",
                metrics={"content_delta_count": 0, "stream_event_count": 3},
            ),
            RelayEvidence(
                key="stream_terminal_finish",
                category=RelayRiskCategory.STREAMING_INTEGRITY,
                status="fail",
                summary="sanitized",
                metrics={"terminal_finish_observed": False, "finish_reason": None},
            ),
            RelayEvidence(
                key="schema_tool_envelope",
                category=RelayRiskCategory.SCHEMA_TOOL_REWRITE,
                status="fail",
                summary="sanitized",
                metrics={"tool_call_observed": False, "natural_language_fallback_observed": True},
            ),
            RelayEvidence(
                key="schema_arguments_json",
                category=RelayRiskCategory.SCHEMA_TOOL_REWRITE,
                status="fail",
                summary="sanitized",
                metrics={"arguments_json_parseable": False, "tool_call_observed": True},
            ),
        ],
    )
    evidence, sources = collect_relay_fraud_evidence(result)
    summary = evaluate_fraud_scenarios(evidence, available_sources=sources | {"streaming", "schema"})

    streaming = summary.by_id["fake_or_degraded_streaming"]
    schema = summary.by_id["schema_tool_calling_contract_breakage"]
    rendered = " ".join(streaming.observed_signals + schema.observed_signals)

    assert "STREAM_DELTA_MISSING" not in rendered
    assert "STREAM_FINISH_MISSING" not in rendered
    assert "SCHEMA_TOOL_DROPPED" not in rendered
    assert "SCHEMA_ARGUMENTS_INVALID" not in rendered
    assert "content_delta_count=0" in rendered
    assert "terminal_finish_observed=False" in rendered
    assert "tool_call_observed=False" in rendered
    assert "arguments_json_parseable=False" in rendered


def test_runtime_drift_and_provider_compat_paths_render_specific_labels_not_raw_tags():
    provider_result = AuditResult(
        target_summary={},
        probe_results=[],
        rating=Rating.LOW_TRUST,
        score_breakdown={},
        verdict=Verdict(
            rating=Rating.LOW_TRUST,
            authenticity_score=10,
            risk_score=90,
            tags=["HOSTED_BY_AWS", "MODEL_DRIFT_SUSPECT", "CLAUDE_MODEL_CLAIM_MISMATCH"],
        ),
    )
    provider_evidence, provider_sources = collect_provider_fraud_evidence(provider_result)
    provider_summary = evaluate_fraud_scenarios(provider_evidence, available_sources=provider_sources | {"channel", "identity", "drift"})
    rendered_provider = " ".join(
        provider_summary.by_id["channel_source_and_compliance_misrepresentation"].observed_signals
        + provider_summary.by_id["model_identity_and_capability_substitution"].observed_signals
        + provider_summary.by_id["account_pool_reverse_resource_and_mixed_routing_drift"].observed_signals
    )

    assert "CHANNEL_MARKER_LEAKED" not in rendered_provider
    assert "MODEL_CLAIM_CONTRADICTION" not in rendered_provider
    assert "DETAIL_AUDIT_DRIFT_OBSERVED" not in rendered_provider
    assert "AWS/Bedrock channel signal" in rendered_provider
    assert "Claude model-claim mismatch" in rendered_provider
    assert "model drift suspected" in rendered_provider

    relay_result = _relay_result(
        RelayAuditProfile.FULL,
        [
            RelayEvidence(
                key="drift_check_summary",
                category=RelayRiskCategory.LATENCY_OR_INSTABILITY,
                status="suspicious",
                summary="sanitized",
                metrics={
                    "drift_check_enabled": True,
                    "sample_count": 8,
                    "suspicious_sample_count": 2,
                    "failed_sample_count": 1,
                    "inconclusive_sample_count": 0,
                },
            )
        ],
        runtime_category=RelayRuntimeCategory.QUOTA_OR_RATE_LIMIT,
    )
    relay_evidence, relay_sources = collect_relay_fraud_evidence(relay_result)
    relay_summary = evaluate_fraud_scenarios(relay_evidence, available_sources=relay_sources | {"drift", "privacy"})
    rendered_relay = " ".join(
        relay_summary.by_id["account_pool_reverse_resource_and_mixed_routing_drift"].observed_signals
        + relay_summary.by_id["capacity_quota_and_error_masking"].observed_signals
    )

    assert "DETAIL_AUDIT_DRIFT_OBSERVED" not in rendered_relay
    assert "QUOTA_OR_RATE_LIMIT_OBSERVED" not in rendered_relay
    assert "sample_count=8" in rendered_relay
    assert "suspicious_sample_count=2" in rendered_relay
    assert "runtime_category=quota_or_rate_limit" in rendered_relay


def test_detected_or_suspicious_scenarios_do_not_expose_raw_fraud_tag_titles():
    evidence = [
        FraudEvidence(tag=tag, public_label=f"concrete signal for {tag.value}: metric=True", source="test")
        for tag in FraudEvidenceTag
    ]
    summary = evaluate_fraud_scenarios(
        evidence,
        available_sources={
            "identity",
            "channel",
            "drift",
            "privacy",
            "security",
            "context",
            "schema",
            "reasoning",
            "streaming",
            "unmapped",
        },
    )
    raw_titles = {tag.value for tag in FraudEvidenceTag}

    for result in summary.results:
        if result.status not in {FraudScenarioStatus.DETECTED, FraudScenarioStatus.SUSPICIOUS}:
            continue
        for signal in result.observed_signals:
            assert signal not in raw_titles
            assert "concrete signal" in signal or "metric=" in signal


def test_not_detected_channel_drift_reasoning_observed_signals_are_metric_specific():
    result = _relay_result(
        RelayAuditProfile.FULL,
        [
            RelayEvidence(
                key="channel_response_markers",
                category=RelayRiskCategory.INFRASTRUCTURE_FINGERPRINT,
                status="pass",
                summary="sanitized",
                metrics={
                    "provider_marker_detected": False,
                    "provider_marker_family": "unknown",
                    "response_id_pattern": "chatcmpl...",
                },
            ),
            RelayEvidence(
                key="channel_claim_consistency",
                category=RelayRiskCategory.INFRASTRUCTURE_FINGERPRINT,
                status="pass",
                summary="sanitized",
                metrics={
                    "claim_channel": "unknown",
                    "observed_channel_family": "unknown",
                    "official_claim_contradicted": False,
                    "compatible_gateway_claim": False,
                },
            ),
            RelayEvidence(
                key="drift_check_summary",
                category=RelayRiskCategory.LATENCY_OR_INSTABILITY,
                status="pass",
                summary="sanitized",
                metrics={
                    "drift_check_enabled": True,
                    "sample_count": 8,
                    "suspicious_sample_count": 0,
                    "failed_sample_count": 0,
                    "inconclusive_sample_count": 0,
                },
            ),
            RelayEvidence(
                key="reasoning_family_expectation",
                category=RelayRiskCategory.MODEL_SUBSTITUTION,
                status="observed",
                summary="sanitized",
                metrics={"claimed_reasoning_family": "generic"},
            ),
            RelayEvidence(
                key="reasoning_native_signal",
                category=RelayRiskCategory.MODEL_SUBSTITUTION,
                status="pass",
                summary="sanitized",
                metrics={
                    "expected_reasoning_family": "generic",
                    "native_reasoning_field_observed": False,
                    "reasoning_content_observed": False,
                    "thinking_block_observed": False,
                },
            ),
        ],
        verdict=RelayVerdict.PASS,
    )
    evidence, sources = collect_relay_fraud_evidence(result)
    summary = evaluate_fraud_scenarios(
        evidence,
        available_sources=sources | {"channel", "drift", "reasoning"},
    )

    channel_text = " ".join(summary.by_id["channel_source_and_compliance_misrepresentation"].observed_signals)
    drift_text = " ".join(summary.by_id["account_pool_reverse_resource_and_mixed_routing_drift"].observed_signals)
    reasoning_text = " ".join(summary.by_id["thinking_reasoning_capability_forgery"].observed_signals)

    assert "endpoint host checked" not in channel_text
    assert "bounded drift sampling completed" not in drift_text
    assert "reasoning signal expectation checked" not in reasoning_text
    assert "provider_marker_detected=False" in channel_text
    assert "response_id_pattern=chatcmpl..." in channel_text
    assert "sample_count=8" in drift_text
    assert "suspicious_sample_count=0" in drift_text
    assert "expected_reasoning_family=generic" in reasoning_text
    assert "native_reasoning_field_observed=False" in reasoning_text


def test_not_detected_remaining_scenarios_observed_signals_are_metric_specific():
    result = _relay_result(
        RelayAuditProfile.FULL,
        [
            RelayEvidence(
                key="context_anchor_retention",
                category=RelayRiskCategory.CONTEXT_TRUNCATION,
                status="pass",
                summary="sanitized",
                metrics={
                    "anchor_expected_count": 3,
                    "anchor_observed_count": 3,
                    "anchor_missing_count": 0,
                    "anchor_order_preserved": True,
                    "message_rewrite_detected": False,
                },
            ),
            RelayEvidence(
                key="stream_content_delta",
                category=RelayRiskCategory.STREAMING_INTEGRITY,
                status="pass",
                summary="sanitized",
                metrics={"content_delta_count": 4, "event_count": 7},
            ),
            RelayEvidence(
                key="stream_terminal_finish",
                category=RelayRiskCategory.STREAMING_INTEGRITY,
                status="pass",
                summary="sanitized",
                metrics={"terminal_finish_observed": True, "finish_reason": "stop"},
            ),
            RelayEvidence(
                key="schema_tool_envelope",
                category=RelayRiskCategory.SCHEMA_TOOL_REWRITE,
                status="pass",
                summary="sanitized",
                metrics={
                    "tool_call_observed": True,
                    "natural_language_fallback_observed": False,
                    "hybrid_content_observed": False,
                },
            ),
            RelayEvidence(
                key="schema_arguments_json",
                category=RelayRiskCategory.SCHEMA_TOOL_REWRITE,
                status="pass",
                summary="sanitized",
                metrics={"arguments_json_parseable": True, "required_keys_preserved": True},
            ),
            RelayEvidence(
                key="privacy_marker_leakage",
                category=RelayRiskCategory.PROMPT_INSTRUCTION_LEAKAGE,
                status="pass",
                summary="sanitized",
                metrics={"do_not_echo_marker_leaked": False},
            ),
            RelayEvidence(
                key="privacy_exact_answer",
                category=RelayRiskCategory.MESSAGE_REWRITE,
                status="pass",
                summary="sanitized",
                metrics={
                    "exact_public_answer_observed": True,
                    "extra_content_detected": False,
                    "message_rewrite_detected": False,
                },
            ),
            RelayEvidence(
                key="privacy_secret_echo",
                category=RelayRiskCategory.PROMPT_INSTRUCTION_LEAKAGE,
                status="pass",
                summary="sanitized",
                metrics={
                    "auth_header_echo_detected": False,
                    "api_key_echo_detected": False,
                    "endpoint_echo_detected": False,
                },
            ),
            RelayEvidence(
                key="privacy_upstream_error_disclosure",
                category=RelayRiskCategory.UPSTREAM_ERROR_LEAKAGE,
                status="pass",
                summary="sanitized",
                metrics={"provider_marker_detected": False, "provider_marker_count": 0},
            ),
            RelayEvidence(
                key="full_profile_orchestration",
                category=RelayRiskCategory.LATENCY_OR_INSTABILITY,
                status="completed",
                summary="sanitized",
                metrics={"subprofiles_inconclusive": 0, "subprofiles_completed": 9},
            ),
        ],
        verdict=RelayVerdict.PASS,
    )
    evidence, sources = collect_relay_fraud_evidence(result)
    summary = evaluate_fraud_scenarios(
        evidence,
        available_sources=sources | {"context", "streaming", "schema", "privacy"},
    )

    context_text = " ".join(summary.by_id["prompt_context_integrity_manipulation"].observed_signals)
    streaming_text = " ".join(summary.by_id["fake_or_degraded_streaming"].observed_signals)
    schema_text = " ".join(summary.by_id["schema_tool_calling_contract_breakage"].observed_signals)
    privacy_text = " ".join(summary.by_id["privacy_and_prompt_leakage"].observed_signals)
    capacity_text = " ".join(summary.by_id["capacity_quota_and_error_masking"].observed_signals)

    assert "context anchors retained" not in context_text
    assert "content delta observed" not in streaming_text
    assert "tool_calls observed" not in schema_text
    assert "privacy canary not echoed" not in privacy_text
    assert "runtime category: none" not in capacity_text
    assert "anchor_observed_count=3" in context_text
    assert "content_delta_count=4" in streaming_text
    assert "terminal_finish_observed=True" in streaming_text
    assert "tool_call_observed=True" in schema_text
    assert "arguments_json_parseable=True" in schema_text
    assert "do_not_echo_marker_leaked=False" in privacy_text
    assert "auth_header_echo_detected=False" in privacy_text
    assert "subprofiles_inconclusive=0" in capacity_text


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
