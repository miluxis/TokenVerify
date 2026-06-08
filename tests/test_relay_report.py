from tokenverify.relay_fake import build_fake_relay_result
from tokenverify.relay_live import RelayLiveTransportResponse, run_minimal_general_live_check
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
from tokenverify.relay_report import render_relay_markdown
from tokenverify.relay_safety import authorize_relay_live_execution


def test_relay_report_renders_required_sections_and_sanitized_endpoint():
    result = build_fake_relay_result(
        profile=RelayAuditProfile.GENERAL,
        scenario=RelayVerdict.SUSPICIOUS,
        endpoint="https://api.relay.com/v1/chat/completions?user=heiyan_studio#frag",
        model="example-model",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
    )

    markdown = render_relay_markdown(result)

    assert "# TokenVerify Relay Technical Profile Report" in markdown
    assert "Technical Result" in markdown
    assert "Supported Scenario Scope" in markdown
    assert "Sanitized Evidence" in markdown
    assert "Method Note" in markdown
    assert "Fake-run mode was deterministic and no live network request was made." in markdown
    assert "api.relay.com" in markdown
    assert result.endpoint_hash in markdown
    assert "https://" not in markdown
    assert "/v1" not in markdown
    assert "heiyan_studio" not in markdown
    assert "#frag" not in markdown


def test_relay_report_supports_chinese_language():
    result = build_fake_relay_result(
        profile=RelayAuditProfile.GENERAL,
        scenario=RelayVerdict.SUSPICIOUS,
        endpoint="https://api.relay.com/v1/chat/completions?user=heiyan_studio#frag",
        model="example-model",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
    )

    markdown = render_relay_markdown(result, language="zh")

    assert "# TokenVerify Relay Technical Profile Report" in markdown
    assert "技术检查结果" in markdown
    assert "支撑场景范围" in markdown
    assert "脱敏证据" in markdown
    assert "方法说明" in markdown
    assert "Fake-run 为确定性演示，未发送真实网络请求。" in markdown
    assert "api.relay.com" in markdown
    assert "https://" not in markdown
    assert "/v1" not in markdown
    assert "heiyan_studio" not in markdown


def test_relay_report_includes_safe_pack_summary_without_private_content():
    result = build_fake_relay_result(
        profile=RelayAuditProfile.GENERAL,
        scenario=RelayVerdict.PASS,
        endpoint="https://relay.example/v1",
        model="example-model",
        pack_summary=RelayPackSummary(
            label="Local Private Pack",
            pack_hash="a1b2c3d4e5f60708",
            pack_id="private-media-pack",
            version="2026.06",
            basename="my_private_pack.yaml",
        ),
    )

    markdown = render_relay_markdown(result)

    assert "Local Private Pack" in markdown
    assert "private-media-pack" in markdown
    assert "2026.06" in markdown
    assert "a1b2c3d4e5f60708" in markdown
    assert "my_private_pack.yaml" in markdown
    assert "raw prompt" not in markdown
    assert "expected answer" not in markdown
    assert "verifier expression" not in markdown
    assert "/Users" not in markdown


def test_relay_report_renders_rich_pack_metadata_without_private_content():
    result = build_fake_relay_result(
        profile=RelayAuditProfile.GENERAL,
        scenario=RelayVerdict.PASS,
        endpoint="https://relay.example/v1",
        model="example-model",
        pack_summary=RelayPackSummary(
            label="Local Private Pack",
            pack_hash="a1b2c3d4e5f60708",
            pack_id="private-media-pack",
            version="2026.06",
            basename="my_private_pack.yaml",
            profiles=["general", "privacy"],
            categories=["model_substitution", "upstream_error_leakage"],
            challenge_count=2,
            public_intents=["Checks a public relay contract."],
        ),
    )

    markdown = render_relay_markdown(result)

    assert "Profiles: general, privacy" in markdown
    assert "Categories: model_substitution, upstream_error_leakage" in markdown
    assert "Challenges: 2" in markdown
    assert "Intent: Checks a public relay contract." in markdown
    assert "stable-case-001" not in markdown
    assert "raw prompt" not in markdown
    assert "private expected answer" not in markdown
    assert "secret verifier" not in markdown


def test_relay_report_inconclusive_section_is_explicit():
    result = build_fake_relay_result(
        profile=RelayAuditProfile.GENERAL,
        scenario=RelayVerdict.INCONCLUSIVE,
        endpoint="https://relay.example/v1",
        model="example-model",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
    )

    markdown = render_relay_markdown(result)

    assert "Inconclusive Explanation" in markdown
    assert "not a relay misconduct finding" in markdown


def test_relay_report_renders_live_mode_without_overclaiming_or_raw_endpoint():
    auth = authorize_relay_live_execution(live_mode=True, profile=RelayAuditProfile.GENERAL)
    result = run_minimal_general_live_check(
        authorization=auth,
        endpoint="https://api.relay.com/v1/chat/completions?user=heiyan_studio#frag",
        model="example-model",
        api_key="sk-secret",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        transport=lambda payload: RelayLiveTransportResponse(
            status_code=200,
            body={"choices": [{"message": {"content": "ok"}}]},
        ),
    )

    markdown = render_relay_markdown(result)

    assert "- Mode: live" in markdown
    assert "Minimal live connectivity check completed" in markdown
    assert "Live mode made only the approved minimal general connectivity request." in markdown
    assert "Fake-run mode was deterministic" not in markdown
    assert "verified upstream" not in markdown.lower()
    assert "sk-secret" not in markdown
    assert "https://" not in markdown
    assert "/v1" not in markdown
    assert "heiyan_studio" not in markdown


def test_relay_report_renders_sanitized_live_runtime_category():
    auth = authorize_relay_live_execution(live_mode=True, profile=RelayAuditProfile.GENERAL)

    def transport(payload):
        raise RuntimeError("HTTP 401 https://api.relay.com/v1?token=secret Authorization: Bearer sk-secret")

    result = run_minimal_general_live_check(
        authorization=auth,
        endpoint="https://api.relay.com/v1?token=secret",
        model="example-model",
        api_key="sk-secret",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        transport=transport,
    )

    markdown = render_relay_markdown(result)

    assert "- Runtime category: auth_error" in markdown
    assert "Provider authentication or authorization error." in markdown
    assert "https://" not in markdown
    assert "token=secret" not in markdown
    assert "sk-secret" not in markdown


def test_channel_inconclusive_report_explains_no_analyzable_channel_response():
    result = RelayResult(
        run_id="relay-channel-auth-error",
        profile=RelayAuditProfile.CHANNEL,
        scenario=RelayVerdict.INCONCLUSIVE,
        mode=RelayAuditMode.LIVE,
        model="claude-sonnet-4-5-20250929-thinking",
        endpoint_host="hk.hboom.ai",
        endpoint_hash="0edc300d891a87a7",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=RelayVerdict.INCONCLUSIVE,
        risk_level=RelayRiskLevel.UNKNOWN,
        risk_categories=[RelayRiskCategory.UPSTREAM_ERROR_LEAKAGE],
        evidence=[
            RelayEvidence(
                key="channel_envelope_unavailable",
                category=RelayRiskCategory.UPSTREAM_ERROR_LEAKAGE,
                status="inconclusive",
                summary="Provider authentication or authorization error.",
                metrics={"http_status": 401, "analyzable_response": False},
            )
        ],
        retest_guidance="Resolve channel runtime conditions.",
        inconclusive_reason="Provider authentication or authorization error.",
    )

    markdown = render_relay_markdown(result, language="zh")

    assert "## 技术信号" in markdown
    assert "channel_envelope_unavailable" in markdown
    assert "http_status=401" in markdown
    assert "analyzable_response=False" in markdown
    assert "没有拿到可分析的 200 响应" in markdown
    assert "channel marker not detected" not in markdown.lower()


def test_channel_profile_report_renders_concrete_marker_metrics():
    result = RelayResult(
        run_id="relay-channel-bedrock",
        profile=RelayAuditProfile.CHANNEL,
        scenario=RelayVerdict.SUSPICIOUS,
        mode=RelayAuditMode.LIVE,
        model="claude-sonnet-4-5-20250929-thinking",
        endpoint_host="hk.hboom.ai",
        endpoint_hash="0edc300d891a87a7",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=RelayVerdict.SUSPICIOUS,
        risk_level=RelayRiskLevel.MEDIUM,
        risk_categories=[RelayRiskCategory.INFRASTRUCTURE_FINGERPRINT],
        evidence=[
            RelayEvidence(
                key="channel_response_markers",
                category=RelayRiskCategory.INFRASTRUCTURE_FINGERPRINT,
                status="observed",
                summary="Sanitized channel marker extraction completed.",
                metrics={
                    "provider_marker_detected": True,
                    "observed_channel_family": "bedrock",
                    "response_id_pattern": "msg_bdrk...",
                    "response_shape_family": "anthropic_messages",
                },
            )
        ],
        retest_guidance="Rerun channel.",
    )

    markdown = render_relay_markdown(result, language="zh")

    assert "observed_channel_family=bedrock" in markdown
    assert "response_id_pattern=msg_bdrk..." in markdown
    assert "response_shape_family=anthropic_messages" in markdown
    assert "endpoint host checked" not in markdown


def test_relay_report_renders_fraud_scenario_summary_with_detected_status_and_breadcrumbs():
    result = RelayResult(
        run_id="relay-security-test",
        profile=RelayAuditProfile.SECURITY,
        scenario=RelayVerdict.FAIL,
        mode=RelayAuditMode.LIVE,
        model="claude-opus-4-5",
        endpoint_host="relay.example",
        endpoint_hash="abcdef1234567890",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=RelayVerdict.FAIL,
        risk_level=RelayRiskLevel.HIGH,
        risk_categories=[RelayRiskCategory.PROMPT_INSTRUCTION_LEAKAGE],
        evidence=[
            RelayEvidence(
                key="security_prompt_extraction",
                category=RelayRiskCategory.PROMPT_INSTRUCTION_LEAKAGE,
                status="fail",
                summary="raw prompt https://relay.example/v1 Authorization: Bearer sk-secret must not appear",
                metrics={"sensitive_core_echo_detected": True},
            )
        ],
        retest_guidance="Retest.",
    )

    markdown = render_relay_markdown(result)

    assert "# TokenVerify Relay Technical Profile Report" in markdown
    assert "Supported Scenario Scope" in markdown
    assert "Prompt-security boundary" in markdown
    assert "https://" not in markdown
    assert "sk-secret" not in markdown
    assert "raw prompt" not in markdown


def test_relay_report_renders_fraud_scenario_summary_in_chinese():
    result = build_fake_relay_result(
        profile=RelayAuditProfile.STREAMING,
        scenario=RelayVerdict.PASS,
        endpoint="https://relay.example/v1",
        model="example-model",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
    )

    markdown = render_relay_markdown(result, language="zh")

    assert "# TokenVerify Relay Technical Profile Report" in markdown
    assert "支撑场景范围" in markdown
    assert "TokenVerify" in markdown


def test_streaming_report_safety_note_and_evidence_are_sanitized():
    result = RelayResult(
        run_id="relay-stream-test",
        profile=RelayAuditProfile.STREAMING,
        scenario=RelayVerdict.SUSPICIOUS,
        mode=RelayAuditMode.LIVE,
        model="example-model",
        endpoint_host="api.relay.com",
        endpoint_hash="abcdef1234567890",
        pack_summary=RelayPackSummary(
            label="Local Pack",
            pack_hash="packhash123",
            basename="private.yaml",
            public_intents=["streaming smoke check"],
        ),
        verdict=RelayVerdict.SUSPICIOUS,
        risk_level=RelayRiskLevel.MEDIUM,
        risk_categories=[RelayRiskCategory.STREAMING_INTEGRITY],
        evidence=[
            RelayEvidence(
                key="synthetic_stream_heuristic",
                category=RelayRiskCategory.STREAMING_INTEGRITY,
                status="suspicious",
                summary=(
                    "Uniform stream chunks are a heuristic risk indicator, not proof of provider forgery. "
                    'data: {"choices": [{"delta": {"content": "raw stream chunk text must not appear"}}]}'
                ),
                metrics={
                    "event_count": 6,
                    "content_delta_count": 5,
                    "terminal_finish_observed": True,
                    "uniform_chunk_size_detected": True,
                    "chunk_count": 5,
                    "finish_reason": "stop",
                },
            )
        ],
        retest_guidance="Rerun streaming checks.",
    )

    markdown = render_relay_markdown(result)

    assert "approved minimal streaming/SSE integrity request" in markdown
    assert "only the approved minimal general connectivity request" not in markdown
    assert "synthetic_stream_heuristic" in markdown
    assert "uniform_chunk_size_detected=True" in markdown
    assert "raw stream chunk text must not appear" not in markdown
    assert "data:" not in markdown
    assert '{"choices"' not in markdown
    assert "private expected answer" not in markdown
    assert "secret verifier expression" not in markdown


def test_streaming_report_strips_multiline_sse_json_shells():
    result = RelayResult(
        run_id="relay-stream-test",
        profile=RelayAuditProfile.STREAMING,
        scenario=RelayVerdict.INCONCLUSIVE,
        mode=RelayAuditMode.LIVE,
        model="example-model",
        endpoint_host="api.relay.com",
        endpoint_hash="abcdef1234567890",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=RelayVerdict.INCONCLUSIVE,
        risk_level=RelayRiskLevel.UNKNOWN,
        risk_categories=[RelayRiskCategory.UPSTREAM_ERROR_LEAKAGE],
        evidence=[
            RelayEvidence(
                key="unknown_runtime_error",
                category=RelayRiskCategory.UPSTREAM_ERROR_LEAKAGE,
                status="inconclusive",
                summary='data: {\n  "choices": [{"delta": {"content": "raw stream chunk text must not appear"}}]\n}',
            )
        ],
        retest_guidance="Rerun streaming checks.",
        inconclusive_reason='{"choices": [\n{"delta": {"content": "raw stream chunk text must not appear"}}\n]}',
    )

    markdown = render_relay_markdown(result)

    assert "raw stream chunk text must not appear" not in markdown
    assert "data:" not in markdown
    assert '{"choices"' not in markdown


def test_schema_report_safety_note_and_evidence_are_sanitized():
    result = RelayResult(
        run_id="relay-schema-test",
        profile=RelayAuditProfile.SCHEMA,
        scenario=RelayVerdict.SUSPICIOUS,
        mode=RelayAuditMode.LIVE,
        model="example-model",
        endpoint_host="api.relay.com",
        endpoint_hash="abcdef1234567890",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=RelayVerdict.SUSPICIOUS,
        risk_level=RelayRiskLevel.MEDIUM,
        risk_categories=[RelayRiskCategory.SCHEMA_TOOL_REWRITE],
        evidence=[
            RelayEvidence(
                key="schema_extra_keys",
                category=RelayRiskCategory.SCHEMA_TOOL_REWRITE,
                status="suspicious",
                summary='{"tool_calls": [{"function": {"arguments": "{\\"secret\\":\\"raw schema argument must not appear\\"}"}}]}',
                metrics={"unexpected_key_count": 1, "hybrid_content_observed": True},
            )
        ],
        retest_guidance="Rerun schema checks.",
    )

    markdown = render_relay_markdown(result)

    assert "approved minimal schema/tool preservation request" in markdown
    assert "schema_extra_keys" in markdown
    assert "unexpected_key_count=1" in markdown
    assert "raw schema argument must not appear" not in markdown
    assert '{"tool_calls"' not in markdown
    assert "function.arguments" not in markdown


def test_full_profile_report_includes_runtime_notice_and_sanitizes_mixed_shells():
    result = RelayResult(
        run_id="relay-full-test",
        profile=RelayAuditProfile.FULL,
        scenario=RelayVerdict.SUSPICIOUS,
        mode=RelayAuditMode.LIVE,
        model="example-model",
        endpoint_host="relay.example",
        endpoint_hash="abcd1234abcd1234",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=RelayVerdict.SUSPICIOUS,
        risk_level=RelayRiskLevel.MEDIUM,
        risk_categories=[RelayRiskCategory.SCHEMA_TOOL_REWRITE],
        evidence=[
            RelayEvidence(
                key="full_profile_runtime_cost_notice",
                category=RelayRiskCategory.LATENCY_OR_INSTABILITY,
                status="notice",
                summary="Full profile uses multiple approved checks and may use more live requests than a single profile.",
                metrics={
                    "planned_live_request_count": 4,
                    "completed_live_request_count": 4,
                    "private_pack_executed": False,
                    "leaky": 'data: {"choices": [{"delta": {"content": "raw stream chunk must not appear"}}]} {"tool_calls": [{"function": {"arguments": "raw schema args must not appear"}}]} {"messages": [{"role": "system", "content": "TV_PRIVACY_MARKER_DO_NOT_ECHO"}]} {"error": {"message": "raw upstream provider error must not appear"}}',
                },
            )
        ],
        retest_guidance="Rerun full profile after resolving any inconclusive subprofile runtime causes.",
    )

    markdown = render_relay_markdown(result)

    assert "## Overall Conclusion" in markdown
    assert "## Fraud Scenario Summary" in markdown
    assert "## Technical Signal Overview" in markdown
    assert "raw stream chunk must not appear" not in markdown
    assert "raw schema args must not appear" not in markdown
    assert "TV_PRIVACY_MARKER_DO_NOT_ECHO" not in markdown
    assert "raw upstream provider error must not appear" not in markdown
    assert '{"tool_calls"' not in markdown
    assert '{"messages"' not in markdown
    assert 'data: {"choices"' not in markdown
    assert '{"error"' not in markdown


def test_full_report_uses_signal_first_overall_conclusion_for_no_signals():
    result = RelayResult(
        run_id="relay-full-no-signal",
        profile=RelayAuditProfile.FULL,
        scenario=RelayVerdict.PASS,
        mode=RelayAuditMode.LIVE,
        model="claude-opus-4-5-20251101",
        endpoint_host="relay.example",
        endpoint_hash="abcd1234abcd1234",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=RelayVerdict.PASS,
        risk_level=RelayRiskLevel.LOW,
        risk_categories=[],
        evidence=[
            RelayEvidence(
                key="full_profile_composite_verdict",
                category=RelayRiskCategory.LATENCY_OR_INSTABILITY,
                status="observed",
                summary="Composite verdict was derived from sanitized subprofile verdicts.",
                metrics={
                    "general": {"verdict": "pass", "evidence_keys": ["minimal_live_connectivity"]},
                    "identity": {"verdict": "pass", "evidence_keys": ["identity_response_envelope"]},
                    "channel": {"verdict": "pass", "evidence_keys": ["channel_claim_consistency"]},
                    "reasoning": {"verdict": "pass", "evidence_keys": ["reasoning_native_signal"]},
                    "streaming": {"verdict": "pass", "evidence_keys": ["stream_content_delta", "stream_terminal_finish"]},
                    "schema": {"verdict": "pass", "evidence_keys": ["schema_tool_envelope", "schema_arguments_json"]},
                    "privacy": {"verdict": "pass", "evidence_keys": ["privacy_marker_leakage"]},
                    "security": {"verdict": "pass", "evidence_keys": ["security_boundary_control"]},
                    "context": {"verdict": "pass", "evidence_keys": ["context_anchor_retention"]},
                },
            )
        ],
        retest_guidance="Rerun full profile.",
    )

    markdown = render_relay_markdown(result, language="zh")

    assert "## 总体结论" in markdown
    assert "## 通俗结论" not in markdown
    assert "总体判断：**未观察到明显高风险信号**" in markdown
    assert "总体判断：**Pass**" not in markdown
    assert "主要风险信号" not in markdown
    assert "本次未观察到" in markdown


def test_full_report_uses_high_risk_signal_judgment_when_scenario_detected():
    result = RelayResult(
        run_id="relay-full-high-risk",
        profile=RelayAuditProfile.FULL,
        scenario=RelayVerdict.FAIL,
        mode=RelayAuditMode.LIVE,
        model="deepseek-r1",
        endpoint_host="relay.example",
        endpoint_hash="abcd1234abcd1234",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=RelayVerdict.FAIL,
        risk_level=RelayRiskLevel.HIGH,
        risk_categories=[RelayRiskCategory.MODEL_SUBSTITUTION],
        evidence=[
            RelayEvidence(
                key="reasoning_native_signal",
                category=RelayRiskCategory.MODEL_SUBSTITUTION,
                status="fail",
                summary="Native reasoning field was not observed for expected reasoning family.",
                metrics={
                    "expected_reasoning_family": "deepseek_r1",
                    "native_reasoning_field_observed": False,
                    "reasoning_content_observed": False,
                },
            )
        ],
        retest_guidance="Rerun full profile.",
    )

    markdown = render_relay_markdown(result, language="zh")

    assert "总体判断：**观察到高风险信号**" in markdown
    assert "主要风险信号" in markdown
    assert "Reasoning native signal" in markdown or "reasoning native" in markdown
    assert "总体判断：**Fail**" not in markdown


def test_full_english_report_main_risk_signals_use_plain_explanation_layer():
    result = RelayResult(
        run_id="relay-full-english-top-risk-explanation",
        profile=RelayAuditProfile.FULL,
        scenario=RelayVerdict.FAIL,
        mode=RelayAuditMode.LIVE,
        model="claude-sonnet-4-5-20250929",
        endpoint_host="relay.example",
        endpoint_hash="abcd1234abcd1234",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=RelayVerdict.FAIL,
        risk_level=RelayRiskLevel.HIGH,
        risk_categories=[RelayRiskCategory.PROMPT_INSTRUCTION_LEAKAGE],
        evidence=[
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
        retest_guidance="Rerun full profile.",
    )

    markdown = render_relay_markdown(result, language="en")
    top_section = markdown.split("## Fraud Scenario Summary", 1)[0]

    assert "Main observed risk signals:" in top_section
    assert "Security-boundary probe failed: the response echoed sensitive core prompt/instruction content. Fields: " in top_section
    assert "Privacy leakage signal: the response echoed sensitive prompt or internal-instruction content. Fields: " in top_section
    assert "  - prompt boundary failure observed: probe=security_prompt_extraction" not in top_section


def test_full_report_scenario_sections_explain_observed_and_absent_signals():
    result = RelayResult(
        run_id="relay-full-signal-section",
        profile=RelayAuditProfile.FULL,
        scenario=RelayVerdict.PASS,
        mode=RelayAuditMode.LIVE,
        model="claude-opus-4-5-20251101",
        endpoint_host="relay.example",
        endpoint_hash="abcd1234abcd1234",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=RelayVerdict.PASS,
        risk_level=RelayRiskLevel.LOW,
        risk_categories=[],
        evidence=[
            RelayEvidence(
                key="full_profile_composite_verdict",
                category=RelayRiskCategory.LATENCY_OR_INSTABILITY,
                status="observed",
                summary="Composite verdict was derived from sanitized subprofile verdicts.",
                metrics={"identity": {"verdict": "pass"}, "channel": {"verdict": "pass"}},
            )
        ],
        retest_guidance="Rerun full profile.",
    )

    markdown = render_relay_markdown(result, language="zh")

    assert "观察到的信号" in markdown
    assert "未观察到的信号" in markdown
    assert "解释" in markdown
    assert "已运行的相关检查中未观察到匹配证据。" not in markdown


def test_full_report_with_security_fail_does_not_render_all_scenarios_not_detected():
    result = RelayResult(
        run_id="relay-full-security-fail",
        profile=RelayAuditProfile.FULL,
        scenario=RelayVerdict.FAIL,
        mode=RelayAuditMode.LIVE,
        model="example-model",
        endpoint_host="relay.example",
        endpoint_hash="abcd1234abcd1234",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=RelayVerdict.FAIL,
        risk_level=RelayRiskLevel.HIGH,
        risk_categories=[RelayRiskCategory.PROMPT_INSTRUCTION_LEAKAGE],
        evidence=[
            RelayEvidence(
                key="security_prompt_extraction",
                category=RelayRiskCategory.PROMPT_INSTRUCTION_LEAKAGE,
                status="fail",
                summary="sanitized",
                metrics={"prompt_extraction_signal_detected": True, "sensitive_core_echo_detected": True},
            )
        ],
        retest_guidance="Rerun full profile.",
    )

    markdown = render_relay_markdown(result, language="zh")

    assert "观察到高风险信号" in markdown
    assert "### 5. 上下文截断 / 请求改写 / 隐藏指令" in markdown
    assert "### 8. 隐私泄漏 / Prompt 泄漏" in markdown
    integrity_section = markdown.split("### 5. 上下文截断 / 请求改写 / 隐藏指令", 1)[1].split("###", 1)[0]
    assert "状态：**not_detected**" not in integrity_section


def test_full_report_renders_technical_signal_overview_not_executed_checks():
    result = RelayResult(
        run_id="relay-full-technical-signal-overview",
        profile=RelayAuditProfile.FULL,
        scenario=RelayVerdict.FAIL,
        mode=RelayAuditMode.LIVE,
        model="deepseek-r1",
        endpoint_host="relay.example",
        endpoint_hash="abcd1234abcd1234",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=RelayVerdict.FAIL,
        risk_level=RelayRiskLevel.HIGH,
        risk_categories=[RelayRiskCategory.MODEL_SUBSTITUTION],
        evidence=[
            RelayEvidence(
                key="reasoning_native_signal",
                category=RelayRiskCategory.MODEL_SUBSTITUTION,
                status="fail",
                summary="Native reasoning field was not observed for expected reasoning family.",
                metrics={
                    "expected_reasoning_family": "deepseek_r1",
                    "native_reasoning_field_observed": False,
                },
            )
        ],
        retest_guidance="Rerun full profile.",
    )

    markdown = render_relay_markdown(result, language="zh")

    assert "## 技术信号概览" in markdown
    assert "## 已执行技术检查" not in markdown
    assert "| Signal | Observed | Interpretation |" in markdown
    assert "Reasoning native field" in markdown
    assert "not_observed" in markdown or "failed_contract" in markdown
    assert "Reasoning fingerprint：fail" not in markdown


def test_technical_evidence_summary_explains_failed_reasoning_and_security():
    result = RelayResult(
        run_id="relay-full-summary-accuracy",
        profile=RelayAuditProfile.FULL,
        scenario=RelayVerdict.FAIL,
        mode=RelayAuditMode.LIVE,
        model="deepseek-r1",
        endpoint_host="relay.example",
        endpoint_hash="abcd1234abcd1234",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=RelayVerdict.FAIL,
        risk_level=RelayRiskLevel.HIGH,
        risk_categories=[RelayRiskCategory.MODEL_SUBSTITUTION, RelayRiskCategory.PROMPT_INSTRUCTION_LEAKAGE],
        evidence=[
            RelayEvidence(
                key="full_profile_composite_verdict",
                category=RelayRiskCategory.LATENCY_OR_INSTABILITY,
                status="observed",
                summary="Composite verdict was derived from sanitized subprofile verdicts.",
                metrics={
                    "reasoning": {"verdict": "fail", "evidence_keys": ["reasoning_native_signal"]},
                    "security": {"verdict": "fail", "evidence_keys": ["security_prompt_extraction"]},
                },
            )
        ],
        retest_guidance="Rerun full profile.",
    )

    markdown = render_relay_markdown(result)

    assert "| reasoning | high-risk signal | native reasoning field not observed for expected reasoning family |" in markdown
    assert "| security | high-risk signal | prompt extraction or override boundary failed |" in markdown
    assert "| reasoning | fail | reasoning capability signals checked |" not in markdown
    assert "| security | fail | extraction/override probes resisted |" not in markdown


def test_reasoning_summary_does_not_claim_fake_thinking_from_passed_fake_marker_key():
    result = RelayResult(
        run_id="relay-full-reasoning-summary-no-fake",
        profile=RelayAuditProfile.FULL,
        scenario=RelayVerdict.FAIL,
        mode=RelayAuditMode.LIVE,
        model="deepseek-r2",
        endpoint_host="relay.example",
        endpoint_hash="abcd1234abcd1234",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=RelayVerdict.FAIL,
        risk_level=RelayRiskLevel.HIGH,
        risk_categories=[RelayRiskCategory.MODEL_SUBSTITUTION],
        evidence=[
            RelayEvidence(
                key="full_profile_composite_verdict",
                category=RelayRiskCategory.LATENCY_OR_INSTABILITY,
                status="observed",
                summary="Composite verdict was derived from sanitized subprofile verdicts.",
                metrics={
                    "reasoning": {
                        "verdict": "fail",
                        "evidence_keys": ["reasoning_native_signal", "reasoning_fake_thinking_signal"],
                    },
                },
            )
        ],
        retest_guidance="Rerun full profile.",
    )

    markdown = render_relay_markdown(result)

    assert "| reasoning | high-risk signal | native reasoning field not observed for expected reasoning family |" in markdown
    assert "fake-thinking marker signal observed" not in markdown


def test_full_report_main_risk_signals_are_deduplicated():
    child_reasoning = RelayResult(
        run_id="relay-reasoning-child",
        profile=RelayAuditProfile.REASONING,
        scenario=RelayVerdict.FAIL,
        mode=RelayAuditMode.LIVE,
        model="deepseek-r2",
        endpoint_host="relay.example",
        endpoint_hash="abcd1234abcd1234",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=RelayVerdict.FAIL,
        risk_level=RelayRiskLevel.HIGH,
        risk_categories=[RelayRiskCategory.MODEL_SUBSTITUTION],
        evidence=[
            RelayEvidence(
                key="reasoning_native_signal",
                category=RelayRiskCategory.MODEL_SUBSTITUTION,
                status="fail",
                summary="Native reasoning field was not observed for expected reasoning family.",
                metrics={
                    "expected_reasoning_family": "deepseek_reasoning",
                    "native_reasoning_field_observed": False,
                    "reasoning_content_observed": False,
                },
            )
        ],
        retest_guidance="Rerun reasoning.",
    )
    result = RelayResult(
        run_id="relay-full-dedupe",
        profile=RelayAuditProfile.FULL,
        scenario=RelayVerdict.FAIL,
        mode=RelayAuditMode.LIVE,
        model="deepseek-r2",
        endpoint_host="relay.example",
        endpoint_hash="abcd1234abcd1234",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=RelayVerdict.FAIL,
        risk_level=RelayRiskLevel.HIGH,
        risk_categories=[RelayRiskCategory.MODEL_SUBSTITUTION],
        evidence=[],
        retest_guidance="Rerun full profile.",
        child_results=[child_reasoning],
    )

    markdown = render_relay_markdown(result)
    repeated = "reasoning native signal missing: expected_reasoning_family=deepseek_reasoning, native_reasoning_field_observed=False, reasoning_content_observed=False"

    assert markdown.count(repeated) >= 1
    top_section = markdown.split("## Fraud Scenario Summary", 1)[0]
    assert top_section.count(repeated) == 1


def test_full_report_renders_unmapped_technical_risk_when_high_risk_evidence_is_unconsumed():
    result = RelayResult(
        run_id="relay-full-unmapped-risk",
        profile=RelayAuditProfile.FULL,
        scenario=RelayVerdict.FAIL,
        mode=RelayAuditMode.LIVE,
        model="example-model",
        endpoint_host="relay.example",
        endpoint_hash="abcd1234abcd1234",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=RelayVerdict.FAIL,
        risk_level=RelayRiskLevel.HIGH,
        risk_categories=[RelayRiskCategory.LATENCY_OR_INSTABILITY],
        evidence=[
            RelayEvidence(
                key="future_unmapped_failure",
                category=RelayRiskCategory.LATENCY_OR_INSTABILITY,
                status="fail",
                summary="sanitized future high-risk evidence",
                metrics={"safe_signal": "future_unmapped_failure"},
            )
        ],
        retest_guidance="Rerun full profile.",
    )

    markdown = render_relay_markdown(result)

    assert "Unmapped Technical Risk Signal" in markdown
    assert "future_unmapped_failure" in markdown
    assert "not_detected" not in markdown.split("Unmapped Technical Risk Signal", 1)[1].split("###", 1)[0]


def test_signal_first_report_sanitizes_observed_and_absent_signal_text():
    result = RelayResult(
        run_id="relay-full-sanitize-signals",
        profile=RelayAuditProfile.FULL,
        scenario=RelayVerdict.FAIL,
        mode=RelayAuditMode.LIVE,
        model="example-model",
        endpoint_host="relay.example",
        endpoint_hash="abcd1234abcd1234",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=RelayVerdict.FAIL,
        risk_level=RelayRiskLevel.HIGH,
        risk_categories=[RelayRiskCategory.INFRASTRUCTURE_FINGERPRINT],
        evidence=[
            RelayEvidence(
                key="channel_response_markers",
                category=RelayRiskCategory.INFRASTRUCTURE_FINGERPRINT,
                status="observed",
                summary="https://relay.example/v1 Authorization: Bearer sk-secret /Users/Teng/private raw model output",
                metrics={
                    "observed_channel_family": "bedrock",
                    "response_id_pattern": "msg_bdrk...",
                    "leaky": "https://relay.example/v1 Authorization: Bearer sk-secret /Users/Teng/private raw model output",
                },
            )
        ],
        retest_guidance="Rerun full profile.",
    )

    markdown = render_relay_markdown(result)

    assert "bedrock" in markdown
    assert "msg_bdrk..." in markdown
    assert "https://" not in markdown
    assert "sk-secret" not in markdown
    assert "/Users/Teng" not in markdown
    assert "raw model output" not in markdown


def test_full_report_uses_child_profile_concrete_channel_evidence():
    child = RelayResult(
        run_id="relay-channel-child",
        profile=RelayAuditProfile.CHANNEL,
        scenario=RelayVerdict.SUSPICIOUS,
        mode=RelayAuditMode.LIVE,
        model="claude-sonnet-4-5-20250929-thinking",
        endpoint_host="relay.example",
        endpoint_hash="abcd1234abcd1234",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=RelayVerdict.SUSPICIOUS,
        risk_level=RelayRiskLevel.MEDIUM,
        risk_categories=[RelayRiskCategory.INFRASTRUCTURE_FINGERPRINT],
        evidence=[
            RelayEvidence(
                key="channel_response_markers",
                category=RelayRiskCategory.INFRASTRUCTURE_FINGERPRINT,
                status="observed",
                summary="Sanitized channel marker extraction completed.",
                metrics={
                    "provider_marker_detected": True,
                    "observed_channel_family": "bedrock",
                    "response_id_pattern": "msg_bdrk...",
                },
            )
        ],
        retest_guidance="Rerun channel.",
    )
    result = RelayResult(
        run_id="relay-full-child-evidence",
        profile=RelayAuditProfile.FULL,
        scenario=RelayVerdict.SUSPICIOUS,
        mode=RelayAuditMode.LIVE,
        model="claude-sonnet-4-5-20250929-thinking",
        endpoint_host="relay.example",
        endpoint_hash="abcd1234abcd1234",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=RelayVerdict.SUSPICIOUS,
        risk_level=RelayRiskLevel.MEDIUM,
        risk_categories=[RelayRiskCategory.INFRASTRUCTURE_FINGERPRINT],
        evidence=[
            RelayEvidence(
                key="full_profile_composite_verdict",
                category=RelayRiskCategory.LATENCY_OR_INSTABILITY,
                status="observed",
                summary="Composite verdict was derived from sanitized subprofile verdicts.",
                metrics={"channel": {"verdict": "suspicious", "evidence_keys": ["channel_response_markers"]}},
            )
        ],
        retest_guidance="Rerun full.",
        child_results=[child],
    )

    markdown = render_relay_markdown(result, language="zh")

    assert "渠道来源与官方渠道伪装" in markdown
    assert "状态：**detected**" in markdown
    assert "observed_channel_family=bedrock" in markdown
    assert "response_id_pattern=msg_bdrk..." in markdown
    assert "endpoint host checked" not in markdown


def test_full_technical_summary_aligns_with_child_channel_detected_signal():
    child = RelayResult(
        run_id="relay-channel-child-summary",
        profile=RelayAuditProfile.CHANNEL,
        scenario=RelayVerdict.PASS,
        mode=RelayAuditMode.LIVE,
        model="claude-sonnet-4-5-20250929-thinking",
        endpoint_host="relay.example",
        endpoint_hash="abcd1234abcd1234",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=RelayVerdict.PASS,
        risk_level=RelayRiskLevel.LOW,
        risk_categories=[RelayRiskCategory.INFRASTRUCTURE_FINGERPRINT],
        evidence=[
            RelayEvidence(
                key="channel_response_markers",
                category=RelayRiskCategory.INFRASTRUCTURE_FINGERPRINT,
                status="pass",
                summary="Sanitized channel marker extraction completed.",
                metrics={"provider_marker_detected": False, "response_id_pattern": "msg_bdrk..."},
            )
        ],
        retest_guidance="Rerun channel.",
    )
    result = RelayResult(
        run_id="relay-full-summary-child-channel",
        profile=RelayAuditProfile.FULL,
        scenario=RelayVerdict.PASS,
        mode=RelayAuditMode.LIVE,
        model="claude-sonnet-4-5-20250929-thinking",
        endpoint_host="relay.example",
        endpoint_hash="abcd1234abcd1234",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=RelayVerdict.PASS,
        risk_level=RelayRiskLevel.LOW,
        risk_categories=[],
        evidence=[
            RelayEvidence(
                key="full_profile_composite_verdict",
                category=RelayRiskCategory.LATENCY_OR_INSTABILITY,
                status="observed",
                summary="Composite verdict was derived from sanitized subprofile verdicts.",
                metrics={"channel": {"verdict": "pass", "evidence_keys": ["channel_response_markers"]}},
            )
        ],
        retest_guidance="Rerun full.",
        child_results=[child],
    )

    markdown = render_relay_markdown(result, language="zh")

    assert "| channel | observed signal | Bedrock-compatible response id observed |" in markdown
    assert "| channel | no significant signal | channel marker consistency checked |" not in markdown
    assert "| Channel fingerprint | msg_bdrk... | Bedrock-compatible response id observed |" in markdown


def test_full_technical_overview_does_not_treat_generic_reasoning_absence_as_expected_missing():
    child = RelayResult(
        run_id="relay-reasoning-generic-child",
        profile=RelayAuditProfile.REASONING,
        scenario=RelayVerdict.PASS,
        mode=RelayAuditMode.LIVE,
        model="claude-sonnet-4-5-20250929",
        endpoint_host="relay.example",
        endpoint_hash="abcd1234abcd1234",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=RelayVerdict.PASS,
        risk_level=RelayRiskLevel.LOW,
        risk_categories=[RelayRiskCategory.MODEL_SUBSTITUTION],
        evidence=[
            RelayEvidence(
                key="reasoning_native_signal",
                category=RelayRiskCategory.MODEL_SUBSTITUTION,
                status="pass",
                summary="No native reasoning expectation was established for this model family.",
                metrics={
                    "expected_reasoning_family": "generic",
                    "native_reasoning_field_observed": False,
                    "reasoning_content_observed": False,
                },
            )
        ],
        retest_guidance="Rerun reasoning.",
    )
    result = RelayResult(
        run_id="relay-full-generic-reasoning",
        profile=RelayAuditProfile.FULL,
        scenario=RelayVerdict.PASS,
        mode=RelayAuditMode.LIVE,
        model="claude-sonnet-4-5-20250929",
        endpoint_host="relay.example",
        endpoint_hash="abcd1234abcd1234",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=RelayVerdict.PASS,
        risk_level=RelayRiskLevel.LOW,
        risk_categories=[],
        evidence=[
            RelayEvidence(
                key="full_profile_composite_verdict",
                category=RelayRiskCategory.LATENCY_OR_INSTABILITY,
                status="observed",
                summary="Composite verdict was derived from sanitized subprofile verdicts.",
                metrics={"reasoning": {"verdict": "pass", "evidence_keys": ["reasoning_native_signal"]}},
            )
        ],
        retest_guidance="Rerun full.",
        child_results=[child],
    )

    markdown = render_relay_markdown(result, language="zh")

    assert "| Reasoning native field | not_applicable | no native reasoning expectation for generic model family |" in markdown
    assert "expected native reasoning signal was not observed" not in markdown


def test_full_report_aborted_after_general_inconclusive_does_not_render_scenario_grid():
    result = RelayResult(
        run_id="relay-full-aborted",
        profile=RelayAuditProfile.FULL,
        scenario=RelayVerdict.INCONCLUSIVE,
        mode=RelayAuditMode.LIVE,
        model="claude-opus-4-5",
        endpoint_host="hk.hboom.ai",
        endpoint_hash="0edc300d891a87a7",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=RelayVerdict.INCONCLUSIVE,
        risk_level=RelayRiskLevel.UNKNOWN,
        risk_categories=[RelayRiskCategory.LATENCY_OR_INSTABILITY],
        evidence=[
            RelayEvidence(
                key="full_profile_aborted",
                category=RelayRiskCategory.LATENCY_OR_INSTABILITY,
                status="inconclusive",
                summary="Full profile stopped after general connectivity failed.",
                metrics={
                    "abort_reason": "general_connectivity_inconclusive",
                    "profiles_executed": "general",
                    "profiles_skipped": "identity,channel,reasoning,streaming,schema,privacy,security,context",
                    "recommended_action": "Check endpoint host, base URL, model name, and API key.",
                },
            ),
            RelayEvidence(
                key="full_profile_composite_verdict",
                category=RelayRiskCategory.LATENCY_OR_INSTABILITY,
                status="inconclusive",
                summary="Composite verdict stopped at general connectivity.",
                metrics={"general": {"verdict": "inconclusive", "evidence_keys": ["minimal_live_connectivity"]}},
            ),
        ],
        retest_guidance="Check endpoint host, base URL, model name, and API key.",
        inconclusive_reason=(
            "The general connectivity check could not reach an analyzable model response. "
            "Check endpoint host, base URL, model name, and API key."
        ),
        runtime_category=RelayRuntimeCategory.UNKNOWN_RUNTIME_ERROR,
    )

    markdown = render_relay_markdown(result, language="zh")

    assert "## 欺诈场景总结" not in markdown
    assert "模型身份与能力冒充" not in markdown
    assert "相关信号已检查" not in markdown
    assert "本次检查未连接到可分析的模型响应" in markdown
    assert "请检查 Endpoint/Base URL、模型名称、API key" in markdown
    assert "| general | inconclusive | minimal connectivity completed |" in markdown
    assert "| identity |" not in markdown
    assert "full_profile_aborted" in markdown


def test_full_profile_report_lists_identity_channel_reasoning_checks():
    result = RelayResult(
        run_id="relay-full-new-profiles",
        profile=RelayAuditProfile.FULL,
        scenario=RelayVerdict.PASS,
        mode=RelayAuditMode.LIVE,
        model="claude-opus-4-5-20251101",
        endpoint_host="relay.example",
        endpoint_hash="abcd1234abcd1234",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=RelayVerdict.PASS,
        risk_level=RelayRiskLevel.LOW,
        risk_categories=[],
        evidence=[
            RelayEvidence(
                key="full_profile_composite_verdict",
                category=RelayRiskCategory.LATENCY_OR_INSTABILITY,
                status="observed",
                summary="Composite verdict was derived from sanitized subprofile verdicts.",
                metrics={
                    "general": {"verdict": "pass", "evidence_keys": ["minimal_live_connectivity"]},
                    "identity": {"verdict": "pass", "evidence_keys": ["identity_response_envelope"]},
                    "channel": {"verdict": "pass", "evidence_keys": ["channel_claim_consistency"]},
                    "reasoning": {"verdict": "pass", "evidence_keys": ["reasoning_native_signal"]},
                    "streaming": {"verdict": "pass", "evidence_keys": ["stream_content_delta"]},
                    "schema": {"verdict": "pass", "evidence_keys": ["schema_tool_envelope"]},
                    "privacy": {"verdict": "pass", "evidence_keys": ["privacy_marker_leakage"]},
                    "security": {"verdict": "pass", "evidence_keys": ["security_prompt_extraction"]},
                    "context": {"verdict": "pass", "evidence_keys": ["context_anchor_retention"]},
                },
            )
        ],
        retest_guidance="Rerun full profile.",
    )

    markdown = render_relay_markdown(result)

    assert "| Identity fingerprint | checked | identity response envelope summary from full profile |" in markdown
    assert "| Channel fingerprint | checked | channel marker summary from full profile |" in markdown
    assert "| Reasoning native field | checked | reasoning fingerprint summary from full profile |" in markdown
    assert "| identity | no significant signal | response envelope + model claim checked |" in markdown
    assert "| channel | no significant signal | channel marker consistency checked |" in markdown
    assert "| reasoning | no significant signal | reasoning capability signals checked |" in markdown


def test_full_profile_report_upgrades_overall_judgment_from_scenario_signals():
    result = RelayResult(
        run_id="relay-full-scenario-attention",
        profile=RelayAuditProfile.FULL,
        scenario=RelayVerdict.PASS,
        mode=RelayAuditMode.LIVE,
        model="claude-opus-4-5-20251101",
        endpoint_host="hk.hboom.ai",
        endpoint_hash="0edc300d891a87a7",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=RelayVerdict.PASS,
        risk_level=RelayRiskLevel.LOW,
        risk_categories=[],
        evidence=[
            RelayEvidence(
                key="full_profile_composite_verdict",
                category=RelayRiskCategory.LATENCY_OR_INSTABILITY,
                status="observed",
                summary="Composite verdict was derived from sanitized subprofile verdicts.",
                metrics={
                    "general": {"verdict": "pass", "risk_level": "low", "runtime_category": None},
                    "streaming": {"verdict": "pass", "risk_level": "low", "runtime_category": None},
                    "schema": {"verdict": "pass", "risk_level": "low", "runtime_category": None},
                    "privacy": {"verdict": "pass", "risk_level": "low", "runtime_category": None},
                    "security": {"verdict": "pass", "risk_level": "low", "runtime_category": None},
                    "context": {"verdict": "pass", "risk_level": "low", "runtime_category": None},
                },
            ),
            RelayEvidence(
                key="relay_identity_candidate_signals",
                category=RelayRiskCategory.MODEL_SUBSTITUTION,
                status="suspicious",
                summary="Model identity signals did not match the claimed family.",
                metrics={},
            ),
        ],
        retest_guidance="Rerun full profile.",
    )

    markdown = render_relay_markdown(result)

    assert "Overall judgment: **Suspicious signals observed**" in markdown
    assert "Risk level: **medium**" in markdown
    assert "Model Identity And Capability Substitution" in markdown
    assert "Status: **suspicious**" in markdown


def test_full_english_report_uses_ascii_colons_for_public_labels():
    result = RelayResult(
        run_id="relay-full-english-colons",
        profile=RelayAuditProfile.FULL,
        scenario=RelayVerdict.PASS,
        mode=RelayAuditMode.LIVE,
        model="claude-sonnet-4-5-20250929",
        endpoint_host="relay.example",
        endpoint_hash="abcd1234abcd1234",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=RelayVerdict.PASS,
        risk_level=RelayRiskLevel.LOW,
        risk_categories=[],
        evidence=[
            RelayEvidence(
                key="full_profile_composite_verdict",
                category=RelayRiskCategory.LATENCY_OR_INSTABILITY,
                status="observed",
                summary="Composite verdict was derived from sanitized subprofile verdicts.",
                metrics={"identity": {"verdict": "pass"}, "channel": {"verdict": "pass"}},
            )
        ],
        retest_guidance="Rerun full profile.",
    )

    markdown = render_relay_markdown(result, language="en")

    assert "Overall judgment: **No significant high-risk signal observed**" in markdown
    assert "Risk level: **low**" in markdown
    assert "Target model: `claude-sonnet-4-5-20250929`" in markdown
    assert "Status: **not_detected**" in markdown
    assert "Observed signals:" in markdown
    assert "Overall judgment：" not in markdown
    assert "Status：" not in markdown


def test_full_profile_report_uses_evidence_driven_candidate_signals_only():
    result = RelayResult(
        run_id="relay-full-evidence-driven-candidates",
        profile=RelayAuditProfile.FULL,
        scenario=RelayVerdict.PASS,
        mode=RelayAuditMode.LIVE,
        model="claude-opus-4-5-20251101",
        endpoint_host="hk.hboom.ai",
        endpoint_hash="0edc300d891a87a7",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=RelayVerdict.PASS,
        risk_level=RelayRiskLevel.LOW,
        risk_categories=[],
        evidence=[
            RelayEvidence(
                key="full_profile_composite_verdict",
                category=RelayRiskCategory.LATENCY_OR_INSTABILITY,
                status="observed",
                summary="Composite verdict was derived from sanitized subprofile verdicts.",
                metrics={"identity": {"verdict": "pass"}, "channel": {"verdict": "pass"}, "reasoning": {"verdict": "pass"}},
            ),
            RelayEvidence(
                key="identity_candidate_family_scores",
                category=RelayRiskCategory.MODEL_SUBSTITUTION,
                status="suspicious",
                summary="Candidate signal was derived from sanitized fingerprints.",
                metrics={"top_candidate": "qwen", "confidence": "medium"},
            ),
        ],
        retest_guidance="Rerun full profile.",
    )

    markdown = render_relay_markdown(result)

    assert "Candidate upstream signals" in markdown
    assert "qwen: medium" in markdown
    assert "GLM-like" not in markdown
    assert "Claude-native / Opus-level reasoning signal" not in markdown
    assert "Claimed model: `claude-opus-4-5-20251101`" not in markdown


def test_full_fake_reasoning_summary_explains_fake_think_marker():
    result = build_fake_relay_result(
        profile=RelayAuditProfile.FULL,
        scenario=RelayVerdict.SUSPICIOUS,
        endpoint="https://relay.example/v1",
        model="claude-opus-4-5-20251101",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
    )

    markdown = render_relay_markdown(result)

    assert "fake-thinking marker observed" in markdown
    assert "fake-thinking marker" in markdown
    assert "No direct evidence of forged think tags was observed." not in markdown
    assert "REASONING_SIGNAL_MISSING" not in markdown


def test_full_profile_report_redacts_privacy_canary_case_and_unicode_variants():
    result = RelayResult(
        run_id="relay-full-canary-test",
        profile=RelayAuditProfile.FULL,
        scenario=RelayVerdict.FAIL,
        mode=RelayAuditMode.LIVE,
        model="example-model",
        endpoint_host="relay.example",
        endpoint_hash="abcd1234abcd1234",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=RelayVerdict.FAIL,
        risk_level=RelayRiskLevel.HIGH,
        risk_categories=[RelayRiskCategory.PROMPT_INSTRUCTION_LEAKAGE],
        evidence=[
            RelayEvidence(
                key="full_profile_privacy_summary",
                category=RelayRiskCategory.PROMPT_INSTRUCTION_LEAKAGE,
                status="failed",
                summary="tv_privacy_marker_do_not_echo and \\u0054\\u0056_PRIVACY_MARKER_DO_NOT_ECHO must not render.",
                metrics={
                    "case_variant": "tv_privacy_marker_do_not_echo",
                    "unicode_variant": "\\u0054\\u0056_PRIVACY_MARKER_DO_NOT_ECHO",
                },
            )
        ],
        retest_guidance="Rerun full profile.",
    )

    markdown = render_relay_markdown(result)

    assert "TV_PRIVACY_MARKER_DO_NOT_ECHO" not in markdown
    assert "tv_privacy_marker_do_not_echo" not in markdown
    assert "\\u0054\\u0056_PRIVACY_MARKER_DO_NOT_ECHO" not in markdown


def test_relay_report_removes_security_markers_from_public_evidence():
    result = RelayResult(
        run_id="relay-security-test",
        profile=RelayAuditProfile.SECURITY,
        scenario=RelayVerdict.FAIL,
        mode=RelayAuditMode.FAKE,
        model="demo-model",
        endpoint_host="relay.example",
        endpoint_hash="relay-endpoint-abc123",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=RelayVerdict.FAIL,
        risk_level=RelayRiskLevel.HIGH,
        risk_categories=[RelayRiskCategory.PROMPT_INSTRUCTION_LEAKAGE],
        evidence=[
            RelayEvidence(
                key="security_hidden_instruction_echo",
                category=RelayRiskCategory.PROMPT_INSTRUCTION_LEAKAGE,
                status="fail",
                summary="Leaked tv_safe_boundary_ok and TV_OVERRIDE_SAFE in public text.",
                metrics={"leaked_marker": "TV_EXTRACTION_SAFE"},
            )
        ],
        retest_guidance="Re-test with security profile.",
    )

    markdown = render_relay_markdown(result)

    assert "tv_safe_boundary_ok" not in markdown.lower()
    assert "tv_extraction_safe" not in markdown.lower()
    assert "tv_override_safe" not in markdown.lower()


def test_security_report_uses_bounded_prompt_security_language():
    result = RelayResult(
        run_id="relay-security-test",
        profile=RelayAuditProfile.SECURITY,
        scenario=RelayVerdict.PASS,
        mode=RelayAuditMode.FAKE,
        model="demo-model",
        endpoint_host="relay.example",
        endpoint_hash="relay-endpoint-abc123",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=RelayVerdict.PASS,
        risk_level=RelayRiskLevel.LOW,
        risk_categories=[RelayRiskCategory.MESSAGE_REWRITE],
        evidence=[
            RelayEvidence(
                key="security_boundary_control",
                category=RelayRiskCategory.MESSAGE_REWRITE,
                status="pass",
                summary="The relay preserved the bounded prompt-security contract.",
            )
        ],
        retest_guidance="Re-test security profile.",
    )

    markdown = render_relay_markdown(result)

    assert "bounded" in markdown.lower() or "not proof" in markdown.lower()
    assert "jailbreak-proof" not in markdown.lower()


def test_relay_report_removes_context_anchors_from_public_evidence():
    result = RelayResult(
        run_id="relay-context-test",
        profile=RelayAuditProfile.CONTEXT,
        scenario=RelayVerdict.FAIL,
        mode=RelayAuditMode.FAKE,
        model="demo-model",
        endpoint_host="relay.example",
        endpoint_hash="relay-endpoint-abc123",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=RelayVerdict.FAIL,
        risk_level=RelayRiskLevel.HIGH,
        risk_categories=[RelayRiskCategory.CONTEXT_TRUNCATION],
        evidence=[
            RelayEvidence(
                key="context_anchor_missing",
                category=RelayRiskCategory.CONTEXT_TRUNCATION,
                status="fail",
                summary="Missing tv_ctx_alpha while TV_CTX_BRAVO appeared.",
                metrics={"leaky_anchor": "TV_CTX_CHARLIE"},
            )
        ],
        retest_guidance="Re-test with context profile.",
    )

    markdown = render_relay_markdown(result)

    assert "tv_ctx_alpha" not in markdown.lower()
    assert "tv_ctx_bravo" not in markdown.lower()
    assert "tv_ctx_charlie" not in markdown.lower()


def test_context_report_uses_bounded_context_retention_language():
    result = RelayResult(
        run_id="relay-context-test",
        profile=RelayAuditProfile.CONTEXT,
        scenario=RelayVerdict.PASS,
        mode=RelayAuditMode.FAKE,
        model="demo-model",
        endpoint_host="relay.example",
        endpoint_hash="relay-endpoint-abc123",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=RelayVerdict.PASS,
        risk_level=RelayRiskLevel.LOW,
        risk_categories=[RelayRiskCategory.CONTEXT_TRUNCATION],
        evidence=[
            RelayEvidence(
                key="context_anchor_retention",
                category=RelayRiskCategory.CONTEXT_TRUNCATION,
                status="pass",
                summary="The relay preserved bounded public context anchors.",
            )
        ],
        retest_guidance="Re-test context profile.",
    )

    markdown = render_relay_markdown(result)

    assert "bounded" in markdown.lower()
    assert "max-context benchmark" not in markdown.lower()
    assert "proof of malicious" not in markdown.lower()
