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

    assert "## Plain-Language Conclusion" in markdown
    assert "## Fraud Scenario Summary" in markdown
    assert "## Executed Technical Checks" in markdown
    assert "raw stream chunk must not appear" not in markdown
    assert "raw schema args must not appear" not in markdown
    assert "TV_PRIVACY_MARKER_DO_NOT_ECHO" not in markdown
    assert "raw upstream provider error must not appear" not in markdown
    assert '{"tool_calls"' not in markdown
    assert '{"messages"' not in markdown
    assert 'data: {"choices"' not in markdown
    assert '{"error"' not in markdown


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

    assert "Overall judgment：**Suspicious**" in markdown
    assert "Risk level：**medium**" in markdown
    assert "Model Identity And Capability Substitution" in markdown
    assert "Status：**suspicious**" in markdown


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
