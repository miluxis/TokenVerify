from dataclasses import replace
from pathlib import Path

from tokenverify.models import AuditResult, Claim, EvidenceItem, ProbeResult, Rating, StreamingMetrics, Verdict
from tokenverify.report import render_markdown


def audit_result() -> AuditResult:
    return AuditResult(
        target_summary={"base_url_host": "api.anthropic.com", "model": "claude-sonnet-4-5", "endpoint": "primary"},
        probe_results=[
            ProbeResult(
                "messages_protocol",
                "passed",
                [EvidenceItem("anthropic_messages_shape", "strong", True, "native shape", tags=["ANTHROPIC_NATIVE_SHAPE_MATCH"])],
            ),
            ProbeResult(
                "extended_thinking",
                "passed",
                [EvidenceItem("extended_thinking_expected", "strong", True, "thinking observed", tags=["EXTENDED_THINKING_MATCH"])],
            ),
            ProbeResult(
                "streaming_features",
                "warning",
                [
                    EvidenceItem(
                        "synthetic_stream_heuristic",
                        "weak",
                        False,
                        "synthetic stream suspected",
                        tags=["SYNTHETIC_STREAM_SUSPECT"],
                    )
                ],
                metrics=StreamingMetrics(0.2, 1.0, [0.1], [3, 7], 10.0, True),
            ),
        ],
        rating=Rating.MEDIUM_TRUST,
        score_breakdown={"strong_passed": 2, "weak_failed": 1},
        verdict=Verdict(
            rating=Rating.MEDIUM_TRUST,
            authenticity_score=78,
            risk_score=25,
            tags=["ANTHROPIC_NATIVE_SHAPE_MATCH", "EXTENDED_THINKING_MATCH", "SYNTHETIC_STREAM_SUSPECT"],
        ),
        report_warnings=["raw logging enabled"],
        raw_log_path=Path("events.jsonl"),
        redacted_config={"endpoint": {"api_key": "***REDACTED***"}},
    )


def test_markdown_contains_required_sections():
    markdown = render_markdown(audit_result())

    assert "# TokenVerify Audit Report" in markdown
    assert "## Plain-Language Summary" in markdown
    assert "## Channel Risk Profile" in markdown
    assert "## Overall Verdict" in markdown
    assert "## Authenticity Assertions" in markdown
    assert "## Heuristic Risk Profile" in markdown
    assert "## Messages Protocol Probe" in markdown
    assert "## Extended Thinking Probe" in markdown
    assert "## Streaming Metrics" in markdown
    assert "## Configuration Summary" in markdown


def test_markdown_redacts_api_key():
    result = audit_result()
    result.redacted_config["endpoint"]["api_key"] = "***REDACTED***"

    markdown = render_markdown(result)

    assert "TOKEN_SHOULD_BE_REDACTED" not in markdown
    assert "***REDACTED***" in markdown


def test_raw_log_path_is_referenced_not_embedded():
    markdown = render_markdown(audit_result())

    assert "events.jsonl" in markdown
    assert "raw_response_body" not in markdown


def test_markdown_separates_authenticity_assertions_from_risk_profile():
    markdown = render_markdown(audit_result())

    assert "## Authenticity Assertions" in markdown
    assert "## Heuristic Risk Profile" in markdown
    assert markdown.index("## Authenticity Assertions") < markdown.index("## Heuristic Risk Profile")


def test_risk_profile_uses_score_language_not_probability_or_accusation():
    markdown = render_markdown(audit_result())

    assert "Risk score" in markdown
    assert "probability" not in markdown.lower()
    assert "风险概率" not in markdown
    assert "定罪" not in markdown


def test_target_summary_omits_unsupplied_none_values():
    result = audit_result()
    result.target_summary["claimed_region"] = None

    markdown = render_markdown(result)

    assert "claimed_region" not in markdown


def test_markdown_renders_openai_compatible_probe_sections():
    result = replace(
        audit_result(),
        probe_results=[
            ProbeResult(
                "chat_completions_shape",
                "passed",
                [EvidenceItem("openai_compatible_chat_shape", "strong", True, "chat shape")],
            ),
            ProbeResult(
                "claude_claim_consistency",
                "passed",
                [EvidenceItem("claude_model_claim", "strong", True, "model matches")],
            ),
            ProbeResult(
                "mixed_provider_consistency",
                "passed",
                [EvidenceItem("mixed_provider_inconsistency", "strong", True, "no mixed provider drift")],
            ),
            ProbeResult(
                "claude_version_thinking_capability",
                "passed",
                [EvidenceItem("claude_thinking_capability", "strong", True, "thinking field observed")],
            ),
            ProbeResult("reasoning_leakage", "passed", []),
            ProbeResult(
                "channel_risk_observations",
                "warning",
                [EvidenceItem("relay_header_markers", "weak", False, "relay header observed")],
            ),
            ProbeResult(
                "openai_compatible_streaming",
                "passed",
                [EvidenceItem("openai_stream_sequence", "strong", True, "finish reason")],
                metrics=StreamingMetrics(0.2, 1.0, [0.1], [2, 2], 4.0, False),
            ),
        ],
    )

    markdown = render_markdown(result)

    assert "## Chat Completions Shape Probe" in markdown
    assert "## Claude Model Claim Consistency Probe" in markdown
    assert "## Mixed Provider Consistency Probe" in markdown
    assert "## Claude Version And Thinking Capability Probe" in markdown
    assert "## Reasoning Leakage Probe" in markdown
    assert "## Channel Risk Observations Probe" in markdown
    assert "## OpenAI-Compatible Streaming Metrics" in markdown


def test_markdown_renders_openai_probe_sections():
    result = replace(
        audit_result(),
        probe_results=[
            ProbeResult(
                "openai_chat_completions_shape",
                "passed",
                [EvidenceItem("openai_chat_shape", "strong", True, "shape")],
            ),
            ProbeResult(
                "openai_model_claim_consistency",
                "passed",
                [EvidenceItem("openai_model_claim", "strong", True, "model")],
            ),
            ProbeResult("openai_reasoning_capability", "skipped", []),
            ProbeResult(
                "openai_channel_risk",
                "passed",
                [EvidenceItem("openai_official_channel", "strong", True, "official")],
            ),
            ProbeResult(
                "openai_compatible_streaming",
                "passed",
                [],
                metrics=StreamingMetrics(0.2, 1.0, [0.1], [2], 2.0, False),
            ),
        ],
    )

    markdown = render_markdown(result)

    assert "## OpenAI Chat Completions Shape Probe" in markdown
    assert "## OpenAI Model Claim Consistency Probe" in markdown
    assert "## OpenAI Reasoning Capability Probe" in markdown
    assert "## OpenAI Channel Risk Probe" in markdown
    assert "## OpenAI-Compatible Streaming Metrics" in markdown


def test_markdown_renders_deepseek_probe_sections():
    result = replace(
        audit_result(),
        target_summary={
            "base_url_host": "api.deepseek.com",
            "model": "deepseek-r1",
            "endpoint": "deepseek",
            "claimed_provider": "deepseek",
            "claimed_api_shape": "openai-compatible",
            "claimed_channel": "official",
        },
        probe_results=[
            ProbeResult(
                "deepseek_chat_completions_shape",
                "passed",
                [EvidenceItem("deepseek_chat_shape", "strong", True, "shape")],
            ),
            ProbeResult(
                "deepseek_model_claim_consistency",
                "passed",
                [EvidenceItem("deepseek_model_claim", "strong", True, "model")],
            ),
            ProbeResult(
                "deepseek_reasoning_content",
                "passed",
                [EvidenceItem("deepseek_reasoning_content", "strong", True, "reasoning")],
            ),
            ProbeResult(
                "deepseek_channel_risk",
                "passed",
                [EvidenceItem("deepseek_official_channel", "strong", True, "official")],
            ),
            ProbeResult(
                "deepseek_compatible_streaming",
                "passed",
                [],
                metrics=StreamingMetrics(0.2, 1.0, [0.1], [2], 2.0, False),
            ),
        ],
    )

    markdown = render_markdown(result)

    assert "## DeepSeek Chat Completions Shape Probe" in markdown
    assert "## DeepSeek Model Claim Consistency Probe" in markdown
    assert "## DeepSeek R1 Reasoning Content Probe" in markdown
    assert "## DeepSeek Channel Risk Probe" in markdown
    assert "## DeepSeek-Compatible Streaming Metrics" in markdown


def test_plain_language_summary_translates_deepseek_missing_reasoning_objectively():
    result = replace(
        audit_result(),
        target_summary={
            "base_url_host": "api.deepseek.com",
            "model": "deepseek-r1",
            "endpoint": "deepseek",
            "claimed_provider": "deepseek",
            "claimed_api_shape": "openai-compatible",
            "claimed_channel": "official",
        },
        probe_results=[
            ProbeResult(
                "deepseek_reasoning_content",
                "failed",
                [
                    EvidenceItem(
                        "deepseek_reasoning_content",
                        "strong",
                        False,
                        "missing",
                        tags=["DEEPSEEK_REASONING_CONTENT_MISSING"],
                    )
                ],
            )
        ],
        verdict=Verdict(
            rating=Rating.LOW_TRUST,
            authenticity_score=39,
            risk_score=0,
            tags=["DEEPSEEK_REASONING_CONTENT_MISSING"],
        ),
    )

    markdown = render_markdown(result, language="zh")

    assert "推理能力缺失：声明为 DeepSeek R1，但未检测到原生 reasoning_content 字段，疑似被路由到不支持 R1 推理能力的模型或兼容层。" in markdown
    assert "阉割" not in markdown
    assert "挂羊头卖狗肉" not in markdown


def test_plain_language_summary_defaults_to_english_before_technical_details():
    markdown = render_markdown(audit_result())

    assert "Audit result: Medium Trust" in markdown
    assert "Found 2 strong evidence items supporting the claim" in markdown
    assert "Found 1 channel or runtime risk signal" in markdown
    assert "本次检测结果" not in markdown
    assert markdown.index("## Plain-Language Summary") < markdown.index("## Evidence Score Breakdown")


def test_plain_language_summary_can_render_chinese_for_localized_reports():
    markdown = render_markdown(audit_result(), language="zh")

    assert "本次检测结果：Medium Trust" in markdown
    assert "发现 2 条强证据支持该接口与声明相符" in markdown
    assert "发现 1 条渠道或运行风险信号" in markdown


def test_channel_risk_profile_explains_official_mismatch_for_users():
    result = replace(
        audit_result(),
        target_summary={
            "base_url_host": "hk.hboom.ai",
            "model": "gpt-5.5",
            "endpoint": "openai-official",
            "claimed_provider": "openai",
            "claimed_api_shape": "openai-compatible",
            "claimed_channel": "official",
        },
        probe_results=[
            ProbeResult(
                "openai_chat_completions_shape",
                "passed",
                [EvidenceItem("openai_chat_shape", "strong", True, "shape", tags=["OPENAI_CHAT_COMPLETION_SHAPE_MATCH"])],
            ),
            ProbeResult(
                "openai_channel_risk",
                "failed",
                [
                    EvidenceItem(
                        "openai_official_channel",
                        "strong",
                        False,
                        "Official OpenAI channel was claimed, but base URL host is not api.openai.com.",
                        tags=["OPENAI_OFFICIAL_CHANNEL_MISMATCH"],
                    )
                ],
            ),
        ],
        rating=Rating.LOW_TRUST,
        verdict=Verdict(
            rating=Rating.LOW_TRUST,
            authenticity_score=39,
            risk_score=0,
            tags=["OPENAI_CHAT_COMPLETION_SHAPE_MATCH", "OPENAI_OFFICIAL_CHANNEL_MISMATCH"],
        ),
    )

    markdown = render_markdown(result, language="zh")

    assert "官方直连：不符合" in markdown
    assert "中转平台：已确认" in markdown
    assert "云托管渠道：未发现明确泄漏" in markdown
    assert "Web 逆向 / 账号池：样本不足，无法判断" in markdown


def test_channel_risk_profile_translates_cloud_and_pool_tags_for_users():
    result = replace(
        audit_result(),
        target_summary={
            "base_url_host": "relay.example",
            "model": "claude-haiku-4-5-20251001",
            "endpoint": "relay",
            "claimed_provider": "anthropic",
            "claimed_api_shape": "openai-compatible",
            "claimed_channel": "unknown",
        },
        verdict=Verdict(
            rating=Rating.MEDIUM_TRUST,
            authenticity_score=72,
            risk_score=45,
            tags=["HOSTED_BY_AWS", "WEB_REVERSE_SUSPECT"],
        ),
    )

    markdown = render_markdown(result, language="zh")

    assert "云托管渠道：疑似 AWS/Bedrock" in markdown
    assert "Web 逆向 / 账号池：存在疑似风险" in markdown
    assert "HOSTED_BY_AWS" not in markdown.split("## Target Summary", 1)[0]


def test_channel_risk_profile_reports_stable_repeat_sampling_without_pool_risk():
    result = replace(
        audit_result(),
        probe_results=[
            ProbeResult("repeated_run_variance", "passed", []),
        ],
        verdict=Verdict(
            rating=Rating.HIGH_TRUST,
            authenticity_score=95,
            risk_score=0,
            tags=[],
        ),
    )

    markdown = render_markdown(result, language="zh")

    assert "Web 逆向 / 账号池：已采样，未发现疑似风险" in markdown


def test_channel_risk_profile_defaults_to_english_for_users():
    result = replace(
        audit_result(),
        target_summary={
            "base_url_host": "hk.hboom.ai",
            "model": "gpt-5.5",
            "endpoint": "openai-official",
            "claimed_provider": "openai",
            "claimed_api_shape": "openai-compatible",
            "claimed_channel": "official",
        },
        verdict=Verdict(
            rating=Rating.LOW_TRUST,
            authenticity_score=39,
            risk_score=0,
            tags=["OPENAI_OFFICIAL_CHANNEL_MISMATCH"],
        ),
    )

    markdown = render_markdown(result)

    assert "Official direct channel: mismatch" in markdown
    assert "Relay platform: confirmed" in markdown
    assert "Cloud-hosted channel: no clear leak observed" in markdown
    assert "Web reverse / account pool: not enough samples to judge" in markdown


def test_suspected_upstream_signals_explain_deepseek_r1_style_under_claude_claim():
    result = replace(
        audit_result(),
        target_summary={
            "base_url_host": "relay.example",
            "model": "claude-sonnet-4-5",
            "endpoint": "claude-relay",
            "claimed_provider": "anthropic",
            "claimed_api_shape": "openai-compatible",
        },
        claim=Claim(model="claude-sonnet-4-5", provider="anthropic", api_shape="openai-compatible"),
        probe_results=[
            ProbeResult(
                "reasoning_leakage",
                "failed",
                [
                    EvidenceItem(
                        "cross_provider_reasoning_leaked",
                        "strong",
                        False,
                        "Response exposed provider-specific reasoning_content in an OpenAI-compatible Claude claim.",
                        details={"observed_model": "deepseek-r1", "observed_fields": ["reasoning_content"]},
                        tags=["CROSS_PROVIDER_REASONING_LEAKED"],
                    )
                ],
            )
        ],
    )

    markdown = render_markdown(result, language="zh")

    assert "## Suspected Upstream Signals / 疑似上游特征" in markdown
    assert "疑似 DeepSeek/R1 风格上游或兼容层" in markdown
    assert "reasoning_content" in markdown
    assert "不能证明真实官方上游" in markdown


def test_suspected_upstream_signals_explain_claude_style_under_openai_claim():
    result = replace(
        audit_result(),
        target_summary={
            "base_url_host": "relay.example",
            "model": "gpt-5",
            "endpoint": "openai-relay",
            "claimed_provider": "openai",
            "claimed_api_shape": "openai-compatible",
        },
        claim=Claim(model="gpt-5", provider="openai", api_shape="openai-compatible"),
        probe_results=[
            ProbeResult(
                "openai_model_claim_consistency",
                "failed",
                [
                    EvidenceItem(
                        "openai_model_claim",
                        "strong",
                        False,
                        "Observed model `claude-3-5-sonnet` belongs to a non-OpenAI provider family.",
                        details={"observed_model": "claude-3-5-sonnet"},
                        tags=["CROSS_PROVIDER_MODEL_LEAKED"],
                    )
                ],
            )
        ],
    )

    markdown = render_markdown(result, language="zh")

    assert "疑似 Claude/Anthropic 风格上游或兼容层" in markdown
    assert "claude-3-5-sonnet" in markdown
    assert "官方 Claude 上游" not in markdown


def test_suspected_upstream_signals_explain_openai_style_under_deepseek_claim():
    result = replace(
        audit_result(),
        target_summary={
            "base_url_host": "relay.example",
            "model": "deepseek-r1",
            "endpoint": "deepseek-relay",
            "claimed_provider": "deepseek",
            "claimed_api_shape": "openai-compatible",
        },
        claim=Claim(model="deepseek-r1", provider="deepseek", api_shape="openai-compatible"),
        probe_results=[
            ProbeResult(
                "deepseek_model_claim_consistency",
                "failed",
                [
                    EvidenceItem(
                        "deepseek_model_claim",
                        "strong",
                        False,
                        "Response exposed provider-exclusive metadata under a DeepSeek claim.",
                        details={"observed_fields": ["system_fingerprint"]},
                        tags=["CROSS_PROVIDER_MODEL_LEAKED"],
                    )
                ],
            )
        ],
    )

    markdown = render_markdown(result, language="zh")

    assert "疑似 OpenAI 风格上游或兼容层" in markdown
    assert "system_fingerprint" in markdown
    assert "不改变可信度评分" in markdown


def test_suspected_upstream_signals_keep_weak_model_strings_auxiliary():
    result = replace(
        audit_result(),
        target_summary={
            "base_url_host": "relay.example",
            "model": "gpt-5",
            "endpoint": "openai-relay",
            "claimed_provider": "openai",
            "claimed_api_shape": "openai-compatible",
        },
        claim=Claim(model="gpt-5", provider="openai", api_shape="openai-compatible"),
        probe_results=[
            ProbeResult(
                "channel_risk_observations",
                "warning",
                [
                    EvidenceItem(
                        "model_name_hint",
                        "weak",
                        False,
                        "A weak relay metadata string mentioned claude-style-model.",
                        details={"observed_model": "claude-style-model"},
                    )
                ],
            )
        ],
        verdict=Verdict(rating=Rating.MEDIUM_TRUST, authenticity_score=78, risk_score=25, tags=[]),
    )

    markdown = render_markdown(result)

    assert "suspected Claude/Anthropic-style upstream or compatibility layer" in markdown
    assert "auxiliary hint" in markdown
    assert "官方 Claude 上游" not in markdown
    assert "- Authenticity score: 78" in markdown


def test_suspected_upstream_signals_can_render_chinese_labels():
    result = replace(
        audit_result(),
        target_summary={
            "base_url_host": "relay.example",
            "model": "gpt-5",
            "endpoint": "openai-relay",
            "claimed_provider": "openai",
            "claimed_api_shape": "openai-compatible",
        },
        claim=Claim(model="gpt-5", provider="openai", api_shape="openai-compatible"),
        probe_results=[
            ProbeResult(
                "channel_risk_observations",
                "warning",
                [
                    EvidenceItem(
                        "model_name_hint",
                        "weak",
                        False,
                        "A weak relay metadata string mentioned claude-style-model.",
                        details={"observed_model": "claude-style-model"},
                    )
                ],
            )
        ],
    )

    markdown = render_markdown(result, language="zh")

    assert "疑似 Claude/Anthropic 风格上游或兼容层" in markdown
    assert "辅助提示" in markdown
