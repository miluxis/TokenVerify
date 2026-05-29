from tokenverify.models import ProviderEvent
from tokenverify.probes import openai_compatible as probes


def test_chat_completions_shape_passes_with_openai_compatible_tag():
    result = probes.evaluate_chat_completions_response({"model": "claude-sonnet-4.5", "choices": [{"message": {"content": "ok"}}]})

    assert result.name == "chat_completions_shape"
    assert result.status == "passed"
    assert result.evidence[0].passed is True
    assert "OPENAI_COMPATIBLE_SHAPE_MATCH" in result.evidence[0].tags


def test_anthropic_native_shape_on_openai_claim_is_mismatch():
    result = probes.evaluate_chat_completions_response({"type": "message", "role": "assistant", "content": [{"type": "text"}]})

    assert result.status == "failed"
    assert result.evidence[0].passed is False
    assert "ANTHROPIC_NATIVE_SHAPE_DETECTED" in result.evidence[0].tags


def test_claude_model_claim_match_and_mismatch():
    match = probes.evaluate_claude_claim_consistency("claude-sonnet-4.5", {"model": "anthropic/claude-sonnet-4.5"})
    mismatch = probes.evaluate_claude_claim_consistency("claude-sonnet-4.5", {"model": "deepseek-r1"})

    assert "CLAUDE_MODEL_CLAIM_MATCH" in match.evidence[0].tags
    assert "CLAUDE_MODEL_CLAIM_MISMATCH" in mismatch.evidence[0].tags


def test_claude_model_claim_matches_dot_and_dash_version_aliases():
    result = probes.evaluate_claude_claim_consistency(
        "claude-sonnet-4.5",
        {"model": "anthropic/claude-sonnet-4-5-20250929"},
    )

    assert result.status == "passed"
    assert "CLAUDE_MODEL_CLAIM_MATCH" in result.evidence[0].tags


def test_mixed_provider_inconsistency_is_conditional_strong_evidence():
    assert hasattr(probes, "evaluate_mixed_provider_consistency")
    result = probes.evaluate_mixed_provider_consistency(
        [
            {"model": "anthropic/claude-sonnet-4.5"},
            {"model": "openai/gpt-4o"},
        ]
    )

    assert result.status == "failed"
    assert result.evidence[0].weight == "strong"
    assert result.evidence[0].passed is False
    assert "conditional" in result.evidence[0].message.lower()
    assert "MIXED_PROVIDER_INCONSISTENCY_DETECTED" in result.evidence[0].tags


def test_version_field_leak_and_thinking_capability_match_are_reported():
    assert hasattr(probes, "evaluate_claude_version_and_thinking_capability")
    result = probes.evaluate_claude_version_and_thinking_capability(
        claimed_model="claude-sonnet-4.5",
        response={
            "model": "anthropic/claude-sonnet-4.5",
            "system_fingerprint": "claude-sonnet-4.5-20250929",
            "choices": [{"message": {"reasoning": "dedicated reasoning field"}}],
        },
    )

    assert result.status == "passed"
    tags = {tag for item in result.evidence for tag in item.tags}
    assert "CLAUDE_VERSION_FIELD_LEAKED" in tags
    assert "CLAUDE_THINKING_CAPABILITY_MATCH" in tags


def test_thinking_capability_mismatch_is_strong_failure_for_thinking_model():
    assert hasattr(probes, "evaluate_claude_version_and_thinking_capability")
    result = probes.evaluate_claude_version_and_thinking_capability(
        claimed_model="claude-sonnet-4.5",
        response={"model": "anthropic/claude-sonnet-4.5", "choices": [{"message": {"content": "ok"}}]},
        thinking_error="unknown field: thinking",
    )

    assert result.status == "failed"
    failures = [item for item in result.evidence if item.passed is False]
    assert failures
    assert "CLAUDE_THINKING_CAPABILITY_MISMATCH" in failures[0].tags


def test_reasoning_content_leak_is_strong_failure():
    result = probes.evaluate_reasoning_leakage({"choices": [{"delta": {"reasoning_content": "hidden"}}]})

    assert result.status == "failed"
    assert result.evidence[0].passed is False
    assert "CROSS_PROVIDER_REASONING_LEAKED" in result.evidence[0].tags


def test_fake_thinking_text_is_heuristic_risk():
    result = probes.evaluate_reasoning_leakage({"choices": [{"message": {"content": "Thinking Process:\n1. Analyzing...\nAnswer: ok"}}]})

    assert result.status == "warning"
    assert result.evidence[0].weight == "weak"
    assert "SYNTHETIC_THINKING_SUSPECT" in result.evidence[0].tags


def test_fake_thinking_text_handles_markdown_and_bracket_prefixes():
    markdown = probes.evaluate_reasoning_leakage({"choices": [{"message": {"content": "### Thinking Process\nAnalyzing request..."}}]})
    bracketed = probes.evaluate_reasoning_leakage({"choices": [{"message": {"content": "[thinking]\nI should reason step by step."}}]})

    assert "SYNTHETIC_THINKING_SUSPECT" in markdown.evidence[0].tags
    assert "SYNTHETIC_THINKING_SUSPECT" in bracketed.evidence[0].tags


def test_streaming_requires_finish_reason_before_done():
    result = probes.evaluate_openai_streaming_features(
        [
            ProviderEvent(0.0, "chat.completion.chunk", text_length=2, data={"finish_reason": None}),
            ProviderEvent(0.1, "chat.completion.chunk", text_length=2, data={"finish_reason": "stop"}),
        ]
    )

    assert result.status == "passed"
    assert "OPENAI_STREAM_SEQUENCE_MATCH" in result.evidence[0].tags


def test_streaming_missing_finish_reason_is_sequence_mismatch():
    result = probes.evaluate_openai_streaming_features(
        [ProviderEvent(0.0, "chat.completion.chunk", text_length=2, data={"finish_reason": None})]
    )

    assert result.status == "failed"
    assert "STREAM_EVENT_SEQUENCE_MISMATCH" in result.evidence[0].tags


def test_content_filter_finish_reason_is_risk_tag():
    result = probes.evaluate_openai_streaming_features(
        [ProviderEvent(0.0, "chat.completion.chunk", text_length=2, data={"finish_reason": "content_filter"})]
    )

    assert result.status == "warning"
    assert "CROSS_PROVIDER_FINISH_REASON_SUSPECT" in result.evidence[0].tags


def test_channel_risk_observations_extract_relay_headers_rate_limit_and_latency_risk():
    assert hasattr(probes, "evaluate_channel_risk_observations")
    result = probes.evaluate_channel_risk_observations(
        response_headers={
            "x-request-id": "req_123",
            "x-openrouter-provider": "anthropic",
            "cf-ray": "abc-SJC",
        },
        error_message="HTTP 429: upstream rate limit exceeded by account pool",
        region_claim="us-east-1",
        latency_samples=[0.2, 3.5, 0.25],
        observed_models=["anthropic/claude-sonnet-4.5", "anthropic/claude-haiku-4.5"],
    )

    assert result.status == "warning"
    tags = {tag for item in result.evidence for tag in item.tags}
    assert "RELAY_HEADER_SUSPECT" in tags
    assert "RATE_LIMIT_RELAY_SUSPECT" in tags
    assert "REGION_LATENCY_INCONSISTENT" in tags
    assert "MODEL_DRIFT_SUSPECT" in tags


def test_repeated_run_variance_debounces_until_enough_samples_exist():
    assert hasattr(probes, "evaluate_repeated_run_variance")
    result = probes.evaluate_repeated_run_variance(latency_samples=[0.2, 3.5], observed_models=["claude-sonnet-4.5"])

    assert result.status == "skipped"
    assert result.evidence[0].passed is None
    assert "debounce" in result.evidence[0].message.lower()


def test_repeated_run_variance_aggregates_latency_and_model_drift_risk():
    assert hasattr(probes, "evaluate_repeated_run_variance")
    result = probes.evaluate_repeated_run_variance(
        latency_samples=[0.2, 0.25, 0.22, 3.6, 3.8],
        observed_models=["claude-sonnet-4.5", "claude-sonnet-4.5", "claude-haiku-4.5"],
    )

    tags = {tag for item in result.evidence for tag in item.tags}
    assert result.status == "warning"
    assert "TTFT_VARIANCE_HIGH" in tags
    assert "MODEL_DRIFT_SUSPECT" in tags


def test_cloud_provider_marker_extraction_from_headers_and_errors():
    aws = probes.evaluate_channel_risk_observations(
        response_headers={"x-amzn-requestid": "bedrock-req"},
        error_message="ValidationException from Amazon Bedrock upstream",
    )
    azure = probes.evaluate_channel_risk_observations(
        response_headers={"x-ms-region": "eastus"},
        error_message="Azure AI Foundry upstream policy rejected the request",
    )

    aws_tags = {tag for item in aws.evidence for tag in item.tags}
    azure_tags = {tag for item in azure.evidence for tag in item.tags}
    assert "HOSTED_BY_AWS" in aws_tags
    assert "HOSTED_BY_AZURE" in azure_tags
