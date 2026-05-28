from tokenverify.models import ProviderEvent
from tokenverify.probes.openai_compatible import (
    evaluate_chat_completions_response,
    evaluate_claude_claim_consistency,
    evaluate_openai_streaming_features,
    evaluate_reasoning_leakage,
)


def test_chat_completions_shape_passes_with_openai_compatible_tag():
    result = evaluate_chat_completions_response({"model": "claude-sonnet-4.5", "choices": [{"message": {"content": "ok"}}]})

    assert result.name == "chat_completions_shape"
    assert result.status == "passed"
    assert result.evidence[0].passed is True
    assert "OPENAI_COMPATIBLE_SHAPE_MATCH" in result.evidence[0].tags


def test_anthropic_native_shape_on_openai_claim_is_mismatch():
    result = evaluate_chat_completions_response({"type": "message", "role": "assistant", "content": [{"type": "text"}]})

    assert result.status == "failed"
    assert result.evidence[0].passed is False
    assert "ANTHROPIC_NATIVE_SHAPE_DETECTED" in result.evidence[0].tags


def test_claude_model_claim_match_and_mismatch():
    match = evaluate_claude_claim_consistency("claude-sonnet-4.5", {"model": "anthropic/claude-sonnet-4.5"})
    mismatch = evaluate_claude_claim_consistency("claude-sonnet-4.5", {"model": "deepseek-r1"})

    assert "CLAUDE_MODEL_CLAIM_MATCH" in match.evidence[0].tags
    assert "CLAUDE_MODEL_CLAIM_MISMATCH" in mismatch.evidence[0].tags


def test_reasoning_content_leak_is_strong_failure():
    result = evaluate_reasoning_leakage({"choices": [{"delta": {"reasoning_content": "hidden"}}]})

    assert result.status == "failed"
    assert result.evidence[0].passed is False
    assert "CROSS_PROVIDER_REASONING_LEAKED" in result.evidence[0].tags


def test_fake_thinking_text_is_heuristic_risk():
    result = evaluate_reasoning_leakage({"choices": [{"message": {"content": "Thinking Process:\n1. Analyzing...\nAnswer: ok"}}]})

    assert result.status == "warning"
    assert result.evidence[0].weight == "weak"
    assert "SYNTHETIC_THINKING_SUSPECT" in result.evidence[0].tags


def test_fake_thinking_text_handles_markdown_and_bracket_prefixes():
    markdown = evaluate_reasoning_leakage({"choices": [{"message": {"content": "### Thinking Process\nAnalyzing request..."}}]})
    bracketed = evaluate_reasoning_leakage({"choices": [{"message": {"content": "[thinking]\nI should reason step by step."}}]})

    assert "SYNTHETIC_THINKING_SUSPECT" in markdown.evidence[0].tags
    assert "SYNTHETIC_THINKING_SUSPECT" in bracketed.evidence[0].tags


def test_streaming_requires_finish_reason_before_done():
    result = evaluate_openai_streaming_features(
        [
            ProviderEvent(0.0, "chat.completion.chunk", text_length=2, data={"finish_reason": None}),
            ProviderEvent(0.1, "chat.completion.chunk", text_length=2, data={"finish_reason": "stop"}),
        ]
    )

    assert result.status == "passed"
    assert "OPENAI_STREAM_SEQUENCE_MATCH" in result.evidence[0].tags


def test_streaming_missing_finish_reason_is_sequence_mismatch():
    result = evaluate_openai_streaming_features(
        [ProviderEvent(0.0, "chat.completion.chunk", text_length=2, data={"finish_reason": None})]
    )

    assert result.status == "failed"
    assert "STREAM_EVENT_SEQUENCE_MISMATCH" in result.evidence[0].tags


def test_content_filter_finish_reason_is_risk_tag():
    result = evaluate_openai_streaming_features(
        [ProviderEvent(0.0, "chat.completion.chunk", text_length=2, data={"finish_reason": "content_filter"})]
    )

    assert result.status == "warning"
    assert "CROSS_PROVIDER_FINISH_REASON_SUSPECT" in result.evidence[0].tags
