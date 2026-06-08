from tokenverify.relay_fingerprint import extract_relay_response_envelope
from tokenverify.relay_models import RelayRiskLevel, RelayVerdict
from tokenverify.relay_reasoning import claimed_reasoning_family, classify_reasoning_observation


def _envelope(body):
    return extract_relay_response_envelope(status_code=200, body=body, headers={})


def test_reasoning_passes_deepseek_r1_with_reasoning_content():
    result = classify_reasoning_observation(
        claimed_model="deepseek-r1",
        envelope=_envelope({"choices": [{"message": {"reasoning_content": "private chain", "content": "answer"}}]}),
        content_text="answer",
    )

    assert result.verdict == RelayVerdict.PASS
    assert result.risk_level == RelayRiskLevel.LOW
    assert "private chain" not in repr(result)


def test_reasoning_fails_deepseek_r1_missing_reasoning_content():
    result = classify_reasoning_observation(
        claimed_model="deepseek-r1",
        envelope=_envelope({"choices": [{"message": {"content": "answer"}}]}),
        content_text="answer",
    )

    assert result.verdict == RelayVerdict.FAIL
    assert result.risk_level == RelayRiskLevel.HIGH


def test_reasoning_fake_think_is_marker_only_not_native_reasoning():
    result = classify_reasoning_observation(
        claimed_model="unknown-model",
        envelope=_envelope({"choices": [{"message": {"content": "<think>private hidden text</think> answer"}}]}),
        content_text="<think>private hidden text</think> answer",
    )

    assert result.verdict == RelayVerdict.SUSPICIOUS
    assert result.risk_level == RelayRiskLevel.MEDIUM
    native = next(item for item in result.evidence if item.key == "reasoning_native_signal")
    fake = next(item for item in result.evidence if item.key == "reasoning_fake_thinking_signal")
    assert native.metrics["native_reasoning_field_observed"] is False
    assert fake.metrics["fake_thinking_text_observed"] is True
    assert "private hidden text" not in repr(result)


def test_reasoning_unknown_family_does_not_fail_for_missing_native_fields():
    result = classify_reasoning_observation(
        claimed_model="custom-model",
        envelope=_envelope({"choices": [{"message": {"content": "answer"}}]}),
        content_text="answer",
    )

    assert result.verdict == RelayVerdict.PASS
    assert result.risk_level == RelayRiskLevel.LOW


def test_reasoning_family_uses_explicit_reasoning_claim_markers():
    assert claimed_reasoning_family("deepseek-r1") == "deepseek_reasoning"
    assert claimed_reasoning_family("deepseek-r2") == "deepseek_reasoning"
    assert claimed_reasoning_family("openai-o1") == "openai_reasoning"
    assert claimed_reasoning_family("o3-mini") == "openai_reasoning"
    assert claimed_reasoning_family("o12-preview") == "openai_reasoning"
    assert claimed_reasoning_family("claude-sonnet-4-5-thinking") == "claude_reasoning"
    assert claimed_reasoning_family("claude-sonnet-4-5-20250929") == "generic"


def test_reasoning_plain_claude_sonnet_does_not_fail_for_missing_native_fields():
    result = classify_reasoning_observation(
        claimed_model="claude-sonnet-4-5-20250929",
        envelope=_envelope({"choices": [{"message": {"content": "answer"}}]}),
        content_text="answer",
    )

    assert result.verdict == RelayVerdict.PASS
    assert result.risk_level == RelayRiskLevel.LOW
    native = next(item for item in result.evidence if item.key == "reasoning_native_signal")
    assert native.status == "pass"
    assert native.metrics["expected_reasoning_family"] == "generic"
