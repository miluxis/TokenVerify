import pytest

from tokenverify.probes.thinking import (
    ProbeConstructionError,
    build_thinking_payload,
    evaluate_thinking_outcome,
)


def test_manual_budget_payload_uses_1024_budget_and_2048_max_tokens():
    payload = build_thinking_payload("claude-sonnet-4-5")

    assert payload["thinking"] == {"type": "enabled", "budget_tokens": 1024}
    assert payload["max_tokens"] == 2048


def test_budget_must_be_lower_than_max_tokens():
    with pytest.raises(ProbeConstructionError, match="budget_tokens must be lower"):
        build_thinking_payload("claude-sonnet-4-5", budget_tokens=2048, max_tokens=2048)


def test_expected_thinking_model_rejecting_param_is_negative_evidence():
    result = evaluate_thinking_outcome(
        model="claude-sonnet-4-5",
        response=None,
        error_message="unknown field: thinking",
    )

    assert result.status == "failed"
    assert result.evidence[0].key == "extended_thinking_expected"
    assert result.evidence[0].passed is False


def test_rate_limit_during_thinking_probe_is_operational_error():
    result = evaluate_thinking_outcome(
        model="claude-haiku-4-5-20251001-thinking",
        response=None,
        error_message="This request would exceed your organization's rate limit of 2,000,000 input tokens per minute",
    )

    assert result.status == "error"
    assert result.evidence[0].passed is None
    assert "operational error" in result.evidence[0].message


def test_cross_provider_reasoning_leak_is_strong_failure():
    result = evaluate_thinking_outcome(
        model="claude-sonnet-4-5",
        response={"choices": [{"delta": {"reasoning_content": "hidden reasoning"}}]},
    )

    assert result.status == "failed"
    assert result.evidence[0].passed is False
    assert "CROSS_PROVIDER_REASONING_LEAKED" in result.evidence[0].tags
