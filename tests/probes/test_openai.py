from tokenverify.models import ProviderEvent
from tokenverify.probes import openai as probes


def test_chat_completion_shape_match():
    result = probes.evaluate_openai_chat_completion_response(
        {
            "object": "chat.completion",
            "model": "gpt-5.1",
            "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
        }
    )

    assert result.status == "passed"
    assert "OPENAI_CHAT_COMPLETION_SHAPE_MATCH" in result.evidence[0].tags


def test_non_openai_shape_detected():
    result = probes.evaluate_openai_chat_completion_response(
        {"type": "message", "role": "assistant", "content": [{"type": "text", "text": "ok"}]}
    )

    assert result.status == "failed"
    assert "NON_OPENAI_PROVIDER_SHAPE_DETECTED" in result.evidence[0].tags


def test_openai_model_claim_match_and_cross_provider_mismatch():
    match = probes.evaluate_openai_model_claim("gpt-5.1", {"model": "gpt-5.1-2026-02-01"})
    mismatch = probes.evaluate_openai_model_claim("gpt-5.1", {"model": "anthropic/claude-sonnet-4.5"})
    downgrade = probes.evaluate_openai_model_claim("gpt-5.1", {"model": "gpt-4o-2024-05-13"})

    assert "OPENAI_MODEL_CLAIM_MATCH" in match.evidence[0].tags
    assert "CROSS_PROVIDER_MODEL_LEAKED" in mismatch.evidence[0].tags
    assert downgrade.status == "failed"
    assert "OPENAI_MODEL_CLAIM_MISMATCH" in downgrade.evidence[0].tags


def test_openai_reasoning_capability_match_and_mismatch():
    passed = probes.evaluate_openai_reasoning_capability(
        "gpt-5.1",
        accepted_parameters=["reasoning_effort"],
        rejected_parameters=[],
        reasoning_tokens=8,
        is_trivial_prompt=False,
    )
    failed = probes.evaluate_openai_reasoning_capability(
        "gpt-5.1",
        accepted_parameters=[],
        rejected_parameters=["reasoning_effort"],
    )

    assert passed.status == "passed"
    assert "OPENAI_REASONING_CAPABILITY_MATCH" in passed.evidence[0].tags
    assert failed.status == "failed"
    assert "OPENAI_REASONING_CAPABILITY_MISMATCH" in failed.evidence[0].tags


def test_openai_reasoning_tokens_zero_handling():
    result_trivial = probes.evaluate_openai_reasoning_capability(
        "gpt-5.1",
        accepted_parameters=["reasoning_effort"],
        rejected_parameters=[],
        reasoning_tokens=0,
        is_trivial_prompt=True,
    )
    result_hard = probes.evaluate_openai_reasoning_capability(
        "gpt-5.1",
        accepted_parameters=["reasoning_effort"],
        rejected_parameters=[],
        reasoning_tokens=0,
        is_trivial_prompt=False,
    )

    assert result_trivial.status == "warning"
    assert result_hard.status == "failed"
    assert "OPENAI_REASONING_CAPABILITY_MISMATCH" in result_hard.evidence[0].tags


def test_openai_stream_sequence_match_and_mismatch():
    match = probes.evaluate_openai_streaming_features(
        [
            ProviderEvent(
                0.0,
                "chat.completion.chunk",
                text_length=2,
                data={"object": "chat.completion.chunk", "finish_reason": "stop"},
            )
        ]
    )
    mismatch = probes.evaluate_openai_streaming_features(
        [ProviderEvent(0.0, "message_start", data={"type": "message_start"})]
    )

    assert "OPENAI_STREAM_SEQUENCE_MATCH" in match.evidence[0].tags
    assert mismatch.status == "failed"
    assert "OPENAI_STREAM_SEQUENCE_MISMATCH" in mismatch.evidence[0].tags


def test_openai_channel_probe_distinguishes_official_and_relay():
    official = probes.evaluate_openai_channel(
        base_url="https://api.openai.com/v1",
        channel_claim="official",
        response_headers={"x-request-id": "req_123"},
    )
    relay = probes.evaluate_openai_channel(
        base_url="https://relay.example/v1",
        channel_claim="official",
        response_headers={"x-openrouter-provider": "openai"},
    )

    assert "OPENAI_OFFICIAL_CHANNEL_MATCH" in official.evidence[0].tags
    relay_tags = {tag for item in relay.evidence for tag in item.tags}
    assert "OPENAI_OFFICIAL_CHANNEL_MISMATCH" in relay_tags
    assert "RELAY_HEADER_SUSPECT" in relay_tags


def test_openai_official_host_with_relay_headers_is_not_accepted_as_clean_official():
    result = probes.evaluate_openai_channel(
        base_url="https://api.openai.com/v1",
        channel_claim="official",
        response_headers={"server": "nginx", "x-openrouter-provider": "openai"},
        error_message='{"error":{"message":"upstream failed","type":"server_error"}}',
    )

    tags = {tag for item in result.evidence for tag in item.tags}
    assert result.status == "warning"
    assert "RELAY_HEADER_SUSPECT" in tags
    assert "OPENAI_OFFICIAL_CHANNEL_MISMATCH" in tags
