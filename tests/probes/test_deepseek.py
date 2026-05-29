from tokenverify.models import ProviderEvent
from tokenverify.probes import deepseek as probes


def test_deepseek_chat_completion_shape_match():
    result = probes.evaluate_deepseek_chat_completion_response(
        {"model": "deepseek-chat", "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]}
    )

    assert result.status == "passed"
    assert "DEEPSEEK_CHAT_COMPLETION_SHAPE_MATCH" in result.evidence[0].tags


def test_non_deepseek_shape_detected():
    result = probes.evaluate_deepseek_chat_completion_response(
        {"type": "message", "role": "assistant", "content": [{"type": "text", "text": "ok"}]}
    )

    assert result.status == "failed"
    assert "NON_DEEPSEEK_PROVIDER_SHAPE_DETECTED" in result.evidence[0].tags


def test_deepseek_model_claim_match_and_cross_provider_mismatch():
    match = probes.evaluate_deepseek_model_claim("deepseek-r1", {"model": "deepseek-reasoner"})
    mismatch = probes.evaluate_deepseek_model_claim("deepseek-r1", {"model": "gpt-4o"})
    fingerprint = probes.evaluate_deepseek_model_claim("deepseek-r1", {"model": "deepseek-r1", "system_fingerprint": "fp_123"})
    downgrade = probes.evaluate_deepseek_model_claim("deepseek-r1", {"model": "deepseek-chat"})

    assert "DEEPSEEK_MODEL_CLAIM_MATCH" in match.evidence[0].tags
    assert "CROSS_PROVIDER_MODEL_LEAKED" in mismatch.evidence[0].tags
    assert "CROSS_PROVIDER_MODEL_LEAKED" in fingerprint.evidence[0].tags
    assert downgrade.status == "failed"
    assert "DEEPSEEK_MODEL_CLAIM_MISMATCH" in downgrade.evidence[0].tags


def test_r1_reasoning_content_match_and_missing():
    match = probes.evaluate_deepseek_reasoning_content(
        "deepseek-r1",
        {"choices": [{"message": {"reasoning_content": "work", "content": "answer"}, "finish_reason": "stop"}]},
        is_trivial_prompt=False,
    )
    missing = probes.evaluate_deepseek_reasoning_content(
        "deepseek-r1",
        {"choices": [{"message": {"content": "answer"}, "finish_reason": "stop"}]},
        is_trivial_prompt=False,
    )
    wrong_type = probes.evaluate_deepseek_reasoning_content(
        "deepseek-r1",
        {"choices": [{"message": {"reasoning_content": [], "content": "answer"}, "finish_reason": "stop"}]},
        is_trivial_prompt=False,
    )
    chat = probes.evaluate_deepseek_reasoning_content(
        "deepseek-chat",
        {"choices": [{"message": {"content": "answer"}, "finish_reason": "stop"}]},
        is_trivial_prompt=False,
    )

    assert match.status == "passed"
    assert "DEEPSEEK_REASONING_CONTENT_MATCH" in match.evidence[0].tags
    assert missing.status == "failed"
    assert "DEEPSEEK_REASONING_CONTENT_MISSING" in missing.evidence[0].tags
    assert wrong_type.status == "failed"
    assert "DEEPSEEK_REASONING_CONTENT_MISSING" in wrong_type.evidence[0].tags
    assert chat.status == "skipped"


def test_deepseek_stream_sequence_and_reasoning_delta():
    result = probes.evaluate_deepseek_streaming_features(
        "deepseek-r1",
        [
            ProviderEvent(
                0.0,
                "chat.completion.chunk",
                data={"choices": [{"delta": {"reasoning_content": "work"}, "finish_reason": None}]},
            ),
            ProviderEvent(
                0.1,
                "chat.completion.chunk",
                data={"choices": [{"delta": {"content": "answer"}, "finish_reason": "stop"}]},
            ),
        ],
    )

    assert result.status == "passed"
    tags = [tag for item in result.evidence for tag in item.tags]
    assert "DEEPSEEK_STREAM_SEQUENCE_MATCH" in tags
    assert "DEEPSEEK_STREAM_REASONING_MATCH" in tags


def test_deepseek_stream_sequence_interleaved_is_suspect():
    result = probes.evaluate_deepseek_streaming_features(
        "deepseek-r1",
        [
            ProviderEvent(0.0, "chat.completion.chunk", data={"choices": [{"delta": {"content": "answer"}}]}),
            ProviderEvent(
                0.1,
                "chat.completion.chunk",
                data={"choices": [{"delta": {"reasoning_content": "fake_thinking"}}]},
            ),
        ],
    )

    assert result.status == "warning"
    tags = [tag for item in result.evidence for tag in item.tags]
    assert "SYNTHETIC_THINKING_SUSPECT" in tags


def test_deepseek_channel_probe_distinguishes_official_and_relay():
    official = probes.evaluate_deepseek_channel("https://api.deepseek.com/v1", "official", response_headers={})
    relay = probes.evaluate_deepseek_channel("https://relay.example/v1", "official", response_headers={"server": "nginx"})

    assert official.status == "passed"
    assert "DEEPSEEK_OFFICIAL_CHANNEL_MATCH" in official.evidence[0].tags
    assert relay.status == "failed"
    assert "DEEPSEEK_OFFICIAL_CHANNEL_MISMATCH" in relay.evidence[0].tags
