from tokenverify.relay_fingerprint import (
    claimed_model_family,
    extract_relay_response_envelope,
    public_response_id_pattern,
)


def test_extract_openai_envelope_sanitizes_raw_content_and_headers():
    envelope = extract_relay_response_envelope(
        status_code=200,
        body={
            "id": "chatcmpl-secret-1234567890",
            "object": "chat.completion",
            "model": "gpt-5",
            "system_fingerprint": "fp_secret",
            "choices": [{"message": {"content": "raw output must not appear"}, "finish_reason": "stop"}],
            "usage": {"output_tokens_details": {"reasoning_tokens": 7}},
        },
        headers={"x-openrouter-route": "secret-route-value", "authorization": "Bearer sk-secret"},
    )

    rendered = repr(envelope)
    assert envelope.response_id_pattern == "chatcmpl-..."
    assert envelope.observed_model_family == "openai"
    assert envelope.response_shape_family == "openai_chat_completions"
    assert envelope.system_fingerprint_observed is True
    assert envelope.reasoning_usage_observed is True
    assert "raw output must not appear" not in rendered
    assert "secret-route-value" not in rendered
    assert "sk-secret" not in rendered


def test_extract_bedrock_and_deepseek_markers_without_raw_values():
    envelope = extract_relay_response_envelope(
        status_code=200,
        body={
            "id": "msg_bdrk_0123456789abcdef",
            "model": "anthropic.claude-opus-4-5-20251101-v1:0",
            "choices": [{"message": {"reasoning_content": "private chain must not appear"}}],
        },
        headers={"x-amzn-requestid": "private-amazon-request-id"},
    )

    rendered = repr(envelope)
    assert envelope.response_id_pattern == "msg_bdrk..."
    assert envelope.provider_marker_detected is True
    assert envelope.provider_marker_family == "bedrock"
    assert envelope.reasoning_content_observed is True
    assert "private chain must not appear" not in rendered
    assert "private-amazon-request-id" not in rendered


def test_model_family_and_response_id_helpers_are_stable():
    assert claimed_model_family("claude-opus-4-5-20251101") == "claude"
    assert claimed_model_family("deepseek-r1") == "deepseek"
    assert claimed_model_family("gpt-5") == "openai"
    assert public_response_id_pattern("msg_bdrk_abcdef") == "msg_bdrk..."
    assert public_response_id_pattern("chatcmpl-abcdef") == "chatcmpl-..."
