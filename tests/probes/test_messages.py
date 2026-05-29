from tokenverify.probes import messages


def test_native_messages_shape_emits_positive_evidence():
    result = messages.evaluate_messages_response(
        {
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "ok"}],
        }
    )

    assert result.status == "passed"
    assert result.evidence[0].key == "anthropic_messages_shape"
    assert result.evidence[0].passed is True


def test_openai_compatible_shape_emits_negative_evidence():
    result = messages.evaluate_messages_response(
        {
            "id": "chatcmpl_1",
            "choices": [{"message": {"role": "assistant", "content": "ok"}}],
        }
    )

    assert result.status == "failed"
    assert result.evidence[0].passed is False
    assert "OpenAI-compatible" in result.evidence[0].message


def test_messages_response_emits_shape_tags():
    native = messages.evaluate_messages_response({"type": "message", "role": "assistant", "content": [{"type": "text"}]})
    openai_like = messages.evaluate_messages_response({"choices": [{"message": {"content": "ok"}}]})

    assert "ANTHROPIC_NATIVE_SHAPE_MATCH" in native.evidence[0].tags
    assert "OPENAI_COMPATIBLE_SHAPE_DETECTED" in openai_like.evidence[0].tags


def test_anthropic_error_schema_emits_strong_match_evidence():
    assert hasattr(messages, "evaluate_messages_error_schema")
    result = messages.evaluate_messages_error_schema(
        {"type": "error", "error": {"type": "invalid_request_error", "message": "bad request"}}
    )

    assert result.status == "passed"
    assert result.evidence[0].weight == "strong"
    assert result.evidence[0].passed is True
    assert "ERROR_SCHEMA_MATCH" in result.evidence[0].tags


def test_non_anthropic_error_schema_emits_strong_mismatch_evidence():
    assert hasattr(messages, "evaluate_messages_error_schema")
    result = messages.evaluate_messages_error_schema({"error": {"message": "bad request", "type": "invalid_request_error"}})

    assert result.status == "failed"
    assert result.evidence[0].passed is False
    assert "ERROR_SCHEMA_MISMATCH" in result.evidence[0].tags
