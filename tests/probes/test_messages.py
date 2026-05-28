from tokenverify.probes.messages import evaluate_messages_response


def test_native_messages_shape_emits_positive_evidence():
    result = evaluate_messages_response(
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
    result = evaluate_messages_response(
        {
            "id": "chatcmpl_1",
            "choices": [{"message": {"role": "assistant", "content": "ok"}}],
        }
    )

    assert result.status == "failed"
    assert result.evidence[0].passed is False
    assert "OpenAI-compatible" in result.evidence[0].message


def test_messages_response_emits_shape_tags():
    native = evaluate_messages_response({"type": "message", "role": "assistant", "content": [{"type": "text"}]})
    openai_like = evaluate_messages_response({"choices": [{"message": {"content": "ok"}}]})

    assert "ANTHROPIC_NATIVE_SHAPE_MATCH" in native.evidence[0].tags
    assert "OPENAI_COMPATIBLE_SHAPE_DETECTED" in openai_like.evidence[0].tags
