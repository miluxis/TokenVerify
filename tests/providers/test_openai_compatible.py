import httpx
import pytest

from tokenverify.providers.openai_compatible import (
    OpenAICompatibleChatClient,
    OpenAICompatibleProviderError,
    SelfRelayLoopError,
    build_chat_completions_payload,
    normalize_error,
    parse_chat_sse_lines,
)


def test_build_chat_completions_payload():
    payload = build_chat_completions_payload(
        model="claude-sonnet-4.5",
        messages=[{"role": "user", "content": "Reply with exactly: ok"}],
        max_tokens=64,
        stream=False,
    )

    assert payload == {
        "model": "claude-sonnet-4.5",
        "messages": [{"role": "user", "content": "Reply with exactly: ok"}],
        "max_tokens": 64,
        "stream": False,
    }


def test_client_posts_chat_completions_with_openai_headers():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["authorization"] = request.headers["authorization"]
        seen["scan"] = request.headers["x-tokenverify-scan"]
        assert "anthropic-version" not in request.headers
        assert "x-api-key" not in request.headers
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    client = OpenAICompatibleChatClient(
        base_url="https://relay.example/v1",
        api_key="TOKEN_PLACEHOLDER",
        transport=httpx.MockTransport(handler),
    )

    response = client.create_chat_completion({"model": "claude-sonnet-4.5", "messages": []})

    assert seen["url"] == "https://relay.example/v1/chat/completions"
    assert seen["authorization"] == "Bearer TOKEN_PLACEHOLDER"
    assert seen["scan"] == "true"
    assert response["choices"][0]["message"]["content"] == "ok"


def test_client_accepts_base_url_that_already_points_to_chat_completions():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    client = OpenAICompatibleChatClient(
        base_url="https://relay.example/v1/chat/completions",
        api_key="TOKEN_PLACEHOLDER",
        transport=httpx.MockTransport(handler),
    )

    client.create_chat_completion({"model": "claude-sonnet-4.5", "messages": []})

    assert seen["url"] == "https://relay.example/v1/chat/completions"


def test_client_short_circuits_self_relay_loop_header():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"x-tokenverify-scan": "true"}, json={"choices": []})

    client = OpenAICompatibleChatClient(
        base_url="https://relay.example/v1",
        api_key="TOKEN_PLACEHOLDER",
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(SelfRelayLoopError):
        client.create_chat_completion({"model": "claude-sonnet-4.5", "messages": []})


def test_parse_chat_sse_lines_records_text_and_finish_reason():
    events = parse_chat_sse_lines(
        [
            'data: {"choices":[{"delta":{"content":"hel"},"finish_reason":null}]}',
            "",
            'data: {"choices":[{"delta":{"content":"lo"},"finish_reason":"stop"}]}',
            "",
            "data: [DONE]",
        ],
        timestamps=[1.0, 1.2],
    )

    assert [event.event_type for event in events] == ["chat.completion.chunk", "chat.completion.chunk"]
    assert [event.text_length for event in events] == [3, 2]
    assert events[-1].data["finish_reason"] == "stop"


def test_normalize_openai_compatible_error():
    error = normalize_error({"error": {"message": "bad request", "type": "invalid_request_error", "code": "bad"}})

    assert isinstance(error, OpenAICompatibleProviderError)
    assert error.is_openai_compatible_shape is True
    assert error.category == "invalid_request_error"
    assert error.code == "bad"
