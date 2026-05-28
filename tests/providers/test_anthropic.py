import httpx

from tokenverify.providers.anthropic import AnthropicMessagesClient, AnthropicProviderError, normalize_error, parse_sse_lines


def test_parse_native_stream_events():
    events = parse_sse_lines(
        [
            "event: message_start",
            'data: {"type":"message_start","message":{"id":"msg_1"}}',
            "",
            "event: content_block_delta",
            'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"hello"}}',
            "",
        ],
        timestamps=[1.0, 1.25],
    )

    assert [event.event_type for event in events] == ["message_start", "content_block_delta"]
    assert events[1].text_length == 5
    assert events[1].timestamp == 1.25


def test_normalize_generic_proxy_error_as_non_anthropic():
    error = normalize_error({"error": {"message": "bad request", "code": "invalid_request"}})

    assert isinstance(error, AnthropicProviderError)
    assert error.is_anthropic_shape is False
    assert error.category == "proxy_or_non_anthropic_error"


def test_client_posts_messages_with_anthropic_headers():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["api_key"] = request.headers["x-api-key"]
        seen["version"] = request.headers["anthropic-version"]
        return httpx.Response(
            200,
            json={"id": "msg_1", "type": "message", "role": "assistant", "content": [{"type": "text", "text": "ok"}]},
        )

    client = AnthropicMessagesClient(
        base_url="https://relay.example",
        api_key="TOKEN_PLACEHOLDER",
        transport=httpx.MockTransport(handler),
    )

    response = client.create_message({"model": "claude-sonnet-4-5", "messages": [], "max_tokens": 16})

    assert seen["url"] == "https://relay.example/v1/messages"
    assert seen["api_key"] == "TOKEN_PLACEHOLDER"
    assert seen["version"]
    assert response["type"] == "message"
