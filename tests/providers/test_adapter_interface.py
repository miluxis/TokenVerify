import httpx

from tokenverify.models import ProviderEvent


def test_anthropic_adapter_implements_provider_adapter_contract():
    from tokenverify.providers.base import ProviderAdapter
    from tokenverify.providers.anthropic import AnthropicProviderAdapter

    def handler(request: httpx.Request) -> httpx.Response:
        payload = request.read()
        if b'"stream":true' in payload.replace(b" ", b""):
            return httpx.Response(
                200,
                text='event: message_start\ndata: {"type":"message_start"}\n\n'
                'event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"text":"ok"}}\n\n',
            )
        return httpx.Response(
            200,
            json={"id": "msg_1", "type": "message", "role": "assistant", "content": [{"type": "text", "text": "ok"}]},
        )

    adapter: ProviderAdapter = AnthropicProviderAdapter(
        base_url="https://relay.example",
        api_key="TOKEN_PLACEHOLDER",
        transport=httpx.MockTransport(handler),
    )

    response = adapter.create_probe_response("claude-sonnet-4-5", "Reply with exactly: ok", max_tokens=32)
    events = adapter.stream_probe_events("claude-sonnet-4-5", "Reply with exactly: ok", max_tokens=32)

    assert response["type"] == "message"
    assert isinstance(events[0], ProviderEvent)


def test_openai_compatible_adapter_implements_provider_adapter_contract():
    from tokenverify.providers.base import ProviderAdapter
    from tokenverify.providers.openai_compatible import OpenAICompatibleProviderAdapter

    def handler(request: httpx.Request) -> httpx.Response:
        payload = request.read()
        if b'"stream":true' in payload.replace(b" ", b""):
            return httpx.Response(
                200,
                text='data: {"choices":[{"delta":{"content":"ok"},"finish_reason":"stop"}]}\n\n'
                "data: [DONE]\n\n",
            )
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    adapter: ProviderAdapter = OpenAICompatibleProviderAdapter(
        base_url="https://relay.example/v1",
        api_key="TOKEN_PLACEHOLDER",
        transport=httpx.MockTransport(handler),
    )

    response = adapter.create_probe_response("claude-sonnet-4.5", "Reply with exactly: ok", max_tokens=32)
    events = adapter.stream_probe_events("claude-sonnet-4.5", "Reply with exactly: ok", max_tokens=32)

    assert response["choices"][0]["message"]["content"] == "ok"
    assert events[-1].data["finish_reason"] == "stop"


def test_openai_adapter_stub_implements_provider_adapter_contract():
    from tokenverify.providers.base import ProviderAdapter
    from tokenverify.providers.openai import OpenAIProviderAdapter

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "https://api.openai.com/v1/chat/completions"
        payload = request.read()
        if b'"stream":true' in payload.replace(b" ", b""):
            return httpx.Response(
                200,
                text='data: {"choices":[{"delta":{"content":"ok"},"finish_reason":"stop"}]}\n\n'
                "data: [DONE]\n\n",
            )
        return httpx.Response(
            200,
            json={
                "object": "chat.completion",
                "model": "gpt-5.1",
                "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
            },
        )

    adapter: ProviderAdapter = OpenAIProviderAdapter(
        api_key="TOKEN_PLACEHOLDER",
        transport=httpx.MockTransport(handler),
    )

    response = adapter.create_probe_response("gpt-5.1", "Reply with exactly: ok", max_tokens=32)
    events = adapter.stream_probe_events("gpt-5.1", "Reply with exactly: ok", max_tokens=32)

    assert response["object"] == "chat.completion"
    assert events[-1].data["finish_reason"] == "stop"
