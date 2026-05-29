from __future__ import annotations

import httpx

from tokenverify.models import ProviderEvent
from tokenverify.providers.openai_compatible import OpenAICompatibleProviderAdapter


class OpenAIProviderAdapter:
    def __init__(
        self,
        api_key: str | None,
        base_url: str = "https://api.openai.com/v1",
        headers: dict[str, str] | None = None,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.adapter = OpenAICompatibleProviderAdapter(
            base_url=base_url,
            api_key=api_key,
            headers=headers,
            transport=transport,
            timeout=timeout,
        )

    def create_probe_response(self, model: str, prompt: str, max_tokens: int = 64) -> dict:
        return self.adapter.create_probe_response(model, prompt, max_tokens=max_tokens)

    def stream_probe_events(self, model: str, prompt: str, max_tokens: int = 64) -> list[ProviderEvent]:
        return self.adapter.stream_probe_events(model, prompt, max_tokens=max_tokens)
