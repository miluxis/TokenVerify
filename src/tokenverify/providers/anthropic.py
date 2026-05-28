from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Iterable

import httpx

from tokenverify.models import ProviderEvent


@dataclass(frozen=True)
class AnthropicProviderError:
    message: str
    category: str
    is_anthropic_shape: bool
    raw: dict


class AnthropicMessagesClient:
    def __init__(
        self,
        base_url: str,
        api_key: str | None,
        headers: dict[str, str] | None = None,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.headers = headers or {}
        self.transport = transport
        self.timeout = timeout

    def create_message(self, payload: dict) -> dict:
        with httpx.Client(transport=self.transport, timeout=self.timeout) as client:
            response = client.post(
                f"{self.base_url}/v1/messages",
                json=payload,
                headers=self._headers(),
            )
            if response.status_code >= 400:
                raise RuntimeError(normalize_error(response.json()).message)
            return response.json()

    def stream_message_events(self, payload: dict) -> list[ProviderEvent]:
        stream_payload = {**payload, "stream": True}
        with httpx.Client(transport=self.transport, timeout=self.timeout) as client:
            with client.stream(
                "POST",
                f"{self.base_url}/v1/messages",
                json=stream_payload,
                headers=self._headers(),
            ) as response:
                if response.status_code >= 400:
                    raise RuntimeError(normalize_error(response.json()).message)
                return parse_sse_lines(response.iter_lines())

    def _headers(self) -> dict[str, str]:
        headers = {
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
            **self.headers,
        }
        if self.api_key:
            headers["x-api-key"] = self.api_key
        return headers


def build_messages_payload(
    model: str,
    messages: list[dict],
    max_tokens: int = 256,
    stream: bool = False,
    thinking: dict | None = None,
) -> dict:
    payload = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
        "stream": stream,
    }
    if thinking is not None:
        payload["thinking"] = thinking
    return payload


def parse_sse_lines(lines: Iterable[str], timestamps: list[float] | None = None) -> list[ProviderEvent]:
    events: list[ProviderEvent] = []
    current_event: str | None = None
    timestamp_index = 0
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("event:"):
            current_event = line.removeprefix("event:").strip()
            continue
        if not line.startswith("data:"):
            continue
        data_text = line.removeprefix("data:").strip()
        if data_text == "[DONE]":
            continue
        data = json.loads(data_text)
        event_type = str(data.get("type") or current_event or "unknown")
        text = ((data.get("delta") or {}).get("text") if isinstance(data.get("delta"), dict) else None)
        timestamp = timestamps[timestamp_index] if timestamps and timestamp_index < len(timestamps) else float(timestamp_index)
        timestamp_index += 1
        events.append(
            ProviderEvent(
                timestamp=timestamp,
                event_type=event_type,
                text_length=len(text) if isinstance(text, str) else None,
                data=data,
            )
        )
    return events


def normalize_error(payload: dict) -> AnthropicProviderError:
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict) and "type" in error and "message" in error:
        return AnthropicProviderError(
            message=str(error["message"]),
            category=str(error["type"]),
            is_anthropic_shape=True,
            raw=payload,
        )
    message = str(error.get("message") if isinstance(error, dict) else payload)
    return AnthropicProviderError(
        message=message,
        category="proxy_or_non_anthropic_error",
        is_anthropic_shape=False,
        raw=payload,
    )
