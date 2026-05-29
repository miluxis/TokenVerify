from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Iterable

import httpx

from tokenverify.models import ProviderEvent


SCAN_HEADER = "x-tokenverify-scan"
SCAN_VALUE = "true"


class SelfRelayLoopError(RuntimeError):
    pass


@dataclass(frozen=True)
class OpenAICompatibleProviderError:
    message: str
    category: str
    code: str | None
    is_openai_compatible_shape: bool
    raw: dict


class OpenAICompatibleChatClient:
    def __init__(
        self,
        base_url: str,
        api_key: str | None,
        headers: dict[str, str] | None = None,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = _normalize_base_url(base_url)
        self.api_key = api_key
        self.headers = headers or {}
        self.transport = transport
        self.timeout = timeout

    def create_chat_completion(self, payload: dict) -> dict:
        with httpx.Client(transport=self.transport, timeout=self.timeout) as client:
            response = client.post(
                self._chat_completions_url(),
                json=payload,
                headers=self._headers(),
            )
            self._raise_on_self_relay_loop(response)
            if response.status_code >= 400:
                raise RuntimeError(normalize_error(response.json()).message)
            return response.json()

    def stream_chat_completion_events(self, payload: dict) -> list[ProviderEvent]:
        stream_payload = {**payload, "stream": True}
        with httpx.Client(transport=self.transport, timeout=self.timeout) as client:
            with client.stream(
                "POST",
                self._chat_completions_url(),
                json=stream_payload,
                headers=self._headers(),
            ) as response:
                self._raise_on_self_relay_loop(response)
                if response.status_code >= 400:
                    raise RuntimeError(normalize_error(response.json()).message)
                return parse_chat_sse_lines(response.iter_lines())

    def _headers(self) -> dict[str, str]:
        headers = {"content-type": "application/json", SCAN_HEADER: SCAN_VALUE, **self.headers}
        if self.api_key:
            headers["authorization"] = f"Bearer {self.api_key}"
        return headers

    def _chat_completions_url(self) -> str:
        return f"{self.base_url}/chat/completions"

    def _raise_on_self_relay_loop(self, response: httpx.Response) -> None:
        if response.headers.get(SCAN_HEADER) == SCAN_VALUE:
            raise SelfRelayLoopError("TokenVerify scan marker was echoed by the relay response")


class OpenAICompatibleProviderAdapter:
    def __init__(
        self,
        base_url: str,
        api_key: str | None,
        headers: dict[str, str] | None = None,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.client = OpenAICompatibleChatClient(
            base_url=base_url,
            api_key=api_key,
            headers=headers,
            transport=transport,
            timeout=timeout,
        )

    def create_probe_response(self, model: str, prompt: str, max_tokens: int = 64) -> dict:
        return self.client.create_chat_completion(
            build_chat_completions_payload(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=max_tokens,
                stream=False,
            )
        )

    def stream_probe_events(self, model: str, prompt: str, max_tokens: int = 64) -> list[ProviderEvent]:
        return self.client.stream_chat_completion_events(
            build_chat_completions_payload(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=max_tokens,
                stream=True,
            )
        )


def build_chat_completions_payload(
    model: str,
    messages: list[dict],
    max_tokens: int = 256,
    stream: bool = False,
) -> dict:
    return {"model": model, "messages": messages, "max_tokens": max_tokens, "stream": stream}


def parse_chat_sse_lines(lines: Iterable[str], timestamps: list[float] | None = None) -> list[ProviderEvent]:
    events: list[ProviderEvent] = []
    timestamp_index = 0
    for raw_line in lines:
        line = raw_line.strip()
        if not line or not line.startswith("data:"):
            continue
        data_text = line.removeprefix("data:").strip()
        if data_text == "[DONE]":
            continue
        data = json.loads(data_text)
        choice = _first_choice(data)
        delta = choice.get("delta") if isinstance(choice, dict) else {}
        text = delta.get("content") if isinstance(delta, dict) else None
        finish_reason = choice.get("finish_reason") if isinstance(choice, dict) else None
        timestamp = timestamps[timestamp_index] if timestamps and timestamp_index < len(timestamps) else float(timestamp_index)
        timestamp_index += 1
        event_data = {**data, "finish_reason": finish_reason}
        events.append(
            ProviderEvent(
                timestamp=timestamp,
                event_type="chat.completion.chunk",
                text_length=len(text) if isinstance(text, str) else None,
                data=event_data,
            )
        )
    return events


def normalize_error(payload: dict) -> OpenAICompatibleProviderError:
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict) and "message" in error:
        return OpenAICompatibleProviderError(
            message=str(error["message"]),
            category=str(error.get("type") or "openai_compatible_error"),
            code=str(error["code"]) if error.get("code") is not None else None,
            is_openai_compatible_shape=True,
            raw=payload,
        )
    return OpenAICompatibleProviderError(
        message=str(payload),
        category="proxy_or_non_openai_compatible_error",
        code=None,
        is_openai_compatible_shape=False,
        raw=payload,
    )


def _normalize_base_url(base_url: str) -> str:
    normalized = base_url.rstrip("/")
    suffix = "/chat/completions"
    if normalized.endswith(suffix):
        return normalized[: -len(suffix)]
    return normalized


def _first_choice(data: dict) -> dict:
    choices = data.get("choices")
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        return choices[0]
    return {}
