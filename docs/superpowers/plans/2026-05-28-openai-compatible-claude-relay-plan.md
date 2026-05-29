# OpenAI-Compatible Claude Relay Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a mocked, test-covered audit path for Claude models exposed through an OpenAI-compatible `/v1/chat/completions` API shape.

**Architecture:** Keep Anthropic native auditing unchanged. Add an OpenAI-compatible provider adapter and focused probes, then route `Claim(provider="anthropic", api_shape="openai-compatible", ...)` to that path. Reports continue using the existing `Verdict`, `Authenticity Assertions`, and `Heuristic Risk Profile` sections.

**Tech Stack:** Python 3.11+, dataclasses, httpx, pytest, existing `tokenverify` CLI and report renderer.

---

## Execution Rules

- Implement one task at a time with TDD: write failing tests, verify failure, implement, verify pass.
- Do not implement official OpenAI model auditing, DeepSeek provider auditing, Gemini, Seed, Qwen, Doubao, dashboard, batch mode, or JSON output.
- Do not run real-network tests.
- Do not commit unless the user explicitly asks.
- Use `PYTHONPATH=src python3 -m pytest ...` for verification.

## File Structure

- Modify `src/tokenverify/models.py`: add new stable evidence/risk tags used by this phase.
- Create `src/tokenverify/providers/openai_compatible.py`: OpenAI-compatible Chat Completions client, payload builder, SSE parser, and error normalizer.
- Create `src/tokenverify/probes/openai_compatible.py`: OpenAI-compatible Claude relay probes.
- Modify `src/tokenverify/audit.py`: route OpenAI-compatible Claude claims to the new path.
- Modify `src/tokenverify/report.py`: render new probe names without special-casing every provider path.
- Create `examples/claude-openai-compatible-audit.yaml`: example config.
- Create `tests/providers/test_openai_compatible.py`: provider unit tests.
- Create `tests/probes/test_openai_compatible.py`: probe unit tests.
- Modify `tests/test_audit_flow.py`: audit routing integration tests.
- Modify `tests/test_report.py`: report rendering coverage for new probe names.
- Modify `README.md`: document OpenAI-compatible Claude relay config.

---

### Task 1: Add Stable Tags For OpenAI-Compatible Claude Relay

**Files:**
- Modify: `src/tokenverify/models.py`
- Test: `tests/test_models.py`

- [ ] **Step 1: Write failing tag tests**

Append to `tests/test_models.py`:

```python
def test_openai_compatible_relay_tag_values_are_stable():
    assert EvidenceTag.OPENAI_COMPATIBLE_SHAPE_MATCH.value == "OPENAI_COMPATIBLE_SHAPE_MATCH"
    assert EvidenceTag.ANTHROPIC_NATIVE_SHAPE_DETECTED.value == "ANTHROPIC_NATIVE_SHAPE_DETECTED"
    assert EvidenceTag.CLAUDE_MODEL_CLAIM_MATCH.value == "CLAUDE_MODEL_CLAIM_MATCH"
    assert EvidenceTag.CLAUDE_MODEL_CLAIM_MISMATCH.value == "CLAUDE_MODEL_CLAIM_MISMATCH"
    assert EvidenceTag.OPENAI_STREAM_SEQUENCE_MATCH.value == "OPENAI_STREAM_SEQUENCE_MATCH"
    assert RiskTag.CROSS_PROVIDER_FINISH_REASON_SUSPECT.value == "CROSS_PROVIDER_FINISH_REASON_SUSPECT"
    assert RiskTag.SELF_RELAY_LOOP_DETECTED.value == "SELF_RELAY_LOOP_DETECTED"
    assert RiskTag.SYNTHETIC_THINKING_SUSPECT.value == "SYNTHETIC_THINKING_SUSPECT"
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_models.py -v
```

Expected: FAIL because these enum values do not exist yet.

- [ ] **Step 3: Add enum values**

In `src/tokenverify/models.py`, add to `EvidenceTag`:

```python
OPENAI_COMPATIBLE_SHAPE_MATCH = "OPENAI_COMPATIBLE_SHAPE_MATCH"
ANTHROPIC_NATIVE_SHAPE_DETECTED = "ANTHROPIC_NATIVE_SHAPE_DETECTED"
CLAUDE_MODEL_CLAIM_MATCH = "CLAUDE_MODEL_CLAIM_MATCH"
CLAUDE_MODEL_CLAIM_MISMATCH = "CLAUDE_MODEL_CLAIM_MISMATCH"
OPENAI_STREAM_SEQUENCE_MATCH = "OPENAI_STREAM_SEQUENCE_MATCH"
```

Add to `RiskTag`:

```python
CROSS_PROVIDER_FINISH_REASON_SUSPECT = "CROSS_PROVIDER_FINISH_REASON_SUSPECT"
SELF_RELAY_LOOP_DETECTED = "SELF_RELAY_LOOP_DETECTED"
SYNTHETIC_THINKING_SUSPECT = "SYNTHETIC_THINKING_SUSPECT"
```

- [ ] **Step 4: Run model tests**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_models.py -v
```

Expected: PASS.

---

### Task 2: Add OpenAI-Compatible Provider Adapter

**Files:**
- Create: `src/tokenverify/providers/openai_compatible.py`
- Test: `tests/providers/test_openai_compatible.py`

- [ ] **Step 1: Write failing provider tests**

Create `tests/providers/test_openai_compatible.py`:

```python
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
```

- [ ] **Step 2: Run provider tests to verify failure**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/providers/test_openai_compatible.py -v
```

Expected: FAIL because the provider module does not exist.

- [ ] **Step 3: Implement provider module**

Create `src/tokenverify/providers/openai_compatible.py`:

```python
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


def build_chat_completions_payload(
    model: str,
    messages: list[dict],
    max_tokens: int = 256,
    stream: bool = False,
) -> dict:
    return {"model": model, "messages": messages, "max_tokens": max_tokens, "stream": stream}


def _normalize_base_url(base_url: str) -> str:
    normalized = base_url.rstrip("/")
    suffix = "/chat/completions"
    if normalized.endswith(suffix):
        return normalized[: -len(suffix)]
    return normalized


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


def _first_choice(data: dict) -> dict:
    choices = data.get("choices")
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        return choices[0]
    return {}
```

- [ ] **Step 4: Run provider tests**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/providers/test_openai_compatible.py -v
```

Expected: PASS.

---

### Task 3: Add OpenAI-Compatible Claude Relay Probes

**Files:**
- Create: `src/tokenverify/probes/openai_compatible.py`
- Test: `tests/probes/test_openai_compatible.py`

- [ ] **Step 1: Write failing probe tests**

Create `tests/probes/test_openai_compatible.py`:

```python
from tokenverify.models import ProviderEvent
from tokenverify.probes.openai_compatible import (
    evaluate_chat_completions_response,
    evaluate_claude_claim_consistency,
    evaluate_openai_streaming_features,
    evaluate_reasoning_leakage,
)


def test_chat_completions_shape_passes_with_openai_compatible_tag():
    result = evaluate_chat_completions_response({"model": "claude-sonnet-4.5", "choices": [{"message": {"content": "ok"}}]})

    assert result.name == "chat_completions_shape"
    assert result.status == "passed"
    assert result.evidence[0].passed is True
    assert "OPENAI_COMPATIBLE_SHAPE_MATCH" in result.evidence[0].tags


def test_anthropic_native_shape_on_openai_claim_is_mismatch():
    result = evaluate_chat_completions_response({"type": "message", "role": "assistant", "content": [{"type": "text"}]})

    assert result.status == "failed"
    assert result.evidence[0].passed is False
    assert "ANTHROPIC_NATIVE_SHAPE_DETECTED" in result.evidence[0].tags


def test_claude_model_claim_match_and_mismatch():
    match = evaluate_claude_claim_consistency("claude-sonnet-4.5", {"model": "anthropic/claude-sonnet-4.5"})
    mismatch = evaluate_claude_claim_consistency("claude-sonnet-4.5", {"model": "deepseek-r1"})

    assert "CLAUDE_MODEL_CLAIM_MATCH" in match.evidence[0].tags
    assert "CLAUDE_MODEL_CLAIM_MISMATCH" in mismatch.evidence[0].tags


def test_reasoning_content_leak_is_strong_failure():
    result = evaluate_reasoning_leakage({"choices": [{"delta": {"reasoning_content": "hidden"}}]})

    assert result.status == "failed"
    assert result.evidence[0].passed is False
    assert "CROSS_PROVIDER_REASONING_LEAKED" in result.evidence[0].tags


def test_fake_thinking_text_is_heuristic_risk():
    result = evaluate_reasoning_leakage({"choices": [{"message": {"content": "Thinking Process:\\n1. Analyzing...\\nAnswer: ok"}}]})

    assert result.status == "warning"
    assert result.evidence[0].weight == "weak"
    assert "SYNTHETIC_THINKING_SUSPECT" in result.evidence[0].tags


def test_fake_thinking_text_handles_markdown_and_bracket_prefixes():
    markdown = evaluate_reasoning_leakage({"choices": [{"message": {"content": "### Thinking Process\\nAnalyzing request..."}}]})
    bracketed = evaluate_reasoning_leakage({"choices": [{"message": {"content": "[thinking]\\nI should reason step by step."}}]})

    assert "SYNTHETIC_THINKING_SUSPECT" in markdown.evidence[0].tags
    assert "SYNTHETIC_THINKING_SUSPECT" in bracketed.evidence[0].tags


def test_streaming_requires_finish_reason_before_done():
    result = evaluate_openai_streaming_features(
        [
            ProviderEvent(0.0, "chat.completion.chunk", text_length=2, data={"finish_reason": None}),
            ProviderEvent(0.1, "chat.completion.chunk", text_length=2, data={"finish_reason": "stop"}),
        ]
    )

    assert result.status == "passed"
    assert "OPENAI_STREAM_SEQUENCE_MATCH" in result.evidence[0].tags


def test_streaming_missing_finish_reason_is_sequence_mismatch():
    result = evaluate_openai_streaming_features(
        [ProviderEvent(0.0, "chat.completion.chunk", text_length=2, data={"finish_reason": None})]
    )

    assert result.status == "failed"
    assert "STREAM_EVENT_SEQUENCE_MISMATCH" in result.evidence[0].tags


def test_content_filter_finish_reason_is_risk_tag():
    result = evaluate_openai_streaming_features(
        [ProviderEvent(0.0, "chat.completion.chunk", text_length=2, data={"finish_reason": "content_filter"})]
    )

    assert result.status == "warning"
    assert "CROSS_PROVIDER_FINISH_REASON_SUSPECT" in result.evidence[0].tags
```

- [ ] **Step 2: Run probe tests to verify failure**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/probes/test_openai_compatible.py -v
```

Expected: FAIL because the probe module does not exist.

- [ ] **Step 3: Implement probe module**

Create `src/tokenverify/probes/openai_compatible.py` with:

```python
from __future__ import annotations

from tokenverify.models import EvidenceItem, EvidenceTag, ProbeResult, ProviderEvent, RiskTag
from tokenverify.probes.streaming import calculate_streaming_metrics


def evaluate_chat_completions_response(response: dict) -> ProbeResult:
    choices = response.get("choices")
    is_openai_shape = isinstance(choices, list) and choices and isinstance(choices[0], dict) and "message" in choices[0]
    if is_openai_shape:
        return ProbeResult(
            "chat_completions_shape",
            "passed",
            [EvidenceItem("openai_compatible_chat_shape", "strong", True, "Response matches OpenAI-compatible Chat Completions shape.", tags=[EvidenceTag.OPENAI_COMPATIBLE_SHAPE_MATCH.value])],
        )
    if response.get("type") == "message" and "content" in response:
        return ProbeResult(
            "chat_completions_shape",
            "failed",
            [EvidenceItem("openai_compatible_chat_shape", "strong", False, "Response is Anthropic native Messages shape despite an OpenAI-compatible claim.", tags=[EvidenceTag.ANTHROPIC_NATIVE_SHAPE_DETECTED.value])],
        )
    return ProbeResult(
        "chat_completions_shape",
        "failed",
        [EvidenceItem("openai_compatible_chat_shape", "strong", False, "Response does not match OpenAI-compatible Chat Completions shape.", tags=[EvidenceTag.OPENAI_COMPATIBLE_SHAPE_MISMATCH.value])],
    )


def evaluate_claude_claim_consistency(claimed_model: str, response: dict) -> ProbeResult:
    observed = str(response.get("model") or "")
    if not observed:
        return ProbeResult("claude_claim_consistency", "skipped", [EvidenceItem("claude_model_claim", "strong", None, "No response model field was observed.")])
    normalized_claim = claimed_model.lower().replace("anthropic/", "")
    normalized_observed = observed.lower().replace("anthropic/", "")
    passed = normalized_claim in normalized_observed or normalized_observed in normalized_claim
    return ProbeResult(
        "claude_claim_consistency",
        "passed" if passed else "failed",
        [
            EvidenceItem(
                "claude_model_claim",
                "strong",
                passed,
                f"Observed response model `{observed}` {'matches' if passed else 'contradicts'} claimed model `{claimed_model}`.",
                tags=[EvidenceTag.CLAUDE_MODEL_CLAIM_MATCH.value if passed else EvidenceTag.CLAUDE_MODEL_CLAIM_MISMATCH.value],
            )
        ],
    )


def evaluate_reasoning_leakage(response: dict) -> ProbeResult:
    if _contains_reasoning_content(response):
        return ProbeResult(
            "reasoning_leakage",
            "failed",
            [EvidenceItem("cross_provider_reasoning_leaked", "strong", False, "Response exposed provider-specific reasoning_content in an OpenAI-compatible Claude claim.", tags=[EvidenceTag.CROSS_PROVIDER_REASONING_LEAKED.value])],
        )
    if _contains_fake_thinking_text(response):
        return ProbeResult(
            "reasoning_leakage",
            "warning",
            [EvidenceItem("synthetic_thinking_text", "weak", False, "Thinking-like text was mixed into normal content with scripted prefixes.", tags=[RiskTag.SYNTHETIC_THINKING_SUSPECT.value])],
        )
    return ProbeResult("reasoning_leakage", "passed", [])


def evaluate_openai_streaming_features(events: list[ProviderEvent]) -> ProbeResult:
    metrics = calculate_streaming_metrics(events)
    finish_reasons = [event.data.get("finish_reason") for event in events]
    terminal = next((reason for reason in reversed(finish_reasons) if reason), None)
    evidence: list[EvidenceItem] = []
    if terminal is None and events:
        evidence.append(EvidenceItem("openai_stream_sequence", "strong", False, "Stream ended without a terminal finish_reason.", tags=[EvidenceTag.STREAM_EVENT_SEQUENCE_MISMATCH.value]))
        return ProbeResult("openai_compatible_streaming", "failed", evidence, metrics=metrics)
    if terminal == "content_filter":
        evidence.append(EvidenceItem("openai_stream_finish_reason", "weak", False, "Stream ended with content_filter finish_reason for a claimed Claude relay.", tags=[RiskTag.CROSS_PROVIDER_FINISH_REASON_SUSPECT.value]))
        return ProbeResult("openai_compatible_streaming", "warning", evidence, metrics=metrics)
    if events:
        evidence.append(EvidenceItem("openai_stream_sequence", "strong", True, "OpenAI-compatible stream included a terminal finish_reason.", tags=[EvidenceTag.OPENAI_STREAM_SEQUENCE_MATCH.value]))
    if metrics.is_synthetic_stream:
        evidence.append(EvidenceItem("synthetic_stream_heuristic", "weak", False, "Stream chunks were uniformly sized and emitted in a short burst.", tags=[RiskTag.SYNTHETIC_STREAM_SUSPECT.value, RiskTag.STREAM_UNIFORMITY_SUSPECT.value]))
    return ProbeResult("openai_compatible_streaming", "warning" if metrics.is_synthetic_stream else "passed", evidence, metrics=metrics)


def _contains_reasoning_content(response: dict) -> bool:
    for choice in _choices(response):
        for key in ("delta", "message"):
            value = choice.get(key)
            if isinstance(value, dict) and "reasoning_content" in value:
                return True
    return False


def _contains_fake_thinking_text(response: dict) -> bool:
    markers = (
        "thinking process:",
        "thinking process",
        "### thinking process",
        "[thinking]",
        "{thinking}",
        "analyzing...",
        "1. analyzing",
    )
    for choice in _choices(response):
        message = choice.get("message")
        delta = choice.get("delta")
        content = None
        if isinstance(message, dict):
            content = message.get("content")
        if content is None and isinstance(delta, dict):
            content = delta.get("content")
        normalized = content.strip().lower() if isinstance(content, str) else ""
        if normalized and any(marker in normalized for marker in markers):
            return True
    return False


def _choices(response: dict) -> list[dict]:
    choices = response.get("choices")
    return [choice for choice in choices if isinstance(choice, dict)] if isinstance(choices, list) else []
```

- [ ] **Step 4: Run probe tests**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/probes/test_openai_compatible.py -v
```

Expected: PASS.

---

### Task 4: Route OpenAI-Compatible Claude Claims In Audit Flow

**Files:**
- Modify: `src/tokenverify/audit.py`
- Test: `tests/test_audit_flow.py`

- [ ] **Step 1: Write failing audit routing tests**

Append to `tests/test_audit_flow.py`:

def test_openai_compatible_claim_uses_chat_completion_observations(tmp_path):
    config_path = tmp_path / "audit.yaml"
    config_path.write_text(
        """
selected_endpoint: relay
endpoints:
  - name: relay
    base_url: https://relay.example/v1
    provider: anthropic
    api_shape: openai-compatible
    model: claude-sonnet-4.5
    api_key: TOKEN_PLACEHOLDER
""",
        encoding="utf-8",
    )
    runtime_config = load_runtime_config(config_path)
    observations = AuditObservations(
        messages_response={"model": "claude-sonnet-4.5", "choices": [{"message": {"content": "ok"}}]},
        stream_events=[
            ProviderEvent(0.0, "chat.completion.chunk", text_length=2, data={"finish_reason": None}),
            ProviderEvent(0.1, "chat.completion.chunk", text_length=2, data={"finish_reason": "stop"}),
        ],
    )

    result = run_audit(runtime_config, observations=observations)

    assert result.target_summary["claimed_api_shape"] == "openai-compatible"
    assert [probe.name for probe in result.probe_results] == [
        "chat_completions_shape",
        "claude_claim_consistency",
        "reasoning_leakage",
        "openai_compatible_streaming",
    ]
    assert result.rating == Rating.HIGH_TRUST


def test_openai_compatible_self_relay_loop_short_circuits(tmp_path):
    config_path = tmp_path / "audit.yaml"
    config_path.write_text(
        """
selected_endpoint: relay
endpoints:
  - name: relay
    base_url: https://relay.example/v1
    provider: anthropic
    api_shape: openai-compatible
    model: claude-sonnet-4.5
    api_key: TOKEN_PLACEHOLDER
""",
        encoding="utf-8",
    )
    runtime_config = load_runtime_config(config_path)
    observations = AuditObservations(messages_error="self-relay-loop: TokenVerify scan marker was echoed")

    result = run_audit(runtime_config, observations=observations)

    assert result.rating == Rating.INCONCLUSIVE
    assert "SELF_RELAY_LOOP_DETECTED" in result.verdict.tags


def test_scoring_counts_openai_compatible_probe_evidence_generically(tmp_path):
    config_path = tmp_path / "audit.yaml"
    config_path.write_text(
        """
selected_endpoint: relay
endpoints:
  - name: relay
    base_url: https://relay.example/v1
    provider: anthropic
    api_shape: openai-compatible
    model: claude-sonnet-4.5
    api_key: TOKEN_PLACEHOLDER
""",
        encoding="utf-8",
    )
    runtime_config = load_runtime_config(config_path)
    observations = AuditObservations(
        messages_response={"model": "claude-sonnet-4.5", "choices": [{"message": {"content": "ok"}}]},
    )

    result = run_audit(runtime_config, observations=observations)

    assert result.score_breakdown["strong_passed"] >= 2
    assert result.verdict.authenticity_score >= 90
```

- [ ] **Step 2: Run audit flow tests to verify failure**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_audit_flow.py -v
```

Expected: FAIL because audit flow still uses native Claude probes for all observations.

- [ ] **Step 3: Implement routing helpers**

In `src/tokenverify/audit.py`, import new provider/probes:

```python
from tokenverify.models import EvidenceItem, RiskTag
from tokenverify.providers.openai_compatible import (
    OpenAICompatibleChatClient,
    SelfRelayLoopError,
    build_chat_completions_payload,
)
from tokenverify.probes.openai_compatible import (
    evaluate_chat_completions_response,
    evaluate_claude_claim_consistency,
    evaluate_openai_streaming_features,
    evaluate_reasoning_leakage,
)
```

At the top of `run_audit`, route by claim:

```python
    claim = runtime_config.endpoint.claim
    if claim and claim.provider == "anthropic" and claim.api_shape == "openai-compatible":
        return _run_openai_compatible_claude_audit(runtime_config, observations)
```

Add:

```python
def _run_openai_compatible_claude_audit(runtime_config, observations: AuditObservations | None) -> AuditResult:
    observations = observations or _collect_openai_compatible_observations(runtime_config)
    probe_results: list[ProbeResult] = []
    if observations.messages_error and "self-relay-loop" in observations.messages_error:
        probe_results.append(
            ProbeResult(
                "self_relay_loop_safety_gate",
                "error",
                [EvidenceItem("self_relay_loop_detected", "weak", False, observations.messages_error, tags=[RiskTag.SELF_RELAY_LOOP_DETECTED.value])],
                errors=[observations.messages_error],
            )
        )
        rating, breakdown, verdict = score_probe_results(probe_results)
        return _result(runtime_config, probe_results, rating, breakdown, verdict)
    if observations.messages_response is not None:
        probe_results.append(evaluate_chat_completions_response(observations.messages_response))
        probe_results.append(evaluate_claude_claim_consistency(runtime_config.endpoint.model, observations.messages_response))
        probe_results.append(evaluate_reasoning_leakage(observations.messages_response))
    if observations.messages_error is not None:
        probe_results.append(ProbeResult("chat_completions_shape", "error", errors=[observations.messages_error]))
    if observations.stream_events:
        probe_results.append(evaluate_openai_streaming_features(observations.stream_events))
        _write_raw_logs(runtime_config.raw_log_path, observations.stream_events, runtime_config.raw_logs_enabled)
    rating, breakdown, verdict = score_probe_results(probe_results)
    return _result(runtime_config, probe_results, rating, breakdown, verdict)
```

Check `src/tokenverify/scoring.py` before finishing this step. It must score by generic `EvidenceItem.weight` and `EvidenceItem.passed` values, not by hard-coded probe names such as `messages_protocol` or `extended_thinking`. The OpenAI-compatible probes `chat_completions_shape`, `claude_claim_consistency`, `reasoning_leakage`, and `openai_compatible_streaming` must be counted automatically through their evidence items.

Add:

```python
def _collect_openai_compatible_observations(runtime_config) -> AuditObservations:
    if not runtime_config.endpoint.api_key:
        return AuditObservations(messages_error="API key is required for live audit.")
    client = OpenAICompatibleChatClient(
        base_url=runtime_config.endpoint.base_url,
        api_key=runtime_config.endpoint.api_key,
        headers=runtime_config.endpoint.headers,
    )
    payload = build_chat_completions_payload(
        model=runtime_config.endpoint.model,
        messages=[{"role": "user", "content": "Reply with exactly: ok"}],
        max_tokens=64,
        stream=False,
    )
    messages_response = None
    messages_error = None
    stream_events: list[ProviderEvent] = []
    try:
        messages_response = client.create_chat_completion(payload)
    except SelfRelayLoopError as exc:
        messages_error = f"self-relay-loop: {exc}"
    except Exception as exc:
        messages_error = str(exc)
    try:
        stream_events = client.stream_chat_completion_events(payload)
    except SelfRelayLoopError as exc:
        messages_error = f"self-relay-loop: {exc}"
    except Exception:
        stream_events = []
    return AuditObservations(messages_response=messages_response, messages_error=messages_error, stream_events=stream_events)
```

Update `_is_inconclusive` in `src/tokenverify/scoring.py` if needed so `"self-relay-loop"` is inconclusive unless other strong failures exist:

```python
"self-relay-loop",
```

- [ ] **Step 4: Run audit flow tests**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_audit_flow.py tests/test_scoring.py -v
```

Expected: PASS.

---

### Task 5: Report Probe Names And Example Config

**Files:**
- Modify: `src/tokenverify/report.py`
- Create: `examples/claude-openai-compatible-audit.yaml`
- Modify: `tests/test_report.py`
- Modify: `README.md`

- [ ] **Step 1: Write failing report/example tests**

Append to `tests/test_report.py`:

```python
from dataclasses import replace


def test_openai_compatible_probe_sections_render_when_present():
    result = replace(
        audit_result(),
        probe_results=[
            ProbeResult("chat_completions_shape", "passed"),
            ProbeResult("claude_claim_consistency", "passed"),
            ProbeResult("openai_compatible_streaming", "passed"),
            ProbeResult("reasoning_leakage", "passed"),
        ],
    )

    markdown = render_markdown(result)

    assert "## Chat Completions Shape Probe" in markdown
    assert "## Claude Claim Consistency Probe" in markdown
    assert "## OpenAI-Compatible Streaming Probe" in markdown
    assert "## Reasoning Leakage Probe" in markdown
```

- [ ] **Step 2: Run report tests to verify failure**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_report.py -v
```

Expected: FAIL because renderer only has native probe sections.

- [ ] **Step 3: Generalize report probe rendering**

In `src/tokenverify/report.py`, add a display-name map:

```python
PROBE_TITLES = {
    "messages_protocol": "Messages Protocol Probe",
    "extended_thinking": "Extended Thinking Probe",
    "streaming_features": "Streaming Metrics",
    "chat_completions_shape": "Chat Completions Shape Probe",
    "claude_claim_consistency": "Claude Claim Consistency Probe",
    "openai_compatible_streaming": "OpenAI-Compatible Streaming Probe",
    "reasoning_leakage": "Reasoning Leakage Probe",
}
```

Replace fixed probe section calls with:

```python
    lines.extend(_probe_sections_for_result(result.probe_results))
```

Add probe order constants:

```python
NATIVE_PROBE_ORDER = ("messages_protocol", "extended_thinking", "streaming_features")
OPENAI_COMPATIBLE_PROBE_ORDER = (
    "chat_completions_shape",
    "claude_claim_consistency",
    "openai_compatible_streaming",
    "reasoning_leakage",
)
```

Add helpers:

```python
def _streaming_section_with_title(title: str, probe: ProbeResult | None) -> list[str]:
    lines = ["", f"## {title}"]
    if probe is None or not isinstance(probe.metrics, StreamingMetrics):
        return lines + ["", "- Not run"]
    metrics = probe.metrics
    lines.extend(["", f"- TTFT seconds: {metrics.ttft_seconds}", f"- Total latency seconds: {metrics.total_latency_seconds}", f"- Chunk intervals: {metrics.chunk_intervals}", f"- Chunk size distribution: {metrics.chunk_size_distribution}", f"- Estimated TPS: {metrics.estimated_tps}", f"- Synthetic stream heuristic: {metrics.is_synthetic_stream}"])
    return lines


def _probe_sections_for_result(probes: list[ProbeResult]) -> list[str]:
    probe_names = {probe.name for probe in probes}
    order = OPENAI_COMPATIBLE_PROBE_ORDER if probe_names.intersection(OPENAI_COMPATIBLE_PROBE_ORDER) else NATIVE_PROBE_ORDER
    lines: list[str] = []
    for name in order:
        probe = _find_probe(probes, name)
        title = PROBE_TITLES[name]
        if name in {"streaming_features", "openai_compatible_streaming"}:
            lines.extend(_streaming_section_with_title(title, probe))
        else:
            lines.extend(_probe_section(title, probe))
    return lines
```

- [ ] **Step 4: Add example YAML**

Create `examples/claude-openai-compatible-audit.yaml`:

```yaml
selected_endpoint: claude-openai-compatible
output: reports/claude-openai-compatible-audit.md
raw_logs:
  enabled: false
  path: null
endpoints:
  - name: claude-openai-compatible
    base_url: https://relay.example/v1
    provider: anthropic
    api_shape: openai-compatible
    model: claude-sonnet-4.5
    api_key_env: RELAY_API_KEY
```

- [ ] **Step 5: Update README**

Add a short usage note after the existing config example:

````markdown
For Claude relays exposed through an OpenAI-compatible Chat Completions API, set an explicit composite claim:

```yaml
provider: anthropic
api_shape: openai-compatible
model: claude-sonnet-4.5
```

This path audits the compatibility layer and Claude claim consistency; it does not claim to prove direct official Anthropic API access.
````

- [ ] **Step 6: Run report tests**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/test_report.py -v
```

Expected: PASS.

---

### Task 6: Full Verification And Final Review

**Files:**
- Verify all changed files.

- [ ] **Step 1: Run focused tests**

Run:

```bash
PYTHONPATH=src python3 -m pytest tests/providers/test_openai_compatible.py tests/probes/test_openai_compatible.py tests/test_audit_flow.py tests/test_report.py tests/test_models.py -v
```

Expected: PASS.

- [ ] **Step 2: Run full test suite**

Run:

```bash
PYTHONPATH=src python3 -m pytest -v
```

Expected: PASS, with real-network tests deselected unless explicitly enabled.

- [ ] **Step 3: Run whitespace check**

Run:

```bash
git diff --check
```

Expected: no output.

- [ ] **Step 4: Generate local example report without real network**

Run:

```bash
PYTHONPATH=src python3 -m tokenverify.cli audit --config examples/claude-openai-compatible-audit.yaml --endpoint claude-openai-compatible --output reports/claude-openai-compatible-audit.md
```

Expected: command exits 0 and report renders the OpenAI-compatible claim. Without `RELAY_API_KEY`, the rating should be `无法判定`; this is acceptable for a no-network local example.

- [ ] **Step 5: Final review checkpoint**

Report:

- Files changed.
- Tests run and results.
- Explicitly note that OpenAI official, DeepSeek provider, Gemini, Seed, Qwen, Doubao, dashboard, batch mode, and JSON output remain out of scope.

---

## Plan Self-Review

Spec coverage:

- `/v1/chat/completions` adapter is covered by Task 2.
- OpenAI-compatible auth and `X-TokenVerify-Scan` are covered by Task 2.
- Self-relay short-circuit is covered by Tasks 2 and 4.
- Chat Completions shape probe is covered by Task 3.
- Claude claim consistency is covered by Task 3.
- `reasoning_content` and fake thinking separation are covered by Task 3.
- `finish_reason` terminal checks are covered by Task 3.
- Audit routing away from `/v1/messages` is covered by Task 4.
- Report probe names and example config are covered by Task 5.

Placeholder scan:

- This plan contains no `TBD`, `TODO`, or "implement later" placeholders.
- All verification commands are explicit.
- All tasks have a red test step before implementation.

Execution handoff:

- Implement sequentially unless the user explicitly requests parallel subagents.
- Stop at final review before commit.
