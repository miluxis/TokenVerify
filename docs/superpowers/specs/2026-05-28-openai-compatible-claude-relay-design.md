# OpenAI-Compatible Claude Relay Design Spec

Date: 2026-05-28
Status: User review gate

## 1. Purpose

This spec defines the next TokenVerify phase after Claude native deepening: auditing endpoints that claim to provide Anthropic Claude models through an OpenAI-compatible Chat Completions API shape.

The target claim is:

```python
Claim(
    provider="anthropic",
    api_shape="openai-compatible",
    model="claude-sonnet-4.5",
    channel_claim="unknown",
    region_claim=None,
)
```

This phase should answer a narrow question: does an OpenAI-compatible endpoint appear to route to Claude-like upstream behavior, or does it merely expose a generic OpenAI-compatible facade while ignoring, translating away, or contradicting Claude-specific capabilities?

## 2. Scope

This phase adds support for one new audit path:

- Claimed provider: `anthropic`.
- Claimed API shape: `openai-compatible`.
- Wire endpoint: OpenAI Chat Completions-compatible `/v1/chat/completions`.
- User interface: existing CLI and YAML configuration.
- Report output: existing Markdown renderer with `Overall Verdict`, `Authenticity Assertions`, and `Heuristic Risk Profile`.

This phase does not implement:

- OpenAI official model authenticity auditing.
- DeepSeek, Gemini, Seed, Qwen, Doubao, or other provider adapters.
- Responses API support.
- Tool calling or multimodal probes.
- Batch endpoint execution.
- JSON report output.
- SaaS dashboard behavior.

## 3. Design Principles

### 3.1 Treat Compatibility As A Claimed API Shape

An OpenAI-compatible Claude relay is not the same audit target as Anthropic native Claude. The claim must explicitly say:

- `provider="anthropic"`
- `api_shape="openai-compatible"`

The endpoint should be judged against the behavior expected from an OpenAI-compatible facade over Claude, not against Anthropic native `/v1/messages` behavior.

### 3.2 Preserve Strong Versus Heuristic Separation

Strong authenticity assertions remain limited to structural evidence:

- Chat Completions response shape is valid or invalid.
- Streaming event shape follows OpenAI-compatible SSE semantics or not.
- Claude-specific model naming and capability claims are preserved or contradicted.
- Claude thinking/reasoning claims are represented, stripped, rejected, or leaked through incompatible fields.
- Error schema is OpenAI-compatible, Anthropic-native, or generic proxy-like.

Heuristic risk profile remains limited to weak channel-health signals:

- TTFT and stream timing anomalies.
- Synthetic OpenAI-style stream chunks.
- Retry, timeout, or unstable relay symptoms.
- Pooling or web-reverse suspicion.

Risk observations must not directly accuse the channel of forgery.

### 3.3 Do Not Pretend OpenAI-Compatible Can Prove Native Claude Internals

OpenAI-compatible relays often translate Claude responses into OpenAI fields. This makes some Anthropic-native evidence unavailable.

This phase should avoid impossible claims such as "official Anthropic API confirmed" when the endpoint only exposes OpenAI-compatible shape. A strong pass should mean:

> The endpoint consistently behaves like an OpenAI-compatible relay for the claimed Claude model.

It should not mean:

> The endpoint is confirmed to be direct official Anthropic API.

## 4. Provider Adapter Design

Add a new provider module:

```text
src/tokenverify/providers/openai_compatible.py
```

Responsibilities:

- Build Chat Completions payloads.
- Send non-streaming requests to `/v1/chat/completions`.
- Send streaming requests to `/v1/chat/completions`.
- Parse OpenAI-compatible SSE lines.
- Normalize OpenAI-compatible error responses.

The adapter should not contain scoring logic.

### 4.1 Request Payload

The minimal non-streaming payload:

```json
{
  "model": "claude-sonnet-4.5",
  "messages": [
    {"role": "user", "content": "Reply with exactly: ok"}
  ],
  "max_tokens": 64,
  "stream": false
}
```

The streaming payload should set `stream: true`.

### 4.2 Headers

Use OpenAI-compatible auth by default:

- `Authorization: Bearer <api_key>`
- `Content-Type: application/json`

Do not send Anthropic-native headers such as `anthropic-version` or `x-api-key` through the OpenAI-compatible adapter unless the user explicitly configures custom headers.

### 4.3 Error Normalization

OpenAI-compatible error shape:

```json
{
  "error": {
    "message": "...",
    "type": "...",
    "code": "..."
  }
}
```

Normalize into:

- message
- category/type
- code if available
- `is_openai_compatible_shape`
- raw payload

If the endpoint returns Anthropic-native error shape while the claim is OpenAI-compatible, this is structurally interesting but not automatically negative. It should emit a tag showing the mismatch or leak, then scoring can interpret it.

## 5. Probe Set

### 5.1 Chat Completions Shape Probe

Send a non-streaming Chat Completions request and inspect response shape.

Strong pass indicators:

- Top-level `choices` list exists.
- First choice contains `message`.
- Message content is represented as a string or compatible content shape.
- Optional `usage` is well-formed if present.

Strong fail indicators:

- Response looks like Anthropic native Messages shape despite the OpenAI-compatible claim.
- Response lacks both OpenAI-compatible Chat Completions fields and Anthropic-native fields.
- Response returns generic proxy payload instead of model response.

Initial tags:

- `OPENAI_COMPATIBLE_SHAPE_MATCH`
- `OPENAI_COMPATIBLE_SHAPE_MISMATCH`
- `ANTHROPIC_NATIVE_SHAPE_DETECTED`
- `GENERIC_PROXY_ERROR_DETECTED`

### 5.2 Claude Claim Consistency Probe

Inspect model and response metadata for contradictions.

Strong evidence can include:

- Response model field preserves or maps recognizably to the claimed Claude model.
- Response model field contradicts the claim with a different provider family.
- Provider-specific fields leak across boundaries, such as DeepSeek-style `reasoning_content`.

Initial tags:

- `CLAUDE_MODEL_CLAIM_MATCH`
- `CLAUDE_MODEL_CLAIM_MISMATCH`
- `CROSS_PROVIDER_REASONING_LEAKED`

This probe should be conservative: absence of a model field is neutral unless combined with other contradictions.

### 5.3 Streaming Shape Probe

Send a streaming Chat Completions request and parse OpenAI-compatible SSE events.

Strong pass indicators:

- Stream emits `data: {...}` JSON events.
- Delta chunks appear under `choices[].delta`.
- Terminal chunk is parsed and includes an explicit `choices[].finish_reason` value such as `stop` or `length`.
- Terminal `[DONE]` marker appears after the final semantic chunk, or the stream closes cleanly after a parsed terminal chunk.

Strong fail indicators:

- Stream emits Anthropic-native event names while the claim is OpenAI-compatible.
- Stream emits invalid JSON in repeated model chunks.
- Stream structure is neither OpenAI-compatible nor Anthropic-native.
- Stream hard-drops before any terminal chunk with `finish_reason`.
- Stream emits `[DONE]` without a prior terminal chunk when earlier chunks looked incomplete.

Weak risk indicators:

- Uniform chunks emitted in a short burst.
- No real incremental generation despite `stream: true`.
- Highly regular chunk timing suggesting synthetic streaming.
- Terminal `finish_reason` is an unexpected provider-specific value such as `content_filter` for a claimed Claude relay. This should not alone prove substitution, but it is useful side evidence for cross-provider or gateway-policy leakage.

Initial tags:

- `OPENAI_STREAM_SEQUENCE_MATCH`
- `STREAM_EVENT_SEQUENCE_MISMATCH`
- `SYNTHETIC_STREAM_SUSPECT`
- `STREAM_UNIFORMITY_SUSPECT`
- `CROSS_PROVIDER_FINISH_REASON_SUSPECT`

### 5.4 Thinking And Reasoning Probe

OpenAI-compatible Claude relays may expose thinking in non-standard ways. This phase should not require Anthropic-native Extended Thinking blocks.

The probe should look for:

- DeepSeek-style `reasoning_content` in `choices[].message` or `choices[].delta`.
- Anthropic-style `thinking` blocks leaked into OpenAI-compatible content.
- OpenAI-compatible reasoning channels where reasoning is physically separated from normal `content`, such as `choices[].delta.reasoning_content`.
- Fake thinking text that is mixed into normal `content` with hard-coded prefixes such as `Thinking Process:`, `Analyzing...`, or numbered pseudo-reasoning steps.
- Claimed thinking support that is ignored or stripped when the relay advertises thinking-capable Claude models.

Interpretation:

- `CROSS_PROVIDER_REASONING_LEAKED` is strong negative evidence when a non-DeepSeek claim exposes DeepSeek-specific reasoning fields.
- Reasoning emitted through a dedicated reasoning field is higher-quality structural evidence than plain text that merely looks like reasoning.
- Plain text "thinking" mixed into normal `content` is not proof of real Extended Thinking. If it has hard-coded prefixes, scripted formatting, or combines with `SYNTHETIC_STREAM_SUSPECT`, emit `SYNTHETIC_THINKING_SUSPECT` as a heuristic risk tag.
- Anthropic `thinking` content inside an OpenAI-compatible wrapper is strong structural evidence that the relay may be passing Claude-native internals through, but it does not prove official Anthropic channel.
- Lack of thinking in an OpenAI-compatible response is neutral unless the endpoint or config explicitly claims thinking support.

## 6. Routing And Audit Flow

Audit orchestration should select provider adapter by `runtime_config.endpoint.claim.api_shape`.

Initial routing:

- `provider="anthropic", api_shape="native"`: existing Anthropic native audit path.
- `provider="anthropic", api_shape="openai-compatible"`: new OpenAI-compatible Claude relay audit path.

Unknown combinations should return a clear configuration error or inconclusive result, not silently use Anthropic native requests.

This is important because sending `/v1/messages` to an OpenAI-compatible endpoint can produce tool-created false negatives.

### 6.1 Self-Relay Loop Safety Gate

Every OpenAI-compatible audit request must include a TokenVerify-owned scan marker header, such as:

```text
X-TokenVerify-Scan: true
```

If the response headers echo this exact marker back, the tool should treat it as evidence that the request may have been routed back through the same gateway layer or a self-referential relay loop. The audit must immediately short-circuit further live probes for that endpoint to avoid token waste, runaway recursion, and misleading latency evidence.

Interpretation:

- If the loop marker appears with no useful model evidence, return `无法判定` with a clear operational warning.
- If the loop marker appears alongside generic proxy payloads, repeated redirects, or contradictory provider evidence, it may support `低可信`.
- Emit `SELF_RELAY_LOOP_DETECTED` so future dashboards can alert or cut traffic.

This safety gate is about preventing tool-induced harm first. It should not be framed as direct proof of malicious forgery by itself.

## 7. Scoring

The existing `Verdict` model should remain unchanged.

Authenticity score should be driven by:

- OpenAI-compatible response shape correctness.
- Claude model claim consistency.
- Streaming schema consistency.
- Cross-provider leakage.
- Error schema consistency.

Risk score should be driven by:

- Synthetic streaming heuristics.
- Synthetic thinking heuristics.
- Timing irregularity with debounce.
- Operational instability.
- Self-relay loop detection, with short-circuit behavior before any repeated probing.

High risk score must not automatically downgrade authenticity rating unless strong structural contradiction is present.

## 8. Configuration

YAML should support explicit OpenAI-compatible Claude relay claims:

```yaml
selected_endpoint: claude-openai-compatible
output: reports/claude-openai-compatible-audit.md
endpoints:
  - name: claude-openai-compatible
    base_url: https://relay.example/v1
    provider: anthropic
    api_shape: openai-compatible
    model: claude-sonnet-4.5
    api_key_env: RELAY_API_KEY
```

Existing inference from `base_url` should continue:

- `/v1/chat/completions` implies `api_shape="openai-compatible"`.
- Non-Anthropic host ending in `/v1` may imply `api_shape="openai-compatible"` unless explicitly overridden.

## 9. Report Requirements

The existing report sections remain:

- `Overall Verdict`
- `Authenticity Assertions`
- `Heuristic Risk Profile`
- probe details
- errors and warnings
- configuration summary

For OpenAI-compatible Claude relay audits, target summary must clearly show:

- Claimed provider: `anthropic`
- Claimed API shape: `openai-compatible`
- Claimed model
- Endpoint host

Probe section names should distinguish this path from Anthropic native probes:

- `Chat Completions Shape Probe`
- `Claude Claim Consistency Probe`
- `OpenAI-Compatible Streaming Probe`
- `Reasoning Leakage Probe`

## 10. Testing Strategy

Tests should be fully mocked and avoid real network calls.

Required tests:

- OpenAI-compatible payload builder uses `/v1/chat/completions` semantics.
- Adapter sends `Authorization: Bearer` rather than Anthropic-native headers.
- Adapter sends `X-TokenVerify-Scan: true` and short-circuits if the same marker is echoed in response headers.
- Chat Completions response shape emits strong pass evidence and `OPENAI_COMPATIBLE_SHAPE_MATCH`.
- Anthropic-native response shape on an OpenAI-compatible claim emits mismatch/detected tags.
- DeepSeek-style `reasoning_content` under `choices[].delta` emits `CROSS_PROVIDER_REASONING_LEAKED`.
- Fake thinking text mixed into normal `content` emits `SYNTHETIC_THINKING_SUSPECT`.
- Streaming parser extracts delta text lengths and handles `[DONE]`.
- Streaming parser records terminal `finish_reason` and emits `STREAM_EVENT_SEQUENCE_MISMATCH` when the stream ends without one.
- Unexpected terminal `finish_reason` values such as `content_filter` emit `CROSS_PROVIDER_FINISH_REASON_SUSPECT`.
- Audit routing uses OpenAI-compatible path when claim says `api_shape="openai-compatible"`.
- Audit routing does not call Anthropic native `/v1/messages` for OpenAI-compatible claims.
- Markdown report renders the OpenAI-compatible claim and probe names.

## 11. Implementation Boundaries

The implementation plan should be narrow:

- Add one OpenAI-compatible provider module.
- Add focused probes for OpenAI-compatible Claude relay.
- Extend audit routing.
- Add example YAML.
- Add tests.

Do not implement official OpenAI model auditing, DeepSeek provider auditing, Gemini, Seed, Qwen, Doubao, dashboard, batch mode, or JSON output in this phase.

## 12. User Review Gate

This document is ready for user review.

No implementation plan or code changes should start until the user approves this spec.
