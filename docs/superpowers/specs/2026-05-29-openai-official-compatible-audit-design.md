# OpenAI Official And Compatible Model Audit Design Spec

Date: 2026-05-29
Status: User review gate

## 1. Purpose

This spec defines the next TokenVerify provider expansion after the Claude deep-dive and OpenAI-compatible Claude relay work: auditing endpoints that claim to provide OpenAI models through the OpenAI Chat Completions-compatible API shape.

The target claims are:

```python
Claim(
    provider="openai",
    api_shape="openai-compatible",
    model="gpt-5.1",
    channel_claim="official",
    region_claim=None,
)
```

and:

```python
Claim(
    provider="openai",
    api_shape="openai-compatible",
    model="gpt-4.1",
    channel_claim="unknown",
    region_claim=None,
)
```

This phase should answer a narrow question: does an endpoint consistently behave like an OpenAI Chat Completions-compatible endpoint for the claimed OpenAI model family, or does it expose contradictions such as non-OpenAI model families, incompatible response shapes, provider-specific reasoning leakage, or relay/channel-risk markers?

## 2. Official Documentation Context

OpenAI's current API reference documents Chat Completions at `POST /v1/chat/completions`, with responses containing fields such as `id`, `object`, `created`, `model`, `choices`, `message`, `finish_reason`, and optional `usage`. The docs also note that new projects should consider the Responses API for latest platform features.

The model docs list current OpenAI model families including GPT-5.2, GPT-5.1, GPT-5, GPT-4.1, GPT-4o, o-series reasoning models, audio/realtime models, and GPT OSS models. Reasoning documentation says reasoning models work better with Responses, while Chat Completions remains supported.

References:

- [Chat Completions API Reference](https://platform.openai.com/docs/api-reference/chat/create-chat-completion)
- [Chat Completions Streaming API Reference](https://platform.openai.com/docs/api-reference/chat-streaming)
- [Responses API Reference](https://platform.openai.com/docs/api-reference/responses)
- [OpenAI Models](https://platform.openai.com/docs/models)
- [OpenAI Reasoning Models Guide](https://platform.openai.com/docs/guides/reasoning)

## 3. Scope

This phase adds one provider expansion path:

- Claimed provider: `openai`.
- Claimed API shape: `openai-compatible`.
- Wire endpoint: Chat Completions-compatible `/v1/chat/completions`.
- Official OpenAI channel detection: `https://api.openai.com/v1` and related OpenAI-native headers are treated as official-channel evidence when observed.
- OpenAI-compatible relay detection: non-OpenAI hosts using Chat Completions shape are treated as OpenAI-compatible channels, not official OpenAI confirmation.
- User interface: existing CLI and YAML configuration.
- Report output: existing Markdown renderer with `Overall Verdict`, `Authenticity Assertions`, and `Heuristic Risk Profile`.

This phase does not implement:

- Responses API auditing.
- Assistants, Realtime, Batch, audio, image, video, embeddings, moderation, or tool-use auditing.
- DeepSeek, Gemini, Anthropic, Seed, Qwen, Doubao, or other non-OpenAI provider expansion.
- Exact black-box identification of every OpenAI-compatible relay.
- Live-network tests.
- Dashboard, batch mode, JSON output, or pricing/rate-limit lookup.

## 4. Design Principles

### 4.1 Treat OpenAI Official And OpenAI-Compatible As Channel Claims

`provider="openai"` states the claimed model family. `api_shape="openai-compatible"` states the wire protocol. `channel_claim` distinguishes official API from a relay or unknown channel.

Strong evidence can support:

- The endpoint is structurally OpenAI Chat Completions-compatible.
- The returned model metadata is consistent with an OpenAI model family.
- Streaming follows OpenAI Chat Completions chunk semantics.
- Error schemas look OpenAI-compatible.

Strong evidence must not overstate:

- A compatible relay is not confirmed official OpenAI merely because it has OpenAI response shape.
- A single missing model field is not proof of substitution.
- A single timeout or latency spike is not proof of account pooling or web reversal.

### 4.2 Preserve Strong Versus Heuristic Separation

Strong authenticity assertions remain structural:

- Chat Completions shape match or mismatch.
- OpenAI model family match or mismatch.
- OpenAI streaming sequence match or mismatch.
- OpenAI-compatible error schema match or mismatch.
- Cross-provider leakage fields, such as `reasoning_content` for DeepSeek-style reasoning, when the claim is OpenAI.

Heuristic risk profile remains channel-health oriented:

- Non-OpenAI host while claiming official channel.
- Proxy, relay, CDN, or upstream markers in headers/errors.
- Synthetic streaming symptoms.
- Repeated-run latency variance after debounce.
- Model drift across repeated observations.

### 4.3 Keep Reasoning Evidence Conservative

Reasoning models may use reasoning tokens that are not visible in normal API output. The audit should check parameter compatibility and metadata consistency, not demand hidden chain-of-thought text.

For Chat Completions:

- `reasoning_effort` support is useful capability evidence when the model family supports it.
- Rejection of `reasoning_effort` for a claimed reasoning-capable model is structural negative evidence.
- Visible `reasoning_content` fields are cross-provider leakage, not proof of OpenAI reasoning.

For Responses:

- Responses-specific reasoning item behavior is out of scope for this phase and should be covered by a separate spec before implementation.

## 5. Provider Adapter Design

Add OpenAI-specific wrappers around the existing OpenAI-compatible Chat Completions provider rather than duplicating HTTP code.

Files:

```text
src/tokenverify/openai_capabilities.py
src/tokenverify/probes/openai.py
```

Reuse:

```text
src/tokenverify/providers/openai_compatible.py
src/tokenverify/providers/base.py
```

Responsibilities:

- Classify OpenAI model families and capability tiers.
- Build minimal Chat Completions probe payloads.
- Evaluate OpenAI model claim consistency.
- Evaluate OpenAI reasoning parameter compatibility.
- Evaluate official versus relay channel evidence.
- Keep scoring generic through existing `EvidenceItem`, `ProbeResult`, `Verdict`, and tag taxonomy.

## 6. Probe Set

### 6.1 OpenAI Chat Completions Shape Probe

Inspect non-streaming Chat Completions responses.

Strong pass indicators:

- Top-level `object` is `chat.completion` when present.
- Top-level `choices` list exists.
- First choice contains `message`.
- `finish_reason` is present at choice level.
- `model` is present and string-valued.

Strong fail indicators:

- Response is Anthropic Messages shape.
- Response exposes DeepSeek/Gemini/non-OpenAI provider-native shape.
- Response lacks both `choices[].message` and any recognizable OpenAI Chat Completions structure.

Initial tags:

- `OPENAI_CHAT_COMPLETION_SHAPE_MATCH`
- `OPENAI_CHAT_COMPLETION_SHAPE_MISMATCH`
- `NON_OPENAI_PROVIDER_SHAPE_DETECTED`

### 6.2 OpenAI Model Claim Consistency Probe

Inspect response model metadata and classify it into OpenAI model families.

Strong pass indicators:

- Claimed and observed model normalize to the same OpenAI family or snapshot alias.
- Official OpenAI model aliases and dated snapshots are recognized conservatively.

Strong fail indicators:

- Observed model belongs to a different provider family such as Claude, DeepSeek, Gemini, Qwen, or Doubao.
- Observed model is a known OpenAI-incompatible local/proxy model name when the claim is official OpenAI.
- Observed model belongs to an obviously lower OpenAI generation or capability tier than the claimed model. Example: `Claim(model="gpt-5.1")` with `response.model="gpt-4o-2024-05-13"` is a hard structured downgrade, not a harmless alias difference, and must emit `OPENAI_MODEL_CLAIM_MISMATCH`.
- Cross-provider model leakage is a stricter subset of model mismatch. Example: `Claim(provider="openai", model="gpt-5.1")` with `response.model="claude-3-5-sonnet"` or `response.model="deepseek-r1"` must emit `CROSS_PROVIDER_MODEL_LEAKED` and be treated as highest-priority strong failure.

Neutral indicators:

- No model field is present.
- Unknown OpenAI-looking future model name without contradiction.

Initial tags:

- `OPENAI_MODEL_CLAIM_MATCH`
- `OPENAI_MODEL_CLAIM_MISMATCH`
- `CROSS_PROVIDER_MODEL_LEAKED`

### 6.3 OpenAI Streaming Sequence Probe

Inspect Chat Completions streaming SSE chunks.

Strong pass indicators:

- Stream emits `data: {...}` JSON chunks.
- Chunk `object` is `chat.completion.chunk` when present.
- Delta content appears under `choices[].delta`.
- Terminal chunk contains a recognized `finish_reason`, followed by `[DONE]` or clean stream close.

Strong fail indicators:

- Anthropic-native stream events appear under an OpenAI claim.
- Invalid JSON appears in repeated model chunks.
- Stream ends without terminal finish reason after content chunks.

Weak risk indicators:

- Uniform short-burst chunks.
- No incremental content despite `stream: true`.

Initial tags:

- `OPENAI_STREAM_SEQUENCE_MATCH`
- `OPENAI_STREAM_SEQUENCE_MISMATCH`
- `SYNTHETIC_STREAM_SUSPECT`
- `STREAM_UNIFORMITY_SUSPECT`

### 6.4 OpenAI Reasoning Capability Probe

Use a capability table rather than guessing from one response.

Model tiers:

- GPT-5.2 / GPT-5.1 / GPT-5 family: reasoning-capable, Chat Completions supported.
- o-series: reasoning-capable, but may have API differences; keep first implementation conservative.
- GPT-4.1 / GPT-4o family: non-reasoning GPT family unless official docs indicate otherwise.
- Unknown future OpenAI-looking models: neutral capability confidence.

Strong pass indicators:

- A reasoning-capable claimed model accepts the relevant Chat Completions reasoning parameter.
- A non-reasoning claimed model rejects or ignores reasoning-only parameters without negative scoring.

Strong fail indicators:

- A reasoning-capable claimed model rejects a minimal supported reasoning parameter with a schema error.
- A claimed non-OpenAI or incompatible model exposes OpenAI-only reasoning metadata while contradicting other structural checks.
- A reasoning-capable claimed model accepts `reasoning_effort`, but a non-trivial reasoning-inducing prompt with high effort and sufficient token budget returns missing `usage.completion_tokens_details.reasoning_tokens` or `reasoning_tokens == 0`. This indicates the gateway may have stripped the reasoning parameter and must emit `OPENAI_REASONING_CAPABILITY_MISMATCH`.

Weak or non-failing indicators:

- A trivial prompt with `reasoning_tokens == 0` is not enough for strong failure. It should be a warning at most, because simple prompts may legitimately require no reasoning tokens.
- A response without usage details is strong negative evidence only for the dedicated reasoning-accounting probe. Do not reuse that rule for unrelated shape probes.

Initial tags:

- `OPENAI_REASONING_CAPABILITY_MATCH`
- `OPENAI_REASONING_CAPABILITY_MISMATCH`

### 6.5 Official Versus Relay Channel Probe

Inspect base URL, response headers, request IDs, and error text.

Strong official-channel evidence:

- Base URL host is `api.openai.com`.
- Response/request headers expose OpenAI-native request IDs such as `x-request-id` without relay/upstream contradiction.

Weak relay/channel-risk indicators:

- `channel_claim="official"` but host is not `api.openai.com`.
- Relay markers such as `x-openrouter-*`, `x-upstream-*`, `x-relay-*`, CDN-only policy markers, or upstream account-pool language.
- Host is `api.openai.com`, but headers or errors expose relay markers such as `x-openrouter-*`, `x-upstream-*`, `x-relay-*`, or `server: nginx`.
- Missing `server: cloudflare` is not a standalone failure condition. It may be recorded as weak supporting context only when paired with other relay or host contradictions.
- Repeated-run model drift or high latency variance after debounce.

Strong fail indicators:

- `channel_claim="official"` and base URL host is not `api.openai.com`.
- `channel_claim="official"` and an OpenAI-shaped error response is paired with relay/upstream/self-hosted gateway headers that contradict official-channel routing.

Initial tags:

- `OPENAI_OFFICIAL_CHANNEL_MATCH`
- `OPENAI_OFFICIAL_CHANNEL_MISMATCH`
- `RELAY_HEADER_SUSPECT`
- `RATE_LIMIT_RELAY_SUSPECT`
- `MODEL_DRIFT_SUSPECT`
- `TTFT_VARIANCE_HIGH`

## 7. Routing And Audit Flow

Audit orchestration should route by `Claim`:

- `provider="anthropic", api_shape="native"`: existing Anthropic native audit path.
- `provider="anthropic", api_shape="openai-compatible"`: existing OpenAI-compatible Claude relay path.
- `provider="openai", api_shape="openai-compatible"`: new OpenAI Chat Completions-compatible audit path.

Unsupported provider claims remain explicitly out of scope.

## 8. Scoring Expectations

The existing generic scoring model should remain in place:

- Strong structural failures lower authenticity.
- Weak channel-risk evidence increases risk score without automatically lowering authenticity.
- Operational failures such as auth, quota, timeout, or rate limit remain inconclusive unless paired with other structural observations.
- `CROSS_PROVIDER_MODEL_LEAKED` has the same highest-priority penalty semantics as `CROSS_PROVIDER_REASONING_LEAKED`: if either tag appears in probe evidence, final rating must be `LOW_TRUST` and authenticity must be forced into the low-trust range regardless of weaker positive evidence.

## 9. Safety And Test Policy

- All tests must use `httpx.MockTransport`, direct probe functions, or no-key CLI paths.
- No normal test may send live network traffic.
- Real-network checks, if ever added, must remain opt-in and marked.
- Do not add non-OpenAI provider implementations under this spec.

## 10. Acceptance Criteria

- `Claim(provider="openai", api_shape="openai-compatible", ...)` routes to the OpenAI audit path.
- OpenAI Chat Completions shape, model claim, streaming sequence, reasoning capability, and channel-risk probes are test-covered.
- Unsupported non-OpenAI provider claims remain out of scope.
- Reports render OpenAI probe sections.
- Roadmap TODO is updated only for spec and plan until implementation is complete.
