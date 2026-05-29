# DeepSeek Official And Compatible Model Audit Design Spec

Date: 2026-05-29
Status: User review gate

## 1. Purpose

This spec defines the next TokenVerify provider expansion after Claude native, OpenAI-compatible Claude relay, and OpenAI-compatible OpenAI audit support: auditing endpoints that claim to provide DeepSeek models through an OpenAI Chat Completions-compatible API shape.

The primary target claims are:

```python
Claim(
    provider="deepseek",
    api_shape="openai-compatible",
    model="deepseek-r1",
    channel_claim="official",
    region_claim=None,
)
```

and:

```python
Claim(
    provider="deepseek",
    api_shape="openai-compatible",
    model="deepseek-chat",
    channel_claim="unknown",
    region_claim=None,
)
```

This phase answers a narrow question: does an endpoint consistently behave like a DeepSeek Chat Completions-compatible endpoint for the claimed DeepSeek model family, especially R1 reasoning behavior, or does it expose contradictions such as non-DeepSeek model names, missing R1 reasoning fields, provider-specific leakage, or relay/channel-risk markers?

## 2. Scope

This phase adds one provider expansion path:

- Claimed provider: `deepseek`.
- Claimed API shape: `openai-compatible`.
- Wire endpoint: Chat Completions-compatible `/v1/chat/completions`.
- Official DeepSeek channel detection: official-channel evidence is limited to known DeepSeek official API hosts such as `api.deepseek.com`.
- DeepSeek-compatible relay detection: non-DeepSeek hosts using Chat Completions shape are treated as compatible relay channels, not official DeepSeek confirmation.
- User interface: existing CLI and YAML configuration, including `--repeat`.
- Report output: existing Markdown renderer with plain-language summary, channel risk profile, authenticity assertions, heuristic risk profile, and technical appendix.

This phase does not implement:

- DeepSeek non-chat endpoints, embeddings, fine-tuning, batch, tools, or JSON output.
- Gemini, Seed, Qwen, Doubao, or any other new provider.
- Exact black-box identification of every mixed routing setup.
- Live-network tests.
- Dashboard, batch mode, machine-readable JSON output, pricing lookup, or quota lookup.

## 3. Design Principles

### 3.1 Treat DeepSeek As Provider Claim, Not Just OpenAI-Compatible Shape

DeepSeek's API is OpenAI-compatible at the transport layer, but DeepSeek R1 has provider-specific reasoning behavior. A response can match Chat Completions shape while still contradicting the claimed DeepSeek model family.

Strong evidence can support:

- The endpoint is structurally Chat Completions-compatible.
- The returned `model` metadata is consistent with a DeepSeek model family.
- A claimed R1 model exposes DeepSeek reasoning fields in non-trivial prompts.
- Streaming follows Chat Completions chunk semantics and, for R1, exposes reasoning deltas when the API returns them.

Strong evidence must not overstate:

- A compatible relay is not confirmed official DeepSeek merely because it has DeepSeek-looking response shape.
- A single missing optional field is not proof of substitution unless the probe was designed to require that field.
- A single timeout, 429, or latency spike is not proof of web reversal or account pooling.

### 3.2 Keep Strong Authenticity Separate From Channel Risk

Strong authenticity assertions remain structural:

- Chat Completions shape match or mismatch.
- DeepSeek model family match or mismatch.
- R1 reasoning field presence or absence under a non-trivial reasoning prompt.
- DeepSeek-compatible streaming sequence match or mismatch.
- Cross-provider leakage such as Claude, OpenAI, Gemini, Qwen, or Doubao model names under a DeepSeek claim.

Heuristic channel-risk signals remain separate:

- Non-DeepSeek host while claiming official channel.
- Relay, proxy, CDN, cloud-hosting, upstream, web, account-pool, or quota markers in headers/errors.
- Repeated-run latency variance after debounce.
- Model drift across repeated observations.
- Synthetic or suspicious streaming symptoms.

### 3.3 R1 Reasoning Evidence Is The Core Capability Probe

DeepSeek R1 is expected to expose reasoning content through OpenAI-compatible response fields in many compatible implementations. The first implementation should check this conservatively:

- For R1 claims, send a non-trivial reasoning-inducing prompt with enough token budget.
- Inspect non-streaming `choices[].message.reasoning_content` when present.
- Inspect streaming `choices[].delta.reasoning_content` or equivalent provider-compatible reasoning deltas when present.
- Treat visible reasoning text inside ordinary `content` as weak synthetic-risk evidence, not as R1 native reasoning field evidence.

Do not require reasoning fields for `deepseek-chat` / V3-style claims.

### 3.4 Avoid Overfitting To One Relay

DeepSeek-compatible relays differ in how they expose model names and reasoning fields. The audit should normalize common model aliases but avoid treating every unknown alias as fraud.

Examples:

- `deepseek-r1`, `deepseek-reasoner`, and dated/suffixed R1 aliases should normalize to the R1 family.
- `deepseek-chat`, `deepseek-v3`, and dated/suffixed chat aliases should normalize to the chat/V3 family.
- Unknown DeepSeek-looking names are neutral unless contradicted by other evidence.
- Non-DeepSeek model names such as `gpt-4o`, `claude-3-5-sonnet`, `gemini-2.5-pro`, `qwen-*`, or `doubao-*` are cross-provider leakage and strong failure.

## 4. Provider Adapter Design

Reuse the existing OpenAI-compatible Chat Completions provider. Do not duplicate HTTP code.

New files:

```text
src/tokenverify/deepseek_capabilities.py
src/tokenverify/probes/deepseek.py
examples/deepseek-compatible-audit.yaml
tests/test_deepseek_capabilities.py
tests/probes/test_deepseek.py
```

Modified files:

```text
src/tokenverify/models.py
src/tokenverify/audit_plan.py
src/tokenverify/audit.py
src/tokenverify/report.py
src/tokenverify/tag_taxonomy.py
src/tokenverify/probes/categories.py
tests/test_models.py
tests/test_audit_plan.py
tests/test_audit_flow.py
tests/test_report.py
tests/test_tag_taxonomy.py
tests/probes/test_categories.py
tests/test_config.py
```

Responsibilities:

- Classify DeepSeek model families and capability tiers.
- Evaluate DeepSeek Chat Completions response shape.
- Evaluate model claim consistency.
- Evaluate R1 reasoning field presence for non-trivial reasoning probes.
- Evaluate DeepSeek-compatible stream sequence and reasoning deltas.
- Evaluate official versus relay channel risk.
- Keep scoring generic through existing `EvidenceItem`, `ProbeResult`, `Verdict`, and tag taxonomy.

## 5. Probe Set

### 5.1 DeepSeek Chat Completions Shape Probe

Inspect non-streaming responses.

Strong pass indicators:

- Top-level `choices` list exists.
- First choice contains `message`.
- `finish_reason` is present at choice level.
- `model` is present and string-valued.

Strong fail indicators:

- Response is Anthropic Messages shape.
- Response exposes Gemini, Claude native, or other non-OpenAI-compatible provider-native structure.
- Response lacks both `choices[].message` and recognizable Chat Completions structure.

Initial tags:

- `DEEPSEEK_CHAT_COMPLETION_SHAPE_MATCH`
- `DEEPSEEK_CHAT_COMPLETION_SHAPE_MISMATCH`
- `NON_DEEPSEEK_PROVIDER_SHAPE_DETECTED`

### 5.2 DeepSeek Model Claim Consistency Probe

Inspect response model metadata and classify it into DeepSeek model families.

Strong pass indicators:

- Claimed and observed model normalize to the same DeepSeek family or snapshot alias.
- R1 aliases normalize to R1.
- Chat/V3 aliases normalize to chat/V3.

Strong fail indicators:

- Observed model belongs to another provider family such as OpenAI, Claude, Gemini, Qwen, Doubao, or generic local model names.
- Observed model is a lower or incompatible DeepSeek family than the claimed model when the claim requires R1 reasoning. Example: `Claim(model="deepseek-r1")` with `response.model="deepseek-chat"` is a capability mismatch.
- Cross-provider model leakage must emit `CROSS_PROVIDER_MODEL_LEAKED` and be highest-priority strong failure.
- Cross-provider leakage is not limited to the JSON `model` field. Under a DeepSeek claim, provider-exclusive companion metadata such as OpenAI `system_fingerprint`, Anthropic native `type: message` / `content[].type: thinking`, Gemini native candidate schema, or explicit upstream provider fingerprints in response metadata must be treated as cross-provider leakage when observed.

Neutral indicators:

- No model field is present.
- Unknown DeepSeek-looking future model name without contradiction.

Initial tags:

- `DEEPSEEK_MODEL_CLAIM_MATCH`
- `DEEPSEEK_MODEL_CLAIM_MISMATCH`
- `CROSS_PROVIDER_MODEL_LEAKED`

### 5.3 DeepSeek R1 Reasoning Content Probe

Inspect non-streaming R1 responses for native reasoning fields.

Strong pass indicators:

- Claimed model is R1/reasoner family.
- Prompt is non-trivial and reasoning-inducing.
- Response includes non-empty `choices[].message.reasoning_content`.

Strong fail indicators:

- Claimed model is R1/reasoner family.
- Prompt is non-trivial with enough budget.
- Response succeeds but `choices[].message.reasoning_content` is missing, absent as a key, empty, whitespace-only, or not string-valued.
- Response only places "thinking" prose inside normal `content`, without native reasoning field.
- The response is successful and not a safety refusal, rate-limit error, upstream error, or empty response; under those conditions, missing native reasoning content for an R1 claim is a core capability failure.

Weak risk indicators:

- Visible fake reasoning text appears in `content`, such as markdown "Reasoning:" or bracketed "thinking" text, but native `reasoning_content` is absent.

Neutral indicators:

- Claimed model is `deepseek-chat` / V3-style; reasoning field is not expected.
- Probe was not run because no response was available.

Initial tags:

- `DEEPSEEK_REASONING_CONTENT_MATCH`
- `DEEPSEEK_REASONING_CONTENT_MISSING`
- `SYNTHETIC_THINKING_SUSPECT`

Scoring requirement:

- `DEEPSEEK_REASONING_CONTENT_MISSING` is a hard-fail tag for R1/reasoner claims. It must force the final rating to `LOW_TRUST`, at the same priority level as cross-provider leakage, because the claimed R1 reasoning channel is the core purchased capability.

### 5.4 DeepSeek Streaming Sequence Probe

Inspect Chat Completions streaming SSE chunks.

Strong pass indicators:

- Stream emits `data: {...}` JSON chunks.
- Delta content appears under `choices[].delta`.
- Terminal chunk contains a recognized `finish_reason`, followed by `[DONE]` or clean stream close.

For R1 claims, additional strong pass indicator:

- At least one chunk exposes `choices[].delta.reasoning_content` under a non-trivial reasoning stream probe.

Strong fail indicators:

- Anthropic-native stream events appear under a DeepSeek claim.
- Invalid JSON appears in repeated chunks.
- Stream ends without terminal finish reason after content chunks.
- R1 stream succeeds but never exposes reasoning delta when the dedicated R1 stream probe is used.

Weak risk indicators:

- Uniform short-burst chunks.
- No incremental content despite `stream: true`.
- Reasoning/content state machine disorder for R1 streams. Allowed order is zero or more `reasoning_content` deltas followed by zero or more `content` deltas. Once `content` has started, any later `reasoning_content`, repeated back-and-forth switching, or a single delta containing both `reasoning_content` and `content` is suspicious synthetic reasoning stream evidence and must emit `SYNTHETIC_THINKING_SUSPECT`.

Initial tags:

- `DEEPSEEK_STREAM_SEQUENCE_MATCH`
- `DEEPSEEK_STREAM_SEQUENCE_MISMATCH`
- `DEEPSEEK_STREAM_REASONING_MATCH`
- `DEEPSEEK_STREAM_REASONING_MISSING`
- `SYNTHETIC_STREAM_SUSPECT`
- `STREAM_UNIFORMITY_SUSPECT`

### 5.5 DeepSeek Official Versus Relay Channel Probe

Inspect base URL, response headers, and error text.

Strong pass indicators:

- `channel_claim="official"`.
- Base host is a known DeepSeek official API host such as `api.deepseek.com`.
- No contradictory relay markers are observed.

Strong fail indicators:

- `channel_claim="official"` but base host is not a known DeepSeek official host.
- Error or headers expose another provider's official infrastructure under an official DeepSeek claim.

Weak risk indicators:

- Headers or errors expose relay/upstream markers such as `openrouter`, `one-api`, `new-api`, `nginx`, `upstream`, `account pool`, `quota`, `web`, `session`, `cookie`, `x-amzn`, `azure`, or similar.
- Repeated-run sampling shows model drift or high latency variance after debounce.

Initial tags:

- `DEEPSEEK_OFFICIAL_CHANNEL_MATCH`
- `DEEPSEEK_OFFICIAL_CHANNEL_MISMATCH`
- Existing `RELAY_HEADER_SUSPECT`, `RATE_LIMIT_RELAY_SUSPECT`, `HOSTED_BY_AWS`, `HOSTED_BY_AZURE`, `MODEL_DRIFT_SUSPECT`, `TTFT_VARIANCE_HIGH`

## 6. Scoring Rules

Reuse generic scoring, with one hard-fail addition if needed:

- `CROSS_PROVIDER_MODEL_LEAKED` remains highest-priority hard failure.
- `DEEPSEEK_REASONING_CONTENT_MISSING` is highest-priority hard failure for claimed R1/reasoner models and must force `LOW_TRUST`.
- `DEEPSEEK_MODEL_CLAIM_MISMATCH` is strong negative evidence.
- Official channel mismatch is strong channel-claim failure.
- Weak channel-risk tags must not automatically lower authenticity unless combined with strong failures by existing scoring rules.

No single latency spike, timeout, disconnect, or rate-limit response should prove fraud.

## 7. Reporting Requirements

The report must include DeepSeek-specific probe sections:

- DeepSeek Chat Completions Shape Probe.
- DeepSeek Model Claim Consistency Probe.
- DeepSeek R1 Reasoning Content Probe.
- DeepSeek Channel Risk Probe.
- DeepSeek-Compatible Streaming Metrics.

Plain-language summary should translate DeepSeek evidence:

- R1 native reasoning field observed.
- R1 native reasoning field missing: "推理能力缺失：声明为 DeepSeek R1，但未检测到原生 reasoning_content 字段，疑似被路由到不支持 R1 推理能力的模型或兼容层。"
- Claimed official DeepSeek channel does not match target host.
- Cross-provider model leakage detected.

Markdown reports must preserve a two-layer structure:

- Executive Summary: plain-language TL;DR for ordinary users, including translated DeepSeek findings and channel-risk interpretation.
- Technical Appendix: expert evidence chain with stable tags, probe names, evidence keys, scores, and redacted configuration.

Technical appendix should retain stable tags and probe details. The Executive Summary must use restrained, objective wording and must not use emotional accusations such as "阉割" or "挂羊头卖狗肉".

## 8. Test And Safety Policy

- All automated tests must use mock observations, `httpx.MockTransport`, or local no-key paths.
- No test may send live network traffic.
- DeepSeek provider expansion must remain isolated from OpenAI and Claude probe logic.
- Do not implement Gemini, Seed, Qwen, Doubao, or other providers in this phase.
- Do not implement dashboard, batch mode, or JSON output in this phase.

## 9. Acceptance Criteria

- `Claim(provider="deepseek", api_shape="openai-compatible")` routes to a DeepSeek audit plan.
- DeepSeek capability lookup classifies R1/reasoner, chat/V3, unknown DeepSeek-looking names, and non-DeepSeek names.
- DeepSeek shape, model claim, R1 reasoning content, channel, and streaming probes are unit-tested.
- Cross-provider leakage forces low trust through existing hard-fail scoring.
- R1 missing reasoning content produces strong negative evidence only for R1/reasoner claims.
- `deepseek-chat` / V3-style claims do not fail for missing reasoning content.
- Markdown report renders DeepSeek-specific sections and user-friendly summary.
- Example config loads.
- Full test suite passes with no live network calls.
