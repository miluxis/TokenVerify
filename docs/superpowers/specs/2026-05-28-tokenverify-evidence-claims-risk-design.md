# TokenVerify Evidence, Claims, and Risk Design Spec

Date: 2026-05-28
Status: User review gate

## 1. Purpose

This spec extends the TokenVerify Phase 1 Claude audit design with a clearer product boundary between authenticity assertions and heuristic channel-risk inference.

The goal is to keep TokenVerify's core claims defensible: strong protocol and capability evidence may support authenticity judgments, while latency, stream regularity, pooling symptoms, and channel-health signals must be reported as risk indicators rather than direct accusations.

This design also prepares the audit core for future provider families by replacing the implicit "model name only" target with a structured claim object and by adding verdict tags that can be consumed by a future SaaS dashboard, alerting layer, or automatic routing policy.

## 2. Scope

This spec covers the next design increment after the current Claude-native MVP:

- Markdown report sectioning for strong authenticity evidence and heuristic risk evidence.
- Structured `Claim` data model.
- Structured `Verdict` data model with scores and tags.
- Separation of authenticity score from heuristic risk score.
- Evidence tags and risk tags for dashboard and routing use.
- Provider expansion priority adjustment that moves DeepSeek up to OpenAI priority.

This spec does not implement:

- A Web UI or SaaS dashboard.
- Batch endpoint execution.
- JSON report output.
- DeepSeek probes themselves.
- OpenAI, Gemini, Seed, or other provider adapters.
- Legal/compliance attestation language.

## 3. Design Principles

### 3.1 Separate Assertion From Inference

TokenVerify must never mix strong authenticity assertions with heuristic risk inference in the same report section or data field.

Strong assertions are limited to evidence with protocol, schema, capability, or provider-native structural grounding. Examples:

- Native API response shape matches or contradicts the claimed API shape.
- Error schema matches Anthropic native behavior, OpenAI-compatible behavior, DeepSeek behavior, or a generic proxy.
- Streaming event type sequence matches or contradicts the claimed provider API.
- Claude Extended Thinking content blocks appear, are absent, or are mishandled for a model expected to support them.
- A claimed provider-specific parameter is accepted, rejected, ignored, or stripped in a structurally observable way.

Heuristic risk inference is limited to symptoms that can be caused by multiple factors and therefore cannot prove forgery by itself. Examples:

- TTFT variance.
- Chunk interval regularity.
- Uniform stream chunk sizes.
- Full-response burst followed by synthetic incremental streaming.
- Retry/rate-limit patterns that resemble account pooling.
- Unstable availability that suggests a fragile relay or unofficial channel.

### 3.2 Use Risk Scores, Not Probability Claims

The report and data model must use `risk_score` on a 0-100 scale, not "risk probability."

Reason: without calibrated labeled datasets, a numeric probability such as "72%" would overstate statistical certainty. A `risk_score` is an audit heuristic suitable for ranking, alerting, and trend comparison.

### 3.3 Model User Claims As Composite Objects

The user claim must not be represented as only a model string. Future routing scenarios can combine provider identity, API shape, model naming, and channel claims in unusual ways.

The core claim object is:

```python
Claim(
    provider="anthropic",
    api_shape="native",
    model="claude-sonnet-4.5",
    channel_claim="official_api",
    region_claim=None,
)
```

Field intent:

- `provider`: The claimed model family or upstream provider, such as `anthropic`, `openai`, `deepseek`, `google`, or `seed`.
- `api_shape`: The wire protocol shape the endpoint claims to expose, such as `native`, `openai-compatible`, `bedrock`, `azure-foundry`, or `unknown`.
- `model`: The claimed model identifier.
- `channel_claim`: Optional claimed hosting or route, such as `official_api`, `aws_bedrock`, `azure_foundry`, `openrouter`, `web_reverse`, or `unknown`.
- `region_claim`: Optional claimed region or deployment locality.

The current YAML endpoint model may continue to accept `base_url`, `model`, and API key fields. During normalization, config loading should produce a `Claim`.

If no explicit `api_shape` is supplied, normalization must first inspect `base_url` and any configured path hints before falling back to the Claude Phase 1 default. For example, a base URL or route that clearly contains OpenAI-style `/v1/chat/completions`, an OpenAI-compatible `/v1` surface, or a known OpenAI-compatible gateway pattern should normalize to `api_shape="openai-compatible"` instead of blindly assuming Anthropic native behavior. If the URL provides no reliable protocol-shape hint, the Claude Phase 1 fallback is:

```python
Claim(
    provider="anthropic",
    api_shape="native",
    model=<configured model>,
    channel_claim="unknown",
    region_claim=None,
)
```

### 3.4 Verdicts Need Scores And Tags

The verdict must contain both human-readable rating and machine-actionable labels.

Target shape:

```python
Verdict(
    rating="MEDIUM_TRUST",
    authenticity_score=78,
    risk_score=42,
    tags=[
        "ANTHROPIC_NATIVE_SHAPE_MATCH",
        "EXTENDED_THINKING_MATCH",
        "STREAM_UNIFORMITY_SUSPECT",
        "CONCURRENT_POOL_SUSPECT",
    ],
)
```

The rating remains the user-facing trust class. Scores and tags are structured output for reports, future JSON rendering, dashboard filtering, alerts, and routing rules.

## 4. Report Design

The Markdown report must visually separate authenticity assertions from heuristic risk inference.

### 4.1 Target Summary

The target summary should render both endpoint fields and normalized claim fields:

- Endpoint name.
- Base URL host.
- Claimed provider.
- Claimed API shape.
- Claimed model.
- Claimed channel, if supplied.
- Claimed region, if supplied.

### 4.2 Overall Verdict

The top-level verdict should include:

- Rating: `高可信`, `中可信`, `低可信`, or `无法判定`.
- Authenticity score: 0-100.
- Risk score: 0-100.
- Tags.

The report must make clear that authenticity score and risk score answer different questions:

- Authenticity score: "How well does the endpoint match the claimed provider/API/model behavior?"
- Risk score: "How many channel-health or relay-risk symptoms were observed?"

### 4.3 Authenticity Assertions

This section contains only strong evidence. It should include concise items such as:

- Protocol shape assertion.
- Error schema assertion.
- Streaming schema assertion.
- Thinking or reasoning content block assertion.
- Model capability alignment assertion.

Each assertion should include:

- Status: pass, fail, neutral, skipped, or error.
- Evidence strength: strong or neutral.
- Tags emitted.
- Short explanation.

This section must not include TTFT variance, chunk size distribution, pooling suspicion, or web-reverse suspicion unless those observations are tied to a provider-native structural violation.

### 4.4 Heuristic Risk Profile

This section contains weak inference and channel-health symptoms.

It should include:

- Risk score: 0-100.
- Risk tags.
- Streaming timing observations.
- Chunk regularity observations.
- Synthetic stream heuristic observations.
- Pooling or unstable relay symptoms when observed.
- A clear statement that these are risk indicators, not proof of upstream identity or misconduct.

Recommended wording:

> These signals are heuristic channel-risk indicators. They can raise operational concern, but they do not by themselves prove provider forgery or unauthorized routing.

### 4.5 Existing Probe Sections

The existing probe sections may remain, but they should support the two main report zones:

- Messages Protocol Probe contributes primarily to Authenticity Assertions.
- Extended Thinking Probe contributes primarily to Authenticity Assertions.
- Streaming Metrics contributes primarily to Heuristic Risk Profile, except for provider-native streaming schema violations.
- Extension Probe Appendix remains observation-only unless a future spec promotes specific extension probes into scoring probes.

## 5. Evidence And Tag Taxonomy

### 5.1 Evidence Tags

Evidence tags describe structurally observed facts. Initial tags:

- `ANTHROPIC_NATIVE_SHAPE_MATCH`
- `ANTHROPIC_NATIVE_SHAPE_MISMATCH`
- `OPENAI_COMPATIBLE_SHAPE_DETECTED`
- `GENERIC_PROXY_ERROR_DETECTED`
- `ERROR_SCHEMA_MATCH`
- `ERROR_SCHEMA_MISMATCH`
- `STREAM_EVENT_SEQUENCE_MATCH`
- `STREAM_EVENT_SEQUENCE_MISMATCH`
- `EXTENDED_THINKING_MATCH`
- `EXTENDED_THINKING_MISSING`
- `EXTENDED_THINKING_REJECTED`
- `EXTENDED_THINKING_IGNORED`
- `MODEL_CAPABILITY_MATCH`
- `MODEL_CAPABILITY_MISMATCH`
- `CROSS_PROVIDER_REASONING_LEAKED`

`CROSS_PROVIDER_REASONING_LEAKED` marks a strong cross-provider contradiction, such as a route claiming a non-DeepSeek model while exposing DeepSeek-R1-style `reasoning_content` or another provider-exclusive reasoning structure. This tag is treated as highest-severity authenticity evidence because it indicates that provider-specific internals leaked through the claimed model boundary.

### 5.2 Risk Tags

Risk tags describe heuristic symptoms or route-risk classifications. Initial tags:

- `STREAM_UNIFORMITY_SUSPECT`
- `SYNTHETIC_STREAM_SUSPECT`
- `TTFT_VARIANCE_HIGH`
- `THROUGHPUT_ANOMALY`
- `CONCURRENT_POOL_SUSPECT`
- `WEB_REVERSE_SUSPECT`
- `UNSTABLE_RELAY_SUSPECT`
- `HOSTED_BY_AWS`
- `HOSTED_BY_AZURE`
- `HOSTED_BY_UNKNOWN_PROXY`

Hosting tags such as `HOSTED_BY_AWS` and `HOSTED_BY_AZURE` must be emitted only when there is concrete evidence, such as a visible endpoint hostname, preserved upstream error detail, or provider-specific response metadata. They must not be inferred from latency alone.

### 5.3 Tag Stability

Tags are external-facing identifiers. Once introduced, they should be treated as stable API-like values. If a tag becomes obsolete, keep it documented as deprecated rather than silently changing its meaning.

## 6. Scoring Model

### 6.1 Authenticity Score

The authenticity score is computed from strong and neutral authenticity evidence.

Initial behavior:

- Strong pass increases authenticity.
- Strong fail decreases authenticity sharply.
- Neutral observations do not materially change the score.
- Authentication, quota, model unavailable, network failure, or insufficient data can force `无法判定` even if no negative evidence exists.

The existing trust rating maps to authenticity score and blocking errors:

- `高可信`: strong evidence matches the claim and no major contradictions are observed.
- `中可信`: core evidence mostly matches, but there are gaps or ambiguous mismatches.
- `低可信`: one or more strong contradictions exist.
- `无法判定`: insufficient reliable evidence.

### 6.2 Risk Score

The risk score is separate from authenticity. It is computed from weak risk observations and risk tags.

Initial behavior:

- Low risk: 0-29.
- Medium risk: 30-69.
- High risk: 70-100.

A high risk score must not automatically downgrade authenticity rating unless a strong authenticity contradiction is also present. The report can show a combination such as:

- Rating: `高可信`
- Authenticity score: 91
- Risk score: 76
- Interpretation: likely matches the claimed provider/API behavior, but channel health or operational risk is elevated.

Risk scoring must include basic debounce behavior for physical network anomalies. A single timeout, disconnect, or one-off TTFT spike should be recorded first as a network or operational anomaly that may make the run `无法判定`; it must not directly emit `TTFT_VARIANCE_HIGH` or sharply raise channel-risk score without repeated samples or corroborating stream symptoms. The same rule applies to short-lived packet loss or a single interrupted stream: classify the measurement quality before inferring pooling, web reverse engineering, or relay misconduct.

### 6.3 Score Calibration

Phase 1 should use deterministic heuristic weights with clear explanations. Future versions may recalibrate weights using labeled datasets, repeated endpoint measurements, or user feedback. Until then, reports must avoid probability language.

## 7. Provider Roadmap Update

The provider expansion roadmap should change from a broad "add other models later" list to a staged evidence strategy:

1. Claude native deepening.
2. OpenAI-compatible Claude relay auditing.
3. OpenAI official/compatible APIs and DeepSeek in parallel priority.
4. Gemini.
5. Seed, Qwen, Doubao, and other provider families.

DeepSeek is moved up because DeepSeek-R1 and DeepSeek-V3 are increasingly used in low-cost substitution, unstable relay products, and enterprise proxy stacks. DeepSeek's reasoning content behavior can also become a strong evidence source when a route claims to be a different provider but leaks DeepSeek-specific reasoning structure or streaming behavior.

This spec does not define DeepSeek probe implementation. It only reserves DeepSeek as a near-term provider family and requires the core data model to support it cleanly.

## 8. Implementation Boundaries

The immediate implementation should stay narrow:

- Add structured claim and verdict fields.
- Preserve existing CLI behavior where possible.
- Preserve Markdown output, but restructure the report.
- Keep raw logs and extension probes unchanged unless the report renderer needs field names.
- Do not add new network probes for non-Claude providers in this phase.
- Do not add dashboard or JSON output in this phase.

## 9. Testing Strategy

Tests should prove the separation between authenticity and risk:

- A high-risk streaming profile should increase `risk_score` and emit risk tags without automatically lowering authenticity rating.
- A strong protocol mismatch should lower authenticity even if risk score is low.
- The Markdown report should contain separate `Authenticity Assertions` and `Heuristic Risk Profile` sections.
- Risk wording should not contain probability or direct accusation language.
- A config without explicit provider/API shape should normalize to an Anthropic native claim for the current Claude flow.
- Verdict tags should render in the report and remain available on the structured result object.

## 10. User Review Gate

This document is ready for user review.

No implementation plan, code changes, multi-agent execution, or provider expansion should start until the user approves this spec.
