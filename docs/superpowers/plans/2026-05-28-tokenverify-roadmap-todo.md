# TokenVerify Roadmap TODO

This checklist is the source of truth for roadmap progress. Update it when a milestone is completed or intentionally deferred.

## Phase 1: Claude Deep-Dive To Usable/Sellable

- [x] Establish Claude native audit MVP.
  - [x] Anthropic Messages protocol shape probe.
  - [x] Claude error/schema normalization.
  - [x] Native stream event parsing and streaming metrics.
  - [x] Extended Thinking payload construction and outcome interpretation.
  - [x] Markdown report output with redacted configuration.
- [x] Separate strong authenticity assertions from heuristic channel-risk profile.
  - [x] Authenticity assertions section for strong protocol/schema/thinking evidence.
  - [x] Heuristic risk profile section with 0-100 risk score.
  - [x] Avoid direct accusation for TTFT variance, stream uniformity, pool-like symptoms, or unstable relay behavior.
- [x] Add composite `Claim`.
  - [x] Track `provider`.
  - [x] Track `api_shape`.
  - [x] Track `model`.
  - [x] Track optional channel and region claims.
  - [x] Infer `api_shape` from `base_url` before falling back to native.
- [x] Add structured `Verdict`.
  - [x] Track rating.
  - [x] Track authenticity score.
  - [x] Track risk score.
  - [x] Track stable evidence/risk tags.
- [x] Add first OpenAI-compatible Claude relay path.
  - [x] Chat Completions payload builder.
  - [x] `Authorization: Bearer` auth.
  - [x] `X-TokenVerify-Scan: true` safety header.
  - [x] Self-relay loop short-circuit detection.
  - [x] SSE parser with terminal `finish_reason`.
  - [x] OpenAI-compatible error normalization.
  - [x] Chat Completions shape probe.
  - [x] Claude model claim consistency probe.
  - [x] Cross-provider `reasoning_content` leakage probe.
  - [x] Fake thinking text heuristic.
  - [x] OpenAI-compatible streaming sequence probe.
  - [x] Relay-specific report sections.
  - [x] Example config.
- [ ] Deepen Claude model/vendor recognition.
  - [ ] Expand strong evidence catalog for Claude-native protocol, errors, stream events, and thinking behavior.
  - [ ] Add mixed-provider inconsistency detection across repeated observations.
  - [ ] Explicitly label mixed-provider detection as conditional, not guaranteed black-box identification.
- [ ] Deepen Claude version / thinking capability assessment.
  - [ ] Expand model capability table.
  - [ ] Add parameter compatibility probes by Claude capability tier.
  - [ ] Add confidence language for inferred version/capability class.
  - [ ] Detect API-leaked model/version fields when available.
- [ ] Deepen channel / official-vs-relay / web-reverse / account-pool risk scoring.
  - [ ] Request ID and response header observations.
  - [ ] Rate-limit behavior probes.
  - [ ] Region/latency consistency observations.
  - [ ] Context stability and model drift probes.
  - [ ] Repeated-run variance aggregation with debounce.
  - [ ] Bedrock/Azure/Foundry marker extraction when headers/errors leak them.

## Phase 2: Multi-Provider Framework Abstraction

- [x] Introduce shared evidence model.
  - [x] Strong evidence.
  - [x] Weak evidence.
  - [x] Neutral observations.
- [x] Use generic scoring over evidence weights and pass/fail state.
- [ ] Formalize `ProviderAdapter` interface.
  - [ ] Anthropic adapter.
  - [ ] OpenAI-compatible adapter.
  - [ ] Future OpenAI adapter stub.
  - [ ] Future DeepSeek adapter stub.
  - [ ] Future Gemini adapter stub.
  - [ ] Future Seed/Qwen/Doubao adapter stubs only when in scope.
- [ ] Formalize probe categories.
  - [ ] Protocol probes.
  - [ ] Capability probes.
  - [ ] Stream probes.
  - [ ] Error probes.
  - [ ] Repeatability probes.
  - [ ] Channel-risk probes.
- [ ] Formalize audit orchestration.
  - [ ] Route by composite `Claim`.
  - [ ] Keep provider-specific probes isolated.
  - [ ] Keep unknown/non-implemented providers explicitly out of scope.
  - [ ] Add repeat-run sampling plan without turning single network anomalies into cheating claims.
- [ ] Prepare dashboard-oriented tag taxonomy.
  - [ ] Stable authenticity tags.
  - [ ] Stable risk tags.
  - [ ] Operational tags.
  - [ ] Cross-provider leakage tags.

## Phase 3: Provider Expansion Order

- [x] Claude native deep-dive foundation.
- [x] OpenAI-compatible Claude relay foundation.
- [ ] OpenAI official / OpenAI-compatible model auditing.
  - [ ] Spec.
  - [ ] Implementation plan.
  - [ ] Tests.
  - [ ] Implementation.
- [ ] DeepSeek official / compatible model auditing.
  - [ ] Spec.
  - [ ] Implementation plan.
  - [ ] Tests.
  - [ ] Implementation.
  - [ ] R1 `reasoning_content` / reasoning stream evidence extraction.
- [ ] Gemini auditing.
  - [ ] Spec.
  - [ ] Implementation plan.
  - [ ] Tests.
  - [ ] Implementation.
- [ ] Seed / Qwen / Doubao / other providers.
  - [ ] Prioritization decision.
  - [ ] Spec.
  - [ ] Implementation plan.
  - [ ] Tests.
  - [ ] Implementation.

## Productization And Operations

- [ ] CLI polish.
  - [ ] Clear command examples for native Claude.
  - [ ] Clear command examples for OpenAI-compatible Claude relay.
  - [ ] Exit-code policy.
  - [ ] Offline/no-key behavior documented.
- [ ] Report polish.
  - [ ] More compact executive summary.
  - [ ] Clear confidence wording.
  - [ ] Clear separation between evidence and risk.
  - [ ] Machine-readable appendix only after JSON output is intentionally in scope.
- [ ] Test and safety policy.
  - [x] No live network in normal tests.
  - [x] Mock provider transport tests.
  - [ ] Real-network tests remain opt-in and marked.
  - [ ] Add regression tests for every new provider/probe class.
- [ ] Release readiness.
  - [ ] Versioning policy.
  - [ ] Packaging check.
  - [ ] Minimal user docs.
  - [ ] Example reports.

## Current Out-Of-Scope Boundaries

- [ ] Do not claim exact black-box identification of every mixed routing setup.
- [ ] Do not treat single TTFT spikes, disconnects, or timeouts as proof of cheating.
- [ ] Do not implement dashboard, batch mode, or JSON output until explicitly planned.
- [ ] Do not implement OpenAI official, DeepSeek, Gemini, Seed, Qwen, Doubao provider auditing without a spec and implementation plan.
- [ ] Do not send live network traffic in tests.

