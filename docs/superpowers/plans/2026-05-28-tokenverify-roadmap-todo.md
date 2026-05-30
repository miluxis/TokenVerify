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
- [x] Deepen Claude model/vendor recognition.
  - [x] Expand strong evidence catalog for Claude-native protocol, errors, stream events, and thinking behavior.
  - [x] Add mixed-provider inconsistency detection across repeated observations.
  - [x] Explicitly label mixed-provider detection as conditional, not guaranteed black-box identification.
- [x] Deepen Claude version / thinking capability assessment.
  - [x] Expand model capability table.
  - [x] Add parameter compatibility probes by Claude capability tier.
  - [x] Add confidence language for inferred version/capability class.
  - [x] Detect API-leaked model/version fields when available.
- [x] Deepen channel / official-vs-relay / web-reverse / account-pool risk scoring.
  - [x] Request ID and response header observations.
  - [x] Rate-limit behavior probes.
  - [x] Region/latency consistency observations.
  - [x] Context stability and model drift probes.
  - [x] Repeated-run variance aggregation with debounce.
  - [x] Bedrock/Azure/Foundry marker extraction when headers/errors leak them.

## Phase 2: Multi-Provider Framework Abstraction

- [x] Introduce shared evidence model.
  - [x] Strong evidence.
  - [x] Weak evidence.
  - [x] Neutral observations.
- [x] Use generic scoring over evidence weights and pass/fail state.
- [ ] Formalize `ProviderAdapter` interface.
  - [x] Anthropic adapter.
  - [x] OpenAI-compatible adapter.
  - [x] Future OpenAI adapter stub.
  - [ ] Future DeepSeek adapter stub.
  - [ ] Future Gemini adapter stub.
  - [ ] Future Seed/Qwen/Doubao adapter stubs only when in scope.
- [x] Formalize probe categories.
  - [x] Protocol probes.
  - [x] Capability probes.
  - [x] Stream probes.
  - [x] Error probes.
  - [x] Repeatability probes.
  - [x] Channel-risk probes.
- [x] Formalize audit orchestration.
  - [x] Route by composite `Claim`.
  - [x] Keep provider-specific probes isolated.
  - [x] Keep unknown/non-implemented providers explicitly out of scope.
  - [x] Add repeat-run sampling plan without turning single network anomalies into cheating claims.
- [x] Prepare dashboard-oriented tag taxonomy.
  - [x] Stable authenticity tags.
  - [x] Stable risk tags.
  - [x] Operational tags.
  - [x] Cross-provider leakage tags.

## Phase 3: Provider Expansion Order

- [x] Claude native deep-dive foundation.
- [x] OpenAI-compatible Claude relay foundation.
- [x] OpenAI official / OpenAI-compatible model auditing.
  - [x] Spec.
  - [x] Implementation plan.
  - [x] Tests.
  - [x] Implementation.
- [x] DeepSeek official / compatible model auditing.
  - [x] Spec.
  - [x] Implementation plan.
  - [x] Tests.
  - [x] Implementation.
  - [x] R1 `reasoning_content` / reasoning stream evidence extraction.
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

- [x] Suspected Upstream Signals explanation layer.
  - [x] Spec.
  - [x] Implementation plan.
  - [x] Tests.
  - [x] Implementation.
  - [x] Report section.
- [x] CLI polish.
  - [x] Clear command examples for native Claude.
  - [x] Clear command examples for OpenAI-compatible Claude relay.
  - [x] Exit-code policy.
  - [x] Offline/no-key behavior documented.
- [ ] Report polish.
  - [x] More compact executive summary.
  - [x] Clear confidence wording.
  - [x] Clear separation between evidence and risk.
  - [x] CLI-selectable English/Chinese report explanations.
  - [ ] Machine-readable appendix only after JSON output is intentionally in scope.
- [x] Test and safety policy.
  - [x] No live network in normal tests.
  - [x] Mock provider transport tests.
  - [x] Real-network tests remain opt-in and marked.
  - [x] Add regression tests for every new provider/probe class.
- [x] Release readiness.
  - [x] Versioning policy.
  - [x] Packaging check.
  - [x] Minimal user docs.
  - [x] Example reports.

## Current Out-Of-Scope Boundaries

- [ ] Do not claim exact black-box identification of every mixed routing setup.
- [ ] Do not treat single TTFT spikes, disconnects, or timeouts as proof of cheating.
- [ ] Do not implement dashboard, batch mode, or JSON output until explicitly planned.
- [ ] Do not implement OpenAI official, DeepSeek, Gemini, Seed, Qwen, Doubao provider auditing without a spec and implementation plan.
- [ ] Do not send live network traffic in tests.
