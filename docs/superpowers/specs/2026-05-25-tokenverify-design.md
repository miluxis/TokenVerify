# TokenVerify Phase 1 Design Spec

Date: 2026-05-25
Status: User review gate

## 1. Purpose

TokenVerify is an audit tool for large language model relay platforms. Its first phase focuses on Claude relay authenticity: determine whether a user-provided endpoint behaves like a real Anthropic Claude Messages API endpoint, especially around native protocol structure and Extended Thinking support.

The MVP should produce a human-readable authenticity report that helps identify relay channels that falsely advertise Claude resources, silently downgrade models, ignore Claude-specific parameters, or expose only a superficial compatibility layer.

## 2. Phase 1 Scope

Phase 1 targets a single audit path:

- Provider family: Claude.
- API shape: Anthropic native Messages API only.
- Entry point: Python package with a CLI as the first user interface.
- Report output: Markdown only.
- Endpoint execution: one endpoint per CLI run.
- Configuration: YAML as the primary configuration source, with CLI overrides for key fields.
- Evidence model: native protocol behavior, Extended Thinking behavior, and low-weight streaming performance signals.

Phase 1 explicitly excludes:

- OpenAI-compatible Claude relay auditing.
- Streamlit or other Web UI.
- Batch execution across multiple endpoints.
- Tokenizer exact-match accounting as a scoring signal.
- Cognitive trap prompt banks as a scoring signal.
- JSON report output.
- Git initialization or committing without separate user approval.

## 3. Design Decisions

### 3.1 Architecture Baseline

Use a layered, plugin-ready audit core rather than a single-file script.

Recommended module boundaries:

- `config`: Load YAML, validate schema, merge CLI overrides, and expose a normalized runtime config.
- `providers.anthropic`: Send Anthropic native Messages API requests, parse streaming events, and normalize provider errors.
- `model_capabilities`: Maintain an updateable Claude model capability table, including whether a model is expected to support Extended Thinking.
- `probes`: Execute built-in audit probes and optional user-defined probes.
- `evidence`: Normalize raw observations into typed evidence objects.
- `scoring`: Convert evidence into a rating, evidence scores, and explanation notes.
- `report`: Render a Markdown report from the audit result.
- `cli`: Thin command-line entry point that wires configuration, audit execution, and report output together.

The CLI must not contain audit logic. Provider code must not contain scoring logic. Report rendering must consume the same result object that a future JSON renderer would use.

### 3.2 Configuration

YAML is the primary configuration format. CLI flags may override selected fields such as:

- `base_url`
- `api_key`
- `model`
- `endpoint`
- `output`
- raw event logging options

API keys should be supplied through environment variables or CLI overrides where practical. The design must not encourage storing API keys in plaintext YAML.

The YAML schema should allow multiple endpoints in the future, but Phase 1 executes only one endpoint per run. If multiple endpoints are present, the CLI must require the user to select one explicitly.

### 3.3 Probe Set

Phase 1 uses built-in fixed probes for the core score:

1. Anthropic Messages protocol structure probe.
2. Extended Thinking / thinking budget probe.
3. Streaming physical feature probe.

YAML extension probes are allowed, but their results only appear in the report appendix. They do not affect the authenticity rating in Phase 1.

The Extended Thinking probe payload must be constructed conservatively so that the probe itself is valid for a real Anthropic endpoint. When using manual thinking budget mode, `thinking.budget_tokens` must be lower than `max_tokens`, and the default probe should use a clear margin such as `budget_tokens=1024` and `max_tokens=2048`. This prevents a valid Anthropic endpoint from rejecting the request because of an invalid audit payload. The model capability table may select a different thinking mode for models where adaptive thinking is preferred or manual budget mode is deprecated.

### 3.4 Model Capability Interpretation

Extended Thinking results must be interpreted through a Claude model capability table.

If the selected model is expected to support Extended Thinking and the endpoint ignores, rejects, strips, or misrepresents thinking parameters, this is strong negative evidence. If the selected model is not expected to support Extended Thinking, lack of support is recorded as an observed capability limitation but not treated as forgery evidence.

The capability table must be updateable without changing probe logic.

## 4. Audit Flow

One CLI audit run follows this sequence:

1. Load YAML configuration.
2. Merge CLI overrides and environment-derived secrets.
3. Select exactly one endpoint.
4. Resolve the target Claude model capability profile.
5. Run the Anthropic Messages protocol structure probe.
6. Run the Extended Thinking probe.
7. Run streaming physical feature sampling.
8. Run optional YAML extension probes if configured.
9. Normalize observations into evidence.
10. Score evidence and compute the final rating.
11. Render a Markdown report.

## 5. Evidence Strategy

### 5.1 Strong Evidence

Strong evidence includes:

- Response structure matching or failing Anthropic Messages semantics.
- Streaming event type sequence matching or failing Anthropic native behavior.
- Anthropic-style error structure versus generic proxy or OpenAI-compatible errors.
- Correct handling of Extended Thinking parameters for models expected to support them.
- Clear signs that thinking parameters are accepted but ignored or stripped.

### 5.2 Weak Evidence

Streaming performance metrics are weak evidence:

- TTFT.
- Total latency.
- Chunk interval distribution.
- Chunk size distribution.
- Estimated TPS.
- Synthetic stream heuristic, such as a stream that emits uniformly sized deltas or releases the full response in a short burst while only mimicking Anthropic event names.

These metrics participate in scoring at low weight only. They affect the overall rating only when repeated samples are extremely abnormal, because network path, region, relay load, and provider load can distort latency.

### 5.3 Non-Scoring Observations

User-defined YAML extension probes are observation-only in Phase 1. They appear in a Markdown appendix and may support manual review, but they do not affect the core authenticity score.

## 6. Rating Model

The Markdown report uses a two-layer output:

- Overall rating: `高可信`, `中可信`, `低可信`, or `无法判定`.
- Evidence scores and explanation notes.

Rating intent:

- `高可信`: Anthropic protocol behavior matches expectations, expected Extended Thinking behavior is present, and no major proxy or compatibility-layer artifacts are detected.
- `中可信`: Core protocol behavior mostly matches, but there are suspicious gaps such as incomplete stream events, non-standard error shapes, or ambiguous capability behavior.
- `低可信`: Core parameters are ignored, Anthropic native structure is absent, Extended Thinking behavior contradicts the model capability profile, or responses strongly resemble a non-Anthropic compatibility layer.
- `无法判定`: Authentication failure, permission failure, quota exhaustion, model unavailable, service outage, network failure, or other conditions prevent enough evidence from being gathered.

## 7. Error Handling

Errors must be classified before scoring:

- Authentication, authorization, quota, model-not-found, and service-unavailable errors produce `无法判定` unless enough other evidence already exists to support a rating.
- Protocol incompatibility, generic proxy errors, and non-Anthropic error shapes are strong negative evidence.
- Extended Thinking rejection is interpreted through the model capability table.
- Timeouts and rate limits are recorded and should recommend retrying; they do not automatically imply low authenticity.

The report must include enough error detail for review without exposing secrets.

## 8. Privacy and Raw Logs

By default, the tool writes only a Markdown summary and does not save raw prompt, response, or thinking content.

The CLI may expose an explicit option to save raw streaming event logs for evidence-chain review. When enabled:

- The report must clearly mark that raw logging was enabled.
- API keys must never be written to logs.
- Raw event logs should be stored separately from the Markdown report.
- The report should reference the log path rather than embedding full raw content.

## 9. Markdown Report Requirements

The Phase 1 CLI outputs Markdown only.

The report should include:

- Audit target summary: base URL host, model, selected endpoint name, and timestamp.
- Overall rating.
- Evidence score breakdown.
- Messages protocol probe summary.
- Extended Thinking probe summary.
- Streaming metrics summary.
- Error and warning summary.
- Optional raw event log path.
- Optional extension probe appendix.
- Configuration summary with secrets redacted.

Markdown rendering should be generated from a structured in-memory result object so that a future JSON renderer can be added without changing audit logic.

## 10. Testing Strategy

Testing should follow module boundaries:

- `config`: YAML loading, schema validation, CLI override precedence, secret redaction.
- `providers.anthropic`: mocked non-streaming and streaming responses, stream event parsing, and error normalization.
- `model_capabilities`: capability lookup, unknown model handling, and update-friendly data shape.
- `probes`: evidence emitted for successful, unsupported, ignored, stripped, malformed, and failed probe cases.
- `scoring`: table-driven tests for `高可信`, `中可信`, `低可信`, and `无法判定`.
- `report`: Markdown contains required sections, redacts API keys, and reflects score explanations accurately.
- `cli`: argument parsing and top-level orchestration using mocks, without real network calls.

Real network integration tests should be optional and disabled by default.

## 11. Future Extension Points

The design intentionally leaves room for:

- OpenAI-compatible Claude relay adapters.
- Batch endpoint execution and comparative reports.
- JSON report output.
- Streamlit or other Web UI.
- Tokenizer exact-match accounting.
- Cognitive trap prompt banks.
- Additional provider families such as GLM, Qwen, DeepSeek, or OpenAI.
- A richer evidence database for longitudinal channel tracking.

These extensions must not be part of Phase 1 implementation unless a later spec explicitly approves them.

## 12. User Review Gate

This document is the approved brainstorming design draft written for user review.

No implementation plan, code, scaffold, git initialization, or commit should happen until the user reviews this spec and gives explicit approval for the next step.
