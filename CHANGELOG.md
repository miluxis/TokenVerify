# Changelog

## TokenVerify v0.5.0-preview

This preview release upgrades Relay Audit into a scenario-first fraud-risk report for open-source Core users.

### Highlights

- Added relay `identity`, `channel`, and `reasoning` fingerprint profiles.
- Expanded `full` relay profile to run `general`, `identity`, `channel`, `reasoning`, `streaming`, `schema`, `privacy`, `security`, and `context`.
- Added Fraud Scenario Summary for model identity substitution, channel-source misrepresentation, mixed-routing drift, reasoning forgery, prompt/context manipulation, fake streaming, schema/tool breakage, privacy leakage, and capacity/error masking.
- Added bounded `--drift-check yes` sampling for account-pool, reverse-resource, fallback, and mixed-provider drift signals.
- Improved English and Chinese full reports with signal-first conclusions, specific `not_detected` explanations, plain-language risk summaries, and sanitized technical breadcrumbs.
- Preserved black-box boundaries: candidate upstream-family signals are behavioral fingerprints, not exact upstream identity proof.

### Safety Boundaries

- Default tests do not send live network traffic.
- Reports remain sanitized: no API key values, auth headers, full prompts, full completion text, full endpoint URLs, local absolute paths, or private challenge answers.
- `--live` remains required for real relay network checks.
- Commercial capabilities such as restricted challenge-pack governance, batch scanning, dashboards, JSON/API output, hosted monitoring, billing reconciliation, and report databases remain outside open-source Core.

### Verification

Local verification for this release:

- `536 passed, 1 deselected`

## TokenVerify v0.2.0-preview

This preview release completes the open-source TokenVerify Core CLI for local endpoint and relay auditing.

### Highlights

- Unified `tokenverify audit` entry for provider/model audits and relay contract audits.
- Relay Audit support for `general`, `streaming`, `schema`, `privacy`, `security`, `context`, and `full` profiles.
- Deterministic no-network `--fake-run` scenarios for demos and regression testing.
- Explicit `--live` gate for all real relay network checks.
- Sanitized Markdown reports with host-only endpoint visibility and public endpoint hashes.
- Route-prefixed report names: `audit-provider-*` and `audit-relay-*`.
- English and Chinese README/user guide updates.
- Open-source Core boundary documented: commercial packs, batch scanning, dashboards, JSON/API output, hosted monitoring, and report databases remain outside this release.

### Safety Boundaries

- Default tests do not send live network traffic.
- Reports do not expose API keys, auth headers, full instruction text, model response text, full endpoint URLs, local absolute paths, or private challenge answers.
- `security` provides bounded black-box prompt-boundary evidence; it does not prove malicious intent or complete jailbreak resistance.
- `context` provides bounded public anchor-retention evidence; it does not measure exact context-window size, estimate billing, or prove malicious truncation.

### Verification

Local verification for this release:

- `436 passed, 1 deselected`
- `git diff --check` passed

## v0.2.0-preview

Dynamic Challenge Suite public preview.

### Dynamic Challenge Suite

- Added built-in public baseline challenge pack.
- Added `--challenge-pack` for local YAML challenge packs.
- Added `--challenge-level basic|standard|strict`.
- Added deterministic local variables: `integer`, `hex`/`nonce`, and `choice`.
- Added local verifiers: `exact_answer`, `required_field`, `forbidden_field`, `json_schema`, and `stream_ordering`.
- Added `Dynamic Challenge Results` report section with sanitized challenge id, category, level, hash, status, and verifier summaries.

### Safety and scoring

- Dynamic challenge results remain auxiliary and do not change existing hard-fail authenticity scoring.
- Expression verification uses an allowlisted AST parser and never uses Python `eval()`.
- No-key paths skip or mark dynamic challenges inconclusive without sending live provider requests.
- Default tests continue to use mock observations, local no-key paths, or `httpx.MockTransport`.

## v0.1.0-preview

Initial public preview of TokenVerify.

### Supported audit paths

- Claude native: Anthropic Messages shape, Extended Thinking behavior, native stream sequence, and error schema.
- OpenAI-compatible Claude relay: Chat Completions shape, Claude model claim consistency, Claude thinking/version clues, reasoning leakage, relay symptoms, and channel-risk signals.
- OpenAI-compatible OpenAI: OpenAI-style Chat Completions shape, model-family consistency, reasoning capability evidence, streaming sequence, and official-vs-compatible channel clues.
- DeepSeek R1: DeepSeek model-family consistency, R1 `reasoning_content`, reasoning/content stream order, and official-vs-compatible channel clues.

### Report and CLI

- Markdown report output with Plain-Language Summary, Channel Risk Profile, Suspected Upstream Signals, Authenticity Assertions, and Heuristic Risk Profile.
- Automatic report filenames under `reports/audit-[model-name]-[date].md`.
- `--detail-audit yes` for deeper relay, reverse-channel, account-pool, latency-variance, and model-drift sampling.
- `--language zh` for Chinese report explanations.
- Script-friendly exit codes for high/medium trust, low trust, configuration errors, and inconclusive results.

### Safety and licensing

- Default tests do not send live network requests.
- Provider HTTP tests use `httpx.MockTransport`.
- Reports and raw logs redact configured API keys.
- Project license is AGPL-3.0-only.
- External contributions require the CLA in `CLA.md`.

### Known limitations

- TokenVerify is a black-box audit tool and does not prove the true upstream provider with certainty.
- Gemini, Seed, Qwen, Doubao, and other provider audits are not implemented until there is a spec and implementation plan.
- JSON output, dashboard UI, batch endpoint execution, and tokenizer exact-match auditing are intentionally out of scope for this preview.
- A single timeout, disconnect, or TTFT spike is treated as an operational anomaly, not proof of routing misconduct.
