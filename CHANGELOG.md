# Changelog

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
