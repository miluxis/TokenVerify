# TokenVerify

[English](README.md) | [简体中文](README.zh-CN.md)

TokenVerify is a black-box audit CLI for checking whether an LLM endpoint
behaves like its claimed provider, API shape, model family, and channel. It
turns protocol behavior, model fields, reasoning signals, streaming metrics, and
relay symptoms into a human-readable Markdown report.

TokenVerify does not prove the true upstream provider with certainty. It is
designed to find strong contradictions, obvious capability downgrades, and
channel-risk signals in user-provided endpoints.

## Quick Start

Install for local development:

```bash
python3 -m pip install -e ".[test]"
```

Run a no-key/offline configuration check:

```bash
PYTHONPATH=src python3 -m tokenverify.cli audit \
  --config examples/claude-audit.yaml \
  --endpoint primary
```

Reports are written automatically under `reports/audit-[model-name]-[date].md`.
If a report with the same name already exists, TokenVerify appends a numeric
suffix instead of overwriting it.

For relay, reverse-channel, account-pool, latency-variance, or model-drift
signals, run a detail audit:

```bash
PYTHONPATH=src python3 -m tokenverify.cli audit \
  --config examples/claude-openai-compatible-audit.yaml \
  --endpoint claude-openai-compatible \
  --detail-audit yes
```

Detail audit uses 8 samples internally. Users do not need to choose a repeat
count; use `--detail-audit no` for the default fast single-sample audit.

Reports use English explanations by default. Generate a Chinese report with:

```bash
PYTHONPATH=src python3 -m tokenverify.cli audit \
  --config examples/deepseek-compatible-audit.yaml \
  --endpoint deepseek-compatible \
  --detail-audit yes \
  --language zh
```

Dynamic Challenge Suite runs a built-in public baseline pack by default. To use
a local YAML pack and choose challenge depth:

```bash
PYTHONPATH=src python3 -m tokenverify.cli audit \
  --config examples/openai-compatible-audit.yaml \
  --endpoint openai-compatible \
  --challenge-pack examples/dynamic-challenge-pack.yaml \
  --challenge-level standard
```

Dynamic challenge results are auxiliary. They appear in the report as sanitized
challenge id, category, level, hash, status, and verifier summaries, and do not
change the hard-fail authenticity scoring.

## Supported Audit Paths

| Path | Example config | What it checks |
| --- | --- | --- |
| Claude native | [`examples/claude-audit.yaml`](examples/claude-audit.yaml) | Anthropic Messages shape, Extended Thinking behavior, native stream sequence, error schema. |
| OpenAI-compatible Claude relay | [`examples/claude-openai-compatible-audit.yaml`](examples/claude-openai-compatible-audit.yaml) | Chat Completions shape, Claude model claim consistency, Claude thinking/version clues, reasoning leakage, relay and channel-risk symptoms. |
| OpenAI-compatible OpenAI | [`examples/openai-compatible-audit.yaml`](examples/openai-compatible-audit.yaml) | OpenAI-style Chat Completions shape, model-family consistency, reasoning capability evidence, streaming sequence, official-vs-compatible channel clues. |
| DeepSeek R1 | [`examples/deepseek-compatible-audit.yaml`](examples/deepseek-compatible-audit.yaml) | DeepSeek model-family consistency, R1 `reasoning_content`, reasoning/content stream order, official-vs-compatible channel clues. |

Current intentional boundaries:

- Gemini, Seed, Qwen, Doubao, and other provider audits are not implemented
  until there is a spec and implementation plan.
- JSON output, dashboard UI, batch endpoint execution, and tokenizer exact-match
  auditing are out of scope for the current CLI.
- A single timeout, disconnect, or TTFT spike is treated as an operational
  anomaly, not proof of routing misconduct.
- Dynamic challenge packs are local deterministic probes, not provider-specific
  audits for unsupported model families.

## Configuration

Prefer `api_key_env` over plaintext API keys in YAML:

```yaml
selected_endpoint: primary
raw_logs:
  enabled: false
  path: null
endpoints:
  - name: primary
    base_url: https://api.anthropic.com
    model: claude-sonnet-4-5
    api_key_env: ANTHROPIC_API_KEY
```

```bash
export ANTHROPIC_API_KEY="your-key"
```

CLI overrides are available for common fields:

```bash
PYTHONPATH=src python3 -m tokenverify.cli audit \
  --config examples/claude-audit.yaml \
  --endpoint primary \
  --base-url https://relay.example.com \
  --model claude-sonnet-4-5 \
  --api-key-env ANTHROPIC_API_KEY
```

Enable raw event logging only when you explicitly need it:

```bash
PYTHONPATH=src python3 -m tokenverify.cli audit \
  --config examples/claude-audit.yaml \
  --endpoint primary \
  --raw-log-path reports/events.jsonl
```

API keys are redacted from reports and raw logs.

### Dynamic Challenge Packs

Local challenge packs use YAML:

```yaml
id: local-baseline-example
version: "2026.05"
challenges:
  - id: arithmetic-exact
    category: arithmetic
    level: basic
    prompt: "Return only the decimal result of {{a}} + {{b}}."
    variables:
      a:
        type: integer
        min: 10
        max: 99
      b:
        type: integer
        min: 10
        max: 99
    verifiers:
      - type: exact_answer
        equals_expression: "a + b"
```

Supported variable types are `integer`, `hex`/`nonce`, and `choice`. Variables
are generated deterministically from pack id, pack version, challenge id,
variable name, and endpoint name. Supported local verifiers include
`exact_answer`, `required_field`, `forbidden_field`, `json_schema`, and
`stream_ordering`. Expression verification uses an allowlisted AST parser; YAML
packs are never executed as Python code.

## Example Reports

- [`examples/reports/claude-native-high-trust.md`](examples/reports/claude-native-high-trust.md)
- [`examples/reports/deepseek-r1-reasoning-missing.md`](examples/reports/deepseek-r1-reasoning-missing.md)

## Report Interpretation

The report separates two kinds of conclusions:

- `Authenticity Assertions`: strong or neutral evidence about the claimed
  provider, API shape, model family, error schema, and reasoning/thinking
  behavior.
- `Heuristic Risk Profile`: weak channel-health indicators such as relay
  headers, synthetic streaming, latency variance, cloud hosting clues, and
  account-pool wording.

The report uses four ratings:

- `High Trust`: protocol behavior and expected capabilities match the claim.
- `Medium Trust`: core behavior mostly matches but has gaps or ambiguous risk.
- `Low Trust`: strong contradictions exist.
- `Inconclusive`: not enough reliable evidence, such as missing API key, auth
  failure, quota failure, unsupported target, or network failure.

Other report fields:

- `authenticity_score`: 0-100, derived from strong evidence against the
  configured claim.
- `risk_score`: 0-100, derived from weak channel-health heuristics. It is not a
  probability and not a direct accusation.
- `tags`: stable labels such as `ANTHROPIC_NATIVE_SHAPE_MATCH`,
  `CROSS_PROVIDER_REASONING_LEAKED`, `DEEPSEEK_REASONING_CONTENT_MISSING`, or
  `SYNTHETIC_STREAM_SUSPECT`.
- `Suspected Upstream Signals`: auxiliary hints that translate observed model
  strings, physical fingerprints, or response fields into provider-style clues
  such as OpenAI-style, Claude-style, or DeepSeek/R1-style. These hints do not
  replace scoring.
- `Dynamic Challenge Results`: auxiliary local challenge outcomes. Reports show
  only challenge id/category/level/hash/status and sanitized verifier summaries;
  full challenge prompts, rendered variables, raw model output, and private
  expected answers are not embedded.

## CLI Exit Codes

`tokenverify audit` writes the Markdown report before returning an audit-result
exit code:

- `0`: audit completed with high or medium trust.
- `1`: audit completed with low trust.
- `2`: configuration or CLI argument error.
- `3`: audit completed but the runtime result is inconclusive.

No-key or offline paths do not send a real provider request. They produce an
`Inconclusive` report and return exit code `3`; check the report for API key,
network, quota, or unsupported-target details.

## Safety and Privacy

- No live network requests are made by the default test suite.
- Provider HTTP tests use `httpx.MockTransport`.
- Probe tests use mock observations or local no-key paths.
- Real-network tests are opt-in and marked `real_network`.
- Reports and raw logs redact configured API keys.
- Do not publish API keys, raw event logs, or customer secrets in issues.

## Development

Run the default test suite:

```bash
PYTHONPATH=src python3 -m pytest -v
```

Run opt-in real-network tests only when you intentionally want to hit configured
external endpoints:

```bash
PYTHONPATH=src python3 -m pytest -v -m real_network
```

Check CLI help:

```bash
PYTHONPATH=src python3 -m tokenverify.cli audit --help
```

Provider and probe regression policy:

- Every new provider or probe module must add regression tests.
- Provider HTTP behavior must use httpx.MockTransport.
- Probe behavior should use direct probe inputs or mock observations.
- Default tests must pass without live network access.

## Project Layout

```text
src/tokenverify/
  audit.py                    # Audit orchestration
  audit_plan.py               # Claim-to-probe routing
  cli.py                      # Typer CLI
  config.py                   # YAML loading, overrides, redaction
  deepseek_capabilities.py    # DeepSeek model-family capability lookup
  model_capabilities.py       # Claude capability lookup
  openai_capabilities.py      # OpenAI model-family capability lookup
  dynamic_challenges.py       # Local deterministic challenge packs and verifiers
  challenge_baseline.yaml     # Built-in public baseline challenge pack
  models.py                   # Shared dataclasses, verdicts, ratings, tags
  providers/                 # Anthropic, OpenAI-compatible, OpenAI adapters
  probes/                    # Provider probes and streaming heuristics
  report.py                   # Markdown report rendering
  scoring.py                  # Rating and score breakdown
  upstream_signals.py         # Auxiliary provider-style signal extraction
```

User-facing docs:

- [`docs/user-guide.md`](docs/user-guide.md)
- [`docs/release-readiness.md`](docs/release-readiness.md)

## Contributor License Agreement

Contributions require the [Contributor License Agreement](CLA.md). Contributors retain copyright, while granting the project maintainer enough rights to distribute contributions under AGPL-3.0-only and possible future commercial license terms.

## License

TokenVerify is licensed under AGPL-3.0-only. See [LICENSE](LICENSE) for the full license text.

To preserve white-box trust for individual developers, researchers, and community users, the core audit logic will remain open under AGPL-3.0-only. For enterprise environments or derivative routing systems where AGPL-3.0 copyleft obligations cannot be met, alternative commercial licensing paths may be explored in the future to support compliant adoption.
