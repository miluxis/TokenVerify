# TokenVerify

[English](README.md) | [简体中文](README.zh-CN.md)

TokenVerify is a black-box audit CLI for checking whether an LLM endpoint or
relay behaves like its claimed provider, API shape, model family, channel, and
relay contract. It turns protocol behavior, model fields, reasoning signals,
streaming metrics, schema/tool preservation, privacy leakage checks, and relay
symptoms into a human-readable Markdown report.

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

Provider reports are written automatically under `reports/audit-provider-[model-name]-[date].md`.
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

### Relay Audit Quick Start

Relay Audit is the focused CLI product path for auditing OpenAI-compatible relay
endpoints. It supports deterministic fake runs and guarded live checks across
`general`, `identity`, `channel`, `reasoning`, `streaming`, `schema`,
`privacy`, `security`, `context`, and `full` profiles.
For ordinary users, `full` is the default public report path. Individual profiles
are advanced technical diagnostics.

Run a deterministic no-network demo:

```bash
PYTHONPATH=src python3 -m tokenverify.cli audit \
  --base-url https://relay.example/v1 \
  --model example-model \
  --fake-run suspicious
```

Run a real live check only when you explicitly opt in:

```bash
export RELAY_API_KEY="your-relay-key"

PYTHONPATH=src python3 -m tokenverify.cli audit \
  --base-url https://relay.example/v1 \
  --model example-model \
  --api-key-env RELAY_API_KEY \
  --live
```

Enable bounded drift checking when your concern is account-pool rotation,
reverse resources, fallback, or mixed-provider routing:

```bash
PYTHONPATH=src python3 -m tokenverify.cli audit \
  --base-url https://relay.example/v1 \
  --model example-model \
  --api-key-env RELAY_API_KEY \
  --live \
  --drift-check yes
```

Run bounded prompt-security checks when your concern is prompt boundaries under
safe extraction and override pressure:

```bash
PYTHONPATH=src python3 -m tokenverify.cli audit \
  --base-url https://relay.example/v1 \
  --model example-model \
  --profile security \
  --api-key-env RELAY_API_KEY \
  --live
```

Run bounded context-retention checks when your concern is early, middle, and
late public context anchors:

```bash
PYTHONPATH=src python3 -m tokenverify.cli audit \
  --base-url https://relay.example/v1 \
  --model example-model \
  --profile context \
  --api-key-env RELAY_API_KEY \
  --live
```

Relay reports show only host-level endpoint text and a public endpoint hash.
They do not print full prompt text, model response text, header values, full URLs, API
keys, or private challenge answers. See the local measurement guide:
[`docs/relay-audit-user-guide.zh-CN.md`](docs/relay-audit-user-guide.zh-CN.md).

`tokenverify relay-audit` remains available as a compatibility command during
migration, but new examples use `tokenverify audit`.

## Unified Audit Entry

Use `tokenverify audit` as the primary entry. TokenVerify routes config-style
inputs to provider/model authenticity audit and direct base-url/model inputs to
relay contract audit.

Automatic routing rules:

- `--config ...` runs provider/model authenticity audit by default.
- `--config ...` with top-level `route: relay` runs relay contract audit from the YAML `relay:` block.
- `--base-url ... --model ...` runs relay contract audit.
- `--api-key-env` is a variable name, not the key itself. For live relay checks, the named variable must exist before execution starts; fake-runs do not require real credentials.

| Input style | Ordinary user scenario |
| --- | --- |
| `tokenverify audit --config ...` | You want to know whether an endpoint behaves like its claimed provider/model family, and whether its reasoning, channel, or compatibility story looks credible. |
| `tokenverify audit --base-url ... --model ...` | You already know this is a relay or suspect relay behavior, and you want to check contract integrity, streaming quality, schema/tool preservation, privacy leakage, and public-report safety. |

## Relay Audit Profiles For Ordinary Users

`full` is the recommended default. It produces a scenario-first report. Single
profiles produce technical profile reports and list the scenario areas they can
support, but they do not claim that a whole fraud scenario passed or failed.

| Profile | Ordinary user scenario |
| --- | --- |
| `full` | Default. Use this when you want one combined scenario report for record-keeping, comparison, or public presentation. |
| `general` | Use this first to confirm the relay is basically reachable and returns a compatible response envelope. |
| `identity` | Use this when your main concern is wrong-model or lower-model substitution. |
| `channel` | Use this when your main concern is observed Bedrock, Azure, OpenRouter, OneAPI, NewAPI, or proxy-compatible channel signals. |
| `reasoning` | Use this when your main concern is fake Thinking/reasoning capability or missing native reasoning fields. |
| `streaming` | Use this when you care whether typing-style streaming looks stable, complete, and not obviously synthetic. |
| `schema` | Use this when your workload depends on tool calling, function calling, or JSON structure that must survive the relay unchanged. |
| `privacy` | Use this when you worry about prompt leakage, hidden instruction echo, message rewrite, or upstream error disclosure. |
| `security` | Use this when you want to check whether a relay preserves prompt boundaries under safe extraction and override pressure. |
| `context` | Use this when you want to check whether a relay preserves early, middle, and late public context anchors instead of silently dropping or rewriting them. |

## Fraud Scenario Summary

Full relay reports include a Fraud Scenario Summary above the detailed technical evidence. It maps existing evidence into user-facing fraud categories such as model identity substitution, channel-source misrepresentation, Thinking/reasoning forgery, account-pool or mixed-routing drift, prompt/context manipulation, fake streaming, schema/tool breakage, privacy leakage, and capacity/error masking.

Full relay reports use a signal-first structure:

- Overall Conclusion
- Fraud Scenario Summary
- Technical Signal Overview
- Technical Evidence Summary
- Method Note

The overall judgment describes observed risk signals rather than presenting a simple pass/fail verdict. Main observed risk signals are rendered with a plain-language explanation first, followed by sanitized evidence fields, so a public report can be read without losing the underlying technical breadcrumbs.

Scenario status values are `detected`, `suspicious`, `not_detected`, and `insufficient_evidence`. `not_detected` means the relevant signals were checked and not observed; it is not an empty result. `insufficient_evidence` means the scenario is relevant but the current run did not collect enough evidence, for example when drift checking was not enabled. Future-only categories such as billing reconciliation or cache-replay databases are not shown as public report rows by default.

The summary is a black-box risk explanation. It can surface candidate upstream-family signals such as `Claude-like`, `OpenAI-compatible`, `DeepSeek-like`, `Qwen-like`, or `GLM-like` when evidence supports them, but these are behavioral fingerprints, not proof of exact upstream identity. It does not prove exact upstream model identity, legal wrongdoing, true intent, exact geography, exact billing, or hidden backend topology. Billing reconciliation, cache-detection databases, channel fingerprint libraries, batch scanning, dashboards, and report comparison databases remain outside the open-source Core.

Config-driven relay audit can use this shape:

```yaml
route: relay
relay:
  base_url: https://relay.example/v1
  model: example-model
  profile: full
  api_key_env: RELAY_API_KEY
  live: true
  drift_check: no
```

## Supported Audit Paths

| Path | Example config | What it checks |
| --- | --- | --- |
| Claude native | [`examples/claude-audit.yaml`](examples/claude-audit.yaml) | Anthropic Messages shape, Extended Thinking behavior, native stream sequence, error schema. |
| OpenAI-compatible Claude relay | [`examples/claude-openai-compatible-audit.yaml`](examples/claude-openai-compatible-audit.yaml) | Chat Completions shape, Claude model claim consistency, Claude thinking/version clues, reasoning leakage, relay and channel-risk symptoms. |
| OpenAI-compatible OpenAI | [`examples/openai-compatible-audit.yaml`](examples/openai-compatible-audit.yaml) | OpenAI-style Chat Completions shape, model-family consistency, reasoning capability evidence, streaming sequence, official-vs-compatible channel clues. |
| DeepSeek R1 | [`examples/deepseek-compatible-audit.yaml`](examples/deepseek-compatible-audit.yaml) | DeepSeek model-family consistency, R1 `reasoning_content`, reasoning/content stream order, official-vs-compatible channel clues. |
| Relay Audit CLI | `tokenverify audit --base-url ... --model ...` | OpenAI-compatible relay checks for identity, channel, reasoning, general connectivity, SSE streaming, schema/tool preservation, privacy leakage, prompt-security boundaries, context retention, and full composite reporting. |

Current intentional boundaries:

- Gemini, Seed, Qwen, Doubao, and other provider audits are future backlog until
  there is a spec and implementation plan.
- JSON output, dashboard UI, batch endpoint execution, commercial challenge-pack
  governance, and tokenizer exact-match auditing are future backlog.
- A single timeout, disconnect, or TTFT spike is treated as an operational
  anomaly, not proof of routing misconduct.
- Dynamic challenge packs are local deterministic probes, not provider-specific
  audits for unsupported model families.
- Relay Audit does not estimate billing or money spent.
- Relay Audit does not run an 8-cycle repeated full-profile deep audit in the current release.
- Relay Audit `security` is bounded black-box evidence about prompt boundaries; it does not prove malicious intent or complete jailbreak resistance.
- Relay Audit `context` is bounded anchor-retention evidence. It does not measure exact context-window size, estimate billing, or prove malicious truncation.
- Relay Audit `identity`, `channel`, and `reasoning` produce black-box fingerprint signals. They can show contradictions and candidate-family signals, but not exact upstream identity without hard evidence.

Open-source Core boundary:

- This repository is the local CLI Core: single-endpoint provider/model audits,
  single-endpoint relay contract audits, deterministic fake-runs, current public
  relay profiles, sanitized Markdown reports, and local metadata summaries.
- Commercial or hosted layers are intentionally outside this open-source Core:
  private challenge-pack governance, signing/encryption/licensing, batch
  scanning, dashboards, report comparison databases, machine-readable JSON/API
  output for automation, hosted monitoring, and enterprise policy layers.

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
  full challenge prompts, rendered variables, raw model text, and private
  expected answers are not embedded.

## CLI Exit Codes

`tokenverify audit` writes the Markdown report before returning an exit code.
For provider-style inputs:

- `0`: audit completed with high or medium trust.
- `1`: audit completed with low trust.
- `2`: configuration or CLI argument error.
- `3`: audit completed but the runtime result is inconclusive.

No-key or offline paths do not send a real provider request. They produce an
`Inconclusive` report and return exit code `3`; check the report for API key,
network, quota, or unsupported-target details.

For relay-style inputs:

- `0`: relay audit completed with verdict `pass` or `suspicious`.
- `1`: relay audit completed with verdict `fail`.
- `2`: CLI argument, configuration, pack metadata, or live-gate error.
- `3`: relay audit completed with verdict `inconclusive`.

## Safety and Privacy

- No live network requests are made by the default test suite.
- Provider HTTP tests use `httpx.MockTransport`.
- Probe tests use mock observations or local no-key paths.
- Real-network tests are opt-in and marked `real_network`.
- Reports and raw logs redact configured API keys.
- Relay Audit public reports hide full prompt text, model response text, header values,
  full endpoint paths/query/fragment, local absolute paths, and private challenge
  answers.
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
  relay_audit.py              # Relay Audit orchestration
  relay_live.py               # Minimal general live relay check
  relay_streaming.py          # Streaming/SSE relay profile
  relay_schema.py             # Schema/tool relay profile
  relay_privacy.py            # Privacy leakage relay profile
  relay_identity.py           # Model identity fingerprint relay profile
  relay_channel.py            # Channel/source fingerprint relay profile
  relay_reasoning.py          # Thinking/reasoning fingerprint relay profile
  relay_full.py               # Full composite relay profile
  relay_report.py             # Sanitized Relay Audit Markdown report
  relay_safety.py             # Live gate, URL/path washing, relay sanitizers
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
