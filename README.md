# TokenVerify

TokenVerify is a Claude relay authenticity audit tool for checking whether a user-provided endpoint behaves like the claimed Claude API shape. Phase 1 focuses on Claude-native protocol signals, OpenAI-compatible Claude relay signals, Extended Thinking behavior, streaming physical features, and a human-readable Markdown report.

## Current MVP

Implemented in this repository:

- Python package with a thin `tokenverify audit` CLI.
- YAML configuration with CLI overrides.
- Anthropic Messages payload builder, HTTP client, SSE stream parser, and error normalization.
- OpenAI-compatible Chat Completions payload builder, HTTP client, SSE parser, self-relay loop safety header, and error normalization for claimed Claude relays.
- Built-in probes for:
  - Anthropic Messages response shape.
  - OpenAI-compatible Chat Completions shape for claimed Claude relays.
  - Claude model claim consistency.
  - Cross-provider reasoning leakage and synthetic thinking text.
  - Extended Thinking payload construction and outcome interpretation.
  - Streaming metrics: TTFT, chunk intervals, chunk size distribution, estimated throughput, and synthetic stream heuristic.
- Claude model capability lookup for interpreting Extended Thinking results.
- Markdown report renderer with secret redaction.
- Optional raw event log path support.
- Unit tests and mocked end-to-end audit flow.

Out of scope for this MVP:

- OpenAI official model authenticity auditing.
- DeepSeek provider auditing.
- Gemini, Seed, Qwen, Doubao, or other non-Claude provider auditing.
- Streamlit or Web UI.
- Batch endpoint execution.
- JSON report output.
- Tokenizer exact-match auditing.
- Cognitive trap prompt scoring.

## Requirements

- Python 3.11+
- Runtime dependencies:
  - `httpx`
  - `PyYAML`
  - `typer`
- Test dependency:
  - `pytest`

Install locally:

```bash
python3 -m pip install -e ".[test]"
```

If editable install is not needed:

```bash
python3 -m pip install httpx PyYAML typer pytest
```

## Configuration

Start from [examples/claude-audit.yaml](/Users/Teng/MyProjects/TokenVerify/examples/claude-audit.yaml):

```yaml
selected_endpoint: primary
output: reports/claude-audit.md
raw_logs:
  enabled: false
  path: null
endpoints:
  - name: primary
    base_url: https://api.anthropic.com
    model: claude-sonnet-4-5
    api_key_env: ANTHROPIC_API_KEY
extension_probes:
  - name: appendix-only-example
    prompt: "This custom probe is observation-only in Phase 1."
```

Prefer `api_key_env` over plaintext API keys in YAML.

```bash
export ANTHROPIC_API_KEY="your-key"
```

For an OpenAI-compatible Claude relay, start from [examples/claude-openai-compatible-audit.yaml](/Users/Teng/MyProjects/TokenVerify/examples/claude-openai-compatible-audit.yaml):

```yaml
selected_endpoint: claude-openai-compatible
output: reports/claude-openai-compatible-audit.md
raw_logs:
  enabled: false
  path: null
endpoints:
  - name: claude-openai-compatible
    base_url: https://relay.example.com/v1
    provider: anthropic
    api_shape: openai-compatible
    model: claude-sonnet-4.5
    api_key_env: CLAUDE_RELAY_API_KEY
```

The OpenAI-compatible path sends Chat Completions requests with `Authorization: Bearer ...` and `X-TokenVerify-Scan: true`. It checks Chat Completions shape, Claude model claim consistency, reasoning leakage, terminal `finish_reason`, and self-relay loop symptoms. It does not audit OpenAI official models or non-Claude providers.

## Usage

Run an audit:

```bash
PYTHONPATH=src python3 -m tokenverify.cli audit \
  --config examples/claude-audit.yaml \
  --endpoint primary \
  --output reports/claude-audit.md
```

Run an OpenAI-compatible Claude relay audit:

```bash
PYTHONPATH=src python3 -m tokenverify.cli audit \
  --config examples/claude-openai-compatible-audit.yaml \
  --endpoint claude-openai-compatible \
  --output reports/claude-openai-compatible-audit.md
```

Useful overrides:

```bash
PYTHONPATH=src python3 -m tokenverify.cli audit \
  --config examples/claude-audit.yaml \
  --endpoint primary \
  --base-url https://relay.example.com \
  --model claude-sonnet-4-5 \
  --api-key-env ANTHROPIC_API_KEY \
  --output reports/relay-audit.md
```

Enable raw event log output explicitly:

```bash
PYTHONPATH=src python3 -m tokenverify.cli audit \
  --config examples/claude-audit.yaml \
  --endpoint primary \
  --raw-log-path reports/events.jsonl
```

API keys are redacted from reports and raw logs.

## Report Ratings

The Markdown report separates two kinds of conclusions:

- `Authenticity Assertions`: protocol, error schema, model capability, and thinking/reasoning block evidence that can support strong authenticity judgments.
- `Heuristic Risk Profile`: timing, streaming regularity, synthetic stream, pooling, and channel-health symptoms. These produce a 0-100 risk score, not a probability and not a direct accusation.

The report uses four authenticity ratings:

- `高可信`: protocol and expected Extended Thinking behavior match.
- `中可信`: core behavior mostly matches but has suspicious gaps.
- `低可信`: strong evidence of non-Anthropic behavior or ignored Claude-native parameters.
- `无法判定`: insufficient evidence, such as missing API key, auth failure, quota failure, or network failure.

The report also includes:

- `authenticity_score`: 0-100, derived from strong evidence against the configured claim.
- `risk_score`: 0-100, derived from weak channel-health heuristics.
- `tags`: stable labels such as `ANTHROPIC_NATIVE_SHAPE_MATCH`, `CROSS_PROVIDER_REASONING_LEAKED`, or `SYNTHETIC_STREAM_SUSPECT` for future dashboard and routing use.

Streaming metrics are weak evidence. A single timeout, disconnect, or TTFT spike is treated as a network or operational anomaly rather than direct channel-risk proof.

## Development

Run the test suite:

```bash
PYTHONPATH=src python3 -m pytest -v
```

Real-network tests are marked `real_network` and skipped by default.

Check CLI help:

```bash
PYTHONPATH=src python3 -m tokenverify.cli audit --help
```

## Project Layout

```text
src/tokenverify/
  audit.py                 # Audit orchestration
  cli.py                   # Typer CLI
  config.py                # YAML loading, overrides, redaction
  model_capabilities.py    # Claude capability table
  models.py                # Shared dataclasses and rating enum
  providers/anthropic.py   # Anthropic client, payloads, SSE parsing
  providers/openai_compatible.py # OpenAI-compatible client, payloads, SSE parsing
  probes/messages.py       # Messages protocol shape probe
  probes/openai_compatible.py # OpenAI-compatible Claude relay probes
  probes/thinking.py       # Extended Thinking probe helpers
  probes/streaming.py      # Streaming metric extraction
  report.py                # Markdown report rendering
  scoring.py               # Rating and score breakdown
```

Design and implementation planning docs live under:

- [docs/superpowers/specs/2026-05-25-tokenverify-design.md](/Users/Teng/MyProjects/TokenVerify/docs/superpowers/specs/2026-05-25-tokenverify-design.md)
- [docs/superpowers/plans/2026-05-25-tokenverify-implementation-plan.md](/Users/Teng/MyProjects/TokenVerify/docs/superpowers/plans/2026-05-25-tokenverify-implementation-plan.md)
