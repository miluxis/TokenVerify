# TokenVerify User Guide

TokenVerify audits whether an endpoint behaves like its claimed provider, API shape, and model family. It writes a Markdown report and exits with a script-friendly status code.

## Claude Native

Use this path when the endpoint claims Anthropic native Messages API behavior.

```bash
PYTHONPATH=src python3 -m tokenverify.cli audit \
  --config examples/claude-audit.yaml \
  --endpoint primary \
  --output reports/claude-audit.md
```

This path checks Anthropic Messages shape, Extended Thinking behavior when expected, and native streaming signals.

## OpenAI-Compatible Claude Relay

Use this path when a relay exposes Chat Completions but claims to route to Claude.

```bash
PYTHONPATH=src python3 -m tokenverify.cli audit \
  --config examples/claude-openai-compatible-audit.yaml \
  --endpoint claude-openai-compatible \
  --repeat 3 \
  --output reports/claude-relay-audit.md
```

This path checks Chat Completions shape, Claude model naming, Claude thinking/version clues, cross-provider reasoning leakage, streaming finish behavior, and channel-risk symptoms.

## OpenAI-Compatible OpenAI

Use this path when the endpoint claims OpenAI models through Chat Completions-compatible behavior.

```bash
PYTHONPATH=src python3 -m tokenverify.cli audit \
  --config examples/openai-compatible-audit.yaml \
  --endpoint openai-compatible \
  --repeat 3 \
  --output reports/openai-compatible-audit.md
```

This path checks OpenAI-style Chat Completions shape, model-family consistency, reasoning capability evidence, streaming sequence, and official-vs-compatible channel clues.

## DeepSeek R1

Use this path when the endpoint claims DeepSeek R1 or another DeepSeek Chat Completions-compatible model.

```bash
PYTHONPATH=src python3 -m tokenverify.cli audit \
  --config examples/deepseek-compatible-audit.yaml \
  --endpoint deepseek-compatible \
  --repeat 3 \
  --output reports/deepseek-compatible-audit.md
```

For R1 claims, TokenVerify expects native `reasoning_content` evidence on non-trivial reasoning prompts. Missing native R1 reasoning fields can lower trust. DeepSeek-compatible relays are not treated as official DeepSeek unless the channel evidence supports that claim.

## No-Key / Offline Behavior

If no API key is configured, TokenVerify does not send a live provider request. It writes an `无法判定` report and returns exit code `3`. This is useful for checking config parsing, report generation, and no-key behavior without live network access.

## Report Interpretation

Plain-Language Summary gives the non-technical result first: rating, authenticity score, risk score, and the most important human-readable finding.

Channel Risk Profile summarizes official-channel fit, relay suspicion, cloud-hosting clues, and web-reverse or account-pool symptoms. It is a channel-health explanation, not proof of misconduct.

Suspected Upstream Signals translates observed model strings, physical fingerprints, or response fields into auxiliary hints such as OpenAI-style, Claude-style, or DeepSeek/R1-style. These hints do not prove the real official upstream and do not replace scoring.

Authenticity Assertions list strong or neutral evidence about the claimed provider/API/model behavior.

Heuristic Risk Profile lists weak operational signals such as relay headers, synthetic streaming, latency variance, or account-pool wording. These signals can raise concern but do not by themselves prove provider forgery.

## Exit Codes

- `0`: high or medium trust report was written.
- `1`: low trust report was written.
- `2`: configuration or CLI argument error.
- `3`: inconclusive report was written.
