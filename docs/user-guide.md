# TokenVerify User Guide

TokenVerify audits whether an endpoint behaves like its claimed provider, API shape, and model family. It writes a Markdown report and exits with a script-friendly status code.

## Unified Audit Entry

Use `tokenverify audit` as the primary entry. TokenVerify routes config-style
inputs to provider/model authenticity audit and direct base-url/model inputs to
relay contract audit.

`tokenverify relay-audit` remains available as a compatibility command during
migration, but new examples use `tokenverify audit`.

Routing is inferred from the input shape:

- `--config ...` runs provider/model authenticity audit unless the YAML declares `route: relay`.
- `--base-url ... --model ...` runs relay contract audit.
- `--endpoint` is valid only with `--config`.
- `--profile` and `--fake-run` apply to relay targets.
- `--api-key-env` must name an environment variable. For live relay checks, the variable must exist before execution starts. Fake-runs do not require real credentials.

| Input style | Use this when |
| --- | --- |
| `tokenverify audit --config ...` | You want provider/model-family authenticity, compatibility, reasoning, and channel-risk analysis. |
| `tokenverify audit --base-url ... --model ...` | You want relay contract checks such as streaming integrity, schema/tool preservation, privacy leakage, and sanitized public reporting. |

Config-driven relay audit uses a top-level route declaration:

```yaml
route: relay
relay:
  base_url: https://relay.example/v1
  model: example-model
  profile: full
  api_key_env: RELAY_API_KEY
  live: true
```

## Claude Native

Use this path when the endpoint claims Anthropic native Messages API behavior.

```bash
PYTHONPATH=src python3 -m tokenverify.cli audit \
  --config examples/claude-audit.yaml \
  --endpoint primary
```

This path checks Anthropic Messages shape, Extended Thinking behavior when expected, and native streaming signals.

## OpenAI-Compatible Claude Relay

Use this path when a relay exposes Chat Completions but claims to route to Claude.

```bash
PYTHONPATH=src python3 -m tokenverify.cli audit \
  --config examples/claude-openai-compatible-audit.yaml \
  --endpoint claude-openai-compatible \
  --detail-audit yes
```

This path checks Chat Completions shape, Claude model naming, Claude thinking/version clues, cross-provider reasoning leakage, streaming finish behavior, and channel-risk symptoms.

## OpenAI-Compatible OpenAI

Use this path when the endpoint claims OpenAI models through Chat Completions-compatible behavior.

```bash
PYTHONPATH=src python3 -m tokenverify.cli audit \
  --config examples/openai-compatible-audit.yaml \
  --endpoint openai-compatible \
  --detail-audit yes
```

This path checks OpenAI-style Chat Completions shape, model-family consistency, reasoning capability evidence, streaming sequence, and official-vs-compatible channel clues.

## DeepSeek R1

Use this path when the endpoint claims DeepSeek R1 or another DeepSeek Chat Completions-compatible model.

```bash
PYTHONPATH=src python3 -m tokenverify.cli audit \
  --config examples/deepseek-compatible-audit.yaml \
  --endpoint deepseek-compatible \
  --detail-audit yes
```

For R1 claims, TokenVerify expects native `reasoning_content` evidence on non-trivial reasoning prompts. Missing native R1 reasoning fields can lower trust. DeepSeek-compatible relays are not treated as official DeepSeek unless the channel evidence supports that claim.

Provider reports are written automatically under `reports/audit-provider-[model-name]-[date].md`. Relay reports use `reports/audit-relay-[model-name]-[date].md`. Detail audit uses 8 samples internally to look for relay, reverse-channel, account-pool, latency-variance, and model-drift risk signals.

Report explanations are English by default. Use `--language zh` for a Chinese report:

```bash
PYTHONPATH=src python3 -m tokenverify.cli audit \
  --config examples/deepseek-compatible-audit.yaml \
  --endpoint deepseek-compatible \
  --detail-audit yes \
  --language zh
```

## Dynamic Challenge Suite

TokenVerify runs a built-in public baseline challenge pack by default. These
results are auxiliary and do not change the hard-fail authenticity rating.

Use a local YAML pack and choose a level when you want deterministic local
challenges beyond the built-in baseline:

```bash
PYTHONPATH=src python3 -m tokenverify.cli audit \
  --config examples/openai-compatible-audit.yaml \
  --endpoint openai-compatible \
  --challenge-pack examples/dynamic-challenge-pack.yaml \
  --challenge-level standard
```

Supported levels are `basic`, `standard`, and `strict`. Supported deterministic
variables are `integer`, `hex`/`nonce`, and `choice`. Supported local verifiers
are `exact_answer`, `required_field`, `forbidden_field`, `json_schema`, and
`stream_ordering`.

Challenge variables are generated from stable local inputs, including pack id,
pack version, challenge id, variable name, and endpoint name. Expression
verification uses an allowlisted AST parser, not Python `eval()`.

## Relay Audit

Use direct relay inputs when your main question is not "is this endpoint really the claimed provider?" but "is this relay preserving the contract it should preserve?"

```bash
PYTHONPATH=src python3 -m tokenverify.cli audit \
  --base-url https://relay.example/v1 \
  --model example-model \
  --profile full \
  --api-key-env RELAY_API_KEY \
  --live
```

Relay Audit profiles for ordinary users:

| Profile | Use this when |
| --- | --- |
| `general` | You want a basic compatibility and reachability check before deeper work. |
| `streaming` | You care whether streaming feels complete and not obviously synthetic. |
| `schema` | You rely on tool calling or JSON structure and want to see whether the relay preserves it. |
| `privacy` | You care about prompt leakage symptoms, message rewrite, or upstream disclosure behavior. |
| `security` | You want to check whether a relay preserves prompt boundaries under safe extraction and override pressure. |
| `context` | You want to check whether a relay preserves early, middle, and late public context anchors instead of silently dropping or rewriting them. |
| `full` | You want one combined relay report for comparison, filing, or public sharing. |

Run bounded prompt-security checks explicitly:

```bash
PYTHONPATH=src python3 -m tokenverify.cli audit \
  --base-url https://relay.example/v1 \
  --model example-model \
  --profile security \
  --api-key-env RELAY_API_KEY \
  --live
```

Run bounded context-retention checks explicitly:

```bash
PYTHONPATH=src python3 -m tokenverify.cli audit \
  --base-url https://relay.example/v1 \
  --model example-model \
  --profile context \
  --api-key-env RELAY_API_KEY \
  --live
```

Current Relay Audit boundaries:

- No billing or money-spent estimation.
- No 8-cycle repeated full-profile deep audit in the current release.
- `security` provides bounded black-box prompt-boundary evidence; it does not prove malicious intent or complete jailbreak resistance.
- `context` provides bounded public anchor-retention evidence; it does not measure exact context-window size, estimate billing, or prove malicious truncation.
- Public relay reports hide full prompt text, model response text, header values, full URLs, local absolute paths, and private challenge answers.

Open-source Core boundary:

- The open-source Core is the local CLI for single-endpoint audits, deterministic fake-runs, public relay profiles, sanitized Markdown reports, and local metadata summaries.
- Commercial or hosted layers remain outside this Core: restricted challenge-pack governance, batch scanning, dashboards, report comparison databases, machine-readable JSON/API output, hosted monitoring, and enterprise policy layers.

## No-Key / Offline Behavior

If no API key is configured, TokenVerify does not send a live provider request. It writes an `Inconclusive` report and returns exit code `3`. This is useful for checking config parsing, report generation, and no-key behavior without live network access.

## Report Interpretation

Plain-Language Summary gives the non-technical result first: rating, authenticity score, risk score, and the most important human-readable finding.

Channel Risk Profile summarizes official-channel fit, relay suspicion, cloud-hosting clues, and web-reverse or account-pool symptoms. It is a channel-health explanation, not proof of misconduct.

Suspected Upstream Signals translates observed model strings, physical fingerprints, or response fields into auxiliary hints such as OpenAI-style, Claude-style, or DeepSeek/R1-style. These hints do not prove the real official upstream and do not replace scoring.

Authenticity Assertions list strong or neutral evidence about the claimed provider/API/model behavior.

Heuristic Risk Profile lists weak operational signals such as relay headers, synthetic streaming, latency variance, or account-pool wording. These signals can raise concern but do not by themselves prove provider forgery.

Dynamic Challenge Results list sanitized local challenge outcomes. The report
shows challenge id, category, level, hash, status, and neutral verifier
summaries. It does not embed full challenge prompts, rendered variables, raw
model output, or private expected answers.

## Exit Codes

- `0`: high or medium trust report was written.
- `1`: low trust report was written.
- `2`: configuration or CLI argument error.
- `3`: inconclusive report was written.
