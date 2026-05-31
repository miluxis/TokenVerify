# TokenVerify Audit Report

## Plain-Language Summary

- Audit result: Low Trust
- Authenticity score: 39
- Channel risk score: 0
- Found 1 strong evidence items contradicting the claim; review the model or channel configuration first.
- Missing reasoning capability: the endpoint claims DeepSeek R1, but native reasoning_content was not observed. It may be routed to a model or compatibility layer that does not support R1 reasoning.
- Black-box checks cannot prove the true upstream source with 100% certainty; they are used to find strong contradictions, obvious downgrades, and channel risk.

## Channel Risk Profile

- Official direct channel: not claimed
- Relay platform: suspected
- Cloud-hosted channel: no clear leak observed
- Web reverse / account pool: not enough samples to judge
- Note: channel profiling is based on hostnames, response headers, error text, model fields, and repeated-request consistency. Unless the server directly leaks upstream identifiers, it is not absolute proof.

## Suspected Upstream Signals

- Note: these hints only explain provider-style or compatibility-layer traits observed in the response. They do not prove the real official upstream and do not change the trust rating.
- No obvious cross-provider upstream style hints were observed.

## Target Summary

- **base_url_host**: relay.example
- **model**: deepseek-r1
- **endpoint**: deepseek-compatible
- **claimed_provider**: deepseek
- **claimed_api_shape**: openai-compatible

## Overall Verdict

- Rating: **Low Trust**
- Authenticity score: 39
- Risk score: 0
- Tags: DEEPSEEK_REASONING_CONTENT_MISSING

Authenticity score measures how well the endpoint matches the claimed provider/API/model behavior.
Risk score measures heuristic channel-health and relay-risk symptoms.

## Evidence Score Breakdown

- `strong_passed`: 1
- `strong_failed`: 1
- `weak_failed`: 0

## Authenticity Assertions

- `deepseek_chat_shape` (strong, pass): Response matches DeepSeek Chat Completions shape. Tags: DEEPSEEK_CHAT_COMPLETION_SHAPE_MATCH.
- `deepseek_reasoning_content` (strong, fail): R1 response did not expose native reasoning_content. Tags: DEEPSEEK_REASONING_CONTENT_MISSING.

## Heuristic Risk Profile

- Risk score: 0
- Risk tags: None
- These signals are heuristic channel-risk indicators. They can raise operational concern, but they do not by themselves prove provider forgery or unauthorized routing.
- No heuristic risk indicators were produced.

## DeepSeek Chat Completions Shape Probe

- Status: passed
- `deepseek_chat_shape` (strong, pass): Response matches DeepSeek Chat Completions shape.

## DeepSeek Model Claim Consistency Probe

- Status: passed
- `deepseek_model_claim` (strong, pass): Observed model `deepseek-r1` matches claimed model `deepseek-r1`.

## DeepSeek R1 Reasoning Content Probe

- Status: failed
- `deepseek_reasoning_content` (strong, fail): R1 response did not expose native reasoning_content.

## DeepSeek Channel Risk Probe

- Not run

## DeepSeek-Compatible Streaming Metrics

- Not run

## Errors and Warnings

- None

## Configuration Summary

```json
{
  "endpoint": {
    "name": "deepseek-compatible",
    "base_url_redacted": "***REDACTED***",
    "base_url_hash": "889271d70d18282b",
    "base_url_host": "relay.example",
    "model": "deepseek-r1"
  }
}
```
