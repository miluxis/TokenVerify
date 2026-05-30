# TokenVerify Audit Report

## Plain-Language Summary

- Audit result: High Trust
- Authenticity score: 96
- Channel risk score: 0
- Found 2 strong evidence items supporting the claim.
- No cross-provider routing, obvious model downgrade, or strong structural contradiction was observed.
- Black-box checks cannot prove the true upstream source with 100% certainty; they are used to find strong contradictions, obvious downgrades, and channel risk.

## Channel Risk Profile

- Official direct channel: appears to match official host
- Relay platform: no clear evidence observed
- Cloud-hosted channel: no clear leak observed
- Web reverse / account pool: not enough samples to judge
- Note: channel profiling is based on hostnames, response headers, error text, model fields, and repeated-request consistency. Unless the server directly leaks upstream identifiers, it is not absolute proof.

## Suspected Upstream Signals

- Note: these hints only explain provider-style or compatibility-layer traits observed in the response. They do not prove the real official upstream and do not change the trust rating.
- No obvious cross-provider upstream style hints were observed.

## Target Summary

- **base_url_host**: api.anthropic.com
- **model**: claude-sonnet-4-5
- **endpoint**: primary
- **claimed_provider**: anthropic
- **claimed_api_shape**: native

## Overall Verdict

- Rating: **High Trust**
- Authenticity score: 96
- Risk score: 0
- Tags: ANTHROPIC_NATIVE_SHAPE_MATCH, EXTENDED_THINKING_MATCH

Authenticity score measures how well the endpoint matches the claimed provider/API/model behavior.
Risk score measures heuristic channel-health and relay-risk symptoms.

## Evidence Score Breakdown

- `strong_passed`: 2
- `strong_failed`: 0
- `weak_failed`: 0

## Authenticity Assertions

- `anthropic_messages_shape` (strong, pass): Response matched Anthropic Messages shape. Tags: ANTHROPIC_NATIVE_SHAPE_MATCH.
- `extended_thinking_expected` (strong, pass): Expected thinking behavior was observed. Tags: EXTENDED_THINKING_MATCH.

## Heuristic Risk Profile

- Risk score: 0
- Risk tags: None
- These signals are heuristic channel-risk indicators. They can raise operational concern, but they do not by themselves prove provider forgery or unauthorized routing.
- No heuristic risk indicators were produced.

## Messages Protocol Probe

- Status: passed
- `anthropic_messages_shape` (strong, pass): Response matched Anthropic Messages shape.

## Extended Thinking Probe

- Status: passed
- `extended_thinking_expected` (strong, pass): Expected thinking behavior was observed.

## Streaming Metrics

- Not run

## Errors and Warnings

- None

## Configuration Summary

```json
{
  "endpoint": {
    "name": "primary",
    "base_url": "https://api.anthropic.com",
    "model": "claude-sonnet-4-5"
  }
}
```
