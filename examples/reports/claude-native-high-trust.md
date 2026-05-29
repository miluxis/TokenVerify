# TokenVerify Audit Report

## Plain-Language Summary

- 本次检测结果：高可信
- 可信度分数：96
- 渠道风险分数：0
- 发现 2 条强证据支持该接口与声明相符。
- 未发现跨厂商串货、模型字段明显降级或强结构矛盾。
- 黑盒检测不能 100% 证明真实上游来源；它用于发现强矛盾、明显降级和渠道风险。

## Channel Risk Profile

- 官方直连：看起来符合官方域名
- 中转平台：未发现明确证据
- 云托管渠道：未发现明确泄漏
- Web 逆向 / 账号池：样本不足，无法判断
- 说明：渠道画像基于域名、响应头、错误信息、模型字段和多次请求一致性；除非服务端直接泄漏上游标识，否则不能当作绝对证明。

## Suspected Upstream Signals / 疑似上游特征

- 说明：这些线索只解释响应里出现的厂商风格或兼容层特征，不能证明真实官方上游，且不改变可信度评分。
- 未发现明显跨厂商上游风格线索。

## Target Summary

- **base_url_host**: api.anthropic.com
- **model**: claude-sonnet-4-5
- **endpoint**: primary
- **claimed_provider**: anthropic
- **claimed_api_shape**: native

## Overall Verdict

- Rating: **高可信**
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
