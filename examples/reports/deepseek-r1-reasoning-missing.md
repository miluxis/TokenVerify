# TokenVerify Audit Report

## Plain-Language Summary

- 本次检测结果：低可信
- 可信度分数：39
- 渠道风险分数：0
- 发现 1 条强证据与声明不符，建议优先复核模型或渠道配置。
- 推理能力缺失：声明为 DeepSeek R1，但未检测到原生 reasoning_content 字段，疑似被路由到不支持 R1 推理能力的模型或兼容层。
- 黑盒检测不能 100% 证明真实上游来源；它用于发现强矛盾、明显降级和渠道风险。

## Channel Risk Profile

- 官方直连：未声明官方直连
- 中转平台：疑似
- 云托管渠道：未发现明确泄漏
- Web 逆向 / 账号池：样本不足，无法判断
- 说明：渠道画像基于域名、响应头、错误信息、模型字段和多次请求一致性；除非服务端直接泄漏上游标识，否则不能当作绝对证明。

## Suspected Upstream Signals / 疑似上游特征

- 说明：这些线索只解释响应里出现的厂商风格或兼容层特征，不能证明真实官方上游，且不改变可信度评分。
- 未发现明显跨厂商上游风格线索。

## Target Summary

- **base_url_host**: relay.example
- **model**: deepseek-r1
- **endpoint**: deepseek-compatible
- **claimed_provider**: deepseek
- **claimed_api_shape**: openai-compatible

## Overall Verdict

- Rating: **低可信**
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
    "base_url": "https://relay.example/v1",
    "model": "deepseek-r1"
  }
}
```
