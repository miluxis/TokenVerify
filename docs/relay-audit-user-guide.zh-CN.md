# TokenVerify Relay Audit 本地测评指南

这份指南面向普通用户，用来在本地对 OpenAI-compatible 中转接口做实际测评。

Relay Audit 是黑盒契约检测工具。它能发现明显的中转风险、schema/tool 改写、streaming 异常、隐私泄漏和运行不稳定信号，但不能 100% 证明真实上游是谁，也不能把单次超时或断连当作作弊证据。

## 0. 先选命令

| 命令 | 适合的普通用户问题 |
| --- | --- |
| `tokenverify audit` | 这个端点到底像不像它声称的 provider / model，reasoning 和渠道特征是否可信？ |
| `tokenverify relay-audit` | 这个中转层有没有改写、截断、泄漏、伪流式、破坏 schema，是否适合公开对比？ |

当前版本把两个命令分开，是因为它们的证据模型、退出码语义和报告合同不同。`audit` 更像 provider/model 真实性审计，`relay-audit` 更像 relay 契约和安全审计。

## 1. 准备环境

在项目根目录安装：

```bash
python3 -m pip install -e ".[test]"
```

确认 CLI 可用：

```bash
PYTHONPATH=src python3 -m tokenverify.cli relay-audit --help
```

## 2. 先跑一次无网络 fake-run

fake-run 不会发送任何真实请求，适合确认报告生成和展示格式。

```bash
PYTHONPATH=src python3 -m tokenverify.cli relay-audit \
  --base-url https://relay.example/v1 \
  --model example-model \
  --profile general \
  --fake-run suspicious
```

报告会写入：

```text
reports/relay-audit-example-model-YYYY-MM-DD.md
```

如果同名文件已存在，会自动追加数字后缀。

## 3. 配置真实中转接口

不要把 API key 直接写进命令行。优先使用环境变量：

```bash
export RELAY_API_KEY="你的真实 key"
```

基础 live 检测：

```bash
PYTHONPATH=src python3 -m tokenverify.cli relay-audit \
  --base-url https://your-relay.example/v1 \
  --model your-model-name \
  --profile general \
  --api-key-env RELAY_API_KEY \
  --live
```

没有 `--live` 时，即使你传了 endpoint、model 和 key，也不会发送真实网络请求。

## 4. 选择测评 profile

普通用户场景表：

| Profile | 普通用户场景 |
| --- | --- |
| `general` | 先确认这个 relay 能不能正常返回兼容包络。 |
| `streaming` | 你关心流式输出是否稳定、完整、不像伪流式。 |
| `schema` | 你依赖 tool calling、function calling 或 JSON 结构，不希望 relay 把结构弄坏。 |
| `privacy` | 你担心提示词泄漏、隐藏指令回显、消息改写或上游错误暴露。 |
| `full` | 你要一次性生成综合报告，用于留档、对比或公开展示。 |

### general

最小连通性和响应包络检查。适合先确认 endpoint/key/model 是否可用。

```bash
PYTHONPATH=src python3 -m tokenverify.cli relay-audit \
  --base-url https://your-relay.example/v1 \
  --model your-model-name \
  --profile general \
  --api-key-env RELAY_API_KEY \
  --live
```

### streaming

检查 SSE/streaming 序列、content delta、finish signal 和静态 chunk-size 异常。

```bash
PYTHONPATH=src python3 -m tokenverify.cli relay-audit \
  --base-url https://your-relay.example/v1 \
  --model your-model-name \
  --profile streaming \
  --api-key-env RELAY_API_KEY \
  --live
```

### schema

检查最小 tool-call/schema 契约是否被保留，包括 tool name、arguments JSON、required keys、type/enum 和自然语言 fallback。

```bash
PYTHONPATH=src python3 -m tokenverify.cli relay-audit \
  --base-url https://your-relay.example/v1 \
  --model your-model-name \
  --profile schema \
  --api-key-env RELAY_API_KEY \
  --live
```

### privacy

检查公开 do-not-echo marker 是否泄漏、简单 `OK` 回复是否被改写、是否出现上游/provider 错误泄漏信号。

```bash
PYTHONPATH=src python3 -m tokenverify.cli relay-audit \
  --base-url https://your-relay.example/v1 \
  --model your-model-name \
  --profile privacy \
  --api-key-env RELAY_API_KEY \
  --live
```

### full

按固定顺序串行运行：

```text
general -> streaming -> schema -> privacy
```

适合一次性出综合报告。由于是串行执行，如果目标 relay 很慢，各子检查的超时会线性叠加。

```bash
PYTHONPATH=src python3 -m tokenverify.cli relay-audit \
  --base-url https://your-relay.example/v1 \
  --model your-model-name \
  --profile full \
  --api-key-env RELAY_API_KEY \
  --live
```

## 5. 使用本地私有 pack metadata

当前 Relay Audit 只读取本地私有 pack 的安全 metadata，不执行私有 prompt，也不展示私有答案。

示例：

```yaml
id: local-relay-pack
version: "2026.06"
profiles:
  - privacy
categories:
  - upstream_error_leakage
challenges:
  - id: case-001
    profile: privacy
    category: upstream_error_leakage
    public_intent: "Checks sanitized privacy behavior."
    prompt: "这里可以是私有 prompt，报告不会展示"
    expected_answer: "私有答案，报告不会展示"
```

运行：

```bash
PYTHONPATH=src python3 -m tokenverify.cli relay-audit \
  --base-url https://your-relay.example/v1 \
  --model your-model-name \
  --profile full \
  --api-key-env RELAY_API_KEY \
  --pack-path ./my_private_pack.yaml \
  --live
```

报告只会展示 pack label、id、version、hash、basename、profiles、categories、challenge count 和 public intent。

## 6. 解读 verdict

Relay Audit 使用四种 verdict：

- `pass`：本次公开契约检查通过。不是永久保证。
- `suspicious`：存在中等风险信号，例如 schema 弱异常、message rewrite、streaming 启发式异常。
- `fail`：存在明确契约失败，例如 forced tool 被丢弃、privacy marker 泄漏、凭证/完整 endpoint 被反射。
- `inconclusive`：无法判定，常见原因是认证、额度、超时、断连、网络或目标不支持。

风险等级：

- `low`
- `medium`
- `high`
- `unknown`

不要把一次 `inconclusive` 当作 relay 作弊证据。先检查 key、额度、endpoint、模型名和网络，再复测。

## 7. 退出码

- `0`：`pass` 或 `suspicious`。
- `1`：`fail`。
- `2`：命令、配置、pack metadata 或 live gate 错误。
- `3`：`inconclusive`。

自动化脚本可以用退出码区分“relay 审计失败”和“命令配置错误”。

## 8. 报告安全边界

Relay Audit 报告默认适合公开展示。报告允许展示：

- host-only endpoint；
- public endpoint hash；
- profile；
- verdict / risk level；
- sanitized evidence；
- pack 安全 metadata。

报告不会展示：

- raw API key；
- raw Authorization header；
- 完整 prompt 文本；
- 模型响应文本；
- 完整 endpoint URL；
- URL path/query/fragment；
- 本地绝对路径、用户名、工作区名；
- private challenge answer；
- private verifier logic。

## 9. 建议测评流程

推荐顺序：

1. 先跑 `fake-run suspicious`，确认报告输出路径和格式。
2. 跑 `general --live`，确认 endpoint/key/model 可用。
3. 跑 `streaming --live`，检查 SSE 行为。
4. 跑 `schema --live`，检查 tool/schema 保真。
5. 跑 `privacy --live`，检查隐私泄漏和改写。
6. 最后跑 `full --live`，生成综合报告。
7. 对 `suspicious` 或 `fail` 的目标，换时间复测一次，避免把临时故障当长期结论。

## 10. 常见问题

### 没加 `--live` 为什么不请求网络？

这是设计边界。Relay Audit 默认禁止真实网络执行，必须显式加 `--live`。

### `--api-key-env sk-...` 为什么报错？

`--api-key-env` 需要的是环境变量名，例如 `RELAY_API_KEY`，不是 key 本身。这样可以避免 key 出现在终端历史和错误输出中。

### full 很慢怎么办？

`full` 是串行组合 profile。目标 relay 慢或不可用时，多个子检查的超时会叠加。可以先分别跑 `general`、`streaming`、`schema`、`privacy` 定位问题。

当前不会做的事情：

- 不做计费金额或账单估算。
- 不做 8 次 full profile 深度循环。

### 报告里为什么没有原始模型回答？

为了防止泄漏 prompt、输出、key、header、URL、私有答案。Relay Audit 报告默认只给公开安全的 evidence 和 metrics。
