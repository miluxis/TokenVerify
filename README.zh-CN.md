# TokenVerify

[English](README.md) | [简体中文](README.zh-CN.md)

TokenVerify 是一个黑盒 LLM 端点审计 CLI，用来检查一个接口是否符合它声明的 provider、API 形态、模型家族和渠道特征。它会把协议结构、模型字段、推理信号、流式响应指标和中转风险症状整理成 Markdown 报告。

TokenVerify 不能 100% 证明真实上游是谁。它的目标是发现强矛盾、明显能力降级和渠道风险信号，让用户更容易判断一个端点是否可信。

## 快速开始

本地开发安装：

```bash
python3 -m pip install -e ".[test]"
```

运行一次无 key / 离线配置检查：

```bash
PYTHONPATH=src python3 -m tokenverify.cli audit \
  --config examples/claude-audit.yaml \
  --endpoint primary
```

报告会自动写入 `reports/audit-[model-name]-[date].md`。如果同名报告已经存在，TokenVerify 会追加数字后缀，不会覆盖旧报告。

如果需要检查中转、逆向渠道、账号池、延迟方差或模型漂移风险，可以运行 detail audit：

```bash
PYTHONPATH=src python3 -m tokenverify.cli audit \
  --config examples/claude-openai-compatible-audit.yaml \
  --endpoint claude-openai-compatible \
  --detail-audit yes
```

`--detail-audit yes` 内部使用 8 次采样。普通用户不需要理解或选择 repeat 次数；默认 `--detail-audit no` 是快速单次检测。

报告默认使用英文解释。需要中文报告时加上：

```bash
PYTHONPATH=src python3 -m tokenverify.cli audit \
  --config examples/deepseek-compatible-audit.yaml \
  --endpoint deepseek-compatible \
  --detail-audit yes \
  --language zh
```

## 支持的检测路径

| 路径 | 示例配置 | 检查内容 |
| --- | --- | --- |
| Claude 原生 | [`examples/claude-audit.yaml`](examples/claude-audit.yaml) | Anthropic Messages 结构、Extended Thinking 行为、原生 stream 序列、错误结构。 |
| OpenAI 兼容 Claude 中转 | [`examples/claude-openai-compatible-audit.yaml`](examples/claude-openai-compatible-audit.yaml) | Chat Completions 结构、Claude 模型声明一致性、Claude thinking/version 线索、reasoning 泄漏、中转与渠道风险症状。 |
| OpenAI 兼容 OpenAI | [`examples/openai-compatible-audit.yaml`](examples/openai-compatible-audit.yaml) | OpenAI 风格 Chat Completions、模型家族一致性、reasoning 能力证据、stream 序列、官方/兼容渠道线索。 |
| DeepSeek R1 | [`examples/deepseek-compatible-audit.yaml`](examples/deepseek-compatible-audit.yaml) | DeepSeek 模型家族一致性、R1 `reasoning_content`、reasoning/content 流式顺序、官方/兼容渠道线索。 |

当前刻意不做的范围：

- Gemini、Seed、Qwen、Doubao 等 provider audit，除非先有 spec 和 implementation plan。
- JSON 输出、dashboard UI、批量 endpoint 执行、tokenizer 精确匹配审计。
- 单次 timeout、断连或 TTFT 尖峰不会被当作渠道作弊证明，只会作为运行异常或弱风险线索。

## 配置

YAML 中优先使用 `api_key_env`，不要明文写 API key：

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

常用字段可以通过 CLI 覆盖：

```bash
PYTHONPATH=src python3 -m tokenverify.cli audit \
  --config examples/claude-audit.yaml \
  --endpoint primary \
  --base-url https://relay.example.com \
  --model claude-sonnet-4-5 \
  --api-key-env ANTHROPIC_API_KEY
```

只有明确需要时才开启 raw event log：

```bash
PYTHONPATH=src python3 -m tokenverify.cli audit \
  --config examples/claude-audit.yaml \
  --endpoint primary \
  --raw-log-path reports/events.jsonl
```

报告和 raw log 会对配置中的 API key 做脱敏。

## 示例报告

- [`examples/reports/claude-native-high-trust.md`](examples/reports/claude-native-high-trust.md)
- [`examples/reports/deepseek-r1-reasoning-missing.md`](examples/reports/deepseek-r1-reasoning-missing.md)

## 报告解读

报告会区分两类结论：

- `Authenticity Assertions`：关于 provider、API 形态、模型家族、错误结构、thinking/reasoning 行为的强证据或中性证据。
- `Heuristic Risk Profile`：中转 header、合成流式输出、延迟方差、云托管线索、账号池措辞等弱渠道健康信号。

报告使用四个 rating：

- `High Trust`：协议行为和预期能力与声明相符。
- `Medium Trust`：核心行为大体匹配，但仍有缺口或模糊风险。
- `Low Trust`：存在强矛盾。
- `Inconclusive`：可靠证据不足，例如缺少 API key、认证失败、额度失败、不支持目标或网络失败。

其他重要字段：

- `authenticity_score`：0-100，来自对配置声明的强证据判断。
- `risk_score`：0-100，来自弱渠道健康启发式；它不是概率，也不是直接指控。
- `tags`：稳定标签，例如 `ANTHROPIC_NATIVE_SHAPE_MATCH`、`CROSS_PROVIDER_REASONING_LEAKED`、`DEEPSEEK_REASONING_CONTENT_MISSING`、`SYNTHETIC_STREAM_SUSPECT`。
- `Suspected Upstream Signals`：把模型字符串、物理指纹或响应字段翻译成 OpenAI 风格、Claude 风格、DeepSeek/R1 风格等辅助线索；它们不替代评分。

## CLI 退出码

`tokenverify audit` 会先写出 Markdown 报告，再返回审计结果退出码：

- `0`：检测完成，结果为 high 或 medium trust。
- `1`：检测完成，结果为 low trust。
- `2`：配置或 CLI 参数错误。
- `3`：检测完成，但结果无法判定。

无 key 或离线路径不会发送真实 provider 请求。它会生成 `Inconclusive` 报告并返回退出码 `3`。

## 安全与隐私

- 默认测试套件不会发送真实公网请求。
- Provider HTTP 测试必须使用 `httpx.MockTransport`。
- Probe 测试使用 mock observations 或本地 no-key 路径。
- Real-network 测试是 opt-in，并标记为 `real_network`。
- 报告和 raw log 会脱敏配置中的 API key。
- 不要在 issue 中发布 API key、raw event log 或客户机密。

## 开发

运行默认测试：

```bash
PYTHONPATH=src python3 -m pytest -v
```

只有在明确希望访问外部端点时，才运行 opt-in real-network 测试：

```bash
PYTHONPATH=src python3 -m pytest -v -m real_network
```

查看 CLI help：

```bash
PYTHONPATH=src python3 -m tokenverify.cli audit --help
```

Provider 和 probe 回归策略：

- 每个新增 provider 或 probe 模块都必须添加回归测试。
- Provider HTTP 行为必须使用 `httpx.MockTransport`。
- Probe 行为应使用直接 probe 输入或 mock observations。
- 默认测试必须在无公网请求的情况下通过。

## 贡献者许可协议

贡献需要接受 [Contributor License Agreement](CLA.md)。贡献者保留版权，但授予项目维护者足够的再许可权，使贡献可以在 AGPL-3.0-only 以及未来可能的商业授权路径下分发。

## 许可证

TokenVerify 使用 AGPL-3.0-only。完整文本见 [LICENSE](LICENSE)。

为了维护个人开发者、研究者和社区用户对审计逻辑的白盒信任，核心审计逻辑会继续以 AGPL-3.0-only 开放。对于无法满足 AGPL-3.0 copyleft 义务的企业环境或衍生路由系统，未来可能探索替代商业授权路径，以支持合规采用。
