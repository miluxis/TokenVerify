# TokenVerify Launch Post

## English launch post

TokenVerify is a black-box CLI for auditing whether an LLM endpoint behaves like its claimed provider, API shape, model family, and channel.

The first public preview focuses on signals that matter when users receive access through direct APIs, OpenAI-compatible relays, or model-routing platforms:

- Claude native and OpenAI-compatible Claude relay checks.
- OpenAI-compatible OpenAI checks.
- DeepSeek R1 checks, including `reasoning_content` evidence.
- Channel Risk Profile for relay, reverse-channel, account-pool, latency-variance, and model-drift symptoms.
- Suspected Upstream Signals that translate response fingerprints into OpenAI-style, Claude-style, or DeepSeek/R1-style hints.
- English reports by default, with Chinese report explanations via `--language zh`.

TokenVerify does not prove the true upstream provider with certainty. It is designed to find strong contradictions, obvious capability downgrades, and channel-risk signals.

Example reports:

- `examples/reports/claude-native-high-trust.md`
- `examples/reports/deepseek-r1-reasoning-missing.md`

License: AGPL-3.0-only. Contributions require the CLA in `CLA.md`.

Feedback wanted:

- Which provider path should be prioritized next?
- Which report wording is unclear?
- Which CLI workflow should be easier?
- What evidence would make the tool more useful for real audits?

## Chinese short version

TokenVerify 是一个黑盒 LLM 端点审计 CLI，用来检查一个接口是否符合它声明的 provider、API 形态、模型家族和渠道特征。

首个 preview 支持 Claude 原生、OpenAI 兼容 Claude 中转、OpenAI 兼容 OpenAI、DeepSeek R1，并提供 Channel Risk Profile 和 Suspected Upstream Signals。

它不能 100% 证明真实上游是谁，但可以帮助发现强矛盾、明显能力降级和渠道风险信号。

示例报告：

- `examples/reports/claude-native-high-trust.md`
- `examples/reports/deepseek-r1-reasoning-missing.md`

项目采用 AGPL-3.0-only，贡献需要接受 `CLA.md`。
