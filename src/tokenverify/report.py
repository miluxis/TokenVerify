from __future__ import annotations

import json

from tokenverify.models import AuditResult, ProbeResult, RiskTag, StreamingMetrics
from tokenverify.upstream_signals import find_suspected_upstream_signals


PROBE_TITLES = {
    "messages_protocol": "Messages Protocol Probe",
    "extended_thinking": "Extended Thinking Probe",
    "chat_completions_shape": "Chat Completions Shape Probe",
    "claude_claim_consistency": "Claude Model Claim Consistency Probe",
    "mixed_provider_consistency": "Mixed Provider Consistency Probe",
    "claude_version_thinking_capability": "Claude Version And Thinking Capability Probe",
    "reasoning_leakage": "Reasoning Leakage Probe",
    "channel_risk_observations": "Channel Risk Observations Probe",
    "repeated_run_variance": "Repeated Run Variance Probe",
    "openai_chat_completions_shape": "OpenAI Chat Completions Shape Probe",
    "openai_model_claim_consistency": "OpenAI Model Claim Consistency Probe",
    "openai_reasoning_capability": "OpenAI Reasoning Capability Probe",
    "openai_channel_risk": "OpenAI Channel Risk Probe",
    "deepseek_chat_completions_shape": "DeepSeek Chat Completions Shape Probe",
    "deepseek_model_claim_consistency": "DeepSeek Model Claim Consistency Probe",
    "deepseek_reasoning_content": "DeepSeek R1 Reasoning Content Probe",
    "deepseek_channel_risk": "DeepSeek Channel Risk Probe",
}
NATIVE_PROBE_ORDER = ("messages_protocol", "extended_thinking", "streaming_features")
OPENAI_COMPATIBLE_PROBE_ORDER = (
    "chat_completions_shape",
    "claude_claim_consistency",
    "mixed_provider_consistency",
    "claude_version_thinking_capability",
    "reasoning_leakage",
    "channel_risk_observations",
    "repeated_run_variance",
    "openai_compatible_streaming",
)
OPENAI_PROBE_ORDER = (
    "openai_chat_completions_shape",
    "openai_model_claim_consistency",
    "openai_reasoning_capability",
    "openai_channel_risk",
    "openai_compatible_streaming",
)
DEEPSEEK_PROBE_ORDER = (
    "deepseek_chat_completions_shape",
    "deepseek_model_claim_consistency",
    "deepseek_reasoning_content",
    "deepseek_channel_risk",
    "deepseek_compatible_streaming",
)


def render_markdown(result: AuditResult) -> str:
    lines = [
        "# TokenVerify Audit Report",
        "",
    ]
    lines.extend(_plain_language_summary(result))
    lines.extend(_channel_risk_profile(result))
    lines.extend(_suspected_upstream_signals_section(result))
    lines.append("## Target Summary")
    for key, value in result.target_summary.items():
        if value is None:
            continue
        lines.append(f"- **{key}**: {value}")
    lines.extend(
        [
            "",
            "## Overall Verdict",
            "",
            f"- Rating: **{result.rating.value}**",
            f"- Authenticity score: {_authenticity_score_text(result)}",
            f"- Risk score: {_risk_score_text(result)}",
            f"- Tags: {_tags_text(result)}",
            "",
            "Authenticity score measures how well the endpoint matches the claimed provider/API/model behavior.",
            "Risk score measures heuristic channel-health and relay-risk symptoms.",
            "",
            "## Evidence Score Breakdown",
        ]
    )
    for key, value in result.score_breakdown.items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(_authenticity_assertions_section(result.probe_results))
    lines.extend(_heuristic_risk_section(result))
    lines.extend(_probe_sections_for_result(result.probe_results))
    lines.extend(["", "## Errors and Warnings"])
    warnings = list(result.report_warnings)
    for probe in result.probe_results:
        warnings.extend(probe.warnings)
        warnings.extend(probe.errors)
    if result.raw_log_path is not None:
        warnings.append(f"Raw event logging enabled. Log path: `{result.raw_log_path}`")
    if warnings:
        lines.extend(f"- {warning}" for warning in warnings)
    else:
        lines.append("- None")
    if result.raw_log_path is not None:
        lines.extend(["", "## Raw Event Log", "", f"Raw event log path: `{result.raw_log_path}`"])
    if result.extension_probe_results:
        lines.extend(["", "## Extension Probe Appendix"])
        for probe in result.extension_probe_results:
            lines.extend([f"### {probe.name}", f"- Status: {probe.status}"])
    lines.extend(
        [
            "",
            "## Configuration Summary",
            "",
            "```json",
            json.dumps(result.redacted_config, ensure_ascii=False, indent=2, default=str),
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def _plain_language_summary(result: AuditResult) -> list[str]:
    breakdown = result.score_breakdown
    strong_passed = int(breakdown.get("strong_passed", 0))
    strong_failed = int(breakdown.get("strong_failed", 0))
    weak_failed = int(breakdown.get("weak_failed", 0))
    neutral = int(breakdown.get("neutral", 0))

    lines = [
        "## Plain-Language Summary",
        "",
        f"- 本次检测结果：{result.rating.value}",
        f"- 可信度分数：{_authenticity_score_text(result)}",
        f"- 渠道风险分数：{_risk_score_text(result)}",
    ]
    if strong_passed:
        lines.append(f"- 发现 {strong_passed} 条强证据支持该接口与声明相符。")
    if strong_failed:
        lines.append(f"- 发现 {strong_failed} 条强证据与声明不符，建议优先复核模型或渠道配置。")
    if weak_failed:
        lines.append(f"- 发现 {weak_failed} 条渠道或运行风险信号。")
    if neutral:
        lines.append(f"- 有 {neutral} 条信息只作为背景记录，不参与真假判断。")
    if not any((strong_passed, strong_failed, weak_failed, neutral)):
        lines.append("- 本次没有拿到足够响应证据，因此无法形成明确判断。")

    tags = set(result.verdict.tags if result.verdict else [])
    if "CROSS_PROVIDER_MODEL_LEAKED" in tags or "CROSS_PROVIDER_REASONING_LEAKED" in tags:
        lines.append("- 发现跨厂商串货或跨厂商字段泄漏，这是高优先级风险。")
    if "DEEPSEEK_REASONING_CONTENT_MISSING" in tags:
        lines.append("- 推理能力缺失：声明为 DeepSeek R1，但未检测到原生 reasoning_content 字段，疑似被路由到不支持 R1 推理能力的模型或兼容层。")
    elif strong_failed == 0:
        lines.append("- 未发现跨厂商串货、模型字段明显降级或强结构矛盾。")

    lines.append("- 黑盒检测不能 100% 证明真实上游来源；它用于发现强矛盾、明显降级和渠道风险。")
    return lines + [""]


def _channel_risk_profile(result: AuditResult) -> list[str]:
    tags = set(result.verdict.tags if result.verdict else [])
    host = str(result.target_summary.get("base_url_host") or "")
    provider = str(result.target_summary.get("claimed_provider") or "")
    api_shape = str(result.target_summary.get("claimed_api_shape") or "")
    channel_claim = str(result.target_summary.get("claimed_channel") or "")

    official_status = "未声明官方直连"
    if channel_claim == "official":
        official_status = "确认" if _is_official_host(provider, host) else "不符合"
    elif _is_official_host(provider, host):
        official_status = "看起来符合官方域名"

    relay_status = "未发现明确证据"
    if "OPENAI_OFFICIAL_CHANNEL_MISMATCH" in tags or "DEEPSEEK_OFFICIAL_CHANNEL_MISMATCH" in tags:
        relay_status = "已确认"
    elif "RELAY_HEADER_SUSPECT" in tags or api_shape == "openai-compatible" and not _is_official_host(provider, host):
        relay_status = "疑似"

    cloud_status = "未发现明确泄漏"
    cloud_markers = []
    if "HOSTED_BY_AWS" in tags:
        cloud_markers.append("AWS/Bedrock")
    if "HOSTED_BY_AZURE" in tags:
        cloud_markers.append("Azure")
    if cloud_markers:
        cloud_status = "疑似 " + " / ".join(cloud_markers)

    pool_status = "样本不足，无法判断"
    if {
        "RATE_LIMIT_RELAY_SUSPECT",
        "MODEL_DRIFT_SUSPECT",
        "TTFT_VARIANCE_HIGH",
        "CONCURRENT_POOL_SUSPECT",
        "WEB_REVERSE_SUSPECT",
    } & tags:
        pool_status = "存在疑似风险"
    else:
        repeated_run_probe = _find_probe(result.probe_results, "repeated_run_variance")
        if repeated_run_probe and repeated_run_probe.status == "passed":
            pool_status = "已采样，未发现疑似风险"

    return [
        "## Channel Risk Profile",
        "",
        f"- 官方直连：{official_status}",
        f"- 中转平台：{relay_status}",
        f"- 云托管渠道：{cloud_status}",
        f"- Web 逆向 / 账号池：{pool_status}",
        "- 说明：渠道画像基于域名、响应头、错误信息、模型字段和多次请求一致性；除非服务端直接泄漏上游标识，否则不能当作绝对证明。",
        "",
    ]


def _is_official_host(provider: str, host: str) -> bool:
    official_hosts = {
        "anthropic": "api.anthropic.com",
        "openai": "api.openai.com",
        "deepseek": "api.deepseek.com",
    }
    return official_hosts.get(provider) == host


def _suspected_upstream_signals_section(result: AuditResult) -> list[str]:
    lines = [
        "## Suspected Upstream Signals / 疑似上游特征",
        "",
        "- 说明：这些线索只解释响应里出现的厂商风格或兼容层特征，不能证明真实官方上游，且不改变可信度评分。",
    ]
    signals = find_suspected_upstream_signals(result)
    if not signals:
        return lines + ["- 未发现明显跨厂商上游风格线索。", ""]
    for signal in signals:
        evidence = ", ".join(signal.evidence) if signal.evidence else "observed response metadata"
        lines.append(f"- {signal.style}：{signal.auxiliary_label}。观察依据：{evidence}。")
    return lines + [""]


def _probe_sections_for_result(probes: list[ProbeResult]) -> list[str]:
    names = {probe.name for probe in probes}
    if names.intersection(DEEPSEEK_PROBE_ORDER[:4]):
        ordered_names = DEEPSEEK_PROBE_ORDER
    elif names.intersection(OPENAI_PROBE_ORDER[:4]):
        ordered_names = OPENAI_PROBE_ORDER
    elif names.intersection(OPENAI_COMPATIBLE_PROBE_ORDER):
        ordered_names = OPENAI_COMPATIBLE_PROBE_ORDER
    else:
        ordered_names = NATIVE_PROBE_ORDER

    lines: list[str] = []
    for name in ordered_names:
        probe = _find_probe(probes, name)
        if name == "streaming_features":
            lines.extend(_streaming_section("Streaming Metrics", probe))
        elif name == "openai_compatible_streaming":
            lines.extend(_streaming_section("OpenAI-Compatible Streaming Metrics", probe))
        elif name == "deepseek_compatible_streaming":
            lines.extend(_streaming_section("DeepSeek-Compatible Streaming Metrics", probe))
        else:
            lines.extend(_probe_section(PROBE_TITLES[name], probe))
    return lines


def _probe_section(title: str, probe: ProbeResult | None) -> list[str]:
    lines = ["", f"## {title}"]
    if probe is None:
        return lines + ["", "- Not run"]
    lines.extend(["", f"- Status: {probe.status}"])
    for item in probe.evidence:
        state = "pass" if item.passed is True else "fail" if item.passed is False else "neutral"
        lines.append(f"- `{item.key}` ({item.weight}, {state}): {item.message}")
    return lines


def _authenticity_assertions_section(probes: list[ProbeResult]) -> list[str]:
    lines = ["", "## Authenticity Assertions"]
    assertions = [
        item
        for probe in probes
        for item in probe.evidence
        if item.weight in {"strong", "neutral"}
    ]
    if not assertions:
        return lines + ["", "- No strong authenticity assertions were produced."]
    lines.append("")
    for item in assertions:
        state = "pass" if item.passed is True else "fail" if item.passed is False else "neutral"
        tags = f" Tags: {', '.join(item.tags)}." if item.tags else ""
        lines.append(f"- `{item.key}` ({item.weight}, {state}): {item.message}{tags}")
    return lines


def _heuristic_risk_section(result: AuditResult) -> list[str]:
    risk_items = [
        item
        for probe in result.probe_results
        for item in probe.evidence
        if item.weight == "weak"
    ]
    lines = [
        "",
        "## Heuristic Risk Profile",
        "",
        f"- Risk score: {_risk_score_text(result)}",
        f"- Risk tags: {_risk_tags_text(result)}",
        "- These signals are heuristic channel-risk indicators. They can raise operational concern, but they do not by themselves prove provider forgery or unauthorized routing.",
    ]
    if not risk_items:
        return lines + ["- No heuristic risk indicators were produced."]
    for item in risk_items:
        state = "pass" if item.passed is True else "fail" if item.passed is False else "neutral"
        tags = f" Tags: {', '.join(item.tags)}." if item.tags else ""
        lines.append(f"- `{item.key}` ({state}): {item.message}{tags}")
    return lines


def _streaming_section(title: str, probe: ProbeResult | None) -> list[str]:
    lines = ["", f"## {title}"]
    if probe is None or not isinstance(probe.metrics, StreamingMetrics):
        return lines + ["", "- Not run"]
    metrics = probe.metrics
    lines.extend(
        [
            "",
            f"- TTFT seconds: {metrics.ttft_seconds}",
            f"- Total latency seconds: {metrics.total_latency_seconds}",
            f"- Chunk intervals: {metrics.chunk_intervals}",
            f"- Chunk size distribution: {metrics.chunk_size_distribution}",
            f"- Estimated TPS: {metrics.estimated_tps}",
            f"- Synthetic stream heuristic: {metrics.is_synthetic_stream}",
        ]
    )
    return lines


def _authenticity_score_text(result: AuditResult) -> str:
    return str(result.verdict.authenticity_score) if result.verdict else "n/a"


def _risk_score_text(result: AuditResult) -> str:
    return str(result.verdict.risk_score) if result.verdict else "n/a"


def _tags_text(result: AuditResult) -> str:
    if not result.verdict or not result.verdict.tags:
        return "None"
    return ", ".join(result.verdict.tags)


def _risk_tags_text(result: AuditResult) -> str:
    if not result.verdict:
        return "None"
    known_risk_tags = {tag.value for tag in RiskTag}
    risk_tags = [tag for tag in result.verdict.tags if tag in known_risk_tags]
    return ", ".join(risk_tags) if risk_tags else "None"


def _find_probe(probes: list[ProbeResult], name: str) -> ProbeResult | None:
    for probe in probes:
        if probe.name == name:
            return probe
    return None
