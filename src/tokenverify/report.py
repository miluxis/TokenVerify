from __future__ import annotations

import json

from tokenverify.models import AuditResult, ProbeResult, RiskTag, StreamingMetrics
from tokenverify.security import public_error_summary, sanitize_public_text
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


def render_markdown(result: AuditResult, language: str = "en") -> str:
    language = _normalize_language(language)
    lines = [
        "# TokenVerify Audit Report",
        "",
    ]
    lines.extend(_plain_language_summary(result, language))
    lines.extend(_audit_route_section("provider", "provider/model authenticity", language))
    lines.extend(_channel_risk_profile(result, language))
    lines.extend(_suspected_upstream_signals_section(result, language))
    lines.append("## Target Summary")
    for key, value in result.target_summary.items():
        if value is None:
            continue
        lines.append(f"- **{sanitize_public_text(key)}**: {sanitize_public_text(value)}")
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
    lines.extend(_dynamic_challenge_section(result))
    lines.extend(_probe_sections_for_result(result.probe_results))
    lines.extend(["", "## Errors and Warnings"])
    warnings = list(result.report_warnings)
    for probe in result.probe_results:
        warnings.extend(probe.warnings)
        warnings.extend(probe.errors)
    if result.raw_log_path is not None:
        warnings.append(f"Raw event logging enabled. Log path: `{result.raw_log_path}`")
    if warnings:
        lines.extend(f"- {_public_warning_text(warning)}" for warning in warnings)
    else:
        lines.append("- None")
    if result.raw_log_path is not None:
        lines.extend(["", "## Raw Event Log", "", f"Raw event log path: `{result.raw_log_path}`"])
    if result.extension_probe_results:
        lines.extend(["", "## Extension Probe Appendix"])
        for probe in result.extension_probe_results:
            lines.extend([f"### {sanitize_public_text(probe.name)}", f"- Status: {sanitize_public_text(probe.status)}"])
    lines.extend(
        [
            "",
            "## Configuration Summary",
            "",
            "```json",
            sanitize_public_text(json.dumps(result.redacted_config, ensure_ascii=False, indent=2, default=str)),
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def _normalize_language(language: str) -> str:
    normalized = language.strip().lower()
    if normalized not in {"en", "zh"}:
        raise ValueError("language must be en or zh")
    return normalized


def _public_warning_text(warning: str) -> str:
    if "raw logging enabled" in warning.lower() or "raw event logging enabled" in warning.lower():
        return sanitize_public_text(warning)
    return public_error_summary(warning)


def _plain_language_summary(result: AuditResult, language: str) -> list[str]:
    breakdown = result.score_breakdown
    strong_passed = int(breakdown.get("strong_passed", 0))
    strong_failed = int(breakdown.get("strong_failed", 0))
    weak_failed = int(breakdown.get("weak_failed", 0))
    neutral = int(breakdown.get("neutral", 0))

    tags = set(result.verdict.tags if result.verdict else [])

    if language == "zh":
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
        if "CROSS_PROVIDER_MODEL_LEAKED" in tags or "CROSS_PROVIDER_REASONING_LEAKED" in tags:
            lines.append("- 发现跨厂商串货或跨厂商字段泄漏，这是高优先级风险。")
        if "DEEPSEEK_REASONING_CONTENT_MISSING" in tags:
            lines.append("- 推理能力缺失：声明为 DeepSeek R1，但未检测到原生 reasoning_content 字段，疑似被路由到不支持 R1 推理能力的模型或兼容层。")
        elif strong_failed == 0:
            lines.append("- 未发现跨厂商串货、模型字段明显降级或强结构矛盾。")
        lines.append("- 黑盒检测不能 100% 证明真实上游来源；它用于发现强矛盾、明显降级和渠道风险。")
        return lines + [""]

    lines = [
        "## Plain-Language Summary",
        "",
        f"- Audit result: {result.rating.value}",
        f"- Authenticity score: {_authenticity_score_text(result)}",
        f"- Channel risk score: {_risk_score_text(result)}",
    ]
    if strong_passed:
        lines.append(f"- Found {strong_passed} strong evidence items supporting the claim.")
    if strong_failed:
        lines.append(f"- Found {strong_failed} strong evidence items contradicting the claim; review the model or channel configuration first.")
    if weak_failed:
        lines.append(f"- Found {weak_failed} channel or runtime risk signal.")
    if neutral:
        lines.append(f"- Found {neutral} informational item used only as background context.")
    if not any((strong_passed, strong_failed, weak_failed, neutral)):
        lines.append("- Not enough response evidence was collected to make a clear judgment.")
    if "CROSS_PROVIDER_MODEL_LEAKED" in tags or "CROSS_PROVIDER_REASONING_LEAKED" in tags:
        lines.append("- Cross-provider model or field leakage was observed; treat this as a high-priority risk.")
    if "DEEPSEEK_REASONING_CONTENT_MISSING" in tags:
        lines.append("- Missing reasoning capability: the endpoint claims DeepSeek R1, but native reasoning_content was not observed. It may be routed to a model or compatibility layer that does not support R1 reasoning.")
    elif strong_failed == 0:
        lines.append("- No cross-provider routing, obvious model downgrade, or strong structural contradiction was observed.")
    lines.append("- Black-box checks cannot prove the true upstream source with 100% certainty; they are used to find strong contradictions, obvious downgrades, and channel risk.")
    return lines + [""]


def _audit_route_section(route: str, route_family: str, language: str) -> list[str]:
    if language == "zh":
        return [
            "## Audit Route",
            "",
            f"- Route: `{route}`",
            f"- Route family: {route_family}",
            "- 这一路径用于判断接口是否符合声明的 provider/model/API 行为。",
            "",
        ]
    return [
        "## Audit Route",
        "",
        f"- Route: `{route}`",
        f"- Route family: {route_family}",
        "- This path evaluates provider/model/API authenticity evidence.",
        "",
    ]


def _channel_risk_profile(result: AuditResult, language: str) -> list[str]:
    tags = set(result.verdict.tags if result.verdict else [])
    host = str(result.target_summary.get("base_url_host") or "")
    provider = str(result.target_summary.get("claimed_provider") or "")
    api_shape = str(result.target_summary.get("claimed_api_shape") or "")
    channel_claim = str(result.target_summary.get("claimed_channel") or "")

    official_status = "not claimed"
    if channel_claim == "official":
        official_status = "confirmed" if _is_official_host(provider, host) else "mismatch"
    elif _is_official_host(provider, host):
        official_status = "appears to match official host"

    relay_status = "no clear evidence observed"
    if "OPENAI_OFFICIAL_CHANNEL_MISMATCH" in tags or "DEEPSEEK_OFFICIAL_CHANNEL_MISMATCH" in tags:
        relay_status = "confirmed"
    elif "RELAY_HEADER_SUSPECT" in tags or api_shape == "openai-compatible" and not _is_official_host(provider, host):
        relay_status = "suspected"

    cloud_status = "no clear leak observed"
    cloud_markers = []
    if "HOSTED_BY_AWS" in tags:
        cloud_markers.append("AWS/Bedrock")
    if "HOSTED_BY_AZURE" in tags:
        cloud_markers.append("Azure")
    if cloud_markers:
        cloud_status = "suspected " + " / ".join(cloud_markers)

    pool_status = "not enough samples to judge"
    if {
        "RATE_LIMIT_RELAY_SUSPECT",
        "MODEL_DRIFT_SUSPECT",
        "TTFT_VARIANCE_HIGH",
        "CONCURRENT_POOL_SUSPECT",
        "WEB_REVERSE_SUSPECT",
    } & tags:
        pool_status = "suspected risk observed"
    else:
        repeated_run_probe = _find_probe(result.probe_results, "repeated_run_variance")
        if repeated_run_probe and repeated_run_probe.status == "passed":
            pool_status = "sampled; no suspected risk observed"

    if language == "zh":
        zh = {
            "not claimed": "未声明官方直连",
            "confirmed": "确认",
            "mismatch": "不符合",
            "appears to match official host": "看起来符合官方域名",
            "no clear evidence observed": "未发现明确证据",
            "suspected": "疑似",
            "no clear leak observed": "未发现明确泄漏",
            "not enough samples to judge": "样本不足，无法判断",
            "suspected risk observed": "存在疑似风险",
            "sampled; no suspected risk observed": "已采样，未发现疑似风险",
        }
        if cloud_markers:
            cloud_status = "疑似 " + " / ".join(cloud_markers)
        else:
            cloud_status = zh[cloud_status]
        return [
            "## Channel Risk Profile",
            "",
            f"- 官方直连：{zh[official_status]}",
            f"- 中转平台：{'已确认' if relay_status == 'confirmed' else zh[relay_status]}",
            f"- 云托管渠道：{cloud_status}",
            f"- Web 逆向 / 账号池：{zh[pool_status]}",
            "- 说明：渠道画像基于域名、响应头、错误信息、模型字段和多次请求一致性；除非服务端直接泄漏上游标识，否则不能当作绝对证明。",
            "",
        ]

    return [
        "## Channel Risk Profile",
        "",
        f"- Official direct channel: {official_status}",
        f"- Relay platform: {relay_status}",
        f"- Cloud-hosted channel: {cloud_status}",
        f"- Web reverse / account pool: {pool_status}",
        "- Note: channel profiling is based on hostnames, response headers, error text, model fields, and repeated-request consistency. Unless the server directly leaks upstream identifiers, it is not absolute proof.",
        "",
    ]


def _is_official_host(provider: str, host: str) -> bool:
    official_hosts = {
        "anthropic": "api.anthropic.com",
        "openai": "api.openai.com",
        "deepseek": "api.deepseek.com",
    }
    return official_hosts.get(provider) == host


def _suspected_upstream_signals_section(result: AuditResult, language: str) -> list[str]:
    if language == "zh":
        lines = [
            "## Suspected Upstream Signals / 疑似上游特征",
            "",
            "- 说明：这些线索只解释响应里出现的厂商风格或兼容层特征，不能证明真实官方上游，且不改变可信度评分。",
        ]
    else:
        lines = [
            "## Suspected Upstream Signals",
            "",
            "- Note: these hints only explain provider-style or compatibility-layer traits observed in the response. They do not prove the real official upstream and do not change the trust rating.",
        ]
    signals = find_suspected_upstream_signals(result)
    if not signals:
        empty_text = "- 未发现明显跨厂商上游风格线索。" if language == "zh" else "- No obvious cross-provider upstream style hints were observed."
        return lines + [empty_text, ""]
    for signal in signals:
        evidence = ", ".join(sanitize_public_text(item) for item in signal.evidence) if signal.evidence else "observed response metadata"
        if language == "zh":
            lines.append(f"- {sanitize_public_text(signal.style)}：{sanitize_public_text(signal.auxiliary_label)}。观察依据：{evidence}。")
        else:
            style = _upstream_style_text(signal.style, language)
            auxiliary_label = _auxiliary_label_text(signal.auxiliary_label, language)
            lines.append(f"- {sanitize_public_text(style)}: {sanitize_public_text(auxiliary_label)}. Evidence: {evidence}.")
    return lines + [""]


def _upstream_style_text(style: str, language: str) -> str:
    if language == "zh":
        return style
    return {
        "疑似 Claude/Anthropic 风格上游或兼容层": "suspected Claude/Anthropic-style upstream or compatibility layer",
        "疑似 OpenAI 风格上游或兼容层": "suspected OpenAI-style upstream or compatibility layer",
        "疑似 DeepSeek/R1 风格上游或兼容层": "suspected DeepSeek/R1-style upstream or compatibility layer",
        "未建模厂商风格线索": "unmodeled provider-style clue",
    }.get(style, style)


def _auxiliary_label_text(label: str, language: str) -> str:
    if language == "zh":
        return label
    return {
        "辅助提示": "auxiliary hint",
        "辅助解释": "auxiliary explanation",
    }.get(label, label)


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
    lines.extend(["", f"- Status: {sanitize_public_text(probe.status)}"])
    for item in probe.evidence:
        state = "pass" if item.passed is True else "fail" if item.passed is False else "neutral"
        lines.append(
            f"- `{sanitize_public_text(item.key)}` ({sanitize_public_text(item.weight)}, {state}): "
            f"{sanitize_public_text(item.message)}"
        )
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
        tags = f" Tags: {', '.join(sanitize_public_text(tag) for tag in item.tags)}." if item.tags else ""
        lines.append(
            f"- `{sanitize_public_text(item.key)}` ({sanitize_public_text(item.weight)}, {state}): "
            f"{sanitize_public_text(item.message)}{tags}"
        )
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
        tags = f" Tags: {', '.join(sanitize_public_text(tag) for tag in item.tags)}." if item.tags else ""
        lines.append(f"- `{sanitize_public_text(item.key)}` ({state}): {sanitize_public_text(item.message)}{tags}")
    return lines


def _dynamic_challenge_section(result: AuditResult) -> list[str]:
    lines = [
        "",
        "## Dynamic Challenge Results",
        "",
        "- Note: dynamic challenges are auxiliary evidence and do not change the trust rating or hard-fail scoring.",
    ]
    if not result.dynamic_challenge_results:
        return lines + ["- Not run"]
    for challenge in result.dynamic_challenge_results:
        lines.extend(
            [
                f"### {sanitize_public_text(challenge.challenge_id)}",
                f"- Category: {sanitize_public_text(challenge.category)}",
                f"- Level: {sanitize_public_text(challenge.level)}",
                f"- challenge_hash: {sanitize_public_text(challenge.challenge_hash)}",
                f"- Status: {sanitize_public_text(challenge.status)}",
            ]
        )
        for verifier in challenge.verifier_results:
            lines.append(
                f"- Verifier `{sanitize_public_text(verifier.type)}`: "
                f"{sanitize_public_text(verifier.status)} ({sanitize_public_text(verifier.message)})"
            )
        if challenge.warning:
            lines.append(f"- Warning: {public_error_summary(challenge.warning)}")
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
            f"- Streaming summary: {len(metrics.chunk_size_distribution)} text chunk(s) observed; raw chunk timing arrays are retained only as internal observations.",
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
