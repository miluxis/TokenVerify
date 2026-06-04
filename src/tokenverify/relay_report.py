from __future__ import annotations

from tokenverify.relay_models import RelayAuditMode, RelayAuditProfile, RelayPackSummary, RelayResult
from tokenverify.relay_safety import sanitize_public_relay_text


RISK_LABELS = {
    "en": {
        "prompt_instruction_leakage": "Prompt or instruction leakage",
        "message_rewrite": "System/developer/user message rewrite",
        "context_truncation": "Context truncation",
        "model_substitution": "Model substitution or identity mismatch",
        "streaming_integrity": "Streaming or SSE integrity anomaly",
        "schema_tool_rewrite": "JSON schema or tool-call rewriting",
        "upstream_error_leakage": "Upstream/provider error leakage",
        "latency_or_instability": "Latency variance or unstable relay behavior",
        "infrastructure_fingerprint": "Suspicious relay infrastructure fingerprint",
    },
    "zh": {
        "prompt_instruction_leakage": "提示词或指令泄漏",
        "message_rewrite": "系统/开发者/用户消息改写",
        "context_truncation": "上下文截断",
        "model_substitution": "模型替换或身份不匹配",
        "streaming_integrity": "流式或 SSE 完整性异常",
        "schema_tool_rewrite": "JSON schema 或 tool-call 改写",
        "upstream_error_leakage": "上游/provider 错误泄漏",
        "latency_or_instability": "延迟波动或运行不稳定",
        "infrastructure_fingerprint": "可疑中转基础设施指纹",
    },
}


def render_relay_markdown(result: RelayResult, language: str = "en") -> str:
    language = _normalize_language(language)
    labels = _labels(language)
    lines = [
        "# TokenVerify Relay Audit Report",
        "",
        labels["plain_language_summary"],
        "",
        f"{labels['relay_verdict']}: **{result.verdict.value}**",
        f"{labels['risk_level']}: **{result.risk_level.value}**",
        labels["plain_language_note"],
        "",
        labels["audit_route"],
        "",
        "- Route: `relay`",
        "- Route family: relay contract/safety",
        labels["audit_route_note"],
        "",
        labels["target_summary"],
        "",
        f"{labels['model']}: {sanitize_public_relay_text(result.model)}",
        f"{labels['profile']}: {result.profile.value}",
        f"{labels['mode']}: {result.mode.value}",
        f"{labels['endpoint_host']}: {sanitize_public_relay_text(result.endpoint_host)}",
        f"{labels['endpoint_hash']}: {sanitize_public_relay_text(result.endpoint_hash)}",
        f"{labels['challenge_pack']}: {_pack_summary_text(result.pack_summary, language)}",
        f"{labels['run_id']}: {sanitize_public_relay_text(result.run_id)}",
        "",
        labels["relay_verdict_section"],
        "",
        f"{labels['verdict']}: **{result.verdict.value}**",
        f"{labels['risk_level']}: **{result.risk_level.value}**",
    ]
    if result.runtime_category:
        lines.append(f"{labels['runtime_category']}: {sanitize_public_relay_text(result.runtime_category.value)}")
    lines.extend(["", labels["risk_categories"], ""])
    if result.risk_categories:
        for category in result.risk_categories:
            lines.append(f"- {_risk_label(category.value, language)} (`{category.value}`)")
    else:
        lines.append(labels["none"])
    lines.extend(["", labels["sanitized_evidence"], ""])
    for item in result.evidence:
        lines.append(f"### {sanitize_public_relay_text(item.key)}")
        lines.append(f"{labels['category']}: {_risk_label(item.category.value, language)}")
        lines.append(f"{labels['status']}: {sanitize_public_relay_text(item.status)}")
        lines.append(f"{labels['summary']}: {sanitize_public_relay_text(item.summary)}")
        if item.metrics:
            safe_metrics = ", ".join(
                f"{sanitize_public_relay_text(key)}={sanitize_public_relay_text(value)}"
                for key, value in sorted(item.metrics.items())
            )
            lines.append(f"{labels['metrics']}: {safe_metrics}")
    if result.inconclusive_reason:
        lines.extend(
            [
                "",
                labels["inconclusive_explanation"],
                "",
                sanitize_public_relay_text(result.inconclusive_reason),
            ]
        )
    lines.extend(
        [
            "",
            labels["retest_guidance"],
            "",
            sanitize_public_relay_text(result.retest_guidance),
            "",
            labels["safety_note"],
            "",
            _safety_note(result, language),
            "",
        ]
    )
    return "\n".join(lines)


def _safety_note(result: RelayResult, language: str) -> str:
    if result.mode == RelayAuditMode.LIVE:
        if result.profile == RelayAuditProfile.STREAMING:
            return (
                "Live mode made only the approved minimal streaming/SSE integrity request."
                if language == "en"
                else "Live 模式只发送了获批的最小 streaming/SSE 完整性请求。"
            )
        if result.profile == RelayAuditProfile.SCHEMA:
            return (
                "Live mode made only the approved minimal schema/tool preservation request."
                if language == "en"
                else "Live 模式只发送了获批的最小 schema/tool 保真请求。"
            )
        if result.profile == RelayAuditProfile.PRIVACY:
            return (
                "Live mode made only the approved minimal privacy contract request."
                if language == "en"
                else "Live 模式只发送了获批的最小隐私契约请求。"
            )
        if result.profile == RelayAuditProfile.FULL:
            return (
                "Full profile combines multiple approved checks. A pass means this endpoint satisfied the bounded "
                "checks in this run, not that all relay risks are impossible. Serial execution can make timeout "
                "delays add up across subprofiles when a relay is slow or unavailable."
                if language == "en"
                else "Full profile 会串行组合多个获批检查。Pass 只表示该端点通过了本次有限范围内的公开检查，不代表所有 relay 风险都不存在。若目标 relay 很慢或不可用，串行执行会让超时延迟在线性叠加。"
            )
        return (
            "Live mode made only the approved minimal general connectivity request."
            if language == "en"
            else "Live 模式只发送了获批的最小 general 连通性请求。"
        )
    return (
        "Fake-run mode was deterministic and no live network request was made."
        if language == "en"
        else "Fake-run 为确定性演示，未发送真实网络请求。"
    )


def _pack_summary_text(summary: RelayPackSummary, language: str) -> str:
    parts = [summary.label]
    if summary.basename:
        parts.append(f"{'File' if language == 'en' else '文件'}: {summary.basename}")
    if summary.pack_id:
        parts.append(f"ID: {summary.pack_id}")
    if summary.version:
        parts.append(f"{'Version' if language == 'en' else '版本'}: {summary.version}")
    if summary.pack_hash:
        parts.append(f"{'Hash' if language == 'en' else '哈希'}: {summary.pack_hash}")
    if summary.profiles:
        parts.append(f"{'Profiles' if language == 'en' else 'Profiles'}: {', '.join(summary.profiles)}")
    if summary.categories:
        parts.append(f"{'Categories' if language == 'en' else 'Categories'}: {', '.join(summary.categories)}")
    if summary.challenge_count:
        parts.append(f"{'Challenges' if language == 'en' else 'Challenges'}: {summary.challenge_count}")
    for intent in summary.public_intents:
        parts.append(f"{'Intent' if language == 'en' else 'Intent'}: {intent}")
    return sanitize_public_relay_text(" | ".join(parts))


def _normalize_language(language: str) -> str:
    normalized = language.strip().lower()
    if normalized in {"en", "zh"}:
        return normalized
    raise ValueError("language must be en or zh")


def _labels(language: str) -> dict[str, str]:
    if language == "zh":
        return {
            "plain_language_summary": "## 通俗摘要",
            "relay_verdict": "- Relay verdict",
            "risk_level": "- 风险等级",
            "plain_language_note": "- 黑盒 relay 检查不能 100% 证明真实上游；这份报告只展示脱敏后的契约级证据。",
            "audit_route": "## Audit Route",
            "audit_route_note": "- 这一路径用于判断 relay 的契约、安全与脱敏行为。",
            "target_summary": "## 目标摘要",
            "model": "- 模型",
            "profile": "- Profile",
            "mode": "- 模式",
            "endpoint_host": "- Endpoint host",
            "endpoint_hash": "- Endpoint hash",
            "challenge_pack": "- Challenge pack",
            "run_id": "- Run ID",
            "relay_verdict_section": "## Relay 结论",
            "verdict": "- Verdict",
            "runtime_category": "- Runtime category",
            "risk_categories": "## 风险类别",
            "none": "- 无",
            "sanitized_evidence": "## 脱敏证据",
            "category": "- 类别",
            "status": "- 状态",
            "summary": "- 摘要",
            "metrics": "- 指标",
            "inconclusive_explanation": "## 无法判定说明",
            "retest_guidance": "## 复测建议",
            "safety_note": "## 安全说明",
        }
    return {
        "plain_language_summary": "## Plain-Language Summary",
        "relay_verdict": "- Relay verdict",
        "risk_level": "- Risk level",
        "plain_language_note": "- Black-box relay checks cannot prove the true upstream with certainty; this report shows sanitized contract-level evidence only.",
        "audit_route": "## Audit Route",
        "audit_route_note": "- This path evaluates relay contract, safety, and sanitization behavior.",
        "target_summary": "## Target Summary",
        "model": "- Model",
        "profile": "- Profile",
        "mode": "- Mode",
        "endpoint_host": "- Endpoint host",
        "endpoint_hash": "- Endpoint hash",
        "challenge_pack": "- Challenge pack",
        "run_id": "- Run ID",
        "relay_verdict_section": "## Relay Verdict",
        "verdict": "- Verdict",
        "runtime_category": "- Runtime category",
        "risk_categories": "## Risk Categories",
        "none": "- None",
        "sanitized_evidence": "## Sanitized Evidence",
        "category": "- Category",
        "status": "- Status",
        "summary": "- Summary",
        "metrics": "- Metrics",
        "inconclusive_explanation": "## Inconclusive Explanation",
        "retest_guidance": "## Retest Guidance",
        "safety_note": "## Safety Note",
    }


def _risk_label(category: str, language: str) -> str:
    return RISK_LABELS[language][category]
