from __future__ import annotations

from tokenverify.relay_fraud import (
    collect_relay_fraud_evidence,
    evaluate_fraud_scenarios,
    FraudScenarioStatus,
    render_fraud_scenario_summary,
)
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
    if result.profile == RelayAuditProfile.FULL:
        return _render_full_relay_markdown(result, language)
    return _render_technical_profile_markdown(result, language)


def _render_full_relay_markdown(result: RelayResult, language: str) -> str:
    fraud_evidence, fraud_sources = collect_relay_fraud_evidence(result)
    fraud_summary = evaluate_fraud_scenarios(fraud_evidence, available_sources=fraud_sources)
    posture = _fraud_posture(result, language, fraud_summary)
    lines = [
        "# TokenVerify Relay Audit Report",
        "",
        "## 通俗结论" if language == "zh" else "## Plain-Language Conclusion",
        "",
        f"- {'总体判断' if language == 'zh' else 'Overall judgment'}：**{posture['judgment']}**",
        f"- {'风险等级' if language == 'zh' else 'Risk level'}：**{posture['risk_level']}**",
        f"- {'测评对象' if language == 'zh' else 'Target model'}：`{sanitize_public_relay_text(result.model)}`",
        f"- Endpoint：`{sanitize_public_relay_text(result.endpoint_host)}`",
        f"- Endpoint hash：`{sanitize_public_relay_text(result.endpoint_hash)}`",
        f"- {'本次 profile' if language == 'zh' else 'Profile'}：`{result.profile.value}`",
        f"- {'Challenge pack' if language == 'en' else 'Challenge pack'}：{_pack_summary_text(result.pack_summary, language)}",
        f"- {'本次结论' if language == 'zh' else 'Conclusion'}：{sanitize_public_relay_text(posture['summary'])}",
        "",
    ]
    lines.extend(render_fraud_scenario_summary(fraud_summary, language=language, report_kind="full"))
    lines.extend(_render_executed_technical_checks(result, language))
    lines.extend(_render_technical_evidence_summary(result, language))
    if result.inconclusive_reason:
        lines.extend(["", "## 无法判定说明" if language == "zh" else "## Inconclusive Explanation", ""])
        lines.append(sanitize_public_relay_text(result.inconclusive_reason))
    if result.runtime_category:
        lines.extend(["", f"- Runtime category: {sanitize_public_relay_text(result.runtime_category.value)}"])
    lines.extend(_render_method_note(language))
    return "\n".join(lines)


def _render_technical_profile_markdown(result: RelayResult, language: str) -> str:
    lines = [
        "# TokenVerify Relay Technical Profile Report",
        "",
        "## 技术检查结果" if language == "zh" else "## Technical Result",
        "",
        f"- Profile: {result.profile.value}",
        f"- Mode: {result.mode.value}",
        f"- Verdict: **{result.verdict.value}**",
        f"- Risk level: **{result.risk_level.value}**",
        f"- Target model: `{sanitize_public_relay_text(result.model)}`",
        f"- Endpoint: `{sanitize_public_relay_text(result.endpoint_host)}`",
        f"- Endpoint hash: `{sanitize_public_relay_text(result.endpoint_hash)}`",
        f"- Challenge pack: {_pack_summary_text(result.pack_summary, language)}",
        "",
    ]
    if result.runtime_category:
        lines.append(f"- Runtime category: {sanitize_public_relay_text(result.runtime_category.value)}")
        lines.append("")
    lines.extend(_render_supported_scenario_scope(result.profile, language))
    lines.extend(_render_sanitized_technical_evidence(result, language))
    lines.extend(["", "## 安全说明" if language == "zh" else "## Safety Note", "", _safety_note(result, language)])
    if result.inconclusive_reason:
        lines.extend(["", "## 无法判定说明" if language == "zh" else "## Inconclusive Explanation", ""])
        lines.append(sanitize_public_relay_text(result.inconclusive_reason))
    lines.extend(_render_method_note(language))
    return "\n".join(lines)


def _fraud_posture(result: RelayResult, language: str, fraud_summary=None) -> dict[str, str]:
    scenario_attention = False
    if fraud_summary is not None:
        scenario_attention = any(
            item.status in {FraudScenarioStatus.DETECTED, FraudScenarioStatus.SUSPICIOUS}
            for item in fraud_summary.results
        )
    if result.verdict.value == "fail":
        judgment = "Fail"
        risk_level = "high"
    elif scenario_attention:
        judgment = "Suspicious"
        risk_level = "medium"
    elif result.verdict.value == "suspicious":
        judgment = "Suspicious"
        risk_level = "medium"
    elif result.verdict.value == "inconclusive":
        judgment = "Inconclusive"
        risk_level = "unknown"
    else:
        judgment = "Pass"
        risk_level = "low"
    if language == "zh":
        summary = (
            "该 endpoint 通过了已执行的基础连通性、streaming、schema、privacy、security 与 context 检查。"
            if judgment == "Pass"
            else "该 endpoint 在本次检查中出现了需要关注的场景信号；请查看下方关键证据。"
        )
    else:
        summary = (
            "This endpoint passed the executed connectivity, streaming, schema, privacy, security, and context checks."
            if judgment == "Pass"
            else "This endpoint produced scenario signals that need attention; review the evidence below."
        )
    return {"judgment": judgment, "risk_level": risk_level, "summary": summary}


def _render_executed_technical_checks(result: RelayResult, language: str) -> list[str]:
    profile_metrics = _full_profile_metrics(result)
    labels = {
        "general": "General connectivity",
        "streaming": "Streaming integrity",
        "schema": "Schema / tool calling",
        "privacy": "Privacy contract",
        "security": "Security boundary",
        "context": "Context retention",
    }
    lines = ["", "## 已执行技术检查" if language == "zh" else "## Executed Technical Checks", ""]
    for profile, label in labels.items():
        status = profile_metrics.get(profile, {}).get("verdict", "not_run")
        lines.append(f"- {label}：{sanitize_public_relay_text(status)}")
    return lines


def _render_technical_evidence_summary(result: RelayResult, language: str) -> list[str]:
    profile_metrics = _full_profile_metrics(result)
    lines = ["", "## 技术证据摘要" if language == "zh" else "## Technical Evidence Summary", ""]
    lines.extend(["| Profile | Result | Key Evidence |", "|---|---|---|"])
    for profile in ("general", "streaming", "schema", "privacy", "security", "context"):
        metrics = profile_metrics.get(profile, {})
        verdict = sanitize_public_relay_text(metrics.get("verdict", "not_run"))
        evidence_keys = metrics.get("evidence_keys") or []
        key_evidence = _summarize_evidence_keys(profile, evidence_keys)
        lines.append(f"| {profile} | {verdict} | {sanitize_public_relay_text(key_evidence)} |")
    return lines


def _render_sanitized_technical_evidence(result: RelayResult, language: str) -> list[str]:
    labels = _labels(language)
    lines = ["", labels["sanitized_evidence"], ""]
    if result.runtime_category:
        lines.append(f"{labels['runtime_category']}: {sanitize_public_relay_text(result.runtime_category.value)}")
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
    return lines


def _render_supported_scenario_scope(profile: RelayAuditProfile, language: str) -> list[str]:
    scope = {
        RelayAuditProfile.GENERAL: ("Basic relay connectivity", "Runtime error and channel-envelope signals"),
        RelayAuditProfile.STREAMING: ("Fake or degraded streaming", "SSE event sequence integrity"),
        RelayAuditProfile.SCHEMA: ("Schema / Tool Calling breakage", "Input or argument rewrite signals related to tool contracts"),
        RelayAuditProfile.PRIVACY: ("Privacy leakage", "Marker leakage and upstream error disclosure"),
        RelayAuditProfile.SECURITY: ("Prompt-security boundary", "Prompt extraction and override-risk signals"),
        RelayAuditProfile.CONTEXT: ("Context retention", "Context anchor loss and rewrite signals"),
    }.get(profile, ("Technical relay behavior", "Run the default full profile for the scenario-first fraud report"))
    lines = ["", "## 支撑场景范围" if language == "zh" else "## Supported Scenario Scope", ""]
    if language == "zh":
        lines.append("该技术 profile 可支撑：")
    else:
        lines.append("This technical profile can support:")
    lines.extend(["", f"- {sanitize_public_relay_text(scope[0])}", f"- {sanitize_public_relay_text(scope[1])}", ""])
    lines.append(
        "它不输出完整欺诈场景 pass/fail 结论。若要生成完整场景报告，请运行默认 full profile。"
        if language == "zh"
        else "It does not render complete fraud-scenario pass/fail conclusions. Run the default full profile for the scenario-first fraud report."
    )
    return lines


def _render_method_note(language: str) -> list[str]:
    return [
        "",
        "## 方法说明" if language == "zh" else "## Method Note",
        "",
        (
            "TokenVerify 使用黑盒探针判断 endpoint 行为是否与声明一致。它可以发现 contract breakage、channel marker、模型能力矛盾、上下文异常、隐私泄漏和流式/schema 破坏信号。它不会在没有硬证据时宣称精确上游模型身份，也不在开源版中进行账单对账或缓存重放数据库分析。"
            if language == "zh"
            else "TokenVerify uses black-box probes to judge whether endpoint behavior matches the claim. It can surface contract breakage, channel markers, model-capability contradictions, context anomalies, privacy leakage, and streaming/schema breakage signals. It does not claim exact upstream identity without hard evidence, and the open-source edition does not perform billing reconciliation or cache-replay database analysis."
        ),
        "",
    ]


def _full_profile_metrics(result: RelayResult) -> dict:
    for item in result.evidence:
        if item.key == "full_profile_composite_verdict" and isinstance(item.metrics, dict):
            return item.metrics
    return {}


def _summarize_evidence_keys(profile: str, evidence_keys) -> str:
    keys = set(evidence_keys or [])
    if profile == "general":
        return "minimal connectivity completed" if keys else "not run"
    if profile == "streaming":
        return "delta + finish observed" if keys else "not run"
    if profile == "schema":
        return "tool call preserved" if keys else "not run"
    if profile == "privacy":
        return "marker not leaked" if keys else "not run"
    if profile == "security":
        return "extraction/override probes resisted" if keys else "not run"
    if profile == "context":
        return "anchor sequence retained" if keys else "not run"
    return ", ".join(evidence_keys or []) or "not run"


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
        if result.profile == RelayAuditProfile.SECURITY:
            return (
                "Live mode made only the approved bounded prompt-security requests. This is not proof of "
                "malicious intent or complete jailbreak resistance."
                if language == "en"
                else "Live 模式只发送了获批的有限提示词安全请求。这不证明中转存在恶意，也不代表具备完整越狱防护。"
            )
        if result.profile == RelayAuditProfile.CONTEXT:
            return (
                "Live mode made only the approved bounded context-retention requests. This is not a long-context "
                "benchmark or proof that any loss is caused by the relay."
                if language == "en"
                else "Live 模式只发送了获批的有限上下文保留请求。这不是长上下文基准，也不证明任何丢失一定由 relay 造成。"
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
        (
            "Fake-run mode was deterministic and no live network request was made. Security profile output is "
            "bounded prompt-security evidence, not proof of malicious intent or complete jailbreak resistance."
            if result.profile == RelayAuditProfile.SECURITY
            else (
                "Fake-run mode was deterministic and no live network request was made. Context profile output is "
                "bounded anchor-retention evidence, not a long-context benchmark."
                if result.profile == RelayAuditProfile.CONTEXT
                else "Fake-run mode was deterministic and no live network request was made."
            )
        )
        if language == "en"
        else (
            "Fake-run 为确定性演示，未发送真实网络请求。Security profile 只提供有限的提示词安全证据，不证明中转存在恶意，也不代表具备完整越狱防护。"
            if result.profile == RelayAuditProfile.SECURITY
            else (
                "Fake-run 为确定性演示，未发送真实网络请求。Context profile 只提供有限上下文锚点保留证据，不是长上下文基准。"
                if result.profile == RelayAuditProfile.CONTEXT
                else "Fake-run 为确定性演示，未发送真实网络请求。"
            )
        )
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
