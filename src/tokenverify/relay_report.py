from __future__ import annotations

from tokenverify.relay_fraud import (
    collect_relay_fraud_evidence,
    evaluate_fraud_scenarios,
    FraudScenarioStatus,
    render_fraud_scenario_summary,
    render_public_observed_signal,
)
from tokenverify.relay_models import RelayAuditMode, RelayAuditProfile, RelayPackSummary, RelayResult, RelayVerdict
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
    aborted = _is_full_profile_aborted(result)
    fraud_summary = None
    if not aborted:
        fraud_evidence, fraud_sources = collect_relay_fraud_evidence(result)
        fraud_summary = evaluate_fraud_scenarios(fraud_evidence, available_sources=fraud_sources)
    posture = _fraud_posture(result, language, fraud_summary)
    lines = [
        "# TokenVerify Relay Audit Report",
        "",
        "## 总体结论" if language == "zh" else "## Overall Conclusion",
        "",
        f"- {'总体判断' if language == 'zh' else 'Overall judgment'}{_label_separator(language)}**{posture['judgment']}**",
        f"- {'风险等级' if language == 'zh' else 'Risk level'}{_label_separator(language)}**{posture['risk_level']}**",
        f"- {'测评对象' if language == 'zh' else 'Target model'}{_label_separator(language)}`{sanitize_public_relay_text(result.model)}`",
        f"- Endpoint{_label_separator(language)}`{sanitize_public_relay_text(result.endpoint_host)}`",
        f"- Endpoint hash{_label_separator(language)}`{sanitize_public_relay_text(result.endpoint_hash)}`",
        f"- {'本次 profile' if language == 'zh' else 'Profile'}{_label_separator(language)}`{result.profile.value}`",
        f"- Challenge pack{_label_separator(language)}{_pack_summary_text(result.pack_summary, language)}",
    ]
    if posture["observed_signals"]:
        lines.append(f"- {'主要风险信号' if language == 'zh' else 'Main observed risk signals'}{_label_separator(language)}")
        for signal in posture["observed_signals"]:
            lines.append(f"  - {sanitize_public_relay_text(signal)}")
    if posture["absent_signals"]:
        lines.append(f"- {'本次未观察到' if language == 'zh' else 'Important signals not observed'}{_label_separator(language)}")
        for signal in posture["absent_signals"]:
            lines.append(f"  - {sanitize_public_relay_text(signal)}")
    lines.extend(
        [
            f"- {'本次结论' if language == 'zh' else 'Conclusion'}{_label_separator(language)}{sanitize_public_relay_text(posture['summary'])}",
            "",
        ]
    )
    if aborted:
        lines.extend(_render_full_aborted_notice(result, language))
    elif fraud_summary is not None:
        lines.extend(render_fraud_scenario_summary(fraud_summary, language=language, report_kind="full"))
    lines.extend(_render_technical_signal_overview(result, language))
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
    lines.extend(_render_technical_profile_signals(result, language))
    lines.extend(_render_sanitized_technical_evidence(result, language))
    lines.extend(["", "## 安全说明" if language == "zh" else "## Safety Note", "", _safety_note(result, language)])
    if result.inconclusive_reason:
        lines.extend(["", "## 无法判定说明" if language == "zh" else "## Inconclusive Explanation", ""])
        lines.append(sanitize_public_relay_text(result.inconclusive_reason))
    lines.extend(_render_method_note(language))
    return "\n".join(lines)


def _render_technical_profile_signals(result: RelayResult, language: str) -> list[str]:
    lines = ["", "## 技术信号" if language == "zh" else "## Technical Signals", ""]
    if result.profile == RelayAuditProfile.CHANNEL and result.verdict == RelayVerdict.INCONCLUSIVE:
        lines.append(
            "本次 channel profile 没有拿到可分析的 200 响应，不能据此判断渠道 marker 是否存在。"
            if language == "zh"
            else "This channel profile did not reach an analyzable 200 response, so no channel-marker conclusion can be drawn."
        )
        lines.append("")
    lines.extend(["| Evidence | Status | Concrete signals |", "|---|---|---|"])
    for item in result.evidence:
        lines.append(
            "| "
            + sanitize_public_relay_text(item.key)
            + " | "
            + sanitize_public_relay_text(item.status)
            + " | "
            + sanitize_public_relay_text(_metrics_text(item.metrics))
            + " |"
        )
    return lines


def _metrics_text(metrics: dict) -> str:
    if not metrics:
        return "not available"
    parts: list[str] = []
    for key, value in sorted(metrics.items()):
        if value is None:
            rendered = "not available"
        else:
            rendered = str(value)
        parts.append(f"{key}={rendered}")
    return ", ".join(parts)


def _fraud_posture(result: RelayResult, language: str, fraud_summary=None) -> dict[str, object]:
    if _is_full_profile_aborted(result):
        judgment_key = "inconclusive"
        risk_level = "unknown"
        summary = (
            "本次检查未连接到可分析的模型响应。请检查 Endpoint/Base URL、模型名称、API key 后重试。"
            if language == "zh"
            else "This run did not reach an analyzable model response. Check the endpoint/base URL, model name, and API key, then retry."
        )
        judgment_labels = {"en": "Inconclusive", "zh": "无法判定"}
        return {
            "judgment": judgment_labels[language],
            "judgment_key": judgment_key,
            "risk_level": risk_level,
            "summary": summary,
            "observed_signals": [],
            "absent_signals": [],
        }
    scenario_statuses = [item.status for item in fraud_summary.results] if fraud_summary is not None else []
    detected = any(item == FraudScenarioStatus.DETECTED for item in scenario_statuses)
    suspicious = any(item == FraudScenarioStatus.SUSPICIOUS for item in scenario_statuses)
    insufficient = any(item == FraudScenarioStatus.INSUFFICIENT_EVIDENCE for item in scenario_statuses)

    if detected:
        judgment_key = "high_risk_signals_observed"
        risk_level = "high"
    elif suspicious:
        judgment_key = "signals_observed"
        risk_level = "medium"
    elif result.verdict.value == "inconclusive" or insufficient:
        judgment_key = "inconclusive"
        risk_level = "unknown"
    else:
        judgment_key = "no_significant_signal"
        risk_level = "low"

    judgment_labels = {
        "en": {
            "no_significant_signal": "No significant high-risk signal observed",
            "signals_observed": "Suspicious signals observed",
            "high_risk_signals_observed": "High-risk signals observed",
            "inconclusive": "Inconclusive",
        },
        "zh": {
            "no_significant_signal": "未观察到明显高风险信号",
            "signals_observed": "观察到可疑信号",
            "high_risk_signals_observed": "观察到高风险信号",
            "inconclusive": "无法判定",
        },
    }
    observed = _main_observed_risk_signals(fraud_summary, language) if fraud_summary else []
    absent = _important_absent_signals(fraud_summary, language) if fraud_summary else []
    summary = _overall_signal_summary(judgment_key, language)
    return {
        "judgment": judgment_labels[language][judgment_key],
        "judgment_key": judgment_key,
        "risk_level": risk_level,
        "summary": summary,
        "observed_signals": observed,
        "absent_signals": absent,
    }


def _is_full_profile_aborted(result: RelayResult) -> bool:
    return result.profile == RelayAuditProfile.FULL and any(item.key == "full_profile_aborted" for item in result.evidence)


def _render_full_aborted_notice(result: RelayResult, language: str) -> list[str]:
    lines = ["", "## 连接检查未通过" if language == "zh" else "## Connectivity Check Failed", ""]
    if language == "zh":
        lines.extend(
            [
                "TokenVerify 在 general connectivity 阶段没有拿到可分析的模型响应，因此已停止 full profile 后续检查。",
                "",
                "请检查 Endpoint/Base URL、模型名称、API key 是否正确，然后重新运行。",
                "",
                "技术停止原因：`full_profile_aborted`",
            ]
        )
    else:
        lines.extend(
            [
                "TokenVerify did not receive an analyzable model response during the general connectivity stage, so later full-profile checks were skipped.",
                "",
                "Check the endpoint/base URL, model name, and API key, then rerun the command.",
                "",
                "Technical stop reason: `full_profile_aborted`",
            ]
        )
    return lines


def _main_observed_risk_signals(fraud_summary, language: str) -> list[str]:
    signals: list[str] = []
    for item in fraud_summary.results:
        if item.status not in {FraudScenarioStatus.DETECTED, FraudScenarioStatus.SUSPICIOUS}:
            continue
        source = item.observed_signals or item.triggered_evidence
        if source:
            signals.append(render_public_observed_signal(str(source[0]), language))
    return list(dict.fromkeys(signals))[:5]


def _important_absent_signals(fraud_summary, language: str) -> list[str]:
    absent: list[str] = []
    for item in fraud_summary.results:
        if item.status != FraudScenarioStatus.NOT_DETECTED:
            continue
        if item.absent_signals:
            absent.append(str(item.absent_signals[0]))
    return absent[:5]


def _overall_signal_summary(judgment_key: str, language: str) -> str:
    if language == "zh":
        if judgment_key == "high_risk_signals_observed":
            return "本次检查观察到高风险信号；主要风险来源见下方场景证据。"
        if judgment_key == "signals_observed":
            return "本次检查观察到可疑信号；建议结合下方证据复测。"
        if judgment_key == "inconclusive":
            return "本次检查未能收集足够证据形成稳定判断。"
        return "本次检查未观察到明显高风险信号。"
    if judgment_key == "high_risk_signals_observed":
        return "This run observed high-risk signals; review the scenario evidence below."
    if judgment_key == "signals_observed":
        return "This run observed suspicious signals; review the evidence below."
    if judgment_key == "inconclusive":
        return "This run did not collect enough usable evidence for a stable judgment."
    return "This run did not observe significant high-risk signals."


def _render_technical_signal_overview(result: RelayResult, language: str) -> list[str]:
    rows = _technical_signal_rows(result, language)
    lines = ["", "## 技术信号概览" if language == "zh" else "## Technical Signal Overview", ""]
    lines.extend(["| Signal | Observed | Interpretation |", "|---|---|---|"])
    for signal, observed, interpretation in rows:
        lines.append(
            f"| {sanitize_public_relay_text(signal)} | {sanitize_public_relay_text(observed)} | {sanitize_public_relay_text(interpretation)} |"
        )
    return lines


def _technical_signal_rows(result: RelayResult, language: str) -> list[tuple[str, str, str]]:
    evidence_by_key = _evidence_by_key_with_children(result)
    rows: list[tuple[str, str, str]] = []

    identity = evidence_by_key.get("identity_response_envelope") or evidence_by_key.get("identity_model_field_consistency")
    if identity:
        observed_family = (identity.metrics or {}).get("observed_model_family", "observed")
        interpretation = (
            "model-family contradiction signal observed"
            if identity.status in {"fail", "failed", "suspicious"}
            else "model-family contradiction not observed"
        )
        rows.append(("Identity fingerprint", str(observed_family), interpretation))

    channel = evidence_by_key.get("channel_response_markers") or evidence_by_key.get("channel_claim_consistency")
    if channel:
        metrics = channel.metrics or {}
        response_id_pattern = metrics.get("response_id_pattern")
        if response_id_pattern == "msg_bdrk...":
            family = response_id_pattern
            interpretation = "Bedrock-compatible response id observed"
        else:
            family = metrics.get("observed_channel_family") or "none_observed"
            interpretation = (
                "third-party channel marker observed"
                if family != "none_observed"
                else "no clear third-party channel marker observed"
            )
        rows.append(("Channel fingerprint", str(family), interpretation))

    reasoning = evidence_by_key.get("reasoning_native_signal")
    if reasoning:
        metrics = reasoning.metrics or {}
        native = metrics.get("native_reasoning_field_observed")
        expected = metrics.get("expected_reasoning_family")
        if expected == "generic":
            rows.append(("Reasoning native field", "not_applicable", "no native reasoning expectation for generic model family"))
        elif native is False and expected:
            rows.append(("Reasoning native field", "not_observed", "expected native reasoning signal was not observed"))
        elif native is False:
            rows.append(("Reasoning native field", "not_observed", "native reasoning signal was not observed"))
        elif native is True:
            rows.append(("Reasoning native field", "observed", "native reasoning signal observed"))
        else:
            rows.append(("Reasoning native field", "not_applicable", "no native reasoning expectation was established"))

    profile_metrics = _full_profile_metrics(result)
    if "identity" in profile_metrics and not identity:
        rows.append(
            (
                "Identity fingerprint",
                "checked" if profile_metrics["identity"].get("verdict") == "pass" else "degraded",
                "identity response envelope summary from full profile",
            )
        )
    if "channel" in profile_metrics and not channel:
        rows.append(
            (
                "Channel fingerprint",
                "checked" if profile_metrics["channel"].get("verdict") == "pass" else "degraded",
                "channel marker summary from full profile",
            )
        )
    if "reasoning" in profile_metrics and not reasoning:
        rows.append(
            (
                "Reasoning native field",
                "checked" if profile_metrics["reasoning"].get("verdict") == "pass" else "not_observed",
                "reasoning fingerprint summary from full profile",
            )
        )
    if "streaming" in profile_metrics:
        rows.append(
            (
                "Streaming",
                "normal" if profile_metrics["streaming"].get("verdict") == "pass" else "degraded",
                "streaming contract summary from full profile",
            )
        )
    if "schema" in profile_metrics:
        rows.append(
            (
                "Schema/tool calling",
                "preserved" if profile_metrics["schema"].get("verdict") == "pass" else "degraded",
                "schema/tool contract summary from full profile",
            )
        )
    if "security" in profile_metrics:
        rows.append(
            (
                "Security boundary",
                "normal" if profile_metrics["security"].get("verdict") == "pass" else "failed_contract",
                "prompt-security boundary summary from full profile",
            )
        )
    if "context" in profile_metrics:
        rows.append(
            (
                "Context retention",
                "preserved" if profile_metrics["context"].get("verdict") == "pass" else "degraded",
                "context anchor-retention summary from full profile",
            )
        )

    return rows or [("Relay checks", "inconclusive", "no technical signal rows were available")]


def _render_technical_evidence_summary(result: RelayResult, language: str) -> list[str]:
    profile_metrics = _full_profile_metrics(result)
    lines = ["", "## 技术证据摘要" if language == "zh" else "## Technical Evidence Summary", ""]
    lines.extend(["| Profile | Result | Key Evidence |", "|---|---|---|"])
    profiles = ("general",) if _is_full_profile_aborted(result) else (
        "general",
        "identity",
        "channel",
        "reasoning",
        "streaming",
        "schema",
        "privacy",
        "security",
        "context",
    )
    for profile in profiles:
        metrics = profile_metrics.get(profile, {})
        override = _profile_summary_override(result, profile)
        if override:
            verdict, key_evidence = override
        else:
            raw_verdict = metrics.get("verdict", "not_run")
            verdict = _public_profile_result_label(raw_verdict)
            evidence_keys = metrics.get("evidence_keys") or []
            key_evidence = _summarize_evidence_keys(profile, evidence_keys, raw_verdict)
        verdict = sanitize_public_relay_text(verdict)
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
        RelayAuditProfile.IDENTITY: (
            "Model identity and capability substitution",
            "Model claim, response envelope, and candidate upstream-family signals",
        ),
        RelayAuditProfile.CHANNEL: (
            "Channel-source and official-channel misrepresentation",
            "Official, Bedrock, Azure, OpenRouter, and proxy compatibility markers",
        ),
        RelayAuditProfile.REASONING: (
            "Thinking / reasoning capability forgery",
            "Native reasoning fields, reasoning usage, and fake public think-tag signals",
        ),
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


def _iter_evidence_with_children(result: RelayResult):
    for item in result.evidence:
        yield item
    for child in result.child_results:
        yield from _iter_evidence_with_children(child)


def _evidence_by_key_with_children(result: RelayResult) -> dict:
    evidence_by_key = {}
    for item in _iter_evidence_with_children(result):
        evidence_by_key.setdefault(item.key, item)
    return evidence_by_key


def _profile_summary_override(result: RelayResult, profile: str) -> tuple[str, str] | None:
    if profile == "channel":
        channel = _evidence_by_key_with_children(result).get("channel_response_markers")
        if channel and (channel.metrics or {}).get("response_id_pattern") == "msg_bdrk...":
            return ("observed signal", "Bedrock-compatible response id observed")
    return None


def _public_profile_result_label(verdict: str) -> str:
    if verdict in {"fail", "failed"}:
        return "high-risk signal"
    if verdict == "suspicious":
        return "suspicious signal"
    if verdict == "inconclusive":
        return "inconclusive"
    if verdict == "pass":
        return "no significant signal"
    return "not_run"


def _summarize_evidence_keys(profile: str, evidence_keys, verdict: str | None = None) -> str:
    keys = set(evidence_keys or [])
    if profile == "general":
        return "minimal connectivity completed" if keys else "not run"
    if profile == "identity":
        return "response envelope + model claim checked" if keys else "not run"
    if profile == "channel":
        return "channel marker consistency checked" if keys else "not run"
    if profile == "reasoning":
        if verdict in {"fail", "failed"}:
            if "reasoning_native_signal" in keys or "reasoning_usage_signal" in keys:
                return "native reasoning field not observed for expected reasoning family"
            if "reasoning_fake_thinking_signal" in keys:
                return "fake-thinking marker signal observed"
            return "native reasoning field not observed for expected reasoning family"
        return "reasoning capability signals checked" if keys else "not run"
    if profile == "streaming":
        return "delta + finish observed" if keys else "not run"
    if profile == "schema":
        return "tool call preserved" if keys else "not run"
    if profile == "privacy":
        return "marker not leaked" if keys else "not run"
    if profile == "security":
        if verdict in {"fail", "failed"}:
            return "prompt extraction or override boundary failed"
        return "prompt-security boundary checked" if keys else "not run"
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
        if result.profile == RelayAuditProfile.IDENTITY:
            return (
                "Live mode made only the approved bounded identity-fingerprint request. Candidate upstream-family "
                "signals are black-box indicators, not exact identity proof."
                if language == "en"
                else "Live 模式只发送了获批的有限 identity 指纹请求。候选上游家族信号是黑盒指标，不是精确身份铁证。"
            )
        if result.profile == RelayAuditProfile.CHANNEL:
            return (
                "Live mode made only the approved bounded channel-fingerprint request. Observed gateway markers "
                "are reported as sanitized channel signals."
                if language == "en"
                else "Live 模式只发送了获批的有限 channel 指纹请求。观察到的网关标记会作为脱敏渠道信号报告。"
            )
        if result.profile == RelayAuditProfile.REASONING:
            return (
                "Live mode made only the approved bounded reasoning-fingerprint request. Public `<think>` text is "
                "not treated as a native reasoning API field."
                if language == "en"
                else "Live 模式只发送了获批的有限 reasoning 指纹请求。正文 `<think>` 文本不会被当作原生 reasoning API 字段。"
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


def _label_separator(language: str) -> str:
    return "：" if language == "zh" else ": "


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
