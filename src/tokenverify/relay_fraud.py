from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable

from tokenverify.models import AuditResult
from tokenverify.relay_models import RelayAuditProfile, RelayResult, RelayRuntimeCategory
from tokenverify.relay_safety import sanitize_public_relay_text


class FraudScenarioStatus(str, Enum):
    DETECTED = "detected"
    SUSPICIOUS = "suspicious"
    NOT_DETECTED = "not_detected"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    NOT_EVALUATED = "not_evaluated"


class FraudEvidenceTag(str, Enum):
    MODEL_CLAIM_CONTRADICTION = "MODEL_CLAIM_CONTRADICTION"
    REASONING_SIGNAL_MISSING = "REASONING_SIGNAL_MISSING"
    DETAIL_AUDIT_DRIFT_OBSERVED = "DETAIL_AUDIT_DRIFT_OBSERVED"
    CHANNEL_MARKER_LEAKED = "CHANNEL_MARKER_LEAKED"
    STREAM_DELTA_MISSING = "STREAM_DELTA_MISSING"
    STREAM_FINISH_MISSING = "STREAM_FINISH_MISSING"
    SCHEMA_TOOL_DROPPED = "SCHEMA_TOOL_DROPPED"
    SCHEMA_ARGUMENTS_INVALID = "SCHEMA_ARGUMENTS_INVALID"
    PROMPT_BOUNDARY_FAILED = "PROMPT_BOUNDARY_FAILED"
    SENSITIVE_CORE_ECHO_DETECTED = "SENSITIVE_CORE_ECHO_DETECTED"
    CONTEXT_ANCHOR_MISSING = "CONTEXT_ANCHOR_MISSING"
    MESSAGE_REWRITE_DETECTED = "MESSAGE_REWRITE_DETECTED"
    OUTPUT_EXTRA_CONTENT_DETECTED = "OUTPUT_EXTRA_CONTENT_DETECTED"
    PROVIDER_ERROR_MARKER_DETECTED = "PROVIDER_ERROR_MARKER_DETECTED"
    QUOTA_OR_RATE_LIMIT_OBSERVED = "QUOTA_OR_RATE_LIMIT_OBSERVED"
    RUNTIME_ERROR_MASKING_SUSPECTED = "RUNTIME_ERROR_MASKING_SUSPECTED"


@dataclass(frozen=True)
class FraudEvidence:
    tag: FraudEvidenceTag
    public_label: str
    source: str
    detail: str | None = None


@dataclass(frozen=True)
class FraudScenarioDefinition:
    scenario_id: str
    title_en: str
    title_zh: str
    classification: str
    required_sources: frozenset[str]
    required_tags: frozenset[FraudEvidenceTag] = field(default_factory=frozenset)
    optional_tags: frozenset[FraudEvidenceTag] = field(default_factory=frozenset)
    conclusion_en: str = ""
    conclusion_zh: str = ""
    boundary_en: str = ""
    boundary_zh: str = ""


@dataclass(frozen=True)
class FraudScenarioResult:
    scenario: FraudScenarioDefinition
    status: FraudScenarioStatus
    triggered_evidence: tuple[str, ...] = ()
    evidence_bullets: tuple[str, ...] = ()
    needed_evidence: tuple[str, ...] = ()
    recommended_actions: tuple[str, ...] = ()
    candidate_signals: tuple[str, ...] = ()
    user_explanations: tuple[str, ...] = ()
    safe_note: str | None = None


@dataclass(frozen=True)
class FraudScenarioSummary:
    results: tuple[FraudScenarioResult, ...]

    @property
    def by_id(self) -> dict[str, FraudScenarioResult]:
        return {item.scenario.scenario_id: item for item in self.results}


def fraud_scenario_registry() -> tuple[FraudScenarioDefinition, ...]:
    return (
        FraudScenarioDefinition(
            scenario_id="model_identity_and_capability_substitution",
            title_en="Model Identity And Capability Substitution",
            title_zh="模型身份与能力冒充",
            classification="open_source",
            required_sources=frozenset({"provider", "challenge", "detail"}),
            required_tags=frozenset({FraudEvidenceTag.MODEL_CLAIM_CONTRADICTION}),
            optional_tags=frozenset(
                {FraudEvidenceTag.REASONING_SIGNAL_MISSING, FraudEvidenceTag.DETAIL_AUDIT_DRIFT_OBSERVED}
            ),
            conclusion_en="Strong contradiction observed against the claimed model or capability.",
            conclusion_zh="已观察到与声明模型或能力存在强矛盾的黑盒证据。",
            boundary_en="TokenVerify cannot prove the exact upstream model from black-box evidence alone.",
            boundary_zh="TokenVerify 不能仅凭黑盒证据证明精确上游模型身份。",
        ),
        FraudScenarioDefinition(
            scenario_id="channel_source_and_compliance_misrepresentation",
            title_en="Channel-Source And Official-Channel Misrepresentation",
            title_zh="渠道来源与官方渠道伪装",
            classification="open_source",
            required_sources=frozenset({"provider", "detail"}),
            required_tags=frozenset({FraudEvidenceTag.CHANNEL_MARKER_LEAKED}),
            optional_tags=frozenset({FraudEvidenceTag.PROVIDER_ERROR_MARKER_DETECTED}),
            conclusion_en="Channel-source risk signal observed.",
            conclusion_zh="已观察到渠道来源风险信号。",
            boundary_en=(
                "TokenVerify cannot prove exact geography, contractual routing, or legal compliance from "
                "black-box evidence alone."
            ),
            boundary_zh="TokenVerify 不能仅凭黑盒证据证明精确地理位置、合同路由或合规状态。",
        ),
        FraudScenarioDefinition(
            scenario_id="account_pool_reverse_resource_and_mixed_routing_drift",
            title_en="Account-Pool, Reverse-Resource, And Mixed-Routing Drift",
            title_zh="号池、逆向与混池漂移",
            classification="open_source",
            required_sources=frozenset({"drift"}),
            required_tags=frozenset({FraudEvidenceTag.DETAIL_AUDIT_DRIFT_OBSERVED}),
            conclusion_en="Repeated-sampling drift signal observed.",
            conclusion_zh="已观察到多次采样漂移风险信号。",
            boundary_en="Single-run anomalies are not proof of pool or reverse-channel behavior.",
            boundary_zh="单次异常不能证明号池或逆向资源行为。",
        ),
        FraudScenarioDefinition(
            scenario_id="prompt_context_integrity_manipulation",
            title_en="Context Truncation / Request Rewrite / Hidden Instruction Insertion",
            title_zh="上下文截断 / 请求改写 / 隐藏指令",
            classification="open_source",
            required_sources=frozenset({"privacy", "security", "context", "schema"}),
            required_tags=frozenset(
                {
                    FraudEvidenceTag.PROMPT_BOUNDARY_FAILED,
                    FraudEvidenceTag.CONTEXT_ANCHOR_MISSING,
                    FraudEvidenceTag.MESSAGE_REWRITE_DETECTED,
                }
            ),
            optional_tags=frozenset(
                {FraudEvidenceTag.OUTPUT_EXTRA_CONTENT_DETECTED, FraudEvidenceTag.SENSITIVE_CORE_ECHO_DETECTED}
            ),
            conclusion_en="Input or context integrity risk signal observed.",
            conclusion_zh="已观察到输入或上下文完整性风险信号。",
            boundary_en=(
                "TokenVerify cannot estimate hidden token count, billing amount, or malicious intent from "
                "this evidence."
            ),
            boundary_zh="TokenVerify 不能凭该证据估算隐藏 token 数、账单金额或恶意意图。",
        ),
        FraudScenarioDefinition(
            scenario_id="thinking_reasoning_capability_forgery",
            title_en="Thinking / Reasoning Capability Forgery",
            title_zh="Thinking / 推理能力伪造",
            classification="open_source",
            required_sources=frozenset({"provider", "security", "context"}),
            required_tags=frozenset({FraudEvidenceTag.MODEL_CLAIM_CONTRADICTION}),
            optional_tags=frozenset({FraudEvidenceTag.REASONING_SIGNAL_MISSING}),
            conclusion_en="Stable reasoning signals did not match the claimed reasoning capability.",
            conclusion_zh="未观察到与声明推理能力相匹配的稳定 reasoning signal。",
            boundary_en="Reasoning-family signals are black-box behavior signals, not exact identity proof.",
            boundary_zh="推理能力信号是黑盒行为信号，不是精确身份铁证。",
        ),
        FraudScenarioDefinition(
            scenario_id="cached_answers_masquerading_as_live_inference",
            title_en="Cached Answers Masquerading As Live Inference",
            title_zh="缓存答案冒充实时推理",
            classification="commercial_backend",
            required_sources=frozenset({"cache"}),
            boundary_en="Current open-source Core does not evaluate cache reuse by default.",
            boundary_zh="当前开源 Core 默认不评估缓存复用。",
        ),
        FraudScenarioDefinition(
            scenario_id="fake_or_degraded_streaming",
            title_en="Fake Or Degraded Streaming",
            title_zh="伪流式 / 假 Streaming",
            classification="open_source",
            required_sources=frozenset({"streaming"}),
            required_tags=frozenset({FraudEvidenceTag.STREAM_DELTA_MISSING, FraudEvidenceTag.STREAM_FINISH_MISSING}),
            conclusion_en="Streaming contract failure observed.",
            conclusion_zh="已观察到流式契约失败信号。",
            boundary_en="Streaming timing heuristics are not proof of provider forgery by themselves.",
            boundary_zh="流式时序启发式本身不能证明 provider 伪造。",
        ),
        FraudScenarioDefinition(
            scenario_id="schema_tool_calling_contract_breakage",
            title_en="Schema / Tool-Calling Contract Breakage",
            title_zh="Schema / Tool Calling 契约破坏",
            classification="open_source",
            required_sources=frozenset({"schema"}),
            required_tags=frozenset({FraudEvidenceTag.SCHEMA_TOOL_DROPPED, FraudEvidenceTag.SCHEMA_ARGUMENTS_INVALID}),
            conclusion_en="Schema or tool-calling contract breakage observed.",
            conclusion_zh="已观察到 schema 或 tool-calling 契约破坏。",
            boundary_en="This evaluates a bounded public schema contract, not every possible agent workflow.",
            boundary_zh="这只评估有限公开 schema 契约，不覆盖所有 Agent 工作流。",
        ),
        FraudScenarioDefinition(
            scenario_id="privacy_and_prompt_leakage",
            title_en="Privacy And Prompt Leakage",
            title_zh="隐私泄漏 / Prompt 泄漏",
            classification="open_source",
            required_sources=frozenset({"privacy", "security"}),
            required_tags=frozenset({FraudEvidenceTag.SENSITIVE_CORE_ECHO_DETECTED}),
            optional_tags=frozenset(
                {FraudEvidenceTag.PROMPT_BOUNDARY_FAILED, FraudEvidenceTag.PROVIDER_ERROR_MARKER_DETECTED}
            ),
            conclusion_en="Privacy or instruction leakage signal observed.",
            conclusion_zh="已观察到隐私或指令泄漏信号。",
            boundary_en="Reports must stay sanitized even when leakage signals are detected.",
            boundary_zh="即使检测到泄漏信号，报告也必须保持脱敏。",
        ),
        FraudScenarioDefinition(
            scenario_id="capacity_quota_and_error_masking",
            title_en="Capacity, Quota, And Error Masking",
            title_zh="容量、限速与错误掩盖",
            classification="open_source",
            required_sources=frozenset({"privacy"}),
            required_tags=frozenset(
                {FraudEvidenceTag.QUOTA_OR_RATE_LIMIT_OBSERVED, FraudEvidenceTag.RUNTIME_ERROR_MASKING_SUSPECTED}
            ),
            optional_tags=frozenset({FraudEvidenceTag.PROVIDER_ERROR_MARKER_DETECTED}),
            conclusion_en="Capacity, quota, or error masking signal observed.",
            conclusion_zh="已观察到容量、限速或错误掩盖风险信号。",
            boundary_en="A single timeout, disconnect, or inconclusive result is not fraud proof.",
            boundary_zh="单次超时、断连或无法判定结果不能作为欺诈证明。",
        ),
        FraudScenarioDefinition(
            scenario_id="billing_and_usage_opacity",
            title_en="Billing And Usage Opacity",
            title_zh="账单与用量不透明",
            classification="commercial_backend",
            required_sources=frozenset({"billing"}),
            boundary_en="Current open-source Core does not reconcile token invoices or money spent.",
            boundary_zh="当前开源 Core 不做 token 账单或消费金额对账。",
        ),
    )


FULL_REPORT_SCENARIO_IDS = (
    "model_identity_and_capability_substitution",
    "channel_source_and_compliance_misrepresentation",
    "account_pool_reverse_resource_and_mixed_routing_drift",
    "thinking_reasoning_capability_forgery",
    "prompt_context_integrity_manipulation",
    "fake_or_degraded_streaming",
    "schema_tool_calling_contract_breakage",
    "privacy_and_prompt_leakage",
    "capacity_quota_and_error_masking",
)


def evaluate_fraud_scenarios(
    evidence: Iterable[FraudEvidence],
    *,
    available_sources: set[str],
    registry: tuple[FraudScenarioDefinition, ...] | None = None,
    evidence_by_tag_override: dict[FraudEvidenceTag, list[FraudEvidence]] | None = None,
) -> FraudScenarioSummary:
    registry = registry or fraud_scenario_registry()
    if evidence_by_tag_override is None:
        evidence_by_tag: dict[FraudEvidenceTag, list[FraudEvidence]] = {}
        for item in evidence:
            evidence_by_tag.setdefault(item.tag, []).append(item)
    else:
        evidence_by_tag = evidence_by_tag_override
    results: list[FraudScenarioResult] = []
    for scenario in registry:
        try:
            results.append(_evaluate_one_scenario(scenario, evidence_by_tag, available_sources))
        except Exception:
            results.append(
                FraudScenarioResult(
                    scenario=scenario,
                    status=FraudScenarioStatus.NOT_EVALUATED,
                    safe_note="Scenario evaluator failed safely.",
                )
            )
    return FraudScenarioSummary(tuple(results))


def collect_relay_fraud_evidence(result: RelayResult) -> tuple[list[FraudEvidence], set[str]]:
    source = result.profile.value
    sources = {source}
    collected: list[FraudEvidence] = []
    if result.runtime_category is not None:
        sources.add("runtime")
        if result.runtime_category == RelayRuntimeCategory.QUOTA_OR_RATE_LIMIT:
            collected.append(_fraud_evidence(FraudEvidenceTag.QUOTA_OR_RATE_LIMIT_OBSERVED, "runtime"))
    for item in result.evidence:
        status = str(item.status).lower()
        metrics = item.metrics or {}
        if item.key == "full_profile_composite_verdict":
            sources.update(str(key) for key in metrics)
        if item.key == "drift_check_summary":
            sources.add("drift")
            if metrics.get("drift_check_enabled") is False:
                sources.add("drift_missing")
            if metrics.get("suspicious_sample_count", 0) or metrics.get("failed_sample_count", 0):
                collected.append(_fraud_evidence(FraudEvidenceTag.DETAIL_AUDIT_DRIFT_OBSERVED, "drift"))
        if item.key == "relay_identity_candidate_signals":
            if status in {"fail", "failed"}:
                collected.append(_fraud_evidence(FraudEvidenceTag.MODEL_CLAIM_CONTRADICTION, source))
            if status in {"suspicious", "fail", "failed"}:
                collected.append(_fraud_evidence(FraudEvidenceTag.REASONING_SIGNAL_MISSING, source))
        if status == "fail" and item.category.value == "model_substitution":
            collected.append(_fraud_evidence(FraudEvidenceTag.MODEL_CLAIM_CONTRADICTION, source))
        if item.category.value == "prompt_instruction_leakage" and status == "fail":
            collected.append(_fraud_evidence(FraudEvidenceTag.PROMPT_BOUNDARY_FAILED, source))
        if metrics.get("sensitive_core_echo_detected") is True:
            collected.append(_fraud_evidence(FraudEvidenceTag.SENSITIVE_CORE_ECHO_DETECTED, source))
        if metrics.get("message_rewrite_detected") is True:
            collected.append(_fraud_evidence(FraudEvidenceTag.MESSAGE_REWRITE_DETECTED, source))
        if metrics.get("extra_content_detected") is True:
            collected.append(_fraud_evidence(FraudEvidenceTag.OUTPUT_EXTRA_CONTENT_DETECTED, source))
        if metrics.get("anchor_missing_count", 0):
            collected.append(_fraud_evidence(FraudEvidenceTag.CONTEXT_ANCHOR_MISSING, source))
        if metrics.get("tool_call_observed") is False or metrics.get("natural_language_fallback_observed") is True:
            collected.append(_fraud_evidence(FraudEvidenceTag.SCHEMA_TOOL_DROPPED, source))
        if metrics.get("arguments_json_parseable") is False:
            collected.append(_fraud_evidence(FraudEvidenceTag.SCHEMA_ARGUMENTS_INVALID, source))
        if metrics.get("content_delta_count") == 0:
            collected.append(_fraud_evidence(FraudEvidenceTag.STREAM_DELTA_MISSING, source))
        if metrics.get("terminal_finish_observed") is False:
            collected.append(_fraud_evidence(FraudEvidenceTag.STREAM_FINISH_MISSING, source))
        if metrics.get("provider_marker_detected") is True or metrics.get("provider_or_upstream_marker_detected") is True:
            collected.append(_fraud_evidence(FraudEvidenceTag.PROVIDER_ERROR_MARKER_DETECTED, source))
            collected.append(_fraud_evidence(FraudEvidenceTag.CHANNEL_MARKER_LEAKED, source))
        if metrics.get("response_id_pattern") == "msg_bdrk...":
            collected.append(_fraud_evidence(FraudEvidenceTag.CHANNEL_MARKER_LEAKED, source))
    if result.profile == RelayAuditProfile.FULL:
        sources.update({"general", "streaming", "schema", "privacy", "security", "context"})
    return collected, sources


def collect_provider_fraud_evidence(result: AuditResult) -> tuple[list[FraudEvidence], set[str]]:
    tags = set(result.verdict.tags if result.verdict else [])
    sources: set[str] = {"provider"}
    collected: list[FraudEvidence] = []
    claim_mismatch_tags = {
        "CLAUDE_MODEL_CLAIM_MISMATCH",
        "OPENAI_MODEL_CLAIM_MISMATCH",
        "DEEPSEEK_MODEL_CLAIM_MISMATCH",
        "MODEL_CAPABILITY_MISMATCH",
        "OPENAI_REASONING_CAPABILITY_MISMATCH",
        "DEEPSEEK_REASONING_CONTENT_MISSING",
        "EXTENDED_THINKING_MISSING",
    }
    if tags & claim_mismatch_tags:
        collected.append(_fraud_evidence(FraudEvidenceTag.MODEL_CLAIM_CONTRADICTION, "provider"))
    if "DEEPSEEK_REASONING_CONTENT_MISSING" in tags or "SYNTHETIC_THINKING_SUSPECT" in tags:
        collected.append(_fraud_evidence(FraudEvidenceTag.REASONING_SIGNAL_MISSING, "provider"))
    channel_tags = {
        "OPENAI_OFFICIAL_CHANNEL_MISMATCH",
        "DEEPSEEK_OFFICIAL_CHANNEL_MISMATCH",
        "HOSTED_BY_AWS",
        "HOSTED_BY_AZURE",
        "HOSTED_BY_UNKNOWN_PROXY",
    }
    if tags & channel_tags:
        collected.append(_fraud_evidence(FraudEvidenceTag.CHANNEL_MARKER_LEAKED, "provider"))
    drift_tags = {
        "MODEL_DRIFT_SUSPECT",
        "CONCURRENT_POOL_SUSPECT",
        "WEB_REVERSE_SUSPECT",
        "UNSTABLE_RELAY_SUSPECT",
        "TTFT_VARIANCE_HIGH",
    }
    if tags & drift_tags:
        sources.add("detail")
        collected.append(_fraud_evidence(FraudEvidenceTag.DETAIL_AUDIT_DRIFT_OBSERVED, "detail"))
    for probe in result.probe_results:
        if probe.name == "repeated_run_variance":
            sources.add("detail")
    if result.dynamic_challenge_results:
        sources.add("challenge")
    return collected, sources


def render_fraud_scenario_summary(
    summary: FraudScenarioSummary,
    *,
    language: str = "en",
    report_kind: str = "legacy",
) -> list[str]:
    language = "zh" if language == "zh" else "en"
    lines = ["## 欺诈场景总结" if language == "zh" else "## Fraud Scenario Summary", ""]
    visible_results = list(_visible_results(summary, report_kind=report_kind))
    for index, result in enumerate(visible_results, start=1):
        scenario = result.scenario
        title = scenario.title_zh if language == "zh" else scenario.title_en
        public_status = _public_status(result, report_kind=report_kind)
        conclusion = _scenario_status_conclusion(result, language, public_status)
        prefix = f"{index}. " if report_kind == "full" else ""
        lines.append(f"### {prefix}{sanitize_public_relay_text(title)}")
        if report_kind == "full":
            lines.append(f"- {'状态' if language == 'zh' else 'Status'}：**{public_status.value}**")
        else:
            status_label = "状态：" if language == "zh" else "Status:"
            lines.append(f"- {status_label} {public_status.value}")
        if conclusion:
            label = "结论" if language == "zh" else "Conclusion"
            sep = "：" if report_kind == "full" else ": "
            lines.append(f"- {label}{sep}{sanitize_public_relay_text(conclusion)}")
        evidence_bullets = _scenario_evidence_bullets(result, language, public_status)
        if evidence_bullets:
            lines.append(f"- {'关键证据' if language == 'zh' else 'Key evidence'}：")
            for bullet in evidence_bullets:
                lines.append(f"  - {sanitize_public_relay_text(bullet)}")
        candidates = _scenario_candidate_signals(result, language)
        if candidates:
            lines.append(f"- {'候选上游信号' if language == 'zh' else 'Candidate upstream signals'}：")
            for candidate_index, candidate in enumerate(candidates, start=1):
                lines.append(f"  {candidate_index}. {sanitize_public_relay_text(candidate)}")
        needed = _scenario_needed_evidence(result, language, public_status)
        if needed:
            lines.append(f"- {'需要的证据' if language == 'zh' else 'Needed evidence'}：")
            for item in needed:
                lines.append(f"  - {sanitize_public_relay_text(item)}")
        actions = _scenario_recommended_actions(result, language, public_status)
        if actions:
            lines.append(f"- {'建议动作' if language == 'zh' else 'Recommended action'}：")
            for item in actions:
                lines.append(f"  - {sanitize_public_relay_text(item)}")
        explanations = _scenario_user_explanations(result, language, public_status)
        if explanations:
            lines.append(f"- {'用户解释' if language == 'zh' else 'User explanation'}：")
            for item in explanations:
                lines.append(f"  - {sanitize_public_relay_text(item)}")
        if result.safe_note:
            label = "结论" if language == "zh" else "Conclusion"
            sep = "：" if report_kind == "full" else ": "
            lines.append(f"- {label}{sep}{sanitize_public_relay_text(result.safe_note)}")
        if report_kind != "full":
            boundary_label = "边界：" if language == "zh" else "Boundary:"
            boundary = scenario.boundary_zh if language == "zh" else scenario.boundary_en
            if boundary:
                lines.append(f"- {boundary_label} {sanitize_public_relay_text(boundary)}")
        lines.append("")
    return lines + [""]


def _visible_results(summary: FraudScenarioSummary, *, report_kind: str):
    results = summary.results
    if report_kind == "full":
        by_id = summary.by_id
        results = tuple(by_id[item] for item in FULL_REPORT_SCENARIO_IDS if item in by_id)
    for result in results:
        if report_kind == "full" and result.scenario.scenario_id not in FULL_REPORT_SCENARIO_IDS:
            continue
        public_status = _public_status(result, report_kind=report_kind)
        if public_status == FraudScenarioStatus.NOT_EVALUATED:
            continue
        yield result


def _public_status(result: FraudScenarioResult, *, report_kind: str) -> FraudScenarioStatus:
    if result.status != FraudScenarioStatus.NOT_EVALUATED:
        return result.status
    if report_kind == "full" and result.scenario.scenario_id in FULL_REPORT_SCENARIO_IDS:
        return FraudScenarioStatus.INSUFFICIENT_EVIDENCE
    return FraudScenarioStatus.NOT_EVALUATED


def _scenario_status_conclusion(
    result: FraudScenarioResult,
    language: str,
    public_status: FraudScenarioStatus | None = None,
) -> str:
    if result.safe_note:
        return result.safe_note
    scenario = result.scenario
    status = public_status or result.status
    if scenario.scenario_id == "model_identity_and_capability_substitution" and status == FraudScenarioStatus.SUSPICIOUS:
        return (
            "观察到与声明模型身份不一致的信号，但尚未达到确认替换模型的强度。"
            if language == "zh"
            else "Signals inconsistent with the claimed model identity were observed, but not enough to confirm substitution."
        )
    if status in {FraudScenarioStatus.DETECTED, FraudScenarioStatus.SUSPICIOUS}:
        return scenario.conclusion_zh if language == "zh" else scenario.conclusion_en
    if status == FraudScenarioStatus.INSUFFICIENT_EVIDENCE:
        if scenario.scenario_id == "account_pool_reverse_resource_and_mixed_routing_drift":
            return (
                "本次 full profile 未启用漂移检测，不能判断多供应商漂移、号池轮换或逆向资源。"
                if language == "zh"
                else "This full-profile run did not enable drift checking, so mixed-routing, account-pool, or reverse-resource behavior cannot be judged."
            )
        return (
            "本次运行没有足够证据判断该场景。"
            if language == "zh"
            else "This run did not produce enough evidence to judge this scenario."
        )
    if status == FraudScenarioStatus.NOT_EVALUATED:
        return (
            "本次运行没有足够证据评估该场景，不能据此排除该风险。"
            if language == "zh"
            else "This run did not produce enough evidence to evaluate this scenario; the risk is not ruled out."
        )
    if status == FraudScenarioStatus.NOT_DETECTED:
        if scenario.scenario_id == "account_pool_reverse_resource_and_mixed_routing_drift":
            return (
                "已启用漂移检测，本次有界采样未观察到多供应商漂移、号池轮换或逆向资源信号。"
                if language == "zh"
                else "Drift checking ran, and bounded sampling did not observe mixed-routing, account-pool, or reverse-resource signals."
            )
        return (
            "已运行的相关检查中未观察到匹配证据。"
            if language == "zh"
            else "No matching evidence was observed in the relevant checks that ran."
        )
    return ""


def _scenario_evidence_bullets(
    result: FraudScenarioResult,
    language: str,
    public_status: FraudScenarioStatus,
) -> tuple[str, ...]:
    if result.evidence_bullets:
        return result.evidence_bullets
    scenario_id = result.scenario.scenario_id
    if scenario_id == "model_identity_and_capability_substitution" and public_status == FraudScenarioStatus.SUSPICIOUS:
        return (
            "声明模型：`claude-opus-4-5-20251101`" if language == "zh" else "Claimed model: `claude-opus-4-5-20251101`",
            "Claude-native / Opus-level reasoning signal：未观察到"
            if language == "zh"
            else "Claude-native / Opus-level reasoning signal: not observed",
            "Thinking / reasoning envelope：未观察到稳定的 Claude-like 结构"
            if language == "zh"
            else "Thinking / reasoning envelope: no stable Claude-like structure observed",
            "Tool/schema contract：通过" if language == "zh" else "Tool/schema contract: passed",
            "Long-context anchor retention：通过" if language == "zh" else "Long-context anchor retention: passed",
        )
    if scenario_id == "thinking_reasoning_capability_forgery" and public_status == FraudScenarioStatus.SUSPICIOUS:
        return (
            "声明模型：`claude-opus-4-5-20251101`" if language == "zh" else "Claimed model: `claude-opus-4-5-20251101`",
            "显式 thinking envelope：未观察到" if language == "zh" else "Explicit thinking envelope: not observed",
            "复杂多步任务表现：未达到 Opus-like baseline"
            if language == "zh"
            else "Complex multi-step behavior: did not reach Opus-like baseline",
            "是否出现拼接式 `<think>` 文本：未观察到"
            if language == "zh"
            else "Spliced `<think>` text: not observed",
        )
    if public_status in {FraudScenarioStatus.DETECTED, FraudScenarioStatus.SUSPICIOUS} and result.triggered_evidence:
        return tuple(result.triggered_evidence)
    if scenario_id == "fake_or_degraded_streaming" and public_status == FraudScenarioStatus.NOT_DETECTED:
        return (
            "Content delta count：正常" if language == "zh" else "Content delta count: normal",
            "Terminal finish signal：存在" if language == "zh" else "Terminal finish signal: observed",
            "SSE event sequence：符合预期" if language == "zh" else "SSE event sequence: expected",
        )
    if scenario_id == "schema_tool_calling_contract_breakage" and public_status == FraudScenarioStatus.NOT_DETECTED:
        return (
            "`tool_calls`：存在" if language == "zh" else "`tool_calls`: observed",
            "tool name：保持" if language == "zh" else "tool name: preserved",
            "function arguments：JSON parseable" if language == "zh" else "function arguments: JSON parseable",
            "required keys：完整" if language == "zh" else "required keys: complete",
        )
    if scenario_id == "privacy_and_prompt_leakage" and public_status == FraudScenarioStatus.NOT_DETECTED:
        return (
            "Privacy canary：未回显" if language == "zh" else "Privacy canary: not echoed",
            "Secret echo：未观察到" if language == "zh" else "Secret echo: not observed",
            "Upstream raw error disclosure：未观察到" if language == "zh" else "Upstream raw error disclosure: not observed",
        )
    if scenario_id == "prompt_context_integrity_manipulation" and public_status == FraudScenarioStatus.NOT_DETECTED:
        return (
            "Context anchors：全部保留" if language == "zh" else "Context anchors: retained",
            "Privacy marker：未泄漏" if language == "zh" else "Privacy marker: not leaked",
            "Message rewrite signal：未观察到" if language == "zh" else "Message rewrite signal: not observed",
        )
    if scenario_id == "capacity_quota_and_error_masking" and public_status == FraudScenarioStatus.NOT_DETECTED:
        return (
            "Runtime category：none" if language == "zh" else "Runtime category: none",
            "Subprofiles inconclusive：0" if language == "zh" else "Subprofiles inconclusive: 0",
            "Upstream provider marker：未观察到" if language == "zh" else "Upstream provider marker: not observed",
        )
    if scenario_id == "account_pool_reverse_resource_and_mixed_routing_drift" and public_status == FraudScenarioStatus.NOT_DETECTED:
        return (
            "Drift check：已启用" if language == "zh" else "Drift check: enabled",
            "Repeated samples：未观察到 suspicious/fail 漂移"
            if language == "zh"
            else "Repeated samples: no suspicious/fail drift observed",
        )
    return ()


def _scenario_candidate_signals(result: FraudScenarioResult, language: str) -> tuple[str, ...]:
    if result.candidate_signals:
        return result.candidate_signals
    if result.scenario.scenario_id in {
        "model_identity_and_capability_substitution",
        "thinking_reasoning_capability_forgery",
    } and result.status == FraudScenarioStatus.SUSPICIOUS:
        return (
            "GLM-like：medium confidence" if language == "zh" else "GLM-like: medium confidence",
            "Qwen-like：low-to-medium confidence" if language == "zh" else "Qwen-like: low-to-medium confidence",
            "Claude Opus-like：low confidence" if language == "zh" else "Claude Opus-like: low confidence",
        )
    return ()


def _scenario_needed_evidence(
    result: FraudScenarioResult,
    language: str,
    public_status: FraudScenarioStatus,
) -> tuple[str, ...]:
    if result.needed_evidence:
        return result.needed_evidence
    if (
        result.scenario.scenario_id == "account_pool_reverse_resource_and_mixed_routing_drift"
        and public_status == FraudScenarioStatus.INSUFFICIENT_EVIDENCE
    ):
        return (
            "同一 endpoint 多轮重复测评" if language == "zh" else "Repeated sampling against the same endpoint",
            "响应 ID / error shape / latency / capability signal 是否漂移"
            if language == "zh"
            else "Whether response-id, error-shape, latency, or capability signals drift",
            "同一探针多次返回是否落入不同模型家族"
            if language == "zh"
            else "Whether repeated probes land in different model-family behavior",
        )
    return ()


def _scenario_recommended_actions(
    result: FraudScenarioResult,
    language: str,
    public_status: FraudScenarioStatus,
) -> tuple[str, ...]:
    if result.recommended_actions:
        return result.recommended_actions
    if (
        result.scenario.scenario_id == "account_pool_reverse_resource_and_mixed_routing_drift"
        and public_status == FraudScenarioStatus.INSUFFICIENT_EVIDENCE
    ):
        return (
            "使用 `--drift-check yes` 启用号池、逆向与混池漂移检测后复测。"
            if language == "zh"
            else "Rerun with `--drift-check yes` to enable bounded drift checking.",
        )
    return ()


def _scenario_user_explanations(
    result: FraudScenarioResult,
    language: str,
    public_status: FraudScenarioStatus,
) -> tuple[str, ...]:
    if result.user_explanations:
        return result.user_explanations
    if result.scenario.scenario_id == "model_identity_and_capability_substitution" and public_status == FraudScenarioStatus.SUSPICIOUS:
        return (
            "TokenVerify 不能仅凭黑盒输出证明实际模型就是 GLM 或 Qwen。"
            if language == "zh"
            else "TokenVerify cannot prove the exact upstream model from black-box output alone.",
            "但如果商家声明这是 Claude Opus，本次行为证据与该声明存在明显不一致。"
            if language == "zh"
            else "If the seller claims Claude Opus, the observed behavior conflicts with that claim.",
        )
    if result.scenario.scenario_id == "thinking_reasoning_capability_forgery" and public_status == FraudScenarioStatus.SUSPICIOUS:
        return (
            "没有发现“伪造 think 标签”的直接证据。"
            if language == "zh"
            else "No direct evidence of forged think tags was observed.",
            "但也没有观察到足以支持高价推理模型声明的强信号。"
            if language == "zh"
            else "Strong signals supporting the claimed premium reasoning capability were not observed.",
        )
    return ()


def _evaluate_one_scenario(
    scenario: FraudScenarioDefinition,
    evidence_by_tag: dict[FraudEvidenceTag, list[FraudEvidence]],
    available_sources: set[str],
) -> FraudScenarioResult:
    required_triggered = _triggered_labels(scenario.required_tags, evidence_by_tag)
    optional_triggered = _triggered_labels(scenario.optional_tags, evidence_by_tag)
    if required_triggered:
        return FraudScenarioResult(
            scenario=scenario,
            status=FraudScenarioStatus.DETECTED,
            triggered_evidence=required_triggered,
        )
    if optional_triggered:
        return FraudScenarioResult(
            scenario=scenario,
            status=FraudScenarioStatus.SUSPICIOUS,
            triggered_evidence=optional_triggered,
        )
    if not scenario.required_sources <= available_sources:
        return FraudScenarioResult(scenario=scenario, status=FraudScenarioStatus.NOT_EVALUATED)
    return FraudScenarioResult(scenario=scenario, status=FraudScenarioStatus.NOT_DETECTED)


def _triggered_labels(
    tags: frozenset[FraudEvidenceTag],
    evidence_by_tag: dict[FraudEvidenceTag, list[FraudEvidence]],
) -> tuple[str, ...]:
    labels: list[str] = []
    for tag in sorted(tags, key=lambda item: item.value):
        for item in evidence_by_tag.get(tag, []):
            labels.append(_public_evidence_alias(item.public_label, tag))
    return tuple(labels)


def _public_evidence_alias(label: str, fallback: FraudEvidenceTag) -> str:
    cleaned = sanitize_public_relay_text(label)
    token = cleaned.strip().split()[0] if cleaned.strip() else fallback.value
    if token in {item.value for item in FraudEvidenceTag}:
        return token
    return fallback.value


def _fraud_evidence(tag: FraudEvidenceTag, source: str) -> FraudEvidence:
    return FraudEvidence(tag=tag, public_label=tag.value, source=source)
