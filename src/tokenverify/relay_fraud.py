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
            title_en="Channel-Source And Compliance Misrepresentation",
            title_zh="渠道来源与合规伪装",
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
            required_sources=frozenset({"detail"}),
            required_tags=frozenset({FraudEvidenceTag.DETAIL_AUDIT_DRIFT_OBSERVED}),
            conclusion_en="Repeated-sampling drift signal observed.",
            conclusion_zh="已观察到多次采样漂移风险信号。",
            boundary_en="Single-run anomalies are not proof of pool or reverse-channel behavior.",
            boundary_zh="单次异常不能证明号池或逆向资源行为。",
        ),
        FraudScenarioDefinition(
            scenario_id="prompt_context_integrity_manipulation",
            title_en="Input / Context Integrity Manipulation",
            title_zh="输入 / Context 完整性破坏",
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
            title_en="Privacy And Instruction Leakage",
            title_zh="隐私泄漏与指令泄漏",
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
            required_sources=frozenset({"runtime", "detail", "privacy"}),
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
    if result.profile == RelayAuditProfile.FULL:
        sources.update({"general", "streaming", "schema", "privacy"})
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


def render_fraud_scenario_summary(summary: FraudScenarioSummary, *, language: str = "en") -> list[str]:
    language = "zh" if language == "zh" else "en"
    lines = ["## 欺诈场景总结" if language == "zh" else "## Fraud Scenario Summary", ""]
    for result in summary.results:
        scenario = result.scenario
        title = scenario.title_zh if language == "zh" else scenario.title_en
        status_label = "状态：" if language == "zh" else "Status:"
        conclusion_label = "结论：" if language == "zh" else "Conclusion:"
        evidence_label = "触发证据：" if language == "zh" else "Triggered evidence:"
        boundary_label = "边界：" if language == "zh" else "Boundary:"
        conclusion = scenario.conclusion_zh if language == "zh" else scenario.conclusion_en
        boundary = scenario.boundary_zh if language == "zh" else scenario.boundary_en
        lines.append(f"### {sanitize_public_relay_text(title)}")
        lines.append(f"- {status_label} {result.status.value}")
        if conclusion:
            lines.append(f"- {conclusion_label} {sanitize_public_relay_text(conclusion)}")
        if result.triggered_evidence:
            safe_evidence = ", ".join(sanitize_public_relay_text(item) for item in result.triggered_evidence)
            lines.append(f"- {evidence_label} {safe_evidence}")
        if result.safe_note:
            lines.append(f"- {conclusion_label} {sanitize_public_relay_text(result.safe_note)}")
        if boundary:
            lines.append(f"- {boundary_label} {sanitize_public_relay_text(boundary)}")
    return lines + [""]


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
