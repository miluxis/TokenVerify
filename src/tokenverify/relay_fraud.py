from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import re
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
    IDENTITY_MODEL_FIELD_CONTRADICTION = "IDENTITY_MODEL_FIELD_CONTRADICTION"
    IDENTITY_CROSS_PROVIDER_METADATA = "IDENTITY_CROSS_PROVIDER_METADATA"
    IDENTITY_ENVELOPE_OBSERVED = "IDENTITY_ENVELOPE_OBSERVED"
    CHANNEL_CHECK_COMPLETED = "CHANNEL_CHECK_COMPLETED"
    DRIFT_CHECK_COMPLETED = "DRIFT_CHECK_COMPLETED"
    REASONING_CHECK_COMPLETED = "REASONING_CHECK_COMPLETED"
    CONTEXT_CHECK_COMPLETED = "CONTEXT_CHECK_COMPLETED"
    STREAMING_CHECK_COMPLETED = "STREAMING_CHECK_COMPLETED"
    SCHEMA_CHECK_COMPLETED = "SCHEMA_CHECK_COMPLETED"
    PRIVACY_CHECK_COMPLETED = "PRIVACY_CHECK_COMPLETED"
    CAPACITY_CHECK_COMPLETED = "CAPACITY_CHECK_COMPLETED"
    IDENTITY_SELF_REPORT_MISMATCH = "IDENTITY_SELF_REPORT_MISMATCH"
    IDENTITY_CANDIDATE_UPSTREAM_SIGNAL = "IDENTITY_CANDIDATE_UPSTREAM_SIGNAL"
    REASONING_SIGNAL_MISSING = "REASONING_SIGNAL_MISSING"
    REASONING_REQUIRED_SIGNAL_MISSING = "REASONING_REQUIRED_SIGNAL_MISSING"
    REASONING_CROSS_PROVIDER_METADATA = "REASONING_CROSS_PROVIDER_METADATA"
    REASONING_FAKE_THINKING_TEXT = "REASONING_FAKE_THINKING_TEXT"
    DETAIL_AUDIT_DRIFT_OBSERVED = "DETAIL_AUDIT_DRIFT_OBSERVED"
    CHANNEL_MARKER_LEAKED = "CHANNEL_MARKER_LEAKED"
    CHANNEL_OFFICIAL_CLAIM_CONTRADICTED = "CHANNEL_OFFICIAL_CLAIM_CONTRADICTED"
    CHANNEL_MARKER_OBSERVED = "CHANNEL_MARKER_OBSERVED"
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
    UNMAPPED_TECHNICAL_RISK = "UNMAPPED_TECHNICAL_RISK"


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
    observed_signals: tuple[str, ...] = ()
    absent_signals: tuple[str, ...] = ()
    explanation: str = ""
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
            required_sources=frozenset({"identity"}),
            required_tags=frozenset(
                {
                    FraudEvidenceTag.MODEL_CLAIM_CONTRADICTION,
                    FraudEvidenceTag.IDENTITY_MODEL_FIELD_CONTRADICTION,
                    FraudEvidenceTag.IDENTITY_CROSS_PROVIDER_METADATA,
                }
            ),
            optional_tags=frozenset(
                {
                    FraudEvidenceTag.IDENTITY_SELF_REPORT_MISMATCH,
                    FraudEvidenceTag.IDENTITY_CANDIDATE_UPSTREAM_SIGNAL,
                    FraudEvidenceTag.REASONING_SIGNAL_MISSING,
                    FraudEvidenceTag.DETAIL_AUDIT_DRIFT_OBSERVED,
                }
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
            required_sources=frozenset({"channel"}),
            required_tags=frozenset(
                {
                    FraudEvidenceTag.CHANNEL_OFFICIAL_CLAIM_CONTRADICTED,
                    FraudEvidenceTag.CHANNEL_MARKER_LEAKED,
                    FraudEvidenceTag.CHANNEL_MARKER_OBSERVED,
                }
            ),
            optional_tags=frozenset(
                {
                    FraudEvidenceTag.PROVIDER_ERROR_MARKER_DETECTED,
                }
            ),
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
            required_sources=frozenset({"reasoning"}),
            required_tags=frozenset(
                {
                    FraudEvidenceTag.REASONING_REQUIRED_SIGNAL_MISSING,
                    FraudEvidenceTag.REASONING_CROSS_PROVIDER_METADATA,
                    FraudEvidenceTag.REASONING_FAKE_THINKING_TEXT,
                }
            ),
            optional_tags=frozenset(
                {
                    FraudEvidenceTag.REASONING_SIGNAL_MISSING,
                }
            ),
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
        FraudScenarioDefinition(
            scenario_id="unmapped_technical_risk_signal",
            title_en="Unmapped Technical Risk Signal",
            title_zh="未映射技术风险信号",
            classification="open_source",
            required_sources=frozenset({"unmapped"}),
            required_tags=frozenset({FraudEvidenceTag.UNMAPPED_TECHNICAL_RISK}),
            conclusion_en="A high-risk technical signal was observed but is not yet mapped to a specific fraud scenario.",
            conclusion_zh="观察到高风险技术信号，但尚未映射到具体欺诈场景。",
            boundary_en="This row should prompt follow-up mapping work.",
            boundary_zh="该行表示需要后续补充场景映射。",
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
    "unmapped_technical_risk_signal",
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
    for child in result.child_results:
        child_evidence, child_sources = collect_relay_fraud_evidence(child)
        collected.extend(child_evidence)
        sources.update(child_sources)
    if result.runtime_category is not None:
        sources.add("runtime")
        if result.runtime_category == RelayRuntimeCategory.QUOTA_OR_RATE_LIMIT:
            collected.append(
                _fraud_evidence(
                    FraudEvidenceTag.QUOTA_OR_RATE_LIMIT_OBSERVED,
                    "runtime",
                    label=f"quota or rate-limit runtime observed: runtime_category={result.runtime_category.value}",
                )
            )
    for item in result.evidence:
        status = str(item.status).lower()
        metrics = item.metrics or {}
        if item.key == "full_profile_composite_verdict":
            sources.update(str(key) for key in metrics)
        if item.key == "full_profile_orchestration":
            collected.append(
                _fraud_evidence(
                    FraudEvidenceTag.CAPACITY_CHECK_COMPLETED,
                    "runtime",
                    label="full profile runtime summary checked"
                    + _metric_pair_suffix(metrics, ("subprofiles_inconclusive", "subprofiles_completed")),
                )
            )
        if item.key == "drift_check_summary":
            sources.add("drift")
            if metrics.get("drift_check_enabled") is False:
                sources.add("drift_missing")
            if metrics.get("suspicious_sample_count", 0) or metrics.get("failed_sample_count", 0):
                collected.append(
                    _fraud_evidence(
                        FraudEvidenceTag.DETAIL_AUDIT_DRIFT_OBSERVED,
                        "drift",
                        label="bounded drift signal observed"
                        + _metric_pair_suffix(
                            metrics,
                            (
                                "sample_count",
                                "suspicious_sample_count",
                                "failed_sample_count",
                                "inconclusive_sample_count",
                            ),
                        ),
                    )
                )
            elif metrics.get("drift_check_enabled") is True:
                collected.append(
                    _fraud_evidence(
                        FraudEvidenceTag.DRIFT_CHECK_COMPLETED,
                        "drift",
                        label="bounded drift check completed"
                        + _metric_pair_suffix(
                            metrics,
                            (
                                "sample_count",
                                "suspicious_sample_count",
                                "failed_sample_count",
                                "inconclusive_sample_count",
                            ),
                        ),
                    )
                )
        if item.key == "relay_identity_candidate_signals":
            for candidate in _candidate_signal_labels(metrics):
                collected.append(
                    _fraud_evidence(
                        FraudEvidenceTag.IDENTITY_CANDIDATE_UPSTREAM_SIGNAL,
                        source,
                        label=f"Candidate upstream-family signal: {candidate}",
                    )
                )
            if status in {"fail", "failed"}:
                collected.append(
                    _fraud_evidence(
                        FraudEvidenceTag.MODEL_CLAIM_CONTRADICTION,
                        source,
                        label="model claim contradiction observed"
                        + _metric_pair_suffix(metrics, ("claimed_model", "observed_model_family", "top_candidate", "confidence")),
                    )
                )
            if status in {"suspicious", "fail", "failed"}:
                collected.append(
                    _fraud_evidence(
                        FraudEvidenceTag.REASONING_SIGNAL_MISSING,
                        source,
                        label="Claimed-model reasoning signal missing"
                        + _metric_pair_suffix(metrics, ("claimed_model", "claude_reasoning_signal")),
                    )
                )
        if item.key == "identity_response_envelope":
            collected.append(
                _fraud_evidence(
                    FraudEvidenceTag.IDENTITY_ENVELOPE_OBSERVED,
                    source,
                    label="identity model-family envelope observed"
                    + _metric_pair_suffix(
                        metrics,
                        (
                            "claimed_model_family",
                            "observed_model_family",
                        ),
                    ),
                )
            )
            channel_label = _channel_marker_label_from_metrics(metrics)
            if channel_label:
                collected.append(
                    _fraud_evidence(
                        FraudEvidenceTag.CHANNEL_MARKER_OBSERVED,
                        "channel",
                        label=channel_label,
                    )
                )
        if item.key == "identity_model_field_consistency":
            if metrics.get("model_family_contradiction") is True or status in {"fail", "failed"}:
                collected.append(
                    _fraud_evidence(
                        FraudEvidenceTag.IDENTITY_MODEL_FIELD_CONTRADICTION,
                        source,
                        label=(
                            "Identity model-field contradiction"
                            + _metric_pair_suffix(
                                metrics,
                                ("claimed_model_family", "observed_model_family"),
                            )
                        ),
                    )
                )
        if item.key == "identity_cross_provider_metadata":
            if metrics.get("cross_provider_metadata_detected") is True or status in {"fail", "failed"}:
                collected.append(
                    _fraud_evidence(
                        FraudEvidenceTag.IDENTITY_CROSS_PROVIDER_METADATA,
                        source,
                        label="Identity cross-provider metadata contradiction",
                    )
                )
        if item.key == "identity_self_report_consistency" and status in {"suspicious", "fail", "failed"}:
            collected.append(
                _fraud_evidence(
                    FraudEvidenceTag.IDENTITY_SELF_REPORT_MISMATCH,
                    source,
                    label="Identity self-report mismatch",
                )
            )
        if item.key == "identity_candidate_family_scores" and status in {"suspicious", "fail", "failed"}:
            candidate_labels = _candidate_signal_labels(metrics)
            if candidate_labels:
                for candidate in candidate_labels:
                    collected.append(
                        _fraud_evidence(
                            FraudEvidenceTag.IDENTITY_CANDIDATE_UPSTREAM_SIGNAL,
                            source,
                            label=f"Candidate upstream-family signal: {candidate}",
                        )
                    )
            else:
                collected.append(
                    _fraud_evidence(
                        FraudEvidenceTag.IDENTITY_CANDIDATE_UPSTREAM_SIGNAL,
                        source,
                        label="Candidate upstream-family signal",
                    )
                )
        if item.key == "channel_claim_consistency":
            if status in {"pass", "observed"}:
                collected.append(
                    _fraud_evidence(
                        FraudEvidenceTag.CHANNEL_CHECK_COMPLETED,
                        source,
                        label="channel claim consistency checked"
                        + _metric_pair_suffix(
                            metrics,
                            (
                                "claim_channel",
                                "observed_channel_family",
                                "official_claim_contradicted",
                                "compatible_gateway_claim",
                            ),
                        ),
                    )
                )
            if metrics.get("official_claim_contradicted") is True or status in {"fail", "failed"}:
                collected.append(
                    _fraud_evidence(
                        FraudEvidenceTag.CHANNEL_OFFICIAL_CLAIM_CONTRADICTED,
                        source,
                        label="Official-channel claim contradicted"
                        + _metric_pair_suffix(metrics, ("claim_channel", "observed_channel_family")),
                    )
                )
            elif metrics.get("observed_channel_family") and status in {"suspicious", "observed"}:
                collected.append(
                    _fraud_evidence(
                        FraudEvidenceTag.CHANNEL_MARKER_OBSERVED,
                        source,
                        label="Channel marker observed"
                        + _metric_pair_suffix(metrics, ("claim_channel", "observed_channel_family")),
                    )
                )
        if item.key in {"channel_response_markers", "channel_header_marker_family"}:
            if status in {"pass", "observed"}:
                collected.append(
                    _fraud_evidence(
                        FraudEvidenceTag.CHANNEL_CHECK_COMPLETED,
                        source,
                        label="channel response markers checked"
                        + _metric_pair_suffix(
                            metrics,
                            (
                                "provider_marker_detected",
                                "provider_marker_family",
                                "response_id_pattern",
                                "header_marker_families",
                            ),
                        ),
                    )
                )
            if metrics.get("provider_marker_detected") is True or metrics.get("observed_channel_family"):
                collected.append(
                    _fraud_evidence(
                        FraudEvidenceTag.CHANNEL_MARKER_OBSERVED,
                        source,
                        label="Channel marker observed"
                        + _metric_pair_suffix(
                            metrics,
                            ("observed_channel_family", "response_id_pattern", "provider_marker_family"),
                        ),
                    )
                )
            if item.key == "channel_header_marker_family" and metrics.get("header_marker_family"):
                collected.append(
                    _fraud_evidence(
                        FraudEvidenceTag.CHANNEL_MARKER_OBSERVED,
                        source,
                        label="Channel header marker observed"
                        + _metric_pair_suffix(metrics, ("header_marker_family",)),
                    )
                )
        if item.key in {"reasoning_native_signal", "reasoning_usage_signal"}:
            if status == "pass":
                collected.append(
                    _fraud_evidence(
                        FraudEvidenceTag.REASONING_CHECK_COMPLETED,
                        source,
                        label="reasoning native/usage signal checked"
                        + _metric_pair_suffix(
                            metrics,
                            (
                                "expected_reasoning_family",
                                "native_reasoning_field_observed",
                                "reasoning_content_observed",
                                "thinking_block_observed",
                                "reasoning_usage_observed",
                            ),
                        ),
                    )
                )
            if status in {"fail", "failed"}:
                label = (
                    "reasoning native signal missing"
                    + _metric_pair_suffix(
                        metrics,
                        (
                            "expected_reasoning_family",
                            "native_reasoning_field_observed",
                            "reasoning_content_observed",
                            "reasoning_usage_observed",
                        ),
                    )
                )
                collected.append(_fraud_evidence(FraudEvidenceTag.REASONING_REQUIRED_SIGNAL_MISSING, source, label=label))
                collected.append(_fraud_evidence(FraudEvidenceTag.REASONING_SIGNAL_MISSING, source, label=label))
        if item.key == "reasoning_cross_provider_signal" and status in {"fail", "failed"}:
            collected.append(
                _fraud_evidence(
                    FraudEvidenceTag.REASONING_CROSS_PROVIDER_METADATA,
                    source,
                    label="Reasoning cross-provider metadata contradiction",
                )
            )
        if item.key == "reasoning_fake_thinking_signal" and status in {"suspicious", "fail", "failed"}:
            collected.append(
                _fraud_evidence(
                    FraudEvidenceTag.REASONING_FAKE_THINKING_TEXT,
                    source,
                    label="fake-thinking marker observed"
                    + _metric_pair_suffix(metrics, ("fake_think_tag_observed", "public_think_text_observed")),
                )
            )
        if (
            status == "fail"
            and item.category.value == "model_substitution"
            and not item.key.startswith("reasoning_")
        ):
            collected.append(
                _fraud_evidence(
                    FraudEvidenceTag.MODEL_CLAIM_CONTRADICTION,
                    source,
                    label="model substitution evidence failed"
                    + _metric_pair_suffix(
                        {"evidence_key": item.key, **metrics},
                        ("evidence_key", "claimed_model_family", "observed_model_family", "top_candidate", "confidence"),
                    ),
                )
            )
        if item.category.value == "prompt_instruction_leakage" and status == "fail":
            collected.append(
                _fraud_evidence(
                    FraudEvidenceTag.PROMPT_BOUNDARY_FAILED,
                    source,
                    label=_prompt_boundary_label(item.key, metrics),
                )
            )
        if metrics.get("sensitive_core_echo_detected") is True:
            collected.append(
                _fraud_evidence(
                    FraudEvidenceTag.SENSITIVE_CORE_ECHO_DETECTED,
                    source,
                    label=_sensitive_echo_label(item.key, metrics),
                )
            )
        if metrics.get("message_rewrite_detected") is True:
            collected.append(
                _fraud_evidence(
                    FraudEvidenceTag.MESSAGE_REWRITE_DETECTED,
                    source,
                    label="message rewrite signal observed"
                    + _metric_pair_suffix(metrics, ("message_rewrite_detected", "exact_public_answer_observed", "extra_content_detected")),
                )
            )
        if metrics.get("extra_content_detected") is True:
            collected.append(
                _fraud_evidence(
                    FraudEvidenceTag.OUTPUT_EXTRA_CONTENT_DETECTED,
                    source,
                    label="extra output content observed"
                    + _metric_pair_suffix(metrics, ("extra_content_detected", "exact_public_answer_observed")),
                )
            )
        if metrics.get("anchor_missing_count", 0):
            collected.append(
                _fraud_evidence(
                    FraudEvidenceTag.CONTEXT_ANCHOR_MISSING,
                    source,
                    label="context anchor missing"
                    + _metric_pair_suffix(metrics, ("anchor_missing_count", "anchor_total_count", "middle_anchor_observed")),
                )
            )
        if item.key.startswith("context_") and status == "pass":
            collected.append(
                _fraud_evidence(
                    FraudEvidenceTag.CONTEXT_CHECK_COMPLETED,
                    source,
                    label="context retention signal checked"
                    + _metric_pair_suffix(
                        metrics,
                        (
                            "anchor_expected_count",
                            "anchor_observed_count",
                            "anchor_missing_count",
                            "anchor_order_preserved",
                            "middle_anchor_observed",
                            "message_rewrite_detected",
                        ),
                    ),
                )
            )
        if metrics.get("tool_call_observed") is False or metrics.get("natural_language_fallback_observed") is True:
            collected.append(
                _fraud_evidence(
                    FraudEvidenceTag.SCHEMA_TOOL_DROPPED,
                    source,
                    label="schema/tool-call envelope broken"
                    + _metric_pair_suffix(
                        metrics,
                        ("tool_call_observed", "natural_language_fallback_observed", "tool_name_observed"),
                    ),
                )
            )
        if metrics.get("arguments_json_parseable") is False:
            collected.append(
                _fraud_evidence(
                    FraudEvidenceTag.SCHEMA_ARGUMENTS_INVALID,
                    source,
                    label="schema arguments JSON invalid"
                    + _metric_pair_suffix(metrics, ("arguments_json_parseable", "tool_call_observed")),
                )
            )
        if item.key.startswith("schema_") and status == "pass":
            suffix = _metric_pair_suffix(
                metrics,
                (
                    "tool_call_observed",
                    "natural_language_fallback_observed",
                    "hybrid_content_observed",
                    "arguments_json_parseable",
                    "required_keys_preserved",
                ),
            )
            if suffix:
                collected.append(
                    _fraud_evidence(
                        FraudEvidenceTag.SCHEMA_CHECK_COMPLETED,
                        source,
                        label="schema/tool-call signal checked" + suffix,
                    )
                )
        if metrics.get("content_delta_count") == 0:
            collected.append(
                _fraud_evidence(
                    FraudEvidenceTag.STREAM_DELTA_MISSING,
                    source,
                    label="stream content delta missing"
                    + _metric_pair_suffix(metrics, ("content_delta_count", "stream_event_count")),
                )
            )
        if metrics.get("terminal_finish_observed") is False:
            collected.append(
                _fraud_evidence(
                    FraudEvidenceTag.STREAM_FINISH_MISSING,
                    source,
                    label="stream terminal finish missing"
                    + _metric_pair_suffix(metrics, ("terminal_finish_observed", "finish_reason")),
                )
            )
        if item.key.startswith("stream_") and status == "pass":
            collected.append(
                _fraud_evidence(
                    FraudEvidenceTag.STREAMING_CHECK_COMPLETED,
                    source,
                    label="streaming signal checked"
                    + _metric_pair_suffix(
                        metrics,
                        ("content_delta_count", "event_count", "terminal_finish_observed", "finish_reason"),
                    ),
                )
            )
        if item.key.startswith("privacy_") and status == "pass":
            collected.append(
                _fraud_evidence(
                    FraudEvidenceTag.PRIVACY_CHECK_COMPLETED,
                    source,
                    label="privacy signal checked"
                    + _metric_pair_suffix(
                        metrics,
                        (
                            "do_not_echo_marker_leaked",
                            "exact_public_answer_observed",
                            "extra_content_detected",
                            "message_rewrite_detected",
                            "provider_marker_detected",
                            "provider_marker_count",
                            "auth_header_echo_detected",
                            "api_key_echo_detected",
                            "endpoint_echo_detected",
                        ),
                    ),
                )
            )
        if item.key == "synthetic_stream_heuristic" and status in {"suspicious", "fail", "failed"}:
            collected.append(
                _fraud_evidence(
                    FraudEvidenceTag.STREAM_DELTA_MISSING,
                    source,
                    label="synthetic stream heuristic observed"
                    + _metric_pair_suffix(metrics, ("chunk_length_variance", "chunk_count")),
                )
            )
        if metrics.get("provider_marker_detected") is True or metrics.get("provider_or_upstream_marker_detected") is True:
            label = "provider/upstream marker observed" + _metric_pair_suffix(
                metrics,
                ("provider_marker_family", "observed_channel_family", "runtime_category", "error_shape_family"),
            )
            collected.append(_fraud_evidence(FraudEvidenceTag.PROVIDER_ERROR_MARKER_DETECTED, source, label=label))
            collected.append(_fraud_evidence(FraudEvidenceTag.CHANNEL_MARKER_LEAKED, source, label=label))
        if metrics.get("response_id_pattern") == "msg_bdrk...":
            collected.append(
                _fraud_evidence(
                    FraudEvidenceTag.CHANNEL_MARKER_LEAKED,
                    source,
                    label="Bedrock-compatible response id observed"
                    + _metric_pair_suffix(metrics, ("response_id_pattern", "response_shape_family")),
                )
            )
    mapped_keys = {
        "reasoning_native_signal",
        "reasoning_usage_signal",
        "reasoning_cross_provider_signal",
        "reasoning_fake_thinking_signal",
        "security_prompt_extraction",
        "security_override_resistance",
        "security_hidden_instruction_echo",
        "channel_claim_consistency",
        "channel_response_markers",
        "channel_header_marker_family",
        "identity_model_field_consistency",
        "identity_candidate_family_scores",
        "identity_cross_provider_metadata",
        "identity_self_report_consistency",
        "identity_response_envelope",
        "relay_identity_candidate_signals",
        "drift_check_summary",
        "full_profile_composite_verdict",
        "full_profile_runtime_cost_notice",
        "stream_content_delta",
        "stream_terminal_finish",
        "stream_event_sequence",
        "schema_tool_envelope",
        "schema_arguments_json",
        "privacy_marker_leakage",
        "privacy_secret_echo",
        "privacy_upstream_error_disclosure",
        "context_anchor_retention",
    }
    for item in result.evidence:
        status = str(item.status).lower()
        if status in {"fail", "failed"} and item.key not in mapped_keys:
            sources.add("unmapped")
            collected.append(
                _fraud_evidence(
                    FraudEvidenceTag.UNMAPPED_TECHNICAL_RISK,
                    "unmapped",
                    label=f"unmapped high-risk evidence: {sanitize_public_relay_text(item.key)}",
                )
            )
    if result.profile == RelayAuditProfile.FULL:
        sources.update(
            {
                "general",
                "identity",
                "channel",
                "reasoning",
                "streaming",
                "schema",
                "privacy",
                "security",
                "context",
            }
        )
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
        collected.append(
            _fraud_evidence(
                FraudEvidenceTag.MODEL_CLAIM_CONTRADICTION,
                "provider",
                label="provider audit model-claim signal observed: signals="
                + _friendly_provider_tags(tags & claim_mismatch_tags),
            )
        )
    if "DEEPSEEK_REASONING_CONTENT_MISSING" in tags or "SYNTHETIC_THINKING_SUSPECT" in tags:
        collected.append(
            _fraud_evidence(
                FraudEvidenceTag.REASONING_SIGNAL_MISSING,
                "provider",
                label="provider audit reasoning signal observed: signals="
                + _friendly_provider_tags(tags & {"DEEPSEEK_REASONING_CONTENT_MISSING", "SYNTHETIC_THINKING_SUSPECT"}),
            )
        )
    channel_tags = {
        "OPENAI_OFFICIAL_CHANNEL_MISMATCH",
        "DEEPSEEK_OFFICIAL_CHANNEL_MISMATCH",
        "HOSTED_BY_AWS",
        "HOSTED_BY_AZURE",
        "HOSTED_BY_UNKNOWN_PROXY",
    }
    if tags & channel_tags:
        collected.append(
            _fraud_evidence(
                FraudEvidenceTag.CHANNEL_MARKER_LEAKED,
                "provider",
                label="provider audit channel signal observed: signals="
                + _friendly_provider_tags(tags & channel_tags),
            )
        )
    drift_tags = {
        "MODEL_DRIFT_SUSPECT",
        "CONCURRENT_POOL_SUSPECT",
        "WEB_REVERSE_SUSPECT",
        "UNSTABLE_RELAY_SUSPECT",
        "TTFT_VARIANCE_HIGH",
    }
    if tags & drift_tags:
        sources.add("detail")
        collected.append(
            _fraud_evidence(
                FraudEvidenceTag.DETAIL_AUDIT_DRIFT_OBSERVED,
                "detail",
                label="provider audit drift signal observed: signals="
                + _friendly_provider_tags(tags & drift_tags),
            )
        )
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
            sep = _label_separator(language)
            lines.append(f"- {'状态' if language == 'zh' else 'Status'}{sep}**{public_status.value}**")
        else:
            status_label = "状态：" if language == "zh" else "Status:"
            lines.append(f"- {status_label} {public_status.value}")
        if conclusion:
            label = "结论" if language == "zh" else "Conclusion"
            sep = _label_separator(language) if report_kind == "full" else ": "
            lines.append(f"- {label}{sep}{sanitize_public_relay_text(conclusion)}")
        observed = _scenario_observed_signals(result, language, public_status)
        if observed:
            lines.append(f"- {'观察到的信号' if language == 'zh' else 'Observed signals'}{_label_separator(language)}")
            for item in observed:
                lines.append(f"  - {sanitize_public_relay_text(_render_observed_signal(item, language))}")
        absent = _scenario_absent_signals(result, language, public_status)
        if absent:
            lines.append(f"- {'未观察到的信号' if language == 'zh' else 'Signals not observed'}{_label_separator(language)}")
            for item in absent:
                lines.append(f"  - {sanitize_public_relay_text(item)}")
        explanation = _scenario_explanation_text(result, language, public_status)
        if explanation:
            lines.append(
                f"- {'解释' if language == 'zh' else 'Explanation'}{_label_separator(language)}{sanitize_public_relay_text(explanation)}"
            )
        evidence_bullets = (
            ()
            if report_kind == "full"
            else _scenario_evidence_bullets(result, language, public_status)
        )
        if evidence_bullets:
            lines.append(f"- {'关键证据' if language == 'zh' else 'Key evidence'}{_label_separator(language)}")
            for bullet in evidence_bullets:
                lines.append(f"  - {sanitize_public_relay_text(bullet)}")
        candidates = _scenario_candidate_signals(result, language)
        if candidates:
            lines.append(f"- {'候选上游信号' if language == 'zh' else 'Candidate upstream signals'}{_label_separator(language)}")
            for candidate_index, candidate in enumerate(candidates, start=1):
                lines.append(f"  {candidate_index}. {sanitize_public_relay_text(candidate)}")
        needed = _scenario_needed_evidence(result, language, public_status)
        if needed:
            lines.append(f"- {'需要的证据' if language == 'zh' else 'Needed evidence'}{_label_separator(language)}")
            for item in needed:
                lines.append(f"  - {sanitize_public_relay_text(item)}")
        actions = _scenario_recommended_actions(result, language, public_status)
        if actions:
            lines.append(f"- {'建议动作' if language == 'zh' else 'Recommended action'}{_label_separator(language)}")
            for item in actions:
                lines.append(f"  - {sanitize_public_relay_text(item)}")
        explanations = _scenario_user_explanations(result, language, public_status)
        if explanations:
            lines.append(f"- {'用户解释' if language == 'zh' else 'User explanation'}{_label_separator(language)}")
            for item in explanations:
                lines.append(f"  - {sanitize_public_relay_text(item)}")
        if result.safe_note:
            label = "结论" if language == "zh" else "Conclusion"
            sep = _label_separator(language) if report_kind == "full" else ": "
            lines.append(f"- {label}{sep}{sanitize_public_relay_text(result.safe_note)}")
        if report_kind != "full":
            boundary_label = "边界：" if language == "zh" else "Boundary:"
            boundary = scenario.boundary_zh if language == "zh" else scenario.boundary_en
            if boundary:
                lines.append(f"- {boundary_label} {sanitize_public_relay_text(boundary)}")
        lines.append("")
    return lines + [""]


def _scenario_observed_signals(
    result: FraudScenarioResult,
    language: str,
    public_status: FraudScenarioStatus,
) -> tuple[str, ...]:
    if result.observed_signals:
        return result.observed_signals
    if public_status in {FraudScenarioStatus.DETECTED, FraudScenarioStatus.SUSPICIOUS}:
        return result.triggered_evidence
    return ()


def render_public_observed_signal(signal: str, language: str) -> str:
    return _render_observed_signal(signal, language)


def _scenario_absent_signals(
    result: FraudScenarioResult,
    language: str,
    public_status: FraudScenarioStatus,
) -> tuple[str, ...]:
    return result.absent_signals


def _scenario_explanation_text(
    result: FraudScenarioResult,
    language: str,
    public_status: FraudScenarioStatus,
) -> str:
    if result.explanation and language != "zh":
        return result.explanation
    if language == "zh":
        if public_status == FraudScenarioStatus.DETECTED:
            return "本场景观察到明确匹配信号。"
        if public_status == FraudScenarioStatus.SUSPICIOUS:
            return "本场景观察到可疑但尚未决定性的信号。"
        if public_status == FraudScenarioStatus.NOT_DETECTED:
            return "相关检查已运行，未观察到目标风险信号。"
        if public_status == FraudScenarioStatus.INSUFFICIENT_EVIDENCE:
            return "本次运行没有收集到足够证据判断该场景。"
    return _scenario_status_conclusion(result, language, public_status)


def _visible_results(summary: FraudScenarioSummary, *, report_kind: str):
    results = summary.results
    if report_kind == "full":
        by_id = summary.by_id
        results = tuple(by_id[item] for item in FULL_REPORT_SCENARIO_IDS if item in by_id)
    for result in results:
        if report_kind == "full" and result.scenario.scenario_id not in FULL_REPORT_SCENARIO_IDS:
            continue
        if (
            report_kind == "full"
            and result.scenario.scenario_id == "unmapped_technical_risk_signal"
            and result.status == FraudScenarioStatus.NOT_EVALUATED
        ):
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
        dynamic = _specific_scenario_conclusion(result, language)
        if dynamic:
            return dynamic
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
        return _not_detected_scenario_conclusion(scenario.scenario_id, language)
    return ""


def _not_detected_scenario_conclusion(scenario_id: str, language: str) -> str:
    zh = {
        "model_identity_and_capability_substitution": "本次未观察到模型家族矛盾或跨 provider metadata 矛盾。",
        "channel_source_and_compliance_misrepresentation": "本次未观察到 Bedrock/Azure/OpenRouter/OneAPI/NewAPI 或代理层 marker。",
        "thinking_reasoning_capability_forgery": "本次未发现伪 `<think>` 文本或跨 provider reasoning metadata 矛盾。",
        "prompt_context_integrity_manipulation": "本次未观察到上下文锚点丢失、请求改写或隐藏指令泄漏。",
        "fake_or_degraded_streaming": "本次 streaming 检查未观察到 content delta 缺失或终止信号异常。",
        "schema_tool_calling_contract_breakage": "本次未观察到 tool_calls 丢失或 function arguments JSON 破坏。",
        "privacy_and_prompt_leakage": "本次未观察到隐私 marker、密钥、endpoint 或上游原始错误回显。",
        "capacity_quota_and_error_masking": "本次未观察到配额、限速、运行时错误掩盖或子检查无法判定信号。",
        "unmapped_technical_risk_signal": "本次未观察到未映射的高风险技术信号。",
    }
    en = {
        "model_identity_and_capability_substitution": "No model-family contradiction or cross-provider metadata contradiction was observed.",
        "channel_source_and_compliance_misrepresentation": "No Bedrock/Azure/OpenRouter/OneAPI/NewAPI or proxy-layer marker was observed.",
        "thinking_reasoning_capability_forgery": "No fake `<think>` text or cross-provider reasoning metadata contradiction was observed.",
        "prompt_context_integrity_manipulation": "No context-anchor loss, request rewrite, or hidden-instruction leakage was observed.",
        "fake_or_degraded_streaming": "Streaming checks did not observe missing content deltas or terminal-finish anomalies.",
        "schema_tool_calling_contract_breakage": "No tool_calls loss or function-arguments JSON breakage was observed.",
        "privacy_and_prompt_leakage": "No privacy marker, credential, endpoint, or raw upstream-error echo was observed.",
        "capacity_quota_and_error_masking": "No quota, rate-limit, runtime-error masking, or inconclusive subcheck signal was observed.",
        "unmapped_technical_risk_signal": "No unmapped high-risk technical signal was observed.",
    }
    labels = zh if language == "zh" else en
    return labels.get(
        scenario_id,
        "相关信号已检查，未观察到目标风险信号。"
        if language == "zh"
        else "Relevant signals were checked and the target risk signal was not observed.",
    )


def _render_observed_signal(signal: str, language: str) -> str:
    text = signal.lower()
    if language != "zh":
        if text.startswith("prompt boundary failure observed"):
            if "sensitive_core_echo_detected=true" in text:
                return "Security-boundary probe failed: the response echoed sensitive core prompt/instruction content. Fields: " + signal
            if "role_boundary_rewrite_detected=true" in text:
                return "Security-boundary probe failed: the response showed role-boundary rewrite. Fields: " + signal
            return "Security-boundary probe failed. Fields: " + signal
        if text.startswith("sensitive prompt/instruction echo observed"):
            return "Privacy leakage signal: the response echoed sensitive prompt or internal-instruction content. Fields: " + signal
        if text.startswith("bedrock-compatible"):
            return "Channel fingerprint signal: response id has a Bedrock-compatible shape. Fields: " + signal
        if text.startswith("reasoning native signal missing"):
            return "Reasoning signal: claimed reasoning family did not expose a native reasoning field. Fields: " + signal
        if text.startswith("fake-thinking marker observed"):
            return "Reasoning signal: public fake-thinking marker appeared in response content. Fields: " + signal
        return signal
    if text.startswith("prompt boundary failure observed"):
        if "sensitive_core_echo_detected=true" in text:
            return "安全边界探针失败：模型响应中出现敏感核心回显。字段: " + signal
        if "role_boundary_rewrite_detected=true" in text:
            return "安全边界探针失败：模型响应出现角色边界改写。字段: " + signal
        return "安全边界探针失败。字段: " + signal
    if text.startswith("sensitive prompt/instruction echo observed"):
        return "隐私泄漏信号：响应回显了敏感 prompt 或内部指令内容。字段: " + signal
    if text.startswith("bedrock-compatible"):
        return "渠道指纹信号：响应 ID 呈现 Bedrock-compatible 形态。字段: " + signal
    if text.startswith("reasoning native signal missing"):
        return "推理能力信号：声明的 reasoning 家族未观察到原生 reasoning 字段。字段: " + signal
    if text.startswith("fake-thinking marker observed"):
        return "推理能力信号：正文中出现伪 reasoning 标记。字段: " + signal
    return signal


def _label_separator(language: str) -> str:
    return "：" if language == "zh" else ": "


def _specific_scenario_conclusion(result: FraudScenarioResult, language: str) -> str:
    scenario_id = result.scenario.scenario_id
    text = " ".join(result.observed_signals + result.triggered_evidence).lower()
    if not text.strip():
        return ""

    if scenario_id == "prompt_context_integrity_manipulation":
        issues: list[str] = []
        if _field_truthy(text, "anchor_missing_count") or "context anchor missing" in text:
            issues.append("上下文截断/anchor 丢失" if language == "zh" else "context truncation or anchor loss")
        if "message_rewrite_detected=true" in text or "extra_content_detected=true" in text:
            issues.append("请求改写或额外输出污染" if language == "zh" else "request rewrite or extra-output contamination")
        if "role_boundary_rewrite_detected=true" in text:
            issues.append("请求改写/角色边界改写" if language == "zh" else "request rewrite or role-boundary rewrite")
        if "prompt boundary failure" in text or "sensitive_core_echo_detected=true" in text:
            issues.append("隐藏指令或 prompt 边界泄漏" if language == "zh" else "hidden-instruction or prompt-boundary leakage")
        return _join_specific_issues(issues, language)

    if scenario_id == "privacy_and_prompt_leakage":
        issues = []
        if "sensitive_core_echo_detected=true" in text:
            issues.append("敏感 prompt/内部指令回显" if language == "zh" else "sensitive prompt or internal-instruction echo")
        if "secret_echo_detected=true" in text:
            issues.append("密钥或认证材料回显" if language == "zh" else "secret or credential echo")
        if "endpoint_echo_detected=true" in text:
            issues.append("完整 endpoint 回显" if language == "zh" else "full endpoint echo")
        if "provider/upstream marker" in text:
            issues.append("上游/provider 错误信息泄漏" if language == "zh" else "upstream/provider error disclosure")
        return _join_specific_issues(issues, language)

    if scenario_id == "fake_or_degraded_streaming":
        issues = []
        if "content_delta_count=0" in text:
            issues.append("流式 content delta 缺失" if language == "zh" else "missing streaming content delta")
        if "terminal_finish_observed=false" in text:
            issues.append("流式终止信号缺失" if language == "zh" else "missing terminal stream finish signal")
        if "synthetic stream heuristic" in text:
            issues.append("静态 chunk 均匀度疑似伪流式" if language == "zh" else "static chunk-uniformity fake-stream heuristic")
        return _join_specific_issues(issues, language)

    if scenario_id == "schema_tool_calling_contract_breakage":
        issues = []
        if "tool_call_observed=false" in text:
            issues.append("tool_calls 丢失" if language == "zh" else "tool_calls missing")
        if "natural_language_fallback_observed=true" in text:
            issues.append("结构化调用退化为自然语言" if language == "zh" else "structured call degraded to natural language")
        if "arguments_json_parseable=false" in text:
            issues.append("function arguments 不是可解析 JSON" if language == "zh" else "function arguments are not parseable JSON")
        return _join_specific_issues(issues, language)

    if scenario_id == "channel_source_and_compliance_misrepresentation":
        issues = []
        if "aws/bedrock" in text or "msg_bdrk" in text:
            issues.append("AWS/Bedrock-compatible 渠道信号" if language == "zh" else "AWS/Bedrock-compatible channel signal")
        if "azure" in text:
            issues.append("Azure 渠道信号" if language == "zh" else "Azure channel signal")
        if "official-channel mismatch" in text:
            issues.append("官方直连声明不一致" if language == "zh" else "official-channel claim mismatch")
        if "unknown proxy" in text or "proxy" in text:
            issues.append("代理层/未知中转信号" if language == "zh" else "proxy or unknown relay signal")
        return _join_specific_issues(issues, language)

    if scenario_id == "account_pool_reverse_resource_and_mixed_routing_drift":
        issues = []
        if (
            "model drift" in text
            or _field_truthy(text, "suspicious_sample_count")
            or _field_truthy(text, "failed_sample_count")
        ):
            issues.append("多轮采样漂移" if language == "zh" else "repeated-sampling drift")
        if "web reverse" in text:
            issues.append("Web 逆向资源信号" if language == "zh" else "web reverse-resource signal")
        if "account-pool" in text or "concurrent account-pool" in text:
            issues.append("号池/并发池信号" if language == "zh" else "account-pool or concurrent-pool signal")
        return _join_specific_issues(issues, language)

    if scenario_id == "capacity_quota_and_error_masking":
        issues = []
        if "quota_or_rate_limit" in text:
            issues.append("配额或限速运行时信号" if language == "zh" else "quota or rate-limit runtime signal")
        if "runtime_error_masking" in text:
            issues.append("错误掩盖信号" if language == "zh" else "runtime error-masking signal")
        if "provider/upstream marker" in text:
            issues.append("上游/provider 错误标记" if language == "zh" else "upstream/provider error marker")
        return _join_specific_issues(issues, language)

    if scenario_id == "thinking_reasoning_capability_forgery":
        issues = []
        if "reasoning native signal missing" in text:
            issues.append("声明 reasoning 能力但原生 reasoning 字段缺失" if language == "zh" else "claimed reasoning capability but native reasoning field is missing")
        if "fake-thinking marker" in text:
            issues.append("正文伪 reasoning 标记" if language == "zh" else "public fake-thinking marker")
        if "cross-provider" in text:
            issues.append("跨 provider reasoning metadata 矛盾" if language == "zh" else "cross-provider reasoning metadata contradiction")
        return _join_specific_issues(issues, language)

    return ""


def _field_truthy(text: str, field: str) -> bool:
    pattern = rf"\b{re.escape(field.lower())}=([^,\s]+)"
    match = re.search(pattern, text)
    if not match:
        return False
    value = match.group(1).strip().strip("`'\"").lower()
    return value not in {"", "0", "0.0", "false", "none", "null", "no"}


def _join_specific_issues(issues: list[str], language: str) -> str:
    unique = list(dict.fromkeys(item for item in issues if item))
    if not unique:
        return ""
    if language == "zh":
        return "本场景具体检测到：" + "、".join(unique) + "。"
    return "This scenario specifically observed: " + "; ".join(unique) + "."


def _scenario_evidence_bullets(
    result: FraudScenarioResult,
    language: str,
    public_status: FraudScenarioStatus,
) -> tuple[str, ...]:
    if result.evidence_bullets:
        return result.evidence_bullets
    scenario_id = result.scenario.scenario_id
    if public_status in {FraudScenarioStatus.DETECTED, FraudScenarioStatus.SUSPICIOUS} and result.triggered_evidence:
        non_candidate = tuple(
            item for item in result.triggered_evidence if not item.startswith("Candidate upstream-family signal:")
        )
        return non_candidate or tuple(result.triggered_evidence)
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
    candidates = []
    for item in result.triggered_evidence:
        prefix = "Candidate upstream-family signal:"
        if item.startswith(prefix):
            candidates.append(item.removeprefix(prefix).strip())
    if candidates:
        return tuple(candidates)
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
            "建议运行时加入 `--drift-check yes`，以开启有界重复采样检测。"
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
            "但如果商家声明这是某个特定高价或特定能力模型，本次行为证据与该声明存在不一致。"
            if language == "zh"
            else "If the seller claims a specific premium or capability-bearing model, the observed behavior conflicts with that claim.",
        )
    if result.scenario.scenario_id == "thinking_reasoning_capability_forgery" and public_status == FraudScenarioStatus.SUSPICIOUS:
        if any("Fake `<think>` text" in item for item in result.triggered_evidence):
            return (
                "观察到正文中的 `<think>` 文本；TokenVerify 将它视为公开文本伪推理标记，而不是原生 reasoning API 字段。"
                if language == "zh"
                else "Public `<think>` text was observed; TokenVerify treats it as a fake-thinking marker, not as a native reasoning API field.",
            )
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
    # Required tags intentionally use OR semantics: any required tag is enough
    # to mark the scenario detected. This lets one strong evidence variant
    # trigger the user-facing scenario without requiring every possible variant.
    required_triggered = _triggered_labels(scenario.required_tags, evidence_by_tag)
    optional_triggered = _triggered_labels(scenario.optional_tags, evidence_by_tag)
    if required_triggered:
        status = FraudScenarioStatus.DETECTED
        triggered = required_triggered
    elif optional_triggered:
        status = FraudScenarioStatus.SUSPICIOUS
        triggered = optional_triggered
    elif not scenario.required_sources <= available_sources:
        status = FraudScenarioStatus.NOT_EVALUATED
        triggered = ()
    else:
        status = FraudScenarioStatus.NOT_DETECTED
        triggered = ()

    informational = _informational_labels_for_scenario(scenario, evidence_by_tag)
    observed_input = triggered if status in {FraudScenarioStatus.DETECTED, FraudScenarioStatus.SUSPICIOUS} else triggered + informational
    observed = _observed_signals_for(scenario, status, observed_input)
    absent = _absent_signals_for(scenario, status)
    explanation = _scenario_explanation(scenario, status, observed, absent)
    return FraudScenarioResult(
        scenario=scenario,
        status=status,
        triggered_evidence=triggered,
        observed_signals=observed,
        absent_signals=absent,
        explanation=explanation,
    )


def _observed_signals_for(
    scenario: FraudScenarioDefinition,
    status: FraudScenarioStatus,
    triggered: tuple[str, ...],
) -> tuple[str, ...]:
    if status in {FraudScenarioStatus.DETECTED, FraudScenarioStatus.SUSPICIOUS}:
        return _dedupe_observed_signals(scenario, triggered)
    if triggered and status == FraudScenarioStatus.NOT_DETECTED:
        return _dedupe_observed_signals(scenario, triggered)
    if scenario.scenario_id == "model_identity_and_capability_substitution":
        signals = ("claimed model family checked", "response envelope family checked")
    elif scenario.scenario_id == "channel_source_and_compliance_misrepresentation":
        signals = ("endpoint host checked",)
    elif scenario.scenario_id == "account_pool_reverse_resource_and_mixed_routing_drift":
        signals = ("bounded drift sampling completed",)
    elif scenario.scenario_id == "thinking_reasoning_capability_forgery":
        signals = ("reasoning signal expectation checked",)
    elif scenario.scenario_id == "prompt_context_integrity_manipulation":
        signals = ("context anchors retained", "privacy marker not leaked", "message rewrite signal not observed")
    elif scenario.scenario_id == "fake_or_degraded_streaming":
        signals = ("content delta observed", "terminal finish observed", "SSE event sequence normal")
    elif scenario.scenario_id == "schema_tool_calling_contract_breakage":
        signals = ("tool_calls observed", "function arguments JSON parseable", "required keys preserved")
    elif scenario.scenario_id == "privacy_and_prompt_leakage":
        signals = ("privacy canary not echoed", "secret echo not observed", "raw upstream error disclosure not observed")
    elif scenario.scenario_id == "capacity_quota_and_error_masking":
        signals = ("runtime category: none", "subprofiles inconclusive: 0")
    else:
        signals = ()
    return _dedupe_observed_signals(scenario, signals)


def _dedupe_observed_signals(
    scenario: FraudScenarioDefinition,
    signals: tuple[str, ...],
) -> tuple[str, ...]:
    unique = tuple(dict.fromkeys(item for item in signals if item))
    if scenario.scenario_id != "channel_source_and_compliance_misrepresentation":
        return unique
    return _dedupe_channel_observed_signals(unique)


def _dedupe_channel_observed_signals(signals: tuple[str, ...]) -> tuple[str, ...]:
    has_bedrock = any(_is_bedrock_equivalent_signal(item) for item in signals)
    if not has_bedrock:
        return tuple(dict.fromkeys(signals))

    canonical_parts: list[str] = []
    if any("observed_channel_family=bedrock" in item.lower() for item in signals):
        canonical_parts.append("observed_channel_family=bedrock")
    if any("response_id_pattern=msg_bdrk..." in item.lower() for item in signals):
        canonical_parts.append("response_id_pattern=msg_bdrk...")
    shape_match = next(
        (
            re.search(r"response_shape_family=([^,\s]+)", item, flags=re.IGNORECASE)
            for item in signals
            if re.search(r"response_shape_family=([^,\s]+)", item, flags=re.IGNORECASE)
        ),
        None,
    )
    if shape_match:
        canonical_parts.append(f"response_shape_family={shape_match.group(1)}")
    if not canonical_parts:
        canonical_parts.append("observed_channel_family=bedrock")

    canonical = "Bedrock-compatible response id observed: " + ", ".join(dict.fromkeys(canonical_parts))
    deduped = [canonical]
    for item in signals:
        if _is_bedrock_equivalent_signal(item):
            continue
        deduped.append(item)
    return tuple(dict.fromkeys(deduped))


def _is_bedrock_equivalent_signal(signal: str) -> bool:
    text = signal.lower()
    return (
        "msg_bdrk" in text
        or "bedrock-compatible" in text
        or "observed_channel_family=bedrock" in text
    )


def _absent_signals_for(scenario: FraudScenarioDefinition, status: FraudScenarioStatus) -> tuple[str, ...]:
    if status != FraudScenarioStatus.NOT_DETECTED:
        return ()
    if scenario.scenario_id == "model_identity_and_capability_substitution":
        return ("model-family contradiction not observed", "cross-provider metadata contradiction not observed")
    if scenario.scenario_id == "channel_source_and_compliance_misrepresentation":
        return (
            "Bedrock/Azure/OpenRouter/OneAPI/NewAPI/proxy marker not observed",
            "provider marker error envelope not observed",
        )
    if scenario.scenario_id == "account_pool_reverse_resource_and_mixed_routing_drift":
        return ("suspicious drift samples not observed", "failed drift samples not observed")
    if scenario.scenario_id == "thinking_reasoning_capability_forgery":
        return ("fake-thinking marker not observed", "cross-provider reasoning metadata not observed")
    return ()


def _scenario_explanation(
    scenario: FraudScenarioDefinition,
    status: FraudScenarioStatus,
    observed: tuple[str, ...],
    absent: tuple[str, ...],
) -> str:
    if status == FraudScenarioStatus.DETECTED:
        return "Clear matching signal observed for this scenario."
    if status == FraudScenarioStatus.SUSPICIOUS:
        return "Concerning but not decisive signal observed for this scenario."
    if status == FraudScenarioStatus.NOT_DETECTED:
        return "Relevant checks ran and did not observe the target risk signal."
    if status == FraudScenarioStatus.INSUFFICIENT_EVIDENCE:
        return "This run did not collect enough evidence to judge this scenario."
    return ""


def _triggered_labels(
    tags: frozenset[FraudEvidenceTag],
    evidence_by_tag: dict[FraudEvidenceTag, list[FraudEvidence]],
) -> tuple[str, ...]:
    labels: list[str] = []
    for tag in sorted(tags, key=lambda item: item.value):
        for item in evidence_by_tag.get(tag, []):
            labels.append(_public_evidence_alias(item.public_label, tag))
    return tuple(labels)


def _informational_labels_for_scenario(
    scenario: FraudScenarioDefinition,
    evidence_by_tag: dict[FraudEvidenceTag, list[FraudEvidence]],
) -> tuple[str, ...]:
    tag_map = {
        "model_identity_and_capability_substitution": {FraudEvidenceTag.IDENTITY_ENVELOPE_OBSERVED},
        "channel_source_and_compliance_misrepresentation": {
            FraudEvidenceTag.CHANNEL_MARKER_OBSERVED,
            FraudEvidenceTag.CHANNEL_CHECK_COMPLETED,
        },
        "account_pool_reverse_resource_and_mixed_routing_drift": {FraudEvidenceTag.DRIFT_CHECK_COMPLETED},
        "thinking_reasoning_capability_forgery": {FraudEvidenceTag.REASONING_CHECK_COMPLETED},
        "prompt_context_integrity_manipulation": {
            FraudEvidenceTag.CONTEXT_CHECK_COMPLETED,
            FraudEvidenceTag.PRIVACY_CHECK_COMPLETED,
        },
        "fake_or_degraded_streaming": {FraudEvidenceTag.STREAMING_CHECK_COMPLETED},
        "schema_tool_calling_contract_breakage": {FraudEvidenceTag.SCHEMA_CHECK_COMPLETED},
        "privacy_and_prompt_leakage": {FraudEvidenceTag.PRIVACY_CHECK_COMPLETED},
        "capacity_quota_and_error_masking": {FraudEvidenceTag.CAPACITY_CHECK_COMPLETED},
    }
    labels: list[str] = []
    for tag in tag_map.get(scenario.scenario_id, set()):
        for item in evidence_by_tag.get(tag, []):
            labels.append(_public_evidence_alias(item.public_label, tag))
    return tuple(dict.fromkeys(labels))


def _public_evidence_alias(label: str, fallback: FraudEvidenceTag) -> str:
    cleaned = sanitize_public_relay_text(label)
    token = cleaned.strip().split()[0] if cleaned.strip() else fallback.value
    if token in {item.value for item in FraudEvidenceTag}:
        return token
    if cleaned.strip():
        return cleaned.strip()
    return fallback.value


def _fraud_evidence(tag: FraudEvidenceTag, source: str, *, label: str | None = None) -> FraudEvidence:
    return FraudEvidence(tag=tag, public_label=label or tag.value, source=source)


def _metric_pair_suffix(metrics: dict, keys: tuple[str, ...]) -> str:
    parts: list[str] = []
    for key in keys:
        value = metrics.get(key)
        if value is None or value == "":
            continue
        parts.append(f"{key}={sanitize_public_relay_text(value)}")
    return ": " + ", ".join(parts) if parts else ""


def _channel_marker_label_from_metrics(metrics: dict) -> str | None:
    response_id_pattern = metrics.get("response_id_pattern")
    if response_id_pattern == "msg_bdrk...":
        return "Bedrock-compatible channel signal observed" + _metric_pair_suffix(
            metrics,
            ("response_id_pattern", "response_shape_family"),
        )
    return None


def _prompt_boundary_label(probe_key: str, metrics: dict) -> str:
    return (
        "prompt boundary failure observed"
        + _metric_pair_suffix(
            {"probe": probe_key, **metrics},
            (
                "probe",
                "sensitive_core_echo_detected",
                "role_boundary_rewrite_detected",
                "secret_echo_detected",
                "endpoint_echo_detected",
                "exact_token_observed",
                "safe_refusal_observed",
            ),
        )
    )


def _sensitive_echo_label(probe_key: str, metrics: dict) -> str:
    return (
        "sensitive prompt/instruction echo observed"
        + _metric_pair_suffix(
            {"probe": probe_key, **metrics},
            (
                "probe",
                "sensitive_core_echo_detected",
                "secret_echo_detected",
                "endpoint_echo_detected",
                "role_boundary_rewrite_detected",
            ),
        )
    )


def _friendly_provider_tags(tags: set[str]) -> str:
    labels = {
        "CLAUDE_MODEL_CLAIM_MISMATCH": "Claude model-claim mismatch",
        "OPENAI_MODEL_CLAIM_MISMATCH": "OpenAI model-claim mismatch",
        "DEEPSEEK_MODEL_CLAIM_MISMATCH": "DeepSeek model-claim mismatch",
        "MODEL_CAPABILITY_MISMATCH": "model capability mismatch",
        "OPENAI_REASONING_CAPABILITY_MISMATCH": "OpenAI reasoning capability mismatch",
        "DEEPSEEK_REASONING_CONTENT_MISSING": "DeepSeek reasoning content missing",
        "EXTENDED_THINKING_MISSING": "extended thinking missing",
        "SYNTHETIC_THINKING_SUSPECT": "synthetic thinking suspected",
        "OPENAI_OFFICIAL_CHANNEL_MISMATCH": "OpenAI official-channel mismatch",
        "DEEPSEEK_OFFICIAL_CHANNEL_MISMATCH": "DeepSeek official-channel mismatch",
        "HOSTED_BY_AWS": "AWS/Bedrock channel signal",
        "HOSTED_BY_AZURE": "Azure channel signal",
        "HOSTED_BY_UNKNOWN_PROXY": "unknown proxy channel signal",
        "MODEL_DRIFT_SUSPECT": "model drift suspected",
        "CONCURRENT_POOL_SUSPECT": "concurrent account-pool signal",
        "WEB_REVERSE_SUSPECT": "web reverse-resource signal",
        "UNSTABLE_RELAY_SUSPECT": "unstable relay signal",
        "TTFT_VARIANCE_HIGH": "high first-token latency variance",
    }
    return sanitize_public_relay_text(", ".join(labels.get(tag, "unknown provider signal") for tag in sorted(tags)))


def _candidate_signal_labels(metrics: dict) -> tuple[str, ...]:
    candidates = metrics.get("candidate_signals")
    labels: list[str] = []
    if isinstance(candidates, list):
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            label = candidate.get("label")
            confidence = candidate.get("confidence")
            if label and confidence:
                labels.append(f"{sanitize_public_relay_text(label)}: {sanitize_public_relay_text(confidence)}")
    top_candidate = metrics.get("top_candidate")
    confidence = metrics.get("confidence")
    if top_candidate and confidence:
        labels.append(f"{sanitize_public_relay_text(top_candidate)}: {sanitize_public_relay_text(confidence)}")
    return tuple(labels)
