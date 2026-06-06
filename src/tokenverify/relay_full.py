from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from tokenverify.relay_models import (
    RelayAuditMode,
    RelayAuditProfile,
    RelayEvidence,
    RelayPackSummary,
    RelayResult,
    RelayRiskCategory,
    RelayRiskLevel,
    RelayRuntimeCategory,
    RelayVerdict,
)
from tokenverify.relay_safety import RelayLiveAuthorization, hash_relay_endpoint, sanitize_public_relay_text, sanitize_to_fqdn

FULL_SUBPROFILE_ORDER = (
    RelayAuditProfile.GENERAL,
    RelayAuditProfile.STREAMING,
    RelayAuditProfile.SCHEMA,
    RelayAuditProfile.PRIVACY,
    RelayAuditProfile.SECURITY,
    RelayAuditProfile.CONTEXT,
)

FullSubprofileRunner = Callable[[RelayAuditProfile], RelayResult]


class RelayFullRuntimeError(RuntimeError):
    pass


@dataclass(frozen=True)
class RelayFullSubprofileSummary:
    profile: RelayAuditProfile
    verdict: RelayVerdict
    risk_level: RelayRiskLevel
    risk_categories: tuple[RelayRiskCategory, ...]
    evidence_keys: tuple[str, ...]
    runtime_category: RelayRuntimeCategory | None
    completed: bool


def aggregate_full_verdict(verdicts: list[RelayVerdict]) -> RelayVerdict:
    if RelayVerdict.FAIL in verdicts:
        return RelayVerdict.FAIL
    if RelayVerdict.SUSPICIOUS in verdicts:
        return RelayVerdict.SUSPICIOUS
    if RelayVerdict.INCONCLUSIVE in verdicts:
        return RelayVerdict.INCONCLUSIVE
    return RelayVerdict.PASS


def aggregate_full_risk_level(risk_levels: list[RelayRiskLevel]) -> RelayRiskLevel:
    if RelayRiskLevel.HIGH in risk_levels:
        return RelayRiskLevel.HIGH
    if RelayRiskLevel.MEDIUM in risk_levels:
        return RelayRiskLevel.MEDIUM
    if RelayRiskLevel.UNKNOWN in risk_levels:
        return RelayRiskLevel.UNKNOWN
    return RelayRiskLevel.LOW


def run_full_live_check(
    *,
    authorization: RelayLiveAuthorization,
    endpoint: str,
    model: str,
    pack_summary: RelayPackSummary,
    subprofile_runner: FullSubprofileRunner,
    drift_check: bool = False,
    drift_samples: list[RelayResult] | None = None,
) -> RelayResult:
    if authorization.profile != RelayAuditProfile.FULL:
        raise RelayFullRuntimeError("Full profile runner requires full live authorization.") from None

    results: list[RelayResult] = []
    for profile in FULL_SUBPROFILE_ORDER:
        try:
            result = subprofile_runner(profile)
        except Exception:
            result = _inconclusive_subprofile_result(
                profile=profile,
                endpoint=endpoint,
                model=model,
                pack_summary=pack_summary,
            )
        results.append(result)

    summaries = [_summarize_subprofile(result) for result in results]
    verdict = aggregate_full_verdict([result.verdict for result in results])
    risk_level = aggregate_full_risk_level([result.risk_level for result in results])
    inconclusive_count = sum(1 for result in results if result.verdict == RelayVerdict.INCONCLUSIVE)
    inconclusive_reason = (
        f"{inconclusive_count} approved subprofile check(s) were inconclusive."
        if inconclusive_count
        else None
    )
    return RelayResult(
        run_id=_full_run_id(endpoint, model, verdict),
        profile=RelayAuditProfile.FULL,
        scenario=verdict,
        mode=RelayAuditMode.LIVE,
        model=sanitize_public_relay_text(model),
        endpoint_host=sanitize_to_fqdn(endpoint),
        endpoint_hash=hash_relay_endpoint(endpoint),
        pack_summary=pack_summary,
        verdict=verdict,
        risk_level=risk_level,
        risk_categories=_collect_risk_categories(results),
        evidence=_build_full_evidence(results, summaries, drift_check=drift_check, drift_samples=drift_samples or []),
        retest_guidance="Rerun full profile after resolving any inconclusive subprofile runtime causes.",
        inconclusive_reason=inconclusive_reason,
        runtime_category=RelayRuntimeCategory.UNKNOWN_RUNTIME_ERROR if inconclusive_count else None,
    )


def _full_run_id(endpoint: str, model: str, verdict: RelayVerdict) -> str:
    material = f"{endpoint}|{model}|full|{verdict.value}"
    return "relay-full-" + hash_relay_endpoint(material)


def _summarize_subprofile(result: RelayResult) -> RelayFullSubprofileSummary:
    return RelayFullSubprofileSummary(
        profile=result.profile,
        verdict=result.verdict,
        risk_level=result.risk_level,
        risk_categories=tuple(result.risk_categories),
        evidence_keys=tuple(sanitize_public_relay_text(evidence.key) for evidence in result.evidence),
        runtime_category=result.runtime_category,
        completed=True,
    )


def _collect_risk_categories(results: list[RelayResult]) -> list[RelayRiskCategory]:
    categories: list[RelayRiskCategory] = []
    for result in results:
        for category in result.risk_categories:
            if category not in categories:
                categories.append(category)
    return categories


def _build_full_evidence(
    results: list[RelayResult],
    summaries: list[RelayFullSubprofileSummary],
    *,
    drift_check: bool = False,
    drift_samples: list[RelayResult] | None = None,
) -> list[RelayEvidence]:
    verdict_counts = {
        "subprofiles_requested": len(FULL_SUBPROFILE_ORDER),
        "subprofiles_completed": len(results),
        "subprofiles_passed": sum(1 for item in results if item.verdict == RelayVerdict.PASS),
        "subprofiles_suspicious": sum(1 for item in results if item.verdict == RelayVerdict.SUSPICIOUS),
        "subprofiles_failed": sum(1 for item in results if item.verdict == RelayVerdict.FAIL),
        "subprofiles_inconclusive": sum(1 for item in results if item.verdict == RelayVerdict.INCONCLUSIVE),
        "planned_live_request_count": len(FULL_SUBPROFILE_ORDER),
        "completed_live_request_count": len(results),
        "private_pack_executed": False,
        "streaming_profile_included": True,
    }
    profile_metrics = {
        summary.profile.value: {
            "verdict": summary.verdict.value,
            "risk_level": summary.risk_level.value,
            "runtime_category": summary.runtime_category.value if summary.runtime_category else None,
            "evidence_keys": list(summary.evidence_keys),
        }
        for summary in summaries
    }
    evidence = [
        RelayEvidence(
            key="full_profile_orchestration",
            category=RelayRiskCategory.LATENCY_OR_INSTABILITY,
            status="completed",
            summary="Full profile ran approved subprofile checks in deterministic order.",
            metrics=verdict_counts,
        ),
        RelayEvidence(
            key="full_profile_composite_verdict",
            category=RelayRiskCategory.LATENCY_OR_INSTABILITY,
            status="observed",
            summary="Composite verdict was derived from sanitized subprofile verdicts.",
            metrics=profile_metrics,
        ),
        RelayEvidence(
            key="full_profile_runtime_cost_notice",
            category=RelayRiskCategory.LATENCY_OR_INSTABILITY,
            status="notice",
            summary=(
                "Full profile uses multiple approved checks and may use more live requests than a single profile. "
                "Serial execution can make timeout delays add up across subprofiles when a relay is slow or unavailable."
            ),
            metrics={
                "planned_live_request_count": len(FULL_SUBPROFILE_ORDER),
                "private_pack_executed": False,
            },
        ),
    ]
    evidence.append(_build_drift_evidence(drift_check, drift_samples or []))
    return evidence


def _build_drift_evidence(drift_check: bool, drift_samples: list[RelayResult]) -> RelayEvidence:
    if not drift_check:
        return RelayEvidence(
            key="drift_check_summary",
            category=RelayRiskCategory.LATENCY_OR_INSTABILITY,
            status="insufficient_evidence",
            summary="Drift check was not enabled for this run.",
            metrics={
                "drift_check_enabled": False,
                "sample_count": 0,
                "recommended_action": "--drift-check yes",
            },
        )
    suspicious_count = sum(1 for sample in drift_samples if sample.verdict == RelayVerdict.SUSPICIOUS)
    fail_count = sum(1 for sample in drift_samples if sample.verdict == RelayVerdict.FAIL)
    inconclusive_count = sum(1 for sample in drift_samples if sample.verdict == RelayVerdict.INCONCLUSIVE)
    status = "pass"
    if fail_count:
        status = "fail"
    elif suspicious_count or inconclusive_count:
        status = "suspicious"
    return RelayEvidence(
        key="drift_check_summary",
        category=RelayRiskCategory.LATENCY_OR_INSTABILITY,
        status=status,
        summary="Bounded drift-check sampling completed.",
        metrics={
            "drift_check_enabled": True,
            "sample_count": len(drift_samples),
            "suspicious_sample_count": suspicious_count,
            "failed_sample_count": fail_count,
            "inconclusive_sample_count": inconclusive_count,
        },
    )


def _inconclusive_subprofile_result(
    *,
    profile: RelayAuditProfile,
    endpoint: str,
    model: str,
    pack_summary: RelayPackSummary,
) -> RelayResult:
    return RelayResult(
        run_id=f"relay-full-{profile.value}-inconclusive-{hash_relay_endpoint(endpoint + model)}",
        profile=profile,
        scenario=RelayVerdict.INCONCLUSIVE,
        mode=RelayAuditMode.LIVE,
        model=sanitize_public_relay_text(model),
        endpoint_host=sanitize_to_fqdn(endpoint),
        endpoint_hash=hash_relay_endpoint(endpoint),
        pack_summary=pack_summary,
        verdict=RelayVerdict.INCONCLUSIVE,
        risk_level=RelayRiskLevel.UNKNOWN,
        risk_categories=[RelayRiskCategory.LATENCY_OR_INSTABILITY],
        evidence=[
            RelayEvidence(
                key=f"full_profile_{profile.value}_summary",
                category=RelayRiskCategory.LATENCY_OR_INSTABILITY,
                status="inconclusive",
                summary="Subprofile returned a sanitized runtime failure before usable evidence.",
                metrics={
                    "profile": profile.value,
                    "runtime_category": RelayRuntimeCategory.UNKNOWN_RUNTIME_ERROR.value,
                },
            )
        ],
        retest_guidance=f"Rerun {profile.value} after checking sanitized runtime conditions.",
        inconclusive_reason="Subprofile returned a sanitized runtime failure.",
        runtime_category=RelayRuntimeCategory.UNKNOWN_RUNTIME_ERROR,
    )
