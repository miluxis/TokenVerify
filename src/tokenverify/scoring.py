from __future__ import annotations

from tokenverify.models import ProbeResult, Rating


def score_probe_results(probe_results: list[ProbeResult]) -> tuple[Rating, dict[str, int]]:
    breakdown = {
        "strong_passed": 0,
        "strong_failed": 0,
        "weak_passed": 0,
        "weak_failed": 0,
        "neutral": 0,
    }
    if _is_inconclusive(probe_results):
        return Rating.INCONCLUSIVE, breakdown

    for result in probe_results:
        for item in result.evidence:
            if item.weight == "strong" and item.passed is True:
                breakdown["strong_passed"] += 1
            elif item.weight == "strong" and item.passed is False:
                breakdown["strong_failed"] += 1
            elif item.weight == "weak" and item.passed is True:
                breakdown["weak_passed"] += 1
            elif item.weight == "weak" and item.passed is False:
                breakdown["weak_failed"] += 1
            else:
                breakdown["neutral"] += 1

    if breakdown["strong_failed"] > 0:
        return Rating.LOW_TRUST, breakdown
    if breakdown["strong_passed"] >= 2 and breakdown["weak_failed"] == 0:
        return Rating.HIGH_TRUST, breakdown
    if breakdown["strong_passed"] > 0:
        return Rating.MEDIUM_TRUST, breakdown
    return Rating.INCONCLUSIVE, breakdown


def _is_inconclusive(probe_results: list[ProbeResult]) -> bool:
    if not probe_results:
        return True
    inconclusive_markers = (
        "authentication",
        "authorization",
        "quota",
        "model-not-found",
        "service unavailable",
        "rate limit",
        "too many requests",
        "try again later",
    )
    for result in probe_results:
        joined_errors = " ".join(result.errors).lower()
        if result.status == "error" and any(marker in joined_errors for marker in inconclusive_markers):
            return True
    return False
