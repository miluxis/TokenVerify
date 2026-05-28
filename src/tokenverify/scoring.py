from __future__ import annotations

from tokenverify.models import ProbeResult, Rating, Verdict


def score_probe_results(probe_results: list[ProbeResult]) -> tuple[Rating, dict[str, int], Verdict]:
    breakdown = {
        "strong_passed": 0,
        "strong_failed": 0,
        "weak_passed": 0,
        "weak_failed": 0,
        "neutral": 0,
    }
    if _is_inconclusive(probe_results):
        verdict = Verdict(
            rating=Rating.INCONCLUSIVE,
            authenticity_score=0,
            risk_score=0,
            tags=_collect_tags(probe_results),
        )
        return Rating.INCONCLUSIVE, breakdown, verdict

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
        rating = Rating.LOW_TRUST
    elif breakdown["strong_passed"] >= 2:
        rating = Rating.HIGH_TRUST
    elif breakdown["strong_passed"] > 0:
        rating = Rating.MEDIUM_TRUST
    else:
        rating = Rating.INCONCLUSIVE

    verdict = Verdict(
        rating=rating,
        authenticity_score=_authenticity_score(rating, breakdown),
        risk_score=_risk_score(probe_results),
        tags=_collect_tags(probe_results),
    )
    return rating, breakdown, verdict


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
        "timeout",
        "timed out",
        "disconnect",
        "connection reset",
        "network",
        "self-relay-loop",
    )
    for result in probe_results:
        joined_errors = " ".join(result.errors).lower()
        if result.status == "error" and any(marker in joined_errors for marker in inconclusive_markers):
            return True
    return False


def _authenticity_score(rating: Rating, breakdown: dict[str, int]) -> int:
    if rating == Rating.INCONCLUSIVE:
        return 0
    score = 50
    score += min(breakdown["strong_passed"] * 25, 50)
    score -= min(breakdown["strong_failed"] * 50, 100)
    if rating == Rating.HIGH_TRUST:
        return max(score, 90)
    if rating == Rating.MEDIUM_TRUST:
        return max(min(score, 89), 50)
    if rating == Rating.LOW_TRUST:
        return min(score, 39)
    return 0


def _risk_score(probe_results: list[ProbeResult]) -> int:
    weak_failures = 0
    for result in probe_results:
        for item in result.evidence:
            if item.weight == "weak" and item.passed is False:
                weak_failures += 1
    return min(weak_failures * 25, 100)


def _collect_tags(probe_results: list[ProbeResult]) -> list[str]:
    tags: list[str] = []
    for result in probe_results:
        for item in result.evidence:
            for tag in item.tags:
                if tag not in tags:
                    tags.append(tag)
    return tags
