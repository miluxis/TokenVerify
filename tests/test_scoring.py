from tokenverify.models import EvidenceItem, ProbeResult, Rating, StreamingMetrics
from tokenverify.scoring import score_probe_results


def strong_evidence(key: str, passed: bool) -> EvidenceItem:
    return EvidenceItem(key=key, weight="strong", passed=passed, message=key)


def weak_evidence(key: str, passed: bool) -> EvidenceItem:
    return EvidenceItem(key=key, weight="weak", passed=passed, message=key)


def test_high_trust_when_protocol_and_thinking_match():
    rating, breakdown = score_probe_results(
        [
            ProbeResult("messages_protocol", "passed", [strong_evidence("anthropic_messages_shape", True)]),
            ProbeResult("extended_thinking", "passed", [strong_evidence("extended_thinking_expected", True)]),
        ]
    )

    assert rating == Rating.HIGH_TRUST
    assert breakdown["strong_passed"] == 2


def test_low_trust_when_thinking_is_ignored_for_capable_model():
    rating, breakdown = score_probe_results(
        [
            ProbeResult("messages_protocol", "passed", [strong_evidence("anthropic_messages_shape", True)]),
            ProbeResult("extended_thinking", "failed", [strong_evidence("extended_thinking_expected", False)]),
        ]
    )

    assert rating == Rating.LOW_TRUST
    assert breakdown["strong_failed"] == 1


def test_streaming_anomaly_only_weakly_affects_score():
    rating, breakdown = score_probe_results(
        [
            ProbeResult("messages_protocol", "passed", [strong_evidence("anthropic_messages_shape", True)]),
            ProbeResult("extended_thinking", "passed", [strong_evidence("extended_thinking_expected", True)]),
            ProbeResult(
                "streaming_features",
                "warning",
                [weak_evidence("synthetic_stream_heuristic", False)],
                metrics=StreamingMetrics(0.01, 0.02, [0.001], [20, 20, 20, 20, 20], 5000.0, True),
            ),
        ]
    )

    assert rating != Rating.LOW_TRUST
    assert breakdown["weak_failed"] == 1


def test_auth_failure_is_inconclusive():
    rating, _ = score_probe_results(
        [ProbeResult("messages_protocol", "error", errors=["authentication failed: invalid x-api-key"])]
    )

    assert rating == Rating.INCONCLUSIVE


def test_rate_limit_failure_is_inconclusive():
    rating, breakdown = score_probe_results(
        [
            ProbeResult(
                "extended_thinking",
                "error",
                [strong_evidence("extended_thinking_expected", False)],
                errors=["This request would exceed your organization's rate limit"],
            )
        ]
    )

    assert rating == Rating.INCONCLUSIVE
    assert breakdown["strong_failed"] == 0
