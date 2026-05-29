from tokenverify.models import EvidenceItem, ProbeResult, Rating, StreamingMetrics
from tokenverify.scoring import score_probe_results


def strong_evidence(key: str, passed: bool) -> EvidenceItem:
    return EvidenceItem(key=key, weight="strong", passed=passed, message=key)


def weak_evidence(key: str, passed: bool) -> EvidenceItem:
    return EvidenceItem(key=key, weight="weak", passed=passed, message=key)


def test_high_trust_when_protocol_and_thinking_match():
    rating, breakdown, verdict = score_probe_results(
        [
            ProbeResult("messages_protocol", "passed", [strong_evidence("anthropic_messages_shape", True)]),
            ProbeResult("extended_thinking", "passed", [strong_evidence("extended_thinking_expected", True)]),
        ]
    )

    assert rating == Rating.HIGH_TRUST
    assert breakdown["strong_passed"] == 2
    assert verdict.rating == Rating.HIGH_TRUST


def test_low_trust_when_thinking_is_ignored_for_capable_model():
    rating, breakdown, verdict = score_probe_results(
        [
            ProbeResult("messages_protocol", "passed", [strong_evidence("anthropic_messages_shape", True)]),
            ProbeResult("extended_thinking", "failed", [strong_evidence("extended_thinking_expected", False)]),
        ]
    )

    assert rating == Rating.LOW_TRUST
    assert breakdown["strong_failed"] == 1
    assert verdict.rating == Rating.LOW_TRUST


def test_streaming_anomaly_only_weakly_affects_score():
    rating, breakdown, verdict = score_probe_results(
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
    assert verdict.risk_score > 0


def test_auth_failure_is_inconclusive():
    rating, _, verdict = score_probe_results(
        [ProbeResult("messages_protocol", "error", errors=["authentication failed: invalid x-api-key"])]
    )

    assert rating == Rating.INCONCLUSIVE
    assert verdict.rating == Rating.INCONCLUSIVE


def test_rate_limit_failure_is_inconclusive():
    rating, breakdown, verdict = score_probe_results(
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
    assert verdict.risk_score == 0


def test_score_probe_results_returns_structured_verdict():
    rating, breakdown, verdict = score_probe_results(
        [
            ProbeResult(
                "messages_protocol",
                "passed",
                [EvidenceItem("anthropic_messages_shape", "strong", True, "ok", tags=["ANTHROPIC_NATIVE_SHAPE_MATCH"])],
            ),
            ProbeResult(
                "extended_thinking",
                "passed",
                [EvidenceItem("extended_thinking_expected", "strong", True, "ok", tags=["EXTENDED_THINKING_MATCH"])],
            ),
        ]
    )

    assert rating == Rating.HIGH_TRUST
    assert verdict.rating == Rating.HIGH_TRUST
    assert verdict.authenticity_score >= 90
    assert verdict.risk_score == 0
    assert "ANTHROPIC_NATIVE_SHAPE_MATCH" in verdict.tags


def test_high_risk_does_not_automatically_lower_authenticity_rating():
    rating, breakdown, verdict = score_probe_results(
        [
            ProbeResult("messages_protocol", "passed", [strong_evidence("anthropic_messages_shape", True)]),
            ProbeResult("extended_thinking", "passed", [strong_evidence("extended_thinking_expected", True)]),
            ProbeResult(
                "streaming_features",
                "warning",
                [
                    EvidenceItem(
                        "synthetic_stream_heuristic",
                        "weak",
                        False,
                        "synthetic stream suspected",
                        tags=["SYNTHETIC_STREAM_SUSPECT", "STREAM_UNIFORMITY_SUSPECT"],
                    )
                ],
            ),
        ]
    )

    assert rating == Rating.HIGH_TRUST
    assert verdict.rating == Rating.HIGH_TRUST
    assert verdict.authenticity_score >= 90
    assert verdict.risk_score > 0


def test_single_network_timeout_is_inconclusive_without_risk_score_spike():
    rating, breakdown, verdict = score_probe_results(
        [ProbeResult("streaming_features", "error", errors=["stream timeout after 5 seconds"])]
    )

    assert rating == Rating.INCONCLUSIVE
    assert verdict.rating == Rating.INCONCLUSIVE
    assert verdict.risk_score == 0
    assert "TTFT_VARIANCE_HIGH" not in verdict.tags


def test_cross_provider_model_leak_forces_low_trust_even_with_other_positive_evidence():
    rating, _, verdict = score_probe_results(
        [
            ProbeResult(
                "openai_chat_completions_shape",
                "passed",
                [
                    EvidenceItem(
                        "openai_chat_shape",
                        "strong",
                        True,
                        "shape",
                        tags=["OPENAI_CHAT_COMPLETION_SHAPE_MATCH"],
                    )
                ],
            ),
            ProbeResult(
                "openai_model_claim_consistency",
                "failed",
                [
                    EvidenceItem(
                        "openai_model_claim",
                        "weak",
                        False,
                        "cross provider",
                        tags=["CROSS_PROVIDER_MODEL_LEAKED"],
                    )
                ],
            ),
        ]
    )

    assert rating == Rating.LOW_TRUST
    assert verdict.rating == Rating.LOW_TRUST
    assert verdict.authenticity_score <= 39


def test_cross_provider_reasoning_leak_forces_low_trust_even_with_other_positive_evidence():
    rating, _, verdict = score_probe_results(
        [
            ProbeResult(
                "messages_protocol",
                "passed",
                [
                    EvidenceItem(
                        "anthropic_messages_shape",
                        "strong",
                        True,
                        "shape",
                        tags=["ANTHROPIC_NATIVE_SHAPE_MATCH"],
                    )
                ],
            ),
            ProbeResult(
                "reasoning_leakage",
                "failed",
                [EvidenceItem("reasoning", "weak", False, "leak", tags=["CROSS_PROVIDER_REASONING_LEAKED"])],
            ),
        ]
    )

    assert rating == Rating.LOW_TRUST
    assert verdict.authenticity_score <= 39
