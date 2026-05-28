from tokenverify.models import Claim, EvidenceTag, Rating, RiskTag, Verdict


def test_rating_values_are_stable_for_report_output():
    assert Rating.HIGH_TRUST.value == "高可信"
    assert Rating.MEDIUM_TRUST.value == "中可信"
    assert Rating.LOW_TRUST.value == "低可信"
    assert Rating.INCONCLUSIVE.value == "无法判定"


def test_claim_defaults_to_anthropic_native_when_no_shape_hint_exists():
    claim = Claim(model="claude-sonnet-4-5")

    assert claim.provider == "anthropic"
    assert claim.api_shape == "native"
    assert claim.model == "claude-sonnet-4-5"
    assert claim.channel_claim == "unknown"
    assert claim.region_claim is None


def test_verdict_exposes_authenticity_and_risk_scores_separately():
    verdict = Verdict(
        rating=Rating.MEDIUM_TRUST,
        authenticity_score=78,
        risk_score=42,
        tags=[EvidenceTag.EXTENDED_THINKING_MATCH.value, RiskTag.STREAM_UNIFORMITY_SUSPECT.value],
    )

    assert verdict.rating == Rating.MEDIUM_TRUST
    assert verdict.authenticity_score == 78
    assert verdict.risk_score == 42
    assert "EXTENDED_THINKING_MATCH" in verdict.tags
    assert "STREAM_UNIFORMITY_SUSPECT" in verdict.tags


def test_tag_values_are_stable_for_dashboard_rules():
    assert EvidenceTag.CROSS_PROVIDER_REASONING_LEAKED.value == "CROSS_PROVIDER_REASONING_LEAKED"
    assert RiskTag.TTFT_VARIANCE_HIGH.value == "TTFT_VARIANCE_HIGH"
