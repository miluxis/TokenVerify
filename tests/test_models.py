from tokenverify.models import Claim, EvidenceTag, ProbeCategory, Rating, RiskTag, Verdict


def test_rating_values_are_stable_for_report_output():
    assert Rating.HIGH_TRUST.value == "High Trust"
    assert Rating.MEDIUM_TRUST.value == "Medium Trust"
    assert Rating.LOW_TRUST.value == "Low Trust"
    assert Rating.INCONCLUSIVE.value == "Inconclusive"


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


def test_openai_compatible_relay_tag_values_are_stable():
    assert EvidenceTag.OPENAI_COMPATIBLE_SHAPE_MATCH.value == "OPENAI_COMPATIBLE_SHAPE_MATCH"
    assert EvidenceTag.ANTHROPIC_NATIVE_SHAPE_DETECTED.value == "ANTHROPIC_NATIVE_SHAPE_DETECTED"
    assert EvidenceTag.CLAUDE_MODEL_CLAIM_MATCH.value == "CLAUDE_MODEL_CLAIM_MATCH"
    assert EvidenceTag.CLAUDE_MODEL_CLAIM_MISMATCH.value == "CLAUDE_MODEL_CLAIM_MISMATCH"
    assert EvidenceTag.OPENAI_STREAM_SEQUENCE_MATCH.value == "OPENAI_STREAM_SEQUENCE_MATCH"
    assert RiskTag.CROSS_PROVIDER_FINISH_REASON_SUSPECT.value == "CROSS_PROVIDER_FINISH_REASON_SUSPECT"
    assert RiskTag.SELF_RELAY_LOOP_DETECTED.value == "SELF_RELAY_LOOP_DETECTED"
    assert RiskTag.SYNTHETIC_THINKING_SUSPECT.value == "SYNTHETIC_THINKING_SUSPECT"


def test_claude_deep_dive_tag_values_are_stable():
    assert EvidenceTag.MIXED_PROVIDER_INCONSISTENCY_DETECTED.value == "MIXED_PROVIDER_INCONSISTENCY_DETECTED"
    assert EvidenceTag.CLAUDE_VERSION_FIELD_LEAKED.value == "CLAUDE_VERSION_FIELD_LEAKED"
    assert EvidenceTag.CLAUDE_THINKING_CAPABILITY_MATCH.value == "CLAUDE_THINKING_CAPABILITY_MATCH"
    assert EvidenceTag.CLAUDE_THINKING_CAPABILITY_MISMATCH.value == "CLAUDE_THINKING_CAPABILITY_MISMATCH"
    assert RiskTag.RELAY_HEADER_SUSPECT.value == "RELAY_HEADER_SUSPECT"
    assert RiskTag.RATE_LIMIT_RELAY_SUSPECT.value == "RATE_LIMIT_RELAY_SUSPECT"
    assert RiskTag.REGION_LATENCY_INCONSISTENT.value == "REGION_LATENCY_INCONSISTENT"
    assert RiskTag.MODEL_DRIFT_SUSPECT.value == "MODEL_DRIFT_SUSPECT"


def test_probe_category_values_are_stable():
    assert ProbeCategory.PROTOCOL.value == "protocol"
    assert ProbeCategory.CAPABILITY.value == "capability"
    assert ProbeCategory.STREAM.value == "stream"
    assert ProbeCategory.ERROR.value == "error"
    assert ProbeCategory.REPEATABILITY.value == "repeatability"
    assert ProbeCategory.CHANNEL_RISK.value == "channel_risk"


def test_openai_audit_tag_values_are_stable():
    assert EvidenceTag.OPENAI_CHAT_COMPLETION_SHAPE_MATCH.value == "OPENAI_CHAT_COMPLETION_SHAPE_MATCH"
    assert EvidenceTag.OPENAI_CHAT_COMPLETION_SHAPE_MISMATCH.value == "OPENAI_CHAT_COMPLETION_SHAPE_MISMATCH"
    assert EvidenceTag.NON_OPENAI_PROVIDER_SHAPE_DETECTED.value == "NON_OPENAI_PROVIDER_SHAPE_DETECTED"
    assert EvidenceTag.OPENAI_MODEL_CLAIM_MATCH.value == "OPENAI_MODEL_CLAIM_MATCH"
    assert EvidenceTag.OPENAI_MODEL_CLAIM_MISMATCH.value == "OPENAI_MODEL_CLAIM_MISMATCH"
    assert EvidenceTag.CROSS_PROVIDER_MODEL_LEAKED.value == "CROSS_PROVIDER_MODEL_LEAKED"
    assert EvidenceTag.OPENAI_STREAM_SEQUENCE_MATCH.value == "OPENAI_STREAM_SEQUENCE_MATCH"
    assert EvidenceTag.OPENAI_STREAM_SEQUENCE_MISMATCH.value == "OPENAI_STREAM_SEQUENCE_MISMATCH"
    assert EvidenceTag.OPENAI_REASONING_CAPABILITY_MATCH.value == "OPENAI_REASONING_CAPABILITY_MATCH"
    assert EvidenceTag.OPENAI_REASONING_CAPABILITY_MISMATCH.value == "OPENAI_REASONING_CAPABILITY_MISMATCH"
    assert EvidenceTag.OPENAI_OFFICIAL_CHANNEL_MATCH.value == "OPENAI_OFFICIAL_CHANNEL_MATCH"
    assert EvidenceTag.OPENAI_OFFICIAL_CHANNEL_MISMATCH.value == "OPENAI_OFFICIAL_CHANNEL_MISMATCH"


def test_deepseek_audit_tag_values_are_stable():
    assert EvidenceTag.DEEPSEEK_CHAT_COMPLETION_SHAPE_MATCH.value == "DEEPSEEK_CHAT_COMPLETION_SHAPE_MATCH"
    assert EvidenceTag.DEEPSEEK_CHAT_COMPLETION_SHAPE_MISMATCH.value == "DEEPSEEK_CHAT_COMPLETION_SHAPE_MISMATCH"
    assert EvidenceTag.NON_DEEPSEEK_PROVIDER_SHAPE_DETECTED.value == "NON_DEEPSEEK_PROVIDER_SHAPE_DETECTED"
    assert EvidenceTag.DEEPSEEK_MODEL_CLAIM_MATCH.value == "DEEPSEEK_MODEL_CLAIM_MATCH"
    assert EvidenceTag.DEEPSEEK_MODEL_CLAIM_MISMATCH.value == "DEEPSEEK_MODEL_CLAIM_MISMATCH"
    assert EvidenceTag.DEEPSEEK_REASONING_CONTENT_MATCH.value == "DEEPSEEK_REASONING_CONTENT_MATCH"
    assert EvidenceTag.DEEPSEEK_REASONING_CONTENT_MISSING.value == "DEEPSEEK_REASONING_CONTENT_MISSING"
    assert EvidenceTag.DEEPSEEK_STREAM_SEQUENCE_MATCH.value == "DEEPSEEK_STREAM_SEQUENCE_MATCH"
    assert EvidenceTag.DEEPSEEK_STREAM_SEQUENCE_MISMATCH.value == "DEEPSEEK_STREAM_SEQUENCE_MISMATCH"
    assert EvidenceTag.DEEPSEEK_STREAM_REASONING_MATCH.value == "DEEPSEEK_STREAM_REASONING_MATCH"
    assert EvidenceTag.DEEPSEEK_STREAM_REASONING_MISSING.value == "DEEPSEEK_STREAM_REASONING_MISSING"
    assert EvidenceTag.DEEPSEEK_OFFICIAL_CHANNEL_MATCH.value == "DEEPSEEK_OFFICIAL_CHANNEL_MATCH"
    assert EvidenceTag.DEEPSEEK_OFFICIAL_CHANNEL_MISMATCH.value == "DEEPSEEK_OFFICIAL_CHANNEL_MISMATCH"
