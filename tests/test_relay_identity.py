from tokenverify.relay_identity import classify_identity_observation
from tokenverify.relay_fingerprint import extract_relay_response_envelope
from tokenverify.relay_models import RelayRiskLevel, RelayVerdict


def _envelope(body, headers=None):
    return extract_relay_response_envelope(status_code=200, body=body, headers=headers or {})


def test_identity_passes_when_claude_claim_matches_claude_envelope():
    result = classify_identity_observation(
        claimed_model="claude-opus-4-5-20251101",
        envelope=_envelope({"id": "msg_123", "model": "claude-opus-4-5-20251101", "type": "message"}),
        self_report_text="Claude",
    )

    assert result.verdict == RelayVerdict.PASS
    assert result.risk_level == RelayRiskLevel.LOW


def test_identity_fails_on_cross_provider_model_field():
    result = classify_identity_observation(
        claimed_model="claude-opus-4-5-20251101",
        envelope=_envelope({"id": "chatcmpl-123", "model": "gpt-5", "system_fingerprint": "fp_secret"}),
        self_report_text=None,
    )

    assert result.verdict == RelayVerdict.FAIL
    assert result.risk_level == RelayRiskLevel.HIGH
    assert any(item.key == "identity_model_field_consistency" and item.status == "fail" for item in result.evidence)


def test_identity_self_report_only_is_suspicious_not_fail():
    result = classify_identity_observation(
        claimed_model="claude-opus-4-5-20251101",
        envelope=_envelope({"id": "msg_123", "model": "claude-opus-4-5-20251101", "type": "message"}),
        self_report_text="I am Qwen.",
    )

    assert result.verdict == RelayVerdict.SUSPICIOUS
    assert result.risk_level == RelayRiskLevel.MEDIUM
    assert not any(item.status == "fail" for item in result.evidence)


def test_identity_omits_candidate_scores_when_no_signal_exists():
    result = classify_identity_observation(
        claimed_model="claude-opus-4-5-20251101",
        envelope=_envelope({"id": "msg_123", "model": "claude-opus-4-5-20251101", "type": "message"}),
        self_report_text=None,
    )

    assert not any(item.key == "identity_candidate_family_scores" for item in result.evidence)
