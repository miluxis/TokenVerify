from tokenverify.relay_channel import classify_channel_observation
from tokenverify.relay_fingerprint import extract_relay_response_envelope
from tokenverify.relay_models import RelayChannelClaim, RelayRiskLevel, RelayVerdict


def _envelope(headers):
    return extract_relay_response_envelope(
        status_code=200,
        body={"id": "msg_bdrk_123", "model": "anthropic.claude-3-5-sonnet"},
        headers=headers,
    )


def test_channel_detects_official_claim_contradicted_by_bedrock_marker():
    result = classify_channel_observation(
        claim=RelayChannelClaim.OFFICIAL,
        envelope=_envelope({"x-amzn-requestid": "private"}),
    )

    assert result.verdict == RelayVerdict.FAIL
    assert result.risk_level == RelayRiskLevel.HIGH
    assert any(item.key == "channel_claim_consistency" and item.status == "fail" for item in result.evidence)


def test_channel_unknown_claim_with_marker_is_suspicious():
    result = classify_channel_observation(
        claim=RelayChannelClaim.UNKNOWN,
        envelope=_envelope({"x-amzn-requestid": "private"}),
    )

    assert result.verdict == RelayVerdict.SUSPICIOUS
    assert result.risk_level == RelayRiskLevel.MEDIUM


def test_channel_compatible_gateway_claims_are_not_detected():
    cases = [
        (RelayChannelClaim.BEDROCK, {"x-amzn-requestid": "private"}),
        (RelayChannelClaim.AZURE, {"x-ms-request-id": "private"}),
        (RelayChannelClaim.OPENROUTER, {"x-openrouter-route": "private"}),
        (RelayChannelClaim.PROXY, {"x-relay-upstream": "private"}),
    ]

    for claim, headers in cases:
        result = classify_channel_observation(claim=claim, envelope=_envelope(headers))
        assert result.verdict == RelayVerdict.PASS
        assert result.risk_level == RelayRiskLevel.LOW
        assert any(item.key == "channel_claim_consistency" and item.status == "pass" for item in result.evidence)


def test_channel_evidence_does_not_expose_raw_header_values():
    result = classify_channel_observation(
        claim=RelayChannelClaim.UNKNOWN,
        envelope=_envelope({"x-openrouter-route": "private-route-value"}),
    )

    assert "private-route-value" not in repr(result)
