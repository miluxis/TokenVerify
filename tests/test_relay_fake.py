from tokenverify.relay_fake import build_fake_relay_result
from tokenverify.relay_models import RelayAuditProfile, RelayPackSummary, RelayRiskLevel, RelayVerdict


FORBIDDEN = [
    "https://",
    "/v1",
    "chat/completions",
    "heiyan_studio",
    "Authorization",
    "Bearer",
    "sk-secret",
    "raw prompt",
    "raw output",
    "expected answer",
]


def _result(scenario: RelayVerdict, profile: RelayAuditProfile = RelayAuditProfile.GENERAL):
    return build_fake_relay_result(
        profile=profile,
        scenario=scenario,
        endpoint="https://api.relay.com/v1/chat/completions?user=heiyan_studio#frag",
        model="example-model",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
    )


def test_all_fake_scenarios_are_deterministic_and_non_empty():
    for scenario in RelayVerdict:
        first = _result(scenario)
        second = _result(scenario)

        assert first == second
        assert first.run_id.startswith("relay-fake-")
        assert first.evidence
        assert all(item.summary for item in first.evidence)


def test_fake_scenarios_map_to_expected_verdicts_and_risk_levels():
    assert _result(RelayVerdict.PASS).risk_level == RelayRiskLevel.LOW
    assert _result(RelayVerdict.SUSPICIOUS).risk_level == RelayRiskLevel.MEDIUM
    assert _result(RelayVerdict.FAIL).risk_level == RelayRiskLevel.HIGH
    assert _result(RelayVerdict.INCONCLUSIVE).risk_level == RelayRiskLevel.UNKNOWN
    assert _result(RelayVerdict.INCONCLUSIVE).inconclusive_reason is not None


def test_fake_evidence_is_sanitized_and_host_only():
    result = _result(RelayVerdict.SUSPICIOUS)
    rendered = str(result)

    assert result.endpoint_host == "api.relay.com"
    assert len(result.endpoint_hash) == 16
    for forbidden in FORBIDDEN:
        assert forbidden not in rendered


def test_non_general_profiles_include_skipped_profile_evidence():
    result = _result(RelayVerdict.PASS, profile=RelayAuditProfile.STREAMING)

    assert result.profile == RelayAuditProfile.STREAMING
    assert any(item.status == "skipped" for item in result.evidence)
    assert any("not implemented" in item.summary.lower() for item in result.evidence)
