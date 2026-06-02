import pytest

from tokenverify.relay_models import (
    RelayAuditConfigError,
    RelayAuditMode,
    RelayAuditProfile,
    RelayEvidence,
    RelayPackSummary,
    RelayResult,
    RelayRiskCategory,
    RelayRiskLevel,
    RelayRuntimeCategory,
    RelayVerdict,
    parse_relay_profile,
    parse_relay_scenario,
)


def test_relay_profile_validation_accepts_all_charter_values():
    assert parse_relay_profile(" general ") == RelayAuditProfile.GENERAL
    assert parse_relay_profile("STREAMING") == RelayAuditProfile.STREAMING
    assert parse_relay_profile("schema") == RelayAuditProfile.SCHEMA
    assert parse_relay_profile("privacy") == RelayAuditProfile.PRIVACY
    assert parse_relay_profile("full") == RelayAuditProfile.FULL


def test_relay_profile_validation_rejects_unknown_value():
    with pytest.raises(RelayAuditConfigError) as exc_info:
        parse_relay_profile("wrong-value")

    assert "Unknown relay audit profile" in str(exc_info.value)
    assert "general, streaming, schema, privacy, full" in str(exc_info.value)
    assert "wrong-value" not in str(exc_info.value)


def test_fake_scenario_validation_accepts_and_rejects_values():
    assert parse_relay_scenario(" PASS ") == RelayVerdict.PASS
    assert parse_relay_scenario("suspicious") == RelayVerdict.SUSPICIOUS
    assert parse_relay_scenario("fail") == RelayVerdict.FAIL
    assert parse_relay_scenario("inconclusive") == RelayVerdict.INCONCLUSIVE

    with pytest.raises(RelayAuditConfigError) as exc_info:
        parse_relay_scenario("demo")

    assert "Unknown relay fake-run scenario" in str(exc_info.value)
    assert "pass, suspicious, fail, inconclusive" in str(exc_info.value)
    assert "demo" not in str(exc_info.value)


def test_relay_result_contract_contains_required_public_fields():
    result = RelayResult(
        run_id="relay-fake-1234567890ab",
        profile=RelayAuditProfile.GENERAL,
        scenario=RelayVerdict.PASS,
        mode=RelayAuditMode.FAKE,
        model="example-model",
        endpoint_host="relay.example",
        endpoint_hash="abc123def4567890",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=RelayVerdict.PASS,
        risk_level=RelayRiskLevel.LOW,
        risk_categories=[RelayRiskCategory.MODEL_SUBSTITUTION],
        evidence=[
            RelayEvidence(
                key="relay_consistency",
                category=RelayRiskCategory.MODEL_SUBSTITUTION,
                status="pass",
                summary="Sanitized fake evidence.",
                metrics={"consistency_score": 0.98},
            )
        ],
        retest_guidance="Repeat with live mode only after explicit approval.",
    )

    assert result.verdict == RelayVerdict.PASS
    assert result.risk_level == RelayRiskLevel.LOW
    assert result.pack_summary.label == "No Pack"
    assert result.evidence[0].metrics["consistency_score"] == 0.98


def test_relay_mode_and_runtime_category_values_are_stable():
    assert RelayAuditMode.FAKE.value == "fake"
    assert RelayAuditMode.LIVE.value == "live"
    assert RelayRuntimeCategory.AUTH_ERROR.value == "auth_error"
    assert RelayRuntimeCategory.QUOTA_OR_RATE_LIMIT.value == "quota_or_rate_limit"
    assert RelayRuntimeCategory.TIMEOUT.value == "timeout"
    assert RelayRuntimeCategory.DISCONNECT.value == "disconnect"
    assert RelayRuntimeCategory.NETWORK_ERROR.value == "network_error"
    assert RelayRuntimeCategory.UNSUPPORTED_LIVE_TARGET.value == "unsupported_live_target"
    assert RelayRuntimeCategory.UNKNOWN_RUNTIME_ERROR.value == "unknown_runtime_error"


def test_relay_result_can_record_live_runtime_category():
    result = RelayResult(
        run_id="relay-live-1234567890abcdef",
        profile=RelayAuditProfile.GENERAL,
        scenario=RelayVerdict.INCONCLUSIVE,
        mode=RelayAuditMode.LIVE,
        model="example-model",
        endpoint_host="relay.example",
        endpoint_hash="abc123def4567890",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=RelayVerdict.INCONCLUSIVE,
        risk_level=RelayRiskLevel.UNKNOWN,
        risk_categories=[RelayRiskCategory.UPSTREAM_ERROR_LEAKAGE],
        evidence=[
            RelayEvidence(
                key="auth_error",
                category=RelayRiskCategory.UPSTREAM_ERROR_LEAKAGE,
                status="inconclusive",
                summary="Provider authentication or authorization error.",
            )
        ],
        retest_guidance="Check credentials, then rerun with --live.",
        inconclusive_reason="Provider authentication or authorization error.",
        runtime_category=RelayRuntimeCategory.AUTH_ERROR,
    )

    assert result.mode == RelayAuditMode.LIVE
    assert result.runtime_category == RelayRuntimeCategory.AUTH_ERROR
