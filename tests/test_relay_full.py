import importlib

from tokenverify.relay_full import (
    FULL_SUBPROFILE_ORDER,
    aggregate_full_risk_level,
    aggregate_full_verdict,
    run_full_live_check,
)
from tokenverify.relay_models import (
    RelayAuditMode,
    RelayAuditProfile,
    RelayEvidence,
    RelayPackSummary,
    RelayResult,
    RelayRiskCategory,
    RelayRiskLevel,
    RelayRuntimeCategory,
    RelayVerdict,
)
from tokenverify.relay_safety import RelayLiveAuthorization


def test_full_profile_requires_privacy_runner_contract():
    relay_privacy = importlib.import_module("tokenverify.relay_privacy")

    assert hasattr(relay_privacy, "run_minimal_privacy_live_check")
    assert hasattr(relay_privacy, "detect_privacy_marker_leak")
    assert hasattr(relay_privacy, "is_exact_public_ok_reply")


def test_privacy_marker_detection_is_case_and_unicode_escape_aware():
    relay_privacy = importlib.import_module("tokenverify.relay_privacy")

    assert relay_privacy.detect_privacy_marker_leak("TV_PRIVACY_MARKER_DO_NOT_ECHO")
    assert relay_privacy.detect_privacy_marker_leak("tv_privacy_marker_do_not_echo")
    assert relay_privacy.detect_privacy_marker_leak("\\u0054\\u0056_PRIVACY_MARKER_DO_NOT_ECHO")


def test_privacy_ok_exact_answer_normalizes_safe_punctuation_noise():
    relay_privacy = importlib.import_module("tokenverify.relay_privacy")

    assert relay_privacy.is_exact_public_ok_reply("OK")
    assert relay_privacy.is_exact_public_ok_reply("OK.")
    assert relay_privacy.is_exact_public_ok_reply("OK\n")
    assert relay_privacy.is_exact_public_ok_reply('"OK"')
    assert relay_privacy.is_exact_public_ok_reply("'OK'")
    assert not relay_privacy.is_exact_public_ok_reply("OK here is more text")


def make_subprofile_result(profile, verdict=RelayVerdict.PASS, risk=RelayRiskLevel.LOW):
    return RelayResult(
        run_id=f"relay-{profile.value}-run",
        profile=profile,
        scenario=verdict,
        mode=RelayAuditMode.LIVE,
        model="example-model",
        endpoint_host="relay.example",
        endpoint_hash="abcd1234abcd1234",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        verdict=verdict,
        risk_level=risk,
        risk_categories=[RelayRiskCategory.LATENCY_OR_INSTABILITY],
        evidence=[
            RelayEvidence(
                key=f"{profile.value}_safe_evidence",
                category=RelayRiskCategory.LATENCY_OR_INSTABILITY,
                status="observed",
                summary=f"{profile.value} safe summary",
                metrics={"profile": profile.value},
            )
        ],
        retest_guidance=f"Rerun {profile.value}.",
    )


def test_aggregate_full_verdict_uses_conservative_precedence():
    assert aggregate_full_verdict(
        [RelayVerdict.PASS, RelayVerdict.SUSPICIOUS, RelayVerdict.INCONCLUSIVE]
    ) == RelayVerdict.SUSPICIOUS
    assert aggregate_full_verdict(
        [RelayVerdict.PASS, RelayVerdict.FAIL, RelayVerdict.SUSPICIOUS]
    ) == RelayVerdict.FAIL
    assert aggregate_full_verdict(
        [RelayVerdict.PASS, RelayVerdict.INCONCLUSIVE]
    ) == RelayVerdict.INCONCLUSIVE
    assert aggregate_full_verdict([RelayVerdict.PASS, RelayVerdict.PASS]) == RelayVerdict.PASS


def test_aggregate_full_risk_uses_conservative_precedence():
    assert aggregate_full_risk_level([RelayRiskLevel.LOW, RelayRiskLevel.UNKNOWN]) == RelayRiskLevel.UNKNOWN
    assert aggregate_full_risk_level([RelayRiskLevel.LOW, RelayRiskLevel.MEDIUM]) == RelayRiskLevel.MEDIUM
    assert aggregate_full_risk_level([RelayRiskLevel.MEDIUM, RelayRiskLevel.HIGH]) == RelayRiskLevel.HIGH
    assert aggregate_full_risk_level([RelayRiskLevel.LOW, RelayRiskLevel.LOW]) == RelayRiskLevel.LOW


def test_full_orchestrator_runs_subprofiles_in_order():
    calls = []

    def runner(profile):
        calls.append(profile)
        return make_subprofile_result(profile)

    result = run_full_live_check(
        authorization=RelayLiveAuthorization(
            live_mode=True,
            profile=RelayAuditProfile.FULL,
            approved_live_path="full_composite_profile",
            network_scope="approved_subprofile_sequence",
        ),
        endpoint="https://relay.example/v1/chat/completions?token=secret#frag",
        model="example-model",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        subprofile_runner=runner,
    )

    assert tuple(calls) == FULL_SUBPROFILE_ORDER
    assert result.profile == RelayAuditProfile.FULL
    assert result.verdict == RelayVerdict.PASS
    assert result.risk_level == RelayRiskLevel.LOW
    assert result.endpoint_host == "relay.example"
    assert result.endpoint_hash


def test_full_orchestrator_converts_raw_subprofile_exception_to_sanitized_inconclusive():
    def runner(profile):
        if profile == RelayAuditProfile.SCHEMA:
            raise RuntimeError(
                'https://api.relay.com/v1/chat/completions?token=secret#frag '
                'data: {"choices": [{"delta": {"content": "raw stream chunk must not appear"}}]} '
                '{"tool_calls": [{"function": {"arguments": "raw schema args must not appear"}}]} '
                '{"messages": [{"role": "system", "content": "TV_PRIVACY_MARKER_DO_NOT_ECHO"}]} '
                "Authorization: Bearer sk-or-v1-private-token"
            )
        return make_subprofile_result(profile)

    result = run_full_live_check(
        authorization=RelayLiveAuthorization(
            live_mode=True,
            profile=RelayAuditProfile.FULL,
            approved_live_path="full_composite_profile",
            network_scope="approved_subprofile_sequence",
        ),
        endpoint="https://relay.example/v1",
        model="example-model",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        subprofile_runner=runner,
    )

    rendered = repr(result)
    assert result.verdict == RelayVerdict.INCONCLUSIVE
    assert result.runtime_category == RelayRuntimeCategory.UNKNOWN_RUNTIME_ERROR
    assert "raw stream chunk must not appear" not in rendered
    assert "raw schema args must not appear" not in rendered
    assert "TV_PRIVACY_MARKER_DO_NOT_ECHO" not in rendered
    assert "sk-or-v1-private-token" not in rendered
