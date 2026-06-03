import traceback

from tokenverify.relay_live import RelayLiveTransportResponse
from tokenverify.relay_models import (
    RelayAuditMode,
    RelayAuditProfile,
    RelayPackSummary,
    RelayRiskLevel,
    RelayRuntimeCategory,
    RelayVerdict,
)
from tokenverify.relay_privacy import (
    RelayPrivacyRuntimeError,
    build_minimal_privacy_payload,
    detect_privacy_marker_leak,
    is_exact_public_ok_reply,
    normalize_privacy_response,
    run_minimal_privacy_live_check,
)
from tokenverify.relay_safety import RelayLiveAuthorization


def test_privacy_marker_detection_is_case_and_unicode_escape_aware():
    assert detect_privacy_marker_leak("TV_PRIVACY_MARKER_DO_NOT_ECHO")
    assert detect_privacy_marker_leak("tv_privacy_marker_do_not_echo")
    assert detect_privacy_marker_leak("\\u0054\\u0056_PRIVACY_MARKER_DO_NOT_ECHO")


def test_privacy_ok_exact_answer_normalizes_safe_punctuation_noise():
    assert is_exact_public_ok_reply("OK")
    assert is_exact_public_ok_reply("OK.")
    assert is_exact_public_ok_reply("OK\n")
    assert is_exact_public_ok_reply('"OK"')
    assert is_exact_public_ok_reply("'OK'")
    assert not is_exact_public_ok_reply("OK here is more text")


def test_minimal_privacy_payload_is_public_and_non_streaming():
    payload = build_minimal_privacy_payload("example-model")

    assert payload["model"] == "example-model"
    assert payload["stream"] is False
    assert payload["max_tokens"] == 32
    assert "TV_PRIVACY_MARKER_DO_NOT_ECHO" in repr(payload)
    assert "private expected answer" not in repr(payload)
    assert "secret verifier expression" not in repr(payload)


def test_normalize_privacy_response_detects_exact_answer_and_rewrite():
    exact = normalize_privacy_response(
        RelayLiveTransportResponse(
            status_code=200,
            body={"choices": [{"message": {"content": "OK."}, "finish_reason": "stop"}]},
        )
    )
    rewrite = normalize_privacy_response(
        RelayLiveTransportResponse(
            status_code=200,
            body={"choices": [{"message": {"content": "OK here is more text"}, "finish_reason": "stop"}]},
        )
    )

    assert exact.exact_public_answer_observed is True
    assert exact.message_rewrite_detected is False
    assert rewrite.exact_public_answer_observed is False
    assert rewrite.extra_content_detected is True
    assert rewrite.message_rewrite_detected is True


def test_run_minimal_privacy_live_check_fails_marker_leak_without_rendering_marker():
    def transport(payload):
        return RelayLiveTransportResponse(
            status_code=200,
            body={
                "choices": [
                    {
                        "message": {"content": "tv_privacy_marker_do_not_echo"},
                        "finish_reason": "stop",
                    }
                ]
            },
        )

    result = run_minimal_privacy_live_check(
        authorization=RelayLiveAuthorization(
            live_mode=True,
            profile=RelayAuditProfile.PRIVACY,
            approved_live_path="privacy_minimal_contract",
            network_scope="single_privacy_request",
        ),
        endpoint="https://api.relay.com/v1/chat/completions?token=secret#frag",
        model="example-model",
        api_key="sk-secret",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        transport=transport,
    )

    rendered = repr(result)
    assert result.profile == RelayAuditProfile.PRIVACY
    assert result.mode == RelayAuditMode.LIVE
    assert result.verdict == RelayVerdict.FAIL
    assert result.risk_level == RelayRiskLevel.HIGH
    assert "TV_PRIVACY_MARKER_DO_NOT_ECHO" not in rendered
    assert "tv_privacy_marker_do_not_echo" not in rendered
    assert "token=secret" not in rendered
    assert "sk-secret" not in rendered


def test_run_minimal_privacy_live_check_marks_message_rewrite_suspicious():
    def transport(payload):
        return RelayLiveTransportResponse(
            status_code=200,
            body={"choices": [{"message": {"content": "OK here is more text"}, "finish_reason": "stop"}]},
        )

    result = run_minimal_privacy_live_check(
        authorization=RelayLiveAuthorization(
            live_mode=True,
            profile=RelayAuditProfile.PRIVACY,
            approved_live_path="privacy_minimal_contract",
            network_scope="single_privacy_request",
        ),
        endpoint="https://api.relay.com/v1",
        model="example-model",
        api_key="sk-secret",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        transport=transport,
    )

    assert result.verdict == RelayVerdict.SUSPICIOUS
    assert result.risk_level == RelayRiskLevel.MEDIUM
    assert any(item.key == "privacy_exact_answer" for item in result.evidence)


def test_run_minimal_privacy_live_check_marks_provider_disclosure_suspicious_without_raw_output():
    def transport(payload):
        return RelayLiveTransportResponse(
            status_code=200,
            body={
                "choices": [
                    {
                        "message": {"content": "Provider gateway disclosed upstream metadata."},
                        "finish_reason": "stop",
                    }
                ]
            },
        )

    result = run_minimal_privacy_live_check(
        authorization=RelayLiveAuthorization(
            live_mode=True,
            profile=RelayAuditProfile.PRIVACY,
            approved_live_path="privacy_minimal_contract",
            network_scope="single_privacy_request",
        ),
        endpoint="https://api.relay.com/v1",
        model="example-model",
        api_key="sk-secret",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        transport=transport,
    )

    rendered = repr(result)
    assert result.verdict == RelayVerdict.SUSPICIOUS
    assert result.risk_level == RelayRiskLevel.MEDIUM
    assert "Provider gateway disclosed upstream metadata" not in rendered
    assert any(item.key == "privacy_upstream_error_disclosure" for item in result.evidence)


def test_privacy_runtime_error_traceback_cuts_raw_exception_chain():
    try:
        try:
            raise RuntimeError("raw privacy output must not appear")
        except RuntimeError:
            raise RelayPrivacyRuntimeError(
                RelayRuntimeCategory.UNKNOWN_RUNTIME_ERROR,
                "Provider privacy runtime error before a conclusive relay result.",
            ) from None
    except RelayPrivacyRuntimeError as exc:
        rendered = "".join(traceback.format_exception(exc))

    assert "raw privacy output must not appear" not in rendered
    assert "Provider privacy runtime error" in rendered
