import traceback

import pytest

from tokenverify.relay_live import (
    RelayLiveRuntimeError,
    RelayLiveTransportResponse,
    build_minimal_live_payload,
    normalize_live_runtime_error,
    run_minimal_general_live_check,
)
from tokenverify.relay_models import RelayAuditMode, RelayAuditProfile, RelayPackSummary, RelayRiskLevel, RelayRuntimeCategory, RelayVerdict
from tokenverify.relay_safety import authorize_relay_live_execution


@pytest.mark.parametrize(
    ("raw_error", "category"),
    [
        ("HTTP 401 auth failed https://api.relay.com/v1?token=secret", RelayRuntimeCategory.AUTH_ERROR),
        ("403 authorization denied with Bearer sk-secret", RelayRuntimeCategory.AUTH_ERROR),
        ("429 rate limit exceeded raw body hidden", RelayRuntimeCategory.QUOTA_OR_RATE_LIMIT),
        ("quota exhausted", RelayRuntimeCategory.QUOTA_OR_RATE_LIMIT),
        ("request timeout after 30s", RelayRuntimeCategory.TIMEOUT),
        ("504 gateway timeout from upstream", RelayRuntimeCategory.TIMEOUT),
        ("connection reset by peer", RelayRuntimeCategory.DISCONNECT),
        ("remote disconnect incomplete read", RelayRuntimeCategory.DISCONNECT),
        ("DNS failure for https://api.relay.com/v1?user=heiyan_studio", RelayRuntimeCategory.NETWORK_ERROR),
        ("502 bad gateway", RelayRuntimeCategory.NETWORK_ERROR),
        ("503 service unavailable", RelayRuntimeCategory.NETWORK_ERROR),
    ],
)
def test_normalize_live_runtime_error_maps_categories_and_sanitizes_text(raw_error, category):
    normalized = normalize_live_runtime_error(Exception(raw_error))

    assert normalized.category == category
    assert normalized.public_message
    assert "https://" not in normalized.public_message
    assert "/v1" not in normalized.public_message
    assert "token=secret" not in normalized.public_message
    assert "sk-secret" not in normalized.public_message
    assert "heiyan_studio" not in normalized.public_message


def test_normalized_runtime_error_does_not_keep_raw_exception_chain():
    raw = RuntimeError("raw provider body https://api.relay.com/v1?token=secret Authorization: Bearer sk-secret")
    normalized = normalize_live_runtime_error(raw)

    with pytest.raises(RelayLiveRuntimeError) as exc_info:
        normalized.raise_for_public_handling()

    exc = exc_info.value
    rendered = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    assert exc.__cause__ is None
    assert "Provider authentication or authorization error." in rendered
    assert "https://" not in rendered
    assert "/v1" not in rendered
    assert "token=secret" not in rendered
    assert "sk-secret" not in rendered
    assert "raw provider body" not in rendered


def test_unknown_runtime_error_uses_sanitized_fallback():
    normalized = normalize_live_runtime_error(ValueError("unexpected https://api.relay.com/v1?secret=1"))

    assert normalized.category == RelayRuntimeCategory.UNKNOWN_RUNTIME_ERROR
    assert normalized.public_message == "Provider runtime error before a conclusive relay result."


def test_minimal_live_payload_is_small_non_streaming_and_non_sensitive():
    payload = build_minimal_live_payload("example-model")

    assert payload["model"] == "example-model"
    assert payload["stream"] is False
    assert payload["max_tokens"] <= 16
    assert "tools" not in payload
    assert "response_format" not in payload
    assert "schema" not in str(payload).lower()
    assert "reasoning" not in str(payload).lower()
    assert "secret" not in str(payload).lower()


def test_minimal_live_success_returns_pass_without_overclaiming():
    calls = []

    def transport(payload):
        calls.append(payload)
        return RelayLiveTransportResponse(
            status_code=200,
            body={"choices": [{"message": {"content": "ok"}}]},
        )

    auth = authorize_relay_live_execution(live_mode=True, profile=RelayAuditProfile.GENERAL)
    result = run_minimal_general_live_check(
        authorization=auth,
        endpoint="https://api.relay.com/v1/chat/completions?user=heiyan_studio#frag",
        model="example-model",
        api_key="sk-secret",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        transport=transport,
    )

    assert len(calls) == 1
    assert result.mode == RelayAuditMode.LIVE
    assert result.verdict == RelayVerdict.PASS
    assert result.risk_level == RelayRiskLevel.LOW
    assert result.endpoint_host == "api.relay.com"
    assert "minimal live connectivity check completed" in result.evidence[0].summary.lower()
    assert "verified" not in result.evidence[0].summary.lower()
    assert "sk-secret" not in str(result)
    assert "/v1" not in str(result)


def test_minimal_live_runtime_failure_returns_inconclusive_result():
    def transport(payload):
        raise RuntimeError("HTTP 401 https://api.relay.com/v1?token=secret Authorization: Bearer sk-secret")

    auth = authorize_relay_live_execution(live_mode=True, profile=RelayAuditProfile.GENERAL)
    result = run_minimal_general_live_check(
        authorization=auth,
        endpoint="https://api.relay.com/v1?token=secret",
        model="example-model",
        api_key="sk-secret",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        transport=transport,
    )

    assert result.mode == RelayAuditMode.LIVE
    assert result.verdict == RelayVerdict.INCONCLUSIVE
    assert result.risk_level == RelayRiskLevel.UNKNOWN
    assert result.runtime_category == RelayRuntimeCategory.AUTH_ERROR
    assert "Provider authentication or authorization error." in result.inconclusive_reason
    assert "https://" not in str(result)
    assert "token=secret" not in str(result)
    assert "sk-secret" not in str(result)


@pytest.mark.parametrize(
    ("status_code", "category"),
    [
        (401, RelayRuntimeCategory.AUTH_ERROR),
        (403, RelayRuntimeCategory.AUTH_ERROR),
        (429, RelayRuntimeCategory.QUOTA_OR_RATE_LIMIT),
        (502, RelayRuntimeCategory.NETWORK_ERROR),
        (503, RelayRuntimeCategory.NETWORK_ERROR),
        (504, RelayRuntimeCategory.TIMEOUT),
        (418, RelayRuntimeCategory.UNKNOWN_RUNTIME_ERROR),
    ],
)
def test_minimal_live_non_success_status_codes_are_inconclusive(status_code, category):
    def transport(payload):
        return RelayLiveTransportResponse(status_code=status_code, body={"error": "raw upstream body hidden"})

    auth = authorize_relay_live_execution(live_mode=True, profile=RelayAuditProfile.GENERAL)
    result = run_minimal_general_live_check(
        authorization=auth,
        endpoint="https://api.relay.com/v1?token=secret",
        model="example-model",
        api_key="sk-secret",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        transport=transport,
    )

    assert result.verdict == RelayVerdict.INCONCLUSIVE
    assert result.risk_level == RelayRiskLevel.UNKNOWN
    assert result.runtime_category == category
    assert "raw upstream body hidden" not in str(result)
