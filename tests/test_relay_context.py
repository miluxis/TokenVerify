from tokenverify.relay_context import (
    ContextProbeStatus,
    classify_context_anchor_sequence,
    classify_context_middle_response,
    is_exact_context_answer,
    normalize_context_answer,
    run_minimal_context_live_check,
)
from tokenverify.relay_live import RelayLiveTransportResponse
from tokenverify.relay_models import RelayAuditProfile, RelayPackSummary, RelayRiskLevel, RelayVerdict
from tokenverify.relay_safety import authorize_relay_live_execution
from tokenverify.relay_safety import sanitize_public_relay_text


def test_sanitize_public_relay_text_removes_context_anchors_case_and_unicode_variants():
    raw = (
        "tv_ctx_alpha TV_CTX_BRAVO Tv_Ctx_Charlie "
        "\\u0054\\u0056_CTX_MIDDLE "
        "sk-or-v1-secret https://relay.example/v1/chat/completions"
    )

    cleaned = sanitize_public_relay_text(raw)

    assert "tv_ctx_alpha" not in cleaned.lower()
    assert "tv_ctx_bravo" not in cleaned.lower()
    assert "tv_ctx_charlie" not in cleaned.lower()
    assert "tv_ctx_middle" not in cleaned.lower()
    assert "\\u0054\\u0056_CTX_MIDDLE" not in cleaned
    assert "sk-or-v1-secret" not in cleaned
    assert "/v1/chat/completions" not in cleaned


def test_context_answer_normalization_accepts_wrapping_noise_and_pipe_spacing():
    assert (
        normalize_context_answer(" `TV_CTX_ALPHA | tv_ctx_bravo | TV_CTX_CHARLIE.` ")
        == "TV_CTX_ALPHA|TV_CTX_BRAVO|TV_CTX_CHARLIE"
    )
    assert normalize_context_answer('"tv_ctx_middle."') == "TV_CTX_MIDDLE"


def test_context_answer_normalization_does_not_turn_degraded_separators_into_exact_match():
    assert not is_exact_context_answer(
        "TV_CTX_ALPHA, TV_CTX_BRAVO, TV_CTX_CHARLIE",
        "TV_CTX_ALPHA|TV_CTX_BRAVO|TV_CTX_CHARLIE",
    )
    assert not is_exact_context_answer(
        "TV_CTX_ALPHA\nTV_CTX_BRAVO\nTV_CTX_CHARLIE",
        "TV_CTX_ALPHA|TV_CTX_BRAVO|TV_CTX_CHARLIE",
    )


def test_context_sequence_exact_match_is_pass():
    observation = classify_context_anchor_sequence("TV_CTX_ALPHA|TV_CTX_BRAVO|TV_CTX_CHARLIE")

    assert observation.status == ContextProbeStatus.PASS
    assert observation.anchor_missing_count == 0
    assert observation.separator_degradation_detected is False


def test_context_sequence_separator_degradation_is_suspicious_not_pass():
    observation = classify_context_anchor_sequence("TV_CTX_ALPHA, TV_CTX_BRAVO, TV_CTX_CHARLIE")

    assert observation.status == ContextProbeStatus.SUSPICIOUS
    assert observation.anchor_missing_count == 0
    assert observation.anchor_order_preserved is True
    assert observation.separator_degradation_detected is True


def test_context_sequence_missing_anchor_is_fail():
    observation = classify_context_anchor_sequence("TV_CTX_ALPHA|TV_CTX_CHARLIE")

    assert observation.status == ContextProbeStatus.FAIL
    assert observation.anchor_missing_count == 1
    assert observation.anchor_order_preserved is False


def test_context_middle_wrong_closing_anchor_is_fail():
    observation = classify_context_middle_response("TV_CTX_CLOSING")

    assert observation.status == ContextProbeStatus.FAIL
    assert observation.middle_anchor_selected is False
    assert observation.closing_anchor_wrongly_selected is True


def _context_authorization():
    return authorize_relay_live_execution(live_mode=True, profile=RelayAuditProfile.CONTEXT)


def _openai_context_response(content: str, finish_reason: str = "stop") -> RelayLiveTransportResponse:
    return RelayLiveTransportResponse(
        status_code=200,
        body={"choices": [{"message": {"content": content}, "finish_reason": finish_reason}]},
    )


def test_context_live_runner_passes_when_all_anchors_are_exact():
    responses = iter(
        [
            _openai_context_response("TV_CTX_ALPHA|TV_CTX_BRAVO|TV_CTX_CHARLIE"),
            _openai_context_response("TV_CTX_MIDDLE"),
        ]
    )
    payloads = []

    def transport(payload):
        payloads.append(payload)
        return next(responses)

    result = run_minimal_context_live_check(
        authorization=_context_authorization(),
        endpoint="https://relay.example/v1",
        model="demo-model",
        api_key="sk-test",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        transport=transport,
    )

    assert result.verdict == RelayVerdict.PASS
    assert result.risk_level == RelayRiskLevel.LOW
    assert len(payloads) == 2
    assert all(payload["stream"] is False for payload in payloads)
    assert max(payload["max_tokens"] for payload in payloads) <= 64


def test_context_live_runner_marks_separator_degradation_suspicious():
    responses = iter(
        [
            _openai_context_response("TV_CTX_ALPHA, TV_CTX_BRAVO, TV_CTX_CHARLIE"),
            _openai_context_response("TV_CTX_MIDDLE"),
        ]
    )

    def transport(payload):
        return next(responses)

    result = run_minimal_context_live_check(
        authorization=_context_authorization(),
        endpoint="https://relay.example/v1",
        model="demo-model",
        api_key="sk-test",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        transport=transport,
    )

    assert result.verdict == RelayVerdict.SUSPICIOUS
    assert result.risk_level == RelayRiskLevel.MEDIUM
    assert any(item.metrics.get("separator_degradation_detected") is True for item in result.evidence)


def test_context_live_runner_fails_on_missing_anchor_without_leaking_text():
    responses = iter(
        [
            _openai_context_response("TV_CTX_ALPHA|TV_CTX_CHARLIE"),
            _openai_context_response("TV_CTX_MIDDLE"),
        ]
    )

    def transport(payload):
        return next(responses)

    result = run_minimal_context_live_check(
        authorization=_context_authorization(),
        endpoint="https://relay.example/v1/private?token=raw",
        model="demo-model",
        api_key="sk-test",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        transport=transport,
    )

    public_text = repr(result)
    assert result.verdict == RelayVerdict.FAIL
    assert result.risk_level == RelayRiskLevel.HIGH
    assert "TV_CTX_ALPHA" not in public_text
    assert "TV_CTX_BRAVO" not in public_text
    assert "/private?token=raw" not in public_text


def test_context_live_runner_inconclusive_on_transport_runtime_error_without_raw_leakage():
    def transport(payload):
        raise TimeoutError(
            "timeout with TV_CTX_ALPHA at https://relay.example/v1/private "
            "Authorization: Bearer sk-secret"
        )

    result = run_minimal_context_live_check(
        authorization=_context_authorization(),
        endpoint="https://relay.example/v1/private",
        model="demo-model",
        api_key="sk-test",
        pack_summary=RelayPackSummary(label="No Pack", pack_hash=None),
        transport=transport,
    )

    public_text = repr(result)
    assert result.verdict == RelayVerdict.INCONCLUSIVE
    assert result.risk_level == RelayRiskLevel.UNKNOWN
    assert result.runtime_category is not None
    assert "TV_CTX_ALPHA" not in public_text
    assert "sk-secret" not in public_text
    assert "/v1/private" not in public_text
