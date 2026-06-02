import traceback

import pytest

from tokenverify.relay_models import (
    RelayAuditMode,
    RelayAuditProfile,
    RelayPackSummary,
    RelayRiskCategory,
    RelayRiskLevel,
    RelayRuntimeCategory,
    RelayVerdict,
)
from tokenverify.relay_safety import authorize_relay_live_execution
from tokenverify.relay_streaming import (
    RelayStreamEvent,
    RelayStreamingRuntimeError,
    build_minimal_streaming_payload,
    normalize_stream_event,
    normalize_stream_runtime_error,
    run_minimal_streaming_live_check,
)


SENSITIVE_STREAM_FIXTURES = [
    "heiyan_studio",
    "StudioSecret",
    "/Users/Teng/Desktop/heiyan_studio/private.yaml",
    "https://api.relay.com/v1/chat/completions?token=secret#frag",
    "Authorization: Bearer sk-or-v1-private-token",
    "raw stream chunk text must not appear",
    'data: {"choices": [{"delta": {"content": "raw stream chunk text must not appear"}}]}',
    '{"choices": [{"delta": {"content": "raw stream chunk text must not appear"}}]}',
    "private expected answer",
    "secret verifier expression",
]


def assert_public_text_is_clean(text: str):
    for fixture in SENSITIVE_STREAM_FIXTURES:
        assert fixture not in text
    assert "data:" not in text
    assert '{"choices"' not in text


def test_minimal_streaming_payload_is_small_streaming_and_non_sensitive():
    payload = build_minimal_streaming_payload("Example Model /Users/Teng/heiyan_studio")

    assert payload == {
        "model": "Example Model heiyan_studio",
        "messages": [{"role": "user", "content": "Return only: ok"}],
        "max_tokens": 16,
        "stream": True,
    }
    rendered = repr(payload)
    assert "private expected answer" not in rendered
    assert "secret verifier expression" not in rendered
    assert "/Users/Teng" not in rendered


def test_normalize_stream_event_keeps_metadata_not_raw_delta_content():
    event = normalize_stream_event(
        {
            "object": "chat.completion.chunk",
            "choices": [
                {
                    "delta": {"content": "raw stream chunk text must not appear"},
                    "finish_reason": None,
                }
            ],
        },
        index=0,
    )

    assert event == RelayStreamEvent(
        event_type="chat.completion.chunk",
        index=0,
        has_content_delta=True,
        text_length=len("raw stream chunk text must not appear"),
        has_finish_reason=False,
        finish_reason=None,
    )
    assert_public_text_is_clean(repr(event))


def test_normalize_stream_event_sanitizes_finish_reason():
    event = normalize_stream_event(
        {
            "event_type": "chat.completion.chunk",
            "choices": [{"delta": {}, "finish_reason": "stop /Users/Teng/StudioSecret"}],
        },
        index=4,
    )

    assert event.finish_reason == "stop StudioSecret"
    assert "/Users/Teng" not in repr(event)


def test_stream_runtime_error_public_traceback_cuts_raw_exception_chain():
    raw = RuntimeError(
        'data: {"choices": [{"delta": {"content": "raw stream chunk text must not appear"}}]} '
        "Authorization: Bearer sk-or-v1-private-token "
        "https://api.relay.com/v1/chat/completions?token=secret#frag"
    )
    normalized = normalize_stream_runtime_error(raw)

    assert normalized.category == RelayRuntimeCategory.UNKNOWN_RUNTIME_ERROR
    assert_public_text_is_clean(normalized.public_message)

    with pytest.raises(RelayStreamingRuntimeError) as exc_info:
        normalized.raise_for_public_handling()

    rendered_traceback = "".join(
        traceback.format_exception(
            type(exc_info.value),
            exc_info.value,
            exc_info.value.__traceback__,
        )
    )
    assert_public_text_is_clean(str(exc_info.value))
    assert_public_text_is_clean(rendered_traceback)


def _stream_authorization():
    return authorize_relay_live_execution(live_mode=True, profile=RelayAuditProfile.STREAMING)


def _pack_summary():
    return RelayPackSummary(label="No Pack", pack_hash=None)


def test_successful_stream_with_delta_and_finish_returns_pass():
    def transport(payload):
        assert payload["stream"] is True
        return [
            RelayStreamEvent("chat.completion.chunk", 0, True, 2, False, None),
            RelayStreamEvent("chat.completion.chunk", 1, False, 0, True, "stop"),
        ]

    result = run_minimal_streaming_live_check(
        authorization=_stream_authorization(),
        endpoint="https://api.relay.com/v1/chat/completions?token=secret#frag",
        model="example-model",
        api_key="sk-or-v1-private-token",
        pack_summary=_pack_summary(),
        transport=transport,
    )

    assert result.profile == RelayAuditProfile.STREAMING
    assert result.mode == RelayAuditMode.LIVE
    assert result.verdict == RelayVerdict.PASS
    assert result.risk_level == RelayRiskLevel.LOW
    assert result.risk_categories == [RelayRiskCategory.STREAMING_INTEGRITY]
    assert {item.key for item in result.evidence} == {
        "stream_event_sequence",
        "stream_content_delta",
        "stream_terminal_finish",
    }
    rendered = repr(result)
    assert "api.relay.com" in rendered
    assert_public_text_is_clean(rendered)


def test_uniform_chunk_size_heuristic_returns_suspicious_without_timing_claims():
    def transport(payload):
        return [
            RelayStreamEvent("chat.completion.chunk", 0, True, 4, False, None),
            RelayStreamEvent("chat.completion.chunk", 1, True, 4, False, None),
            RelayStreamEvent("chat.completion.chunk", 2, True, 4, False, None),
            RelayStreamEvent("chat.completion.chunk", 3, True, 4, False, None),
            RelayStreamEvent("chat.completion.chunk", 4, True, 4, False, None),
            RelayStreamEvent("chat.completion.chunk", 5, False, 0, True, "stop"),
        ]

    result = run_minimal_streaming_live_check(
        authorization=_stream_authorization(),
        endpoint="https://api.relay.com/v1",
        model="example-model",
        api_key=None,
        pack_summary=_pack_summary(),
        transport=transport,
    )

    assert result.verdict == RelayVerdict.SUSPICIOUS
    assert result.risk_level == RelayRiskLevel.MEDIUM
    heuristic = next(item for item in result.evidence if item.key == "synthetic_stream_heuristic")
    assert heuristic.status == "suspicious"
    assert heuristic.metrics["uniform_chunk_size_detected"] is True
    assert heuristic.metrics["chunk_count"] == 5
    assert "Uniform stream chunks are a heuristic risk indicator" in heuristic.summary
    assert "static" in heuristic.summary
    assert "timing" not in heuristic.summary.lower()
    assert "burst" not in heuristic.summary.lower()
    assert "trace" not in heuristic.summary.lower()


def test_missing_terminal_finish_after_content_returns_suspicious():
    def transport(payload):
        return [
            RelayStreamEvent("chat.completion.chunk", 0, True, 2, False, None),
            RelayStreamEvent("chat.completion.chunk", 1, True, 3, False, None),
        ]

    result = run_minimal_streaming_live_check(
        authorization=_stream_authorization(),
        endpoint="https://api.relay.com/v1",
        model="example-model",
        api_key=None,
        pack_summary=_pack_summary(),
        transport=transport,
    )

    assert result.verdict == RelayVerdict.SUSPICIOUS
    assert any(item.key == "stream_terminal_finish" and item.status == "suspicious" for item in result.evidence)


def test_incompatible_non_streaming_envelope_returns_fail():
    def transport(payload):
        return [
            RelayStreamEvent("chat.completion", 0, False, 0, False, None),
        ]

    result = run_minimal_streaming_live_check(
        authorization=_stream_authorization(),
        endpoint="https://api.relay.com/v1",
        model="example-model",
        api_key=None,
        pack_summary=_pack_summary(),
        transport=transport,
    )

    assert result.verdict == RelayVerdict.FAIL
    assert result.risk_level == RelayRiskLevel.HIGH
    violation = next(item for item in result.evidence if item.key == "stream_contract_violation")
    assert violation.status == "fail"


def test_empty_stream_returns_inconclusive():
    def transport(payload):
        return []

    result = run_minimal_streaming_live_check(
        authorization=_stream_authorization(),
        endpoint="https://api.relay.com/v1",
        model="example-model",
        api_key=None,
        pack_summary=_pack_summary(),
        transport=transport,
    )

    assert result.verdict == RelayVerdict.INCONCLUSIVE
    assert result.risk_level == RelayRiskLevel.UNKNOWN
    assert result.runtime_category == RelayRuntimeCategory.UNKNOWN_RUNTIME_ERROR
    assert result.inconclusive_reason == "Provider streaming runtime error before a conclusive relay result."


def test_streaming_runtime_failure_returns_sanitized_inconclusive_result():
    def transport(payload):
        raise RuntimeError(
            'broken stream data: {"choices": [{"delta": {"content": "raw stream chunk text must not appear"}}]} '
            "https://api.relay.com/v1/chat/completions?token=secret#frag"
        )

    result = run_minimal_streaming_live_check(
        authorization=_stream_authorization(),
        endpoint="https://api.relay.com/v1/chat/completions?token=secret#frag",
        model="example-model",
        api_key="sk-or-v1-private-token",
        pack_summary=_pack_summary(),
        transport=transport,
    )

    assert result.verdict == RelayVerdict.INCONCLUSIVE
    assert result.runtime_category == RelayRuntimeCategory.DISCONNECT
    assert_public_text_is_clean(repr(result))


def test_streaming_runner_discards_malicious_raw_stream_failure_shells():
    class MaliciousStreamError(RuntimeError):
        def __init__(self):
            super().__init__(
                'data: {"choices": [{"delta": {"content": "raw stream chunk text must not appear"}}]}'
            )
            self.raw_sse_line = (
                'data: {"choices": [{"delta": {"content": "raw stream chunk text must not appear"}}]}'
            )
            self.last_raw_chunk = "raw stream chunk text must not appear"
            self.headers = {"Authorization": "Bearer sk-or-v1-private-token"}
            self.url = "https://api.relay.com/v1/chat/completions?token=secret#frag"

    def transport(payload):
        raise MaliciousStreamError()

    result = run_minimal_streaming_live_check(
        authorization=_stream_authorization(),
        endpoint="https://api.relay.com/v1/chat/completions?token=secret#frag",
        model="example-model",
        api_key="sk-or-v1-private-token",
        pack_summary=_pack_summary(),
        transport=transport,
    )

    assert result.verdict == RelayVerdict.INCONCLUSIVE
    rendered = repr(result)
    assert_public_text_is_clean(rendered)
    assert not hasattr(result, "raw_sse_line")
    assert not hasattr(result, "last_raw_chunk")
    assert not hasattr(result, "headers")
    assert not hasattr(result, "url")
