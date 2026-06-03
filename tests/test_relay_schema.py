import json
import traceback

import pytest

from tokenverify.relay_live import RelayLiveTransportResponse
from tokenverify.relay_models import (
    RelayAuditMode,
    RelayAuditProfile,
    RelayPackSummary,
    RelayRiskCategory,
    RelayRiskLevel,
    RelayRuntimeCategory,
    RelayVerdict,
)
from tokenverify.relay_schema import (
    RelaySchemaRuntimeError,
    build_minimal_schema_payload,
    normalize_schema_response,
    normalize_schema_runtime_error,
    run_minimal_schema_live_check,
)
from tokenverify.relay_safety import authorize_relay_live_execution
from tokenverify.relay_safety import sanitize_public_relay_text


SENSITIVE_SCHEMA_FIXTURES = [
    "heiyan_studio",
    "StudioSecret",
    "/Users/Teng/Desktop/heiyan_studio/private.yaml",
    "https://api.relay.com/v1/chat/completions?token=secret#frag",
    "Authorization: Bearer sk-or-v1-private-token",
    "raw schema argument must not appear",
    "raw natural language fallback must not appear",
    '{"tool_calls": [{"function": {"arguments": "{\\"secret\\":\\"raw schema argument must not appear\\"}"}}]}',
    '{\\\\\\"tool_calls\\\\\\": [{\\\\\\"function\\\\\\": {\\\\\\"arguments\\\\\\": \\\\\\"{\\\\\\\\\\\\\\"secret\\\\\\\\\\\\\\":\\\\\\\\\\\\\\"raw schema argument must not appear\\\\\\\\\\\\\\"}\\\\\\"}}]}',
    "{'tool_calls': [{'function': {'arguments': '{\"secret\":\"raw schema argument must not appear\"}'}}]}",
    "tool_calls",
    "function.arguments",
    "private expected answer",
    "secret verifier expression",
]


def assert_public_text_is_clean(text: str):
    for fixture in SENSITIVE_SCHEMA_FIXTURES:
        assert fixture not in text
    assert '{"tool_calls"' not in text
    assert "{\\\\\\\"tool_calls\\\\\\\"" not in text
    assert "{'tool_calls'" not in text
    assert "function.arguments" not in text


def test_minimal_schema_payload_is_public_forced_tool_contract():
    payload = build_minimal_schema_payload("Example Model /Users/Teng/heiyan_studio")

    assert payload["model"] == "Example Model heiyan_studio"
    assert payload["messages"] == [
        {"role": "user", "content": 'Call the provided tool with item_count=2 and status="ok".'}
    ]
    assert payload["max_tokens"] == 64
    assert payload["stream"] is False
    assert payload["tool_choice"] == {"type": "function", "function": {"name": "tv_schema_echo"}}
    tool = payload["tools"][0]["function"]
    assert tool["name"] == "tv_schema_echo"
    assert tool["parameters"]["required"] == ["item_count", "status"]
    assert tool["parameters"]["properties"]["item_count"]["enum"] == [2]
    assert tool["parameters"]["properties"]["status"]["enum"] == ["ok"]
    rendered = repr(payload)
    assert "/Users/Teng" not in rendered
    assert "private expected answer" not in rendered
    assert "secret verifier expression" not in rendered


def test_normalize_schema_response_extracts_safe_metrics_without_raw_arguments():
    response = RelayLiveTransportResponse(
        status_code=200,
        body={
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {
                        "tool_calls": [
                            {
                                "type": "function",
                                "function": {
                                    "name": "tv_schema_echo",
                                    "arguments": '{"item_count":2,"status":"ok","secret":"raw schema argument must not appear"}',
                                },
                            }
                        ]
                    },
                }
            ]
        },
    )

    observation = normalize_schema_response(response)

    assert observation.tool_call_observed is True
    assert observation.tool_name_preserved is True
    assert observation.arguments_json_parseable is True
    assert observation.required_key_count == 2
    assert observation.required_keys_present_count == 2
    assert observation.unexpected_key_count == 1
    assert observation.item_count_type_match is True
    assert observation.status_type_match is True
    assert observation.enum_values_match is True
    assert observation.natural_language_fallback_observed is False
    assert observation.hybrid_content_observed is False
    assert observation.finish_reason == "tool-call-finish"
    assert_public_text_is_clean(repr(observation))


def test_normalize_schema_runtime_error_cuts_raw_exception_chain():
    raw = RuntimeError(
        '{"tool_calls": [{"function": {"arguments": "{\\"secret\\":\\"raw schema argument must not appear\\"}"}}]} '
        "Authorization: Bearer sk-or-v1-private-token "
        "https://api.relay.com/v1/chat/completions?token=secret#frag"
    )
    normalized = normalize_schema_runtime_error(raw)

    assert normalized.category == RelayRuntimeCategory.UNKNOWN_RUNTIME_ERROR
    assert_public_text_is_clean(normalized.public_message)

    with pytest.raises(RelaySchemaRuntimeError) as exc_info:
        normalized.raise_for_public_handling()

    rendered_traceback = "".join(
        traceback.format_exception(type(exc_info.value), exc_info.value, exc_info.value.__traceback__)
    )
    assert_public_text_is_clean(str(exc_info.value))
    assert_public_text_is_clean(rendered_traceback)


def test_json_decode_error_doc_never_reaches_public_traceback():
    raw_doc = (
        '{"tool_calls": [{"function": {"arguments": "{\\"secret\\":\\"raw schema argument must not appear\\"}"}}]}'
    )
    raw = json.JSONDecodeError("Expecting value", raw_doc, 0)
    normalized = normalize_schema_runtime_error(raw)

    assert normalized.category == RelayRuntimeCategory.UNKNOWN_RUNTIME_ERROR
    assert_public_text_is_clean(normalized.public_message)

    with pytest.raises(RelaySchemaRuntimeError) as exc_info:
        normalized.raise_for_public_handling()

    rendered_traceback = "".join(
        traceback.format_exception(type(exc_info.value), exc_info.value, exc_info.value.__traceback__)
    )
    assert "raw schema argument must not appear" not in rendered_traceback
    assert '{"tool_calls"' not in rendered_traceback


@pytest.mark.parametrize(
    "raw_shell",
    [
        '{"tool_calls": [{"function": {"arguments": "{\\"secret\\":\\"raw schema argument must not appear\\"}"}}]}',
        '{\n  "tool_calls": [\n    {"function": {"arguments": "{\\"secret\\":\\"raw schema argument must not appear\\"}"}}\n  ]\n}',
        '{\\\\\\"tool_calls\\\\\\": [{\\\\\\"function\\\\\\": {\\\\\\"arguments\\\\\\": \\\\\\"{\\\\\\\\\\\\\\"secret\\\\\\\\\\\\\\":\\\\\\\\\\\\\\"raw schema argument must not appear\\\\\\\\\\\\\\"}\\\\\\"}}]}',
        "{'tool_calls': [{'function': {'arguments': '{\"secret\":\"raw schema argument must not appear\"}'}}]}",
        '{"message": {"function.arguments": "raw schema argument must not appear"}}',
    ],
)
def test_schema_shell_scrubber_removes_compact_multiline_escaped_and_mixed_quote_shells(raw_shell):
    cleaned = sanitize_public_relay_text(raw_shell)

    assert "raw schema argument must not appear" not in cleaned
    assert '{"tool_calls"' not in cleaned
    assert "{\\\\\\\"tool_calls\\\\\\\"" not in cleaned
    assert "{'tool_calls'" not in cleaned
    assert "function.arguments" not in cleaned


def _schema_authorization():
    return authorize_relay_live_execution(live_mode=True, profile=RelayAuditProfile.SCHEMA)


def _pack_summary():
    return RelayPackSummary(label="No Pack", pack_hash=None)


def _response(arguments: str, *, name: str = "tv_schema_echo", content: str | None = None):
    message = {
        "tool_calls": [
            {
                "type": "function",
                "function": {"name": name, "arguments": arguments},
            }
        ]
    }
    if content is not None:
        message["content"] = content
    return RelayLiveTransportResponse(
        status_code=200,
        body={"choices": [{"finish_reason": "tool_calls", "message": message}]},
    )


def test_schema_pass_for_matching_tool_contract():
    def transport(payload):
        assert payload["stream"] is False
        assert payload["tool_choice"]["function"]["name"] == "tv_schema_echo"
        return _response('{"item_count":2,"status":"ok"}')

    result = run_minimal_schema_live_check(
        authorization=_schema_authorization(),
        endpoint="https://api.relay.com/v1/chat/completions?token=secret#frag",
        model="example-model",
        api_key="sk-or-v1-private-token",
        pack_summary=_pack_summary(),
        transport=transport,
    )

    assert result.profile == RelayAuditProfile.SCHEMA
    assert result.mode == RelayAuditMode.LIVE
    assert result.verdict == RelayVerdict.PASS
    assert result.risk_level == RelayRiskLevel.LOW
    assert result.risk_categories == [RelayRiskCategory.SCHEMA_TOOL_REWRITE]
    assert {item.key for item in result.evidence} == {
        "schema_tool_envelope",
        "schema_tool_name_preservation",
        "schema_arguments_json",
        "schema_required_keys",
        "schema_type_enum_match",
    }
    assert_public_text_is_clean(repr(result))


def test_schema_extra_keys_are_suspicious():
    def transport(payload):
        return _response('{"item_count":2,"status":"ok","extra":"raw schema argument must not appear"}')

    result = run_minimal_schema_live_check(
        authorization=_schema_authorization(),
        endpoint="https://api.relay.com/v1",
        model="example-model",
        api_key=None,
        pack_summary=_pack_summary(),
        transport=transport,
    )

    assert result.verdict == RelayVerdict.SUSPICIOUS
    assert result.risk_level == RelayRiskLevel.MEDIUM
    extra = next(item for item in result.evidence if item.key == "schema_extra_keys")
    assert extra.metrics["unexpected_key_count"] == 1
    assert_public_text_is_clean(repr(result))


def test_schema_hybrid_tool_and_content_is_suspicious_without_raw_content():
    def transport(payload):
        return _response(
            '{"item_count":2,"status":"ok"}',
            content="raw natural language fallback must not appear",
        )

    result = run_minimal_schema_live_check(
        authorization=_schema_authorization(),
        endpoint="https://api.relay.com/v1",
        model="example-model",
        api_key=None,
        pack_summary=_pack_summary(),
        transport=transport,
    )

    assert result.verdict == RelayVerdict.SUSPICIOUS
    assert result.risk_level == RelayRiskLevel.MEDIUM
    envelope = next(item for item in result.evidence if item.key == "schema_tool_envelope")
    assert envelope.metrics["hybrid_content_observed"] is True
    assert "raw natural language fallback must not appear" not in repr(result)


def test_schema_natural_language_fallback_without_tool_call_fails():
    def transport(payload):
        return RelayLiveTransportResponse(
            status_code=200,
            body={
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": "raw natural language fallback must not appear"},
                    }
                ]
            },
        )

    result = run_minimal_schema_live_check(
        authorization=_schema_authorization(),
        endpoint="https://api.relay.com/v1",
        model="example-model",
        api_key=None,
        pack_summary=_pack_summary(),
        transport=transport,
    )

    assert result.verdict == RelayVerdict.FAIL
    assert result.risk_level == RelayRiskLevel.HIGH
    violation = next(item for item in result.evidence if item.key == "schema_contract_violation")
    assert violation.metrics["natural_language_fallback_observed"] is True
    assert_public_text_is_clean(repr(result))


def test_schema_tool_name_rewrite_fails():
    def transport(payload):
        return _response('{"item_count":2,"status":"ok"}', name="rewritten_tool")

    result = run_minimal_schema_live_check(
        authorization=_schema_authorization(),
        endpoint="https://api.relay.com/v1",
        model="example-model",
        api_key=None,
        pack_summary=_pack_summary(),
        transport=transport,
    )

    assert result.verdict == RelayVerdict.FAIL
    assert next(item for item in result.evidence if item.key == "schema_tool_name_preservation").status == "fail"


def test_schema_unparseable_arguments_fail_without_raw_arguments():
    def transport(payload):
        return _response('{"secret":"raw schema argument must not appear"')

    result = run_minimal_schema_live_check(
        authorization=_schema_authorization(),
        endpoint="https://api.relay.com/v1",
        model="example-model",
        api_key=None,
        pack_summary=_pack_summary(),
        transport=transport,
    )

    assert result.verdict == RelayVerdict.FAIL
    assert next(item for item in result.evidence if item.key == "schema_arguments_json").status == "fail"
    assert_public_text_is_clean(repr(result))


def test_schema_empty_response_is_inconclusive():
    def transport(payload):
        return RelayLiveTransportResponse(status_code=200, body={})

    result = run_minimal_schema_live_check(
        authorization=_schema_authorization(),
        endpoint="https://api.relay.com/v1",
        model="example-model",
        api_key=None,
        pack_summary=_pack_summary(),
        transport=transport,
    )

    assert result.verdict == RelayVerdict.INCONCLUSIVE
    assert result.risk_level == RelayRiskLevel.UNKNOWN


def test_schema_runtime_failure_returns_sanitized_inconclusive():
    def transport(payload):
        raise RuntimeError(
            '{"tool_calls": [{"function": {"arguments": "{\\"secret\\":\\"raw schema argument must not appear\\"}"}}]} '
            "https://api.relay.com/v1/chat/completions?token=secret#frag"
        )

    result = run_minimal_schema_live_check(
        authorization=_schema_authorization(),
        endpoint="https://api.relay.com/v1/chat/completions?token=secret#frag",
        model="example-model",
        api_key="sk-or-v1-private-token",
        pack_summary=_pack_summary(),
        transport=transport,
    )

    assert result.verdict == RelayVerdict.INCONCLUSIVE
    assert_public_text_is_clean(repr(result))


def test_schema_runner_discards_malicious_raw_failure_attributes():
    class MaliciousSchemaError(RuntimeError):
        def __init__(self):
            super().__init__(
                '{"tool_calls": [{"function": {"arguments": "{\\"secret\\":\\"raw schema argument must not appear\\"}"}}]}'
            )
            self.raw_arguments = '{"secret":"raw schema argument must not appear"}'
            self.response_body = '{"tool_calls": []}'
            self.headers = {"Authorization": "Bearer sk-or-v1-private-token"}
            self.url = "https://api.relay.com/v1/chat/completions?token=secret#frag"

    def transport(payload):
        raise MaliciousSchemaError()

    result = run_minimal_schema_live_check(
        authorization=_schema_authorization(),
        endpoint="https://api.relay.com/v1/chat/completions?token=secret#frag",
        model="example-model",
        api_key="sk-or-v1-private-token",
        pack_summary=_pack_summary(),
        transport=transport,
    )

    assert result.verdict == RelayVerdict.INCONCLUSIVE
    rendered = repr(result)
    assert_public_text_is_clean(rendered)
    assert not hasattr(result, "raw_arguments")
    assert not hasattr(result, "response_body")
    assert not hasattr(result, "headers")
    assert not hasattr(result, "url")
