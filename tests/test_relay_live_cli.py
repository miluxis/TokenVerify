import traceback

import pytest
from typer.testing import CliRunner

import tokenverify.cli as cli_module
from tokenverify.cli import app
from tokenverify.relay_live import RelayLiveTransportResponse
from tokenverify.relay_streaming import RelayStreamEvent


def test_relay_cli_live_general_uses_default_transport_factory_after_authorization(tmp_path, monkeypatch):
    calls = []

    def fake_default_transport(request):
        calls.append(("factory-called", request.base_url, request.api_key))

        def transport(payload):
            calls.append(("transport-called", payload["model"]))
            return RelayLiveTransportResponse(
                status_code=200,
                body={"choices": [{"message": {"content": "ok"}}]},
            )

        return transport

    monkeypatch.setattr(cli_module, "_default_relay_live_transport", fake_default_transport)
    output_path = tmp_path / "live-report.md"

    result = CliRunner().invoke(
        app,
        [
            "relay-audit",
            "--base-url",
            "https://api.relay.com/v1/chat/completions?user=heiyan_studio#frag",
            "--model",
            "example-model",
            "--profile",
            "general",
            "--api-key-env",
            "RELAY_API_KEY",
            "--live",
            "--output",
            str(output_path),
        ],
        env={"RELAY_API_KEY": "sk-secret"},
    )

    assert result.exit_code == 0
    assert calls == [
        ("factory-called", "https://api.relay.com/v1/chat/completions?user=heiyan_studio#frag", "sk-secret"),
        ("transport-called", "example-model"),
    ]
    markdown = output_path.read_text(encoding="utf-8")
    assert "Relay audit completed with verdict: pass" in result.output
    assert "- Mode: live" in markdown
    assert "api.relay.com" in markdown
    assert "https://" not in markdown
    assert "/v1" not in markdown
    assert "heiyan_studio" not in markdown
    assert "sk-secret" not in markdown


def test_relay_cli_without_live_does_not_call_default_transport_factory(monkeypatch):
    calls = []

    def fake_default_transport(request):
        calls.append("factory-called")
        return None

    monkeypatch.setattr(cli_module, "_default_relay_live_transport", fake_default_transport)

    result = CliRunner().invoke(
        app,
        [
            "relay-audit",
            "--base-url",
            "https://relay.example/v1",
            "--model",
            "example-model",
            "--api-key",
            "sk-secret",
        ],
    )

    assert result.exit_code == 2
    assert "Network execution blocked: --live flag missing." in result.output
    assert calls == []
    assert "sk-secret" not in result.output


def test_relay_cli_live_runtime_inconclusive_exits_three_and_writes_report(tmp_path, monkeypatch):
    def fake_default_transport(request):
        def transport(payload):
            raise RuntimeError("HTTP 401 https://api.relay.com/v1?token=secret Authorization: Bearer sk-secret")

        return transport

    monkeypatch.setattr(cli_module, "_default_relay_live_transport", fake_default_transport)
    output_path = tmp_path / "live-inconclusive.md"

    result = CliRunner().invoke(
        app,
        [
            "relay-audit",
            "--base-url",
            "https://api.relay.com/v1?token=secret",
            "--model",
            "example-model",
            "--api-key",
            "sk-secret",
            "--live",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 3
    assert "Relay audit completed with verdict: inconclusive" in result.output
    assert "sk-secret" not in result.output
    assert output_path.exists()
    markdown = output_path.read_text(encoding="utf-8")
    assert "- Runtime category: auth_error" in markdown
    assert "https://" not in markdown
    assert "token=secret" not in markdown
    assert "sk-secret" not in markdown


def test_relay_cli_api_key_env_guard_blocks_raw_secret_before_other_errors(tmp_path):
    result = CliRunner().invoke(
        app,
        [
            "relay-audit",
            "--base-url",
            "https://api.relay.com/v1",
            "--model",
            "example-model",
            "--api-key-env",
            "sk-or-v1-abcdef",
            "--pack-path",
            str(tmp_path / "missing-private.yaml"),
            "--live",
        ],
    )

    assert result.exit_code == 2
    assert "--api-key-env expects an environment variable name" in result.output
    assert "sk-or-v1-abcdef" not in result.output
    assert "missing-private.yaml" not in result.output


def test_relay_cli_streaming_live_writes_sanitized_report(monkeypatch, tmp_path):
    touched = False

    def fake_default_stream_factory(request):
        nonlocal touched

        def factory():
            nonlocal touched
            touched = True

            def transport(payload):
                assert payload["stream"] is True
                return [
                    RelayStreamEvent("chat.completion.chunk", 0, True, len("ok"), False, None),
                    RelayStreamEvent("chat.completion.chunk", 1, False, 0, True, "stop"),
                ]

            return transport

        return factory

    monkeypatch.setattr(cli_module, "_default_relay_stream_transport_factory", fake_default_stream_factory)
    output_path = tmp_path / "stream-report.md"
    result = CliRunner().invoke(
        app,
        [
            "relay-audit",
            "--base-url",
            "https://api.relay.com/v1/chat/completions?token=secret#frag",
            "--model",
            "example-model",
            "--profile",
            "streaming",
            "--api-key-env",
            "RELAY_API_KEY",
            "--live",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    assert touched is True
    markdown = output_path.read_text(encoding="utf-8")
    assert "Profile: streaming" in markdown
    assert "stream_event_sequence" in markdown
    assert "stream_content_delta" in markdown
    assert "stream_terminal_finish" in markdown
    assert "chat/completions" not in markdown
    assert "token=secret" not in markdown
    assert "data:" not in markdown
    assert '{"choices"' not in markdown


def test_relay_cli_streaming_without_live_exits_2_and_does_not_touch_stream_factory(monkeypatch, tmp_path):
    touched = False

    def forbidden_factory(request):
        nonlocal touched
        touched = True
        raise AssertionError("stream factory must not be constructed without --live")

    monkeypatch.setattr(cli_module, "_default_relay_stream_transport_factory", forbidden_factory)
    output_path = tmp_path / "blocked.md"
    result = CliRunner().invoke(
        app,
        [
            "relay-audit",
            "--base-url",
            "https://api.relay.com/v1",
            "--model",
            "example-model",
            "--profile",
            "streaming",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 2
    assert "Network execution blocked: --live flag missing." in result.output
    assert touched is False
    assert not output_path.exists()


def test_relay_cli_streaming_raw_api_key_env_guard_wins_before_pack_and_stream(monkeypatch, tmp_path):
    touched = False

    def forbidden_factory(request):
        nonlocal touched
        touched = True
        raise AssertionError("stream factory must not be constructed after raw-secret guard")

    monkeypatch.setattr(cli_module, "_default_relay_stream_transport_factory", forbidden_factory)
    private_pack = tmp_path / "heiyan_studio_private.yaml"
    private_pack.write_text("id: private\n", encoding="utf-8")
    output_path = tmp_path / "guarded.md"

    result = CliRunner().invoke(
        app,
        [
            "relay-audit",
            "--base-url",
            "https://api.relay.com/v1",
            "--model",
            "example-model",
            "--profile",
            "streaming",
            "--api-key-env",
            "sk-or-v1-private-token",
            "--pack-path",
            str(private_pack),
            "--live",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 2
    assert "--api-key-env expects an environment variable name" in result.output
    assert "sk-or-v1-private-token" not in result.output
    assert "heiyan_studio" not in result.output
    assert touched is False
    assert not output_path.exists()


def test_relay_cli_streaming_suspicious_exits_0(monkeypatch, tmp_path):
    def fake_default_stream_factory(request):
        def factory():
            def transport(payload):
                return [
                    RelayStreamEvent("chat.completion.chunk", 0, True, 4, False, None),
                    RelayStreamEvent("chat.completion.chunk", 1, True, 4, False, None),
                    RelayStreamEvent("chat.completion.chunk", 2, True, 4, False, None),
                    RelayStreamEvent("chat.completion.chunk", 3, True, 4, False, None),
                    RelayStreamEvent("chat.completion.chunk", 4, True, 4, False, None),
                    RelayStreamEvent("chat.completion.chunk", 5, False, 0, True, "stop"),
                ]

            return transport

        return factory

    monkeypatch.setattr(cli_module, "_default_relay_stream_transport_factory", fake_default_stream_factory)
    output_path = tmp_path / "suspicious.md"
    result = CliRunner().invoke(
        app,
        [
            "relay-audit",
            "--base-url",
            "https://api.relay.com/v1",
            "--model",
            "example-model",
            "--profile",
            "streaming",
            "--live",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    assert "Relay audit completed with verdict: suspicious" in result.output
    assert "synthetic_stream_heuristic" in output_path.read_text(encoding="utf-8")


def test_relay_cli_streaming_fail_exits_1(monkeypatch, tmp_path):
    def fake_default_stream_factory(request):
        def factory():
            def transport(payload):
                return [RelayStreamEvent("chat.completion", 0, False, 0, False, None)]

            return transport

        return factory

    monkeypatch.setattr(cli_module, "_default_relay_stream_transport_factory", fake_default_stream_factory)
    output_path = tmp_path / "fail.md"
    result = CliRunner().invoke(
        app,
        [
            "relay-audit",
            "--base-url",
            "https://api.relay.com/v1",
            "--model",
            "example-model",
            "--profile",
            "streaming",
            "--live",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 1
    assert "Relay audit completed with verdict: fail" in result.output
    assert "stream_contract_violation" in output_path.read_text(encoding="utf-8")


def test_relay_cli_streaming_inconclusive_exits_3(monkeypatch, tmp_path):
    def fake_default_stream_factory(request):
        def factory():
            def transport(payload):
                raise TimeoutError("gateway timeout with raw stream chunk text must not appear")

            return transport

        return factory

    monkeypatch.setattr(cli_module, "_default_relay_stream_transport_factory", fake_default_stream_factory)
    output_path = tmp_path / "inconclusive.md"
    result = CliRunner().invoke(
        app,
        [
            "relay-audit",
            "--base-url",
            "https://api.relay.com/v1",
            "--model",
            "example-model",
            "--profile",
            "streaming",
            "--live",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 3
    assert "Relay audit completed with verdict: inconclusive" in result.output
    markdown = output_path.read_text(encoding="utf-8")
    assert "timeout" in markdown
    assert "raw stream chunk text must not appear" not in markdown


def test_parse_stream_json_line_decodes_bytes_without_b_prefix():
    parsed = cli_module._parse_stream_json_line(
        b'data: {"object": "chat.completion.chunk", "choices": [{"delta": {"content": "ok"}}]}'
    )

    assert parsed == {
        "object": "chat.completion.chunk",
        "choices": [{"delta": {"content": "ok"}}],
    }


def test_parse_stream_json_line_malformed_bytes_error_is_sanitized():
    with pytest.raises(RuntimeError) as exc_info:
        cli_module._parse_stream_json_line(
            b'data: {"choices": [{"delta": {"content": "raw stream chunk text must not appear"}}]\xff'
        )

    rendered = "".join(
        traceback.format_exception(
            type(exc_info.value),
            exc_info.value,
            exc_info.value.__traceback__,
        )
    )
    assert "Malformed streaming event envelope." in str(exc_info.value)
    assert "raw stream chunk text must not appear" not in rendered
    assert "data:" not in rendered
    assert '{"choices"' not in rendered


def test_relay_cli_streaming_malicious_failure_output_is_sanitized(monkeypatch, tmp_path):
    def fake_default_stream_factory(request):
        def factory():
            def transport(payload):
                raise RuntimeError(
                    'data: {"choices": [{"delta": {"content": "raw stream chunk text must not appear"}}]} '
                    "Authorization: Bearer sk-or-v1-private-token"
                )

            return transport

        return factory

    monkeypatch.setattr(cli_module, "_default_relay_stream_transport_factory", fake_default_stream_factory)
    output_path = tmp_path / "malicious.md"
    result = CliRunner().invoke(
        app,
        [
            "relay-audit",
            "--base-url",
            "https://api.relay.com/v1/chat/completions?token=secret#frag",
            "--model",
            "example-model",
            "--profile",
            "streaming",
            "--live",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 3
    assert "raw stream chunk text must not appear" not in result.output
    assert "data:" not in result.output
    assert '{"choices"' not in result.output
    markdown = output_path.read_text(encoding="utf-8")
    assert "raw stream chunk text must not appear" not in markdown
    assert "data:" not in markdown
    assert '{"choices"' not in markdown


def test_relay_cli_schema_live_writes_sanitized_report(monkeypatch, tmp_path):
    touched = False

    def fake_default_schema_factory(request):
        def factory():
            nonlocal touched
            touched = True

            def transport(payload):
                assert payload["tool_choice"]["function"]["name"] == "tv_schema_echo"
                return RelayLiveTransportResponse(
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
                                                "arguments": '{"item_count":2,"status":"ok"}',
                                            },
                                        }
                                    ]
                                },
                            }
                        ]
                    },
                )

            return transport

        return factory

    monkeypatch.setattr(cli_module, "_default_relay_schema_transport_factory", fake_default_schema_factory)
    output_path = tmp_path / "schema-report.md"
    result = CliRunner().invoke(
        app,
        [
            "relay-audit",
            "--base-url",
            "https://api.relay.com/v1/chat/completions?token=secret#frag",
            "--model",
            "example-model",
            "--profile",
            "schema",
            "--api-key-env",
            "RELAY_API_KEY",
            "--live",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    assert touched is True
    markdown = output_path.read_text(encoding="utf-8")
    assert "Profile: schema" in markdown
    assert "schema_tool_envelope" in markdown
    assert "schema_required_keys" in markdown
    assert "chat/completions" not in markdown
    assert "token=secret" not in markdown
    assert '{"tool_calls"' not in markdown
    assert "raw schema argument must not appear" not in markdown


def test_relay_cli_schema_without_live_exits_2_and_does_not_touch_schema_factory(monkeypatch, tmp_path):
    touched = False

    def forbidden_factory(request):
        nonlocal touched
        touched = True
        raise AssertionError("schema factory must not be constructed without --live")

    monkeypatch.setattr(cli_module, "_default_relay_schema_transport_factory", forbidden_factory)
    output_path = tmp_path / "blocked.md"
    result = CliRunner().invoke(
        app,
        [
            "relay-audit",
            "--base-url",
            "https://api.relay.com/v1",
            "--model",
            "example-model",
            "--profile",
            "schema",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 2
    assert "Network execution blocked: --live flag missing." in result.output
    assert touched is False
    assert not output_path.exists()


def test_relay_cli_schema_raw_api_key_env_guard_wins_before_pack_and_transport(monkeypatch, tmp_path):
    touched = False

    def forbidden_factory(request):
        nonlocal touched
        touched = True
        raise AssertionError("schema factory must not be constructed after raw-secret guard")

    monkeypatch.setattr(cli_module, "_default_relay_schema_transport_factory", forbidden_factory)
    private_pack = tmp_path / "heiyan_studio_private.yaml"
    private_pack.write_text("id: private\n", encoding="utf-8")
    result = CliRunner().invoke(
        app,
        [
            "relay-audit",
            "--base-url",
            "https://api.relay.com/v1",
            "--model",
            "example-model",
            "--profile",
            "schema",
            "--api-key-env",
            "sk-or-v1-private-token",
            "--pack-path",
            str(private_pack),
            "--live",
        ],
    )

    assert result.exit_code == 2
    assert "--api-key-env expects an environment variable name" in result.output
    assert "sk-or-v1-private-token" not in result.output
    assert "heiyan_studio" not in result.output
    assert touched is False


def test_relay_cli_schema_malicious_failure_output_is_sanitized(monkeypatch, tmp_path):
    def fake_default_schema_factory(request):
        def factory():
            def transport(payload):
                raise RuntimeError(
                    '{\\\\\\"tool_calls\\\\\\": [{\\\\\\"function\\\\\\": {\\\\\\"arguments\\\\\\": \\\\\\"{\\\\\\\\\\\\\\"secret\\\\\\\\\\\\\\":\\\\\\\\\\\\\\"raw schema argument must not appear\\\\\\\\\\\\\\"}\\\\\\"}}]} '
                    "Authorization: Bearer sk-or-v1-private-token"
                )

            return transport

        return factory

    monkeypatch.setattr(cli_module, "_default_relay_schema_transport_factory", fake_default_schema_factory)
    output_path = tmp_path / "malicious-schema.md"
    result = CliRunner().invoke(
        app,
        [
            "relay-audit",
            "--base-url",
            "https://api.relay.com/v1/chat/completions?token=secret#frag",
            "--model",
            "example-model",
            "--profile",
            "schema",
            "--live",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 3
    assert "raw schema argument must not appear" not in result.output
    assert '{"tool_calls"' not in result.output
    assert "{\\\\\\\"tool_calls\\\\\\\"" not in result.output
    markdown = output_path.read_text(encoding="utf-8")
    assert "raw schema argument must not appear" not in markdown
    assert '{"tool_calls"' not in markdown
    assert "{\\\\\\\"tool_calls\\\\\\\"" not in markdown


def test_relay_cli_full_live_writes_sanitized_report(monkeypatch, tmp_path):
    calls = []

    def fake_general_factory(request):
        def factory():
            def transport(payload):
                calls.append("general")
                return RelayLiveTransportResponse(status_code=200, body={"choices": [{"message": {"content": "ok"}}]})

            return transport

        return factory

    def fake_stream_factory(request):
        def factory():
            def transport(payload):
                calls.append("streaming")
                return [
                    RelayStreamEvent("chat.completion.chunk", 0, True, len("ok"), False, None),
                    RelayStreamEvent("chat.completion.chunk", 1, False, 0, True, "stop"),
                ]

            return transport

        return factory

    def fake_schema_factory(request):
        def factory():
            def transport(payload):
                calls.append("schema")
                return RelayLiveTransportResponse(
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
                                                "arguments": '{"item_count":2,"status":"ok"}',
                                            },
                                        }
                                    ]
                                },
                            }
                        ]
                    },
                )

            return transport

        return factory

    def fake_privacy_factory(request):
        def factory():
            def transport(payload):
                calls.append("privacy")
                return RelayLiveTransportResponse(
                    status_code=200,
                    body={"choices": [{"message": {"content": "OK."}, "finish_reason": "stop"}]},
                )

            return transport

        return factory

    monkeypatch.setattr(cli_module, "_default_relay_live_transport_factory", fake_general_factory)
    monkeypatch.setattr(cli_module, "_default_relay_stream_transport_factory", fake_stream_factory)
    monkeypatch.setattr(cli_module, "_default_relay_schema_transport_factory", fake_schema_factory)
    monkeypatch.setattr(cli_module, "_default_relay_privacy_transport_factory", fake_privacy_factory)
    output_path = tmp_path / "full-report.md"
    result = CliRunner().invoke(
        app,
        [
            "relay-audit",
            "--base-url",
            "https://api.relay.com/v1/chat/completions?token=secret#frag",
            "--model",
            "example-model",
            "--profile",
            "full",
            "--api-key-env",
            "RELAY_API_KEY",
            "--live",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    assert calls == ["general", "streaming", "schema", "privacy"]
    markdown = output_path.read_text(encoding="utf-8")
    assert "Profile: full" in markdown
    assert "Full profile" in markdown
    assert "Serial execution can make timeout delays add up across subprofiles" in markdown
    assert "api.relay.com" in markdown
    assert "chat/completions" not in markdown
    assert "token=secret" not in markdown


def test_relay_cli_full_live_raw_secret_guard_wins_before_report(monkeypatch, tmp_path):
    touched = False

    def forbidden_factory(request):
        nonlocal touched
        touched = True
        raise AssertionError("factory must not be constructed after raw-secret guard")

    monkeypatch.setattr(cli_module, "_default_relay_live_transport_factory", forbidden_factory)
    monkeypatch.setattr(cli_module, "_default_relay_stream_transport_factory", forbidden_factory)
    monkeypatch.setattr(cli_module, "_default_relay_schema_transport_factory", forbidden_factory)
    monkeypatch.setattr(cli_module, "_default_relay_privacy_transport_factory", forbidden_factory)
    output_path = tmp_path / "full-report.md"

    result = CliRunner().invoke(
        app,
        [
            "relay-audit",
            "--base-url",
            "https://relay.example/v1",
            "--model",
            "example-model",
            "--profile",
            "full",
            "--api-key-env",
            "sk-or-v1-private-token",
            "--live",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 2
    assert touched is False
    assert not output_path.exists()
    assert "sk-or-v1-private-token" not in result.output
