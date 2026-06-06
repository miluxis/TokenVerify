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


def test_unified_audit_relay_route_requires_model_when_base_url_present():
    result = CliRunner().invoke(
        app,
        [
            "audit",
            "--base-url",
            "https://api.relay.com/v1",
        ],
    )

    assert result.exit_code == 2
    assert "Detected --base-url" in result.output
    assert "--model" in result.output


def test_unified_audit_relay_route_requires_base_url_when_model_present():
    result = CliRunner().invoke(
        app,
        [
            "audit",
            "--model",
            "example-model",
        ],
    )

    assert result.exit_code == 2
    assert "Detected --model" in result.output
    assert "--base-url" in result.output


def test_unified_audit_provider_endpoint_requires_config():
    result = CliRunner().invoke(
        app,
        [
            "audit",
            "--endpoint",
            "primary",
        ],
    )

    assert result.exit_code == 2
    assert "Detected --endpoint" in result.output
    assert "--config" in result.output


def test_unified_audit_direct_relay_fake_run_writes_relay_report(tmp_path):
    output_path = tmp_path / "relay.md"

    result = CliRunner().invoke(
        app,
        [
            "audit",
            "--base-url",
            "https://api.relay.com/v1/chat/completions?user=heiyan_studio#frag",
            "--model",
            "example-model",
            "--profile",
            "privacy",
            "--fake-run",
            "suspicious",
            "--output",
            str(output_path),
        ],
        env={"RELAY_API_KEY": "sk-secret"},
    )

    assert result.exit_code == 0
    assert "Wrote relay audit report:" in result.output
    markdown = output_path.read_text(encoding="utf-8")
    assert "TokenVerify Relay Technical Profile Report" in markdown
    assert "Technical Result" in markdown
    assert "privacy" in markdown
    assert "https://" not in markdown
    assert "heiyan_studio" not in markdown


def test_unified_relay_audit_defaults_to_full_profile_for_direct_relay_inputs(tmp_path):
    output_path = tmp_path / "default-full.md"

    result = CliRunner().invoke(
        app,
        [
            "audit",
            "--base-url",
            "https://api.relay.com/v1",
            "--model",
            "example-model",
            "--fake-run",
            "pass",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    markdown = output_path.read_text(encoding="utf-8")
    assert "- Profile：`full`" in markdown or "- 本次 profile：`full`" in markdown


def test_unified_relay_audit_accepts_drift_check_yes(tmp_path):
    output_path = tmp_path / "drift-check.md"

    result = CliRunner().invoke(
        app,
        [
            "audit",
            "--base-url",
            "https://api.relay.com/v1",
            "--model",
            "example-model",
            "--fake-run",
            "suspicious",
            "--drift-check",
            "yes",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    markdown = output_path.read_text(encoding="utf-8")
    assert "drift" in markdown.lower() or "漂移" in markdown
    assert "Drift check was not enabled" not in markdown
    assert "This full-profile run did not enable drift checking" not in markdown
    assert "Rerun with `--drift-check yes`" not in markdown


def test_unified_relay_audit_rejects_invalid_drift_check():
    result = CliRunner().invoke(
        app,
        [
            "audit",
            "--base-url",
            "https://api.relay.com/v1",
            "--model",
            "example-model",
            "--fake-run",
            "pass",
            "--drift-check",
            "maybe",
        ],
    )

    assert result.exit_code == 2
    assert "--drift-check must be yes or no" in result.output


def test_unified_audit_relay_detail_audit_yes_is_rejected():
    result = CliRunner().invoke(
        app,
        [
            "audit",
            "--base-url",
            "https://api.relay.com/v1",
            "--model",
            "example-model",
            "--detail-audit",
            "yes",
        ],
    )

    assert result.exit_code == 2
    assert "relay repeated full-profile audit is not part of the current release" in result.output.lower()


def test_unified_audit_relay_unexpected_runtime_failure_exits_one(monkeypatch):
    def broken_run_relay_audit(request):
        raise AttributeError("internal bug with https://api.relay.com/v1?token=secret")

    monkeypatch.setattr(cli_module, "run_relay_audit", broken_run_relay_audit)

    result = CliRunner().invoke(
        app,
        [
            "audit",
            "--base-url",
            "https://api.relay.com/v1?token=secret",
            "--model",
            "example-model",
            "--fake-run",
            "pass",
        ],
    )

    assert result.exit_code == 1
    assert "Relay audit failed before a public result could be produced." in result.output
    assert "https://" not in result.output
    assert "token=secret" not in result.output


def test_unified_audit_config_route_relay_uses_relay_block(tmp_path):
    config_path = tmp_path / "relay.yaml"
    output_path = tmp_path / "relay-config.md"
    config_path.write_text(
        """
route: relay
relay:
  base_url: https://api.relay.com/v1/chat/completions?user=heiyan_studio#frag
  model: example-model
  profile: general
  fake_run: pass
""",
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        app,
        [
            "audit",
            "--config",
            str(config_path),
            "--output",
            str(output_path),
        ],
        env={"RELAY_API_KEY": "sk-secret"},
    )

    assert result.exit_code == 0
    markdown = output_path.read_text(encoding="utf-8")
    assert "TokenVerify Relay Technical Profile Report" in markdown
    assert "Technical Result" in markdown
    assert "https://" not in markdown
    assert "heiyan_studio" not in markdown


def test_relay_cli_live_general_supports_zh_report_language(tmp_path, monkeypatch):
    def fake_default_transport(request):
        def transport(payload):
            return RelayLiveTransportResponse(
                status_code=200,
                body={"choices": [{"message": {"content": "ok"}}]},
            )

        return transport

    monkeypatch.setattr(cli_module, "_default_relay_live_transport", fake_default_transport)
    output_path = tmp_path / "live-report-zh.md"

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
            "--language",
            "zh",
            "--output",
            str(output_path),
        ],
        env={"RELAY_API_KEY": "sk-secret"},
    )

    assert result.exit_code == 0
    markdown = output_path.read_text(encoding="utf-8")
    assert "技术检查结果" in markdown
    assert "支撑场景范围" in markdown
    assert "方法说明" in markdown
    assert "https://" not in markdown
    assert "/v1" not in markdown
    assert "heiyan_studio" not in markdown


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
        env={"RELAY_API_KEY": "sk-secret"},
    )

    assert result.exit_code == 3
    assert "Relay audit completed with verdict: inconclusive" in result.output
    assert "sk-secret" not in result.output
    assert output_path.exists()
    markdown = output_path.read_text(encoding="utf-8")
    assert "Inconclusive" in markdown
    assert "Runtime category" in markdown
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


def test_unified_audit_relay_missing_api_key_env_exits_two_before_transport(monkeypatch, tmp_path):
    monkeypatch.delenv("RELAY_API_KEY", raising=False)
    touched = False

    def forbidden_transport(request):
        nonlocal touched
        touched = True
        raise AssertionError("transport factory must not be touched when env is missing")

    monkeypatch.setattr(cli_module, "_default_relay_live_transport", forbidden_transport)
    output_path = tmp_path / "missing-env.md"

    result = CliRunner().invoke(
        app,
        [
            "audit",
            "--base-url",
            "https://api.relay.com/v1",
            "--model",
            "example-model",
            "--api-key-env",
            "RELAY_API_KEY",
            "--live",
            "--output",
            str(output_path),
        ],
        env={},
    )

    assert result.exit_code == 2
    assert "RELAY_API_KEY" in result.output
    assert "not found in the current environment" in result.output
    assert touched is False
    assert not output_path.exists()


def test_relay_audit_compat_missing_api_key_env_exits_two_before_transport(monkeypatch, tmp_path):
    monkeypatch.delenv("RELAY_API_KEY", raising=False)
    touched = False

    def forbidden_transport(request):
        nonlocal touched
        touched = True
        raise AssertionError("transport factory must not be touched when env is missing")

    monkeypatch.setattr(cli_module, "_default_relay_live_transport", forbidden_transport)
    output_path = tmp_path / "missing-env-compat.md"

    result = CliRunner().invoke(
        app,
        [
            "relay-audit",
            "--base-url",
            "https://api.relay.com/v1",
            "--model",
            "example-model",
            "--api-key-env",
            "RELAY_API_KEY",
            "--live",
            "--output",
            str(output_path),
        ],
        env={},
    )

    assert result.exit_code == 2
    assert "RELAY_API_KEY" in result.output
    assert "not found in the current environment" in result.output
    assert touched is False
    assert not output_path.exists()


def test_unified_audit_relay_fake_run_does_not_require_api_key_env_to_exist(tmp_path):
    output_path = tmp_path / "fake-run.md"

    result = CliRunner().invoke(
        app,
        [
            "audit",
            "--base-url",
            "https://api.relay.com/v1",
            "--model",
            "example-model",
            "--api-key-env",
            "RELAY_API_KEY",
            "--fake-run",
            "pass",
            "--output",
            str(output_path),
        ],
        env={},
    )

    assert result.exit_code == 0
    assert output_path.exists()


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
        env={"RELAY_API_KEY": "sk-secret"},
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


def test_unified_audit_security_fake_run_pass_creates_low_risk_report(tmp_path):
    output_path = tmp_path / "security-pass.md"
    result = CliRunner().invoke(
        app,
        [
            "audit",
            "--base-url",
            "https://relay.example/v1",
            "--model",
            "demo-model",
            "--profile",
            "security",
            "--fake-run",
            "pass",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    report = output_path.read_text(encoding="utf-8")
    assert "security" in report.lower()
    assert "Verdict: **pass**" in report
    assert "Risk level: **low**" in report


def test_unified_audit_security_fake_run_fail_is_sanitized(tmp_path):
    output_path = tmp_path / "security-fail.md"
    result = CliRunner().invoke(
        app,
        [
            "audit",
            "--base-url",
            "https://relay.example/v1/private?token=raw",
            "--model",
            "demo-model",
            "--profile",
            "security",
            "--fake-run",
            "fail",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 1
    report = output_path.read_text(encoding="utf-8")
    assert "Verdict: **fail**" in report
    assert "Risk level: **high**" in report
    assert "tv_safe_boundary_ok" not in report.lower()
    assert "tv_extraction_safe" not in report.lower()
    assert "tv_override_safe" not in report.lower()
    assert "/private?token=raw" not in report


def test_unified_audit_security_fake_run_inconclusive_uses_exit_3(tmp_path):
    output_path = tmp_path / "security-inconclusive.md"
    result = CliRunner().invoke(
        app,
        [
            "audit",
            "--base-url",
            "https://relay.example/v1",
            "--model",
            "demo-model",
            "--profile",
            "security",
            "--fake-run",
            "inconclusive",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 3
    report = output_path.read_text(encoding="utf-8")
    assert "Verdict: **inconclusive**" in report
    assert "Risk level: **unknown**" in report


def test_security_live_missing_env_fails_before_transport_construction(monkeypatch, tmp_path):
    constructed = []

    def factory(request):
        constructed.append("security")
        return None

    monkeypatch.setattr(cli_module, "_default_relay_security_transport_factory", factory, raising=False)
    output_path = tmp_path / "security.md"
    result = CliRunner().invoke(
        app,
        [
            "audit",
            "--base-url",
            "https://relay.example/v1",
            "--model",
            "demo-model",
            "--profile",
            "security",
            "--api-key-env",
            "MISSING_RELAY_KEY",
            "--live",
            "--output",
            str(output_path),
        ],
        env={},
    )

    assert result.exit_code == 2
    assert constructed == []
    assert "MISSING_RELAY_KEY" in result.output
    assert not output_path.exists()


def test_security_live_raw_secret_api_key_env_wins_before_transport(monkeypatch, tmp_path):
    constructed = []

    def factory(request):
        constructed.append("security")
        return None

    monkeypatch.setattr(cli_module, "_default_relay_security_transport_factory", factory, raising=False)
    result = CliRunner().invoke(
        app,
        [
            "audit",
            "--base-url",
            "https://relay.example/v1",
            "--model",
            "demo-model",
            "--profile",
            "security",
            "--api-key-env",
            "sk-or-v1-raw-secret",
            "--live",
            "--output",
            str(tmp_path / "security.md"),
        ],
    )

    assert result.exit_code == 2
    assert constructed == []
    assert "sk-or-v1-raw-secret" not in result.output


def test_security_live_uses_delayed_default_transport_after_preflight(monkeypatch, tmp_path):
    constructed = []

    def factory(request):
        def build_transport():
            constructed.append((request.profile.value, request.live))
            responses = iter(
                [
                    RelayLiveTransportResponse(
                        200,
                        {"choices": [{"message": {"content": "TV_SAFE_BOUNDARY_OK"}, "finish_reason": "stop"}]},
                    ),
                    RelayLiveTransportResponse(
                        200,
                        {"choices": [{"message": {"content": "TV_EXTRACTION_SAFE"}, "finish_reason": "stop"}]},
                    ),
                    RelayLiveTransportResponse(
                        200,
                        {"choices": [{"message": {"content": "TV_OVERRIDE_SAFE"}, "finish_reason": "stop"}]},
                    ),
                ]
            )

            def transport(payload):
                return next(responses)

            return transport

        return build_transport

    monkeypatch.setattr(cli_module, "_default_relay_security_transport_factory", factory, raising=False)
    output_path = tmp_path / "security-live.md"
    result = CliRunner().invoke(
        app,
        [
            "audit",
            "--base-url",
            "https://relay.example/v1",
            "--model",
            "demo-model",
            "--profile",
            "security",
            "--api-key-env",
            "RELAY_TEST_KEY",
            "--live",
            "--output",
            str(output_path),
        ],
        env={"RELAY_TEST_KEY": "sk-test"},
    )

    assert result.exit_code == 0
    assert constructed == [("security", True)]
    assert "Verdict: **pass**" in output_path.read_text(encoding="utf-8")


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


def test_unified_audit_relay_auto_report_path_has_relay_prefix(tmp_path, monkeypatch):
    class FixedDate:
        @classmethod
        def today(cls):
            return "2026-06-03"

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli_module, "date", FixedDate)

    result = CliRunner().invoke(
        app,
        [
            "audit",
            "--base-url",
            "https://api.relay.com/v1",
            "--model",
            "example-model",
            "--fake-run",
            "pass",
        ],
    )

    expected_path = tmp_path / "reports" / "audit-relay-example-model-2026-06-03.md"
    assert result.exit_code == 0
    assert expected_path.exists()
    assert "audit-relay-example-model-2026-06-03.md" in result.output


def test_relay_audit_compatibility_notice_goes_to_stderr(monkeypatch, tmp_path):
    output_path = tmp_path / "compat.md"
    notices = []
    original_echo = cli_module.typer.echo

    def capture_echo(message=None, *args, **kwargs):
        if "Compatibility notice" in str(message):
            notices.append(kwargs.get("err", False))
        return original_echo(message, *args, **kwargs)

    monkeypatch.setattr(cli_module.typer, "echo", capture_echo)
    result = CliRunner().invoke(
        app,
        [
            "relay-audit",
            "--base-url",
            "https://api.relay.com/v1",
            "--model",
            "example-model",
            "--fake-run",
            "pass",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    assert notices == [True]
    assert "Relay audit completed with verdict: pass" in result.output


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
        env={"RELAY_API_KEY": "sk-secret"},
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
        env={"RELAY_API_KEY": "sk-secret"},
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

    def fake_security_factory(request):
        def factory():
            def transport(payload):
                calls.append("security")
                text = str(payload)
                if "TV_EXTRACTION_SAFE" in text:
                    content = "TV_EXTRACTION_SAFE"
                elif "TV_OVERRIDE_SAFE" in text:
                    content = "TV_OVERRIDE_SAFE"
                else:
                    content = "TV_SAFE_BOUNDARY_OK"
                return RelayLiveTransportResponse(
                    status_code=200,
                    body={"choices": [{"message": {"content": content}, "finish_reason": "stop"}]},
                )

            return transport

        return factory

    def fake_context_factory(request):
        def factory():
            def transport(payload):
                calls.append("context")
                text = str(payload)
                content = "TV_CTX_MIDDLE" if "TV_CTX_MIDDLE" in text else "TV_CTX_ALPHA|TV_CTX_BRAVO|TV_CTX_CHARLIE"
                return RelayLiveTransportResponse(
                    status_code=200,
                    body={"choices": [{"message": {"content": content}, "finish_reason": "stop"}]},
                )

            return transport

        return factory

    monkeypatch.setattr(cli_module, "_default_relay_live_transport_factory", fake_general_factory)
    monkeypatch.setattr(cli_module, "_default_relay_stream_transport_factory", fake_stream_factory)
    monkeypatch.setattr(cli_module, "_default_relay_schema_transport_factory", fake_schema_factory)
    monkeypatch.setattr(cli_module, "_default_relay_privacy_transport_factory", fake_privacy_factory)
    monkeypatch.setattr(cli_module, "_default_relay_security_transport_factory", fake_security_factory)
    monkeypatch.setattr(cli_module, "_default_relay_context_transport_factory", fake_context_factory)
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
        env={"RELAY_API_KEY": "sk-secret"},
    )

    assert result.exit_code == 0
    assert calls == ["general", "streaming", "schema", "privacy", "security", "security", "security", "context", "context"]
    markdown = output_path.read_text(encoding="utf-8")
    assert "Profile}：`full`" not in markdown
    assert "Profile：`full`" in markdown or "Profile: `full`" in markdown
    assert "Executed Technical Checks" in markdown
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


def test_unified_audit_context_fake_run_pass_creates_low_risk_report(tmp_path):
    output_path = tmp_path / "context-pass.md"
    result = CliRunner().invoke(
        app,
        [
            "audit",
            "--base-url",
            "https://relay.example/v1",
            "--model",
            "demo-model",
            "--profile",
            "context",
            "--fake-run",
            "pass",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    report = output_path.read_text(encoding="utf-8")
    assert "context" in report.lower()
    assert "Verdict: **pass**" in report
    assert "Risk level: **low**" in report


def test_unified_audit_context_fake_run_fail_is_sanitized(tmp_path):
    output_path = tmp_path / "context-fail.md"
    result = CliRunner().invoke(
        app,
        [
            "audit",
            "--base-url",
            "https://relay.example/v1/private?token=raw",
            "--model",
            "demo-model",
            "--profile",
            "context",
            "--fake-run",
            "fail",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 1
    report = output_path.read_text(encoding="utf-8")
    assert "Verdict: **fail**" in report
    assert "Risk level: **high**" in report
    assert "tv_ctx_alpha" not in report.lower()
    assert "tv_ctx_middle" not in report.lower()
    assert "/private?token=raw" not in report


def test_unified_audit_context_fake_run_suspicious_exits_zero(tmp_path):
    output_path = tmp_path / "context-suspicious.md"
    result = CliRunner().invoke(
        app,
        [
            "audit",
            "--base-url",
            "https://relay.example/v1",
            "--model",
            "demo-model",
            "--profile",
            "context",
            "--fake-run",
            "suspicious",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    report = output_path.read_text(encoding="utf-8")
    assert "Verdict: **suspicious**" in report
    assert "separator_degradation_detected=True" in report


def test_unified_audit_context_fake_run_inconclusive_uses_exit_3(tmp_path):
    output_path = tmp_path / "context-inconclusive.md"
    result = CliRunner().invoke(
        app,
        [
            "audit",
            "--base-url",
            "https://relay.example/v1",
            "--model",
            "demo-model",
            "--profile",
            "context",
            "--fake-run",
            "inconclusive",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 3
    report = output_path.read_text(encoding="utf-8")
    assert "Verdict: **inconclusive**" in report
    assert "Risk level: **unknown**" in report


def test_context_live_missing_env_fails_before_transport_construction(monkeypatch, tmp_path):
    constructed = []

    def factory(request):
        constructed.append("context")
        return None

    monkeypatch.setattr(cli_module, "_default_relay_context_transport_factory", factory, raising=False)
    output_path = tmp_path / "context.md"
    result = CliRunner().invoke(
        app,
        [
            "audit",
            "--base-url",
            "https://relay.example/v1",
            "--model",
            "demo-model",
            "--profile",
            "context",
            "--api-key-env",
            "MISSING_RELAY_KEY",
            "--live",
            "--output",
            str(output_path),
        ],
        env={},
    )

    assert result.exit_code == 2
    assert constructed == []
    assert "MISSING_RELAY_KEY" in result.output
    assert not output_path.exists()


def test_context_live_raw_secret_api_key_env_wins_before_transport(monkeypatch, tmp_path):
    constructed = []

    def factory(request):
        constructed.append("context")
        return None

    monkeypatch.setattr(cli_module, "_default_relay_context_transport_factory", factory, raising=False)
    result = CliRunner().invoke(
        app,
        [
            "audit",
            "--base-url",
            "https://relay.example/v1",
            "--model",
            "demo-model",
            "--profile",
            "context",
            "--api-key-env",
            "sk-or-v1-raw-secret",
            "--live",
            "--output",
            str(tmp_path / "context.md"),
        ],
    )

    assert result.exit_code == 2
    assert constructed == []
    assert "sk-or-v1-raw-secret" not in result.output


def test_context_live_uses_delayed_default_transport_after_preflight(monkeypatch, tmp_path):
    constructed = []

    def factory(request):
        def build_transport():
            constructed.append((request.profile.value, request.live))
            responses = iter(
                [
                    RelayLiveTransportResponse(
                        200,
                        {
                            "choices": [
                                {
                                    "message": {"content": "TV_CTX_ALPHA|TV_CTX_BRAVO|TV_CTX_CHARLIE"},
                                    "finish_reason": "stop",
                                }
                            ]
                        },
                    ),
                    RelayLiveTransportResponse(
                        200,
                        {"choices": [{"message": {"content": "TV_CTX_MIDDLE"}, "finish_reason": "stop"}]},
                    ),
                ]
            )

            def transport(payload):
                return next(responses)

            return transport

        return build_transport

    monkeypatch.setattr(cli_module, "_default_relay_context_transport_factory", factory, raising=False)
    output_path = tmp_path / "context-live.md"
    result = CliRunner().invoke(
        app,
        [
            "audit",
            "--base-url",
            "https://relay.example/v1",
            "--model",
            "demo-model",
            "--profile",
            "context",
            "--api-key-env",
            "RELAY_TEST_KEY",
            "--live",
            "--output",
            str(output_path),
        ],
        env={"RELAY_TEST_KEY": "sk-test"},
    )

    assert result.exit_code == 0
    assert constructed == [("context", True)]
    assert "Verdict: **pass**" in output_path.read_text(encoding="utf-8")
