from typer.testing import CliRunner

import tokenverify.cli as cli_module
from tokenverify.cli import app
from tokenverify.relay_live import RelayLiveTransportResponse


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
