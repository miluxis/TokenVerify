from typer.testing import CliRunner

import tokenverify.cli as cli_module
from tokenverify.cli import app


def test_relay_cli_fake_run_writes_sanitized_report(tmp_path):
    output_path = tmp_path / "relay-report.md"

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
            "--fake-run",
            "suspicious",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    assert "Wrote relay audit report:" in result.output
    assert "Relay audit completed with verdict: suspicious" in result.output
    markdown = output_path.read_text(encoding="utf-8")
    assert "TokenVerify Relay Audit Report" in markdown
    assert "api.relay.com" in markdown
    assert "https://" not in markdown
    assert "/v1" not in markdown
    assert "heiyan_studio" not in markdown


def test_relay_cli_fail_and_inconclusive_exit_codes(tmp_path):
    fail_output = tmp_path / "fail.md"
    fail = CliRunner().invoke(
        app,
        [
            "relay-audit",
            "--base-url",
            "https://relay.example/v1",
            "--model",
            "example-model",
            "--fake-run",
            "fail",
            "--output",
            str(fail_output),
        ],
    )
    assert fail.exit_code == 1
    assert fail_output.exists()

    inconclusive_output = tmp_path / "inconclusive.md"
    inconclusive = CliRunner().invoke(
        app,
        [
            "relay-audit",
            "--base-url",
            "https://relay.example/v1",
            "--model",
            "example-model",
            "--fake-run",
            "inconclusive",
            "--output",
            str(inconclusive_output),
        ],
    )
    assert inconclusive.exit_code == 3
    assert inconclusive_output.exists()


def test_relay_cli_config_errors_exit_two_not_verdict_fail(tmp_path):
    result = CliRunner().invoke(
        app,
        [
            "relay-audit",
            "--base-url",
            "https://relay.example/v1",
            "--model",
            "example-model",
            "--profile",
            "wrong-value",
            "--fake-run",
            "pass",
            "--output",
            str(tmp_path / "report.md"),
        ],
    )

    assert result.exit_code == 2
    assert "Unknown relay audit profile" in result.output
    assert "wrong-value" not in result.output


def test_relay_cli_missing_pack_error_is_sanitized_and_exit_two(tmp_path):
    result = CliRunner().invoke(
        app,
        [
            "relay-audit",
            "--base-url",
            "https://relay.example/v1",
            "--model",
            "example-model",
            "--fake-run",
            "pass",
            "--pack-path",
            "~/Desktop/heiyan_studio/missing_private.yaml",
            "--output",
            str(tmp_path / "report.md"),
        ],
    )

    assert result.exit_code == 2
    assert "missing_private.yaml" in result.output
    assert "heiyan_studio" not in result.output
    assert "Desktop" not in result.output
    assert "~" not in result.output


def test_relay_cli_pack_summary_excludes_private_pack_content(tmp_path):
    pack_path = tmp_path / "my_private_pack.yaml"
    pack_path.write_text(
        """
id: local-private
version: "2026.06"
challenges:
  - id: secret
    prompt: "raw prompt must not appear"
    expected_answer: "private answer"
""",
        encoding="utf-8",
    )
    output_path = tmp_path / "report.md"

    result = CliRunner().invoke(
        app,
        [
            "relay-audit",
            "--base-url",
            "https://relay.example/v1",
            "--model",
            "example-model",
            "--fake-run",
            "pass",
            "--pack-path",
            str(pack_path),
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    markdown = output_path.read_text(encoding="utf-8")
    assert "local-private" in markdown
    assert "2026.06" in markdown
    assert "my_private_pack.yaml" in markdown
    assert "raw prompt" not in markdown
    assert "private answer" not in markdown
    assert str(tmp_path) not in markdown


def test_relay_cli_pack_summary_includes_safe_metadata_and_count(tmp_path):
    pack_path = tmp_path / "my_private_pack.yaml"
    pack_path.write_text(
        """
id: private-media-pack
version: "2026.06"
profiles:
  - general
categories:
  - model_substitution
challenges:
  - id: hidden-case-id
    profile: general
    category: model_substitution
    public_intent: "Checks a public relay contract."
    prompt: "raw prompt must not appear"
    expected_answer: "private expected answer"
    verifier: "secret verifier expression"
""",
        encoding="utf-8",
    )
    output_path = tmp_path / "report.md"

    result = CliRunner().invoke(
        app,
        [
            "relay-audit",
            "--base-url",
            "https://relay.example/v1",
            "--model",
            "example-model",
            "--fake-run",
            "pass",
            "--pack-path",
            str(pack_path),
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 0
    markdown = output_path.read_text(encoding="utf-8")
    assert "private-media-pack" in markdown
    assert "2026.06" in markdown
    assert "Profiles: general" in markdown
    assert "Categories: model_substitution" in markdown
    assert "Challenges: 1" in markdown
    assert "Intent: Checks a public relay contract." in markdown
    assert "hidden-case-id" not in markdown
    assert "raw prompt" not in markdown
    assert "private expected answer" not in markdown
    assert "secret verifier" not in markdown
    assert str(tmp_path) not in markdown


def test_relay_cli_without_fake_run_blocks_network_boundary():
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
    assert "sk-secret" not in result.output


def test_relay_cli_with_live_without_transport_returns_inconclusive_report(monkeypatch, tmp_path):
    monkeypatch.setattr(cli_module, "_default_relay_live_transport_factory", lambda request: lambda: None)
    output_path = tmp_path / "live-inconclusive.md"

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
            "--live",
            "--output",
            str(output_path),
        ],
    )

    assert result.exit_code == 3
    assert "Relay audit completed with verdict: inconclusive" in result.output
    assert output_path.exists()
    assert "sk-secret" not in result.output


def test_relay_cli_auto_generates_report_path_from_model_and_date(tmp_path, monkeypatch):
    class FixedDate:
        @classmethod
        def today(cls):
            return "2026-06-02"

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli_module, "date", FixedDate)

    result = CliRunner().invoke(
        app,
        [
            "relay-audit",
            "--base-url",
            "https://relay.example/v1",
            "--model",
            "example model",
            "--fake-run",
            "pass",
        ],
    )

    expected_path = tmp_path / "reports" / "relay-audit-example-model-2026-06-02.md"
    assert result.exit_code == 0
    assert expected_path.exists()


def test_relay_cli_help_documents_fake_run_and_live_gate():
    result = CliRunner().invoke(app, ["relay-audit", "--help"])

    assert result.exit_code == 0
    assert "--fake-run" in result.output
    assert "--profile" in result.output
    assert "--pack-path" in result.output
    assert "--live" in result.output
    compact_output = " ".join(result.output.split())
    assert "approved minimal general connectivity" in compact_output
    assert "streaming/SSE integrity" in compact_output
