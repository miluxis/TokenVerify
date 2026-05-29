from pathlib import Path

from typer.testing import CliRunner

from tokenverify.cli import app
from tokenverify.models import AuditResult, Rating


def test_cli_writes_markdown_report_with_mocked_audit(tmp_path, monkeypatch):
    config_path = tmp_path / "audit.yaml"
    output_path = tmp_path / "report.md"
    config_path.write_text(
        """
selected_endpoint: primary
endpoints:
  - name: primary
    base_url: https://api.anthropic.com
    model: claude-sonnet-4-5
    api_key: TOKEN_PLACEHOLDER
""",
        encoding="utf-8",
    )

    def fake_run_audit(runtime_config, repeat_count=1):
        assert repeat_count == 1
        return AuditResult(
            target_summary={"base_url_host": "api.anthropic.com", "model": runtime_config.endpoint.model},
            probe_results=[],
            rating=Rating.HIGH_TRUST,
            score_breakdown={},
            redacted_config=runtime_config.redacted_config,
        )

    monkeypatch.setattr("tokenverify.cli.run_audit", fake_run_audit)

    result = CliRunner().invoke(
        app,
        ["audit", "--config", str(config_path), "--endpoint", "primary", "--output", str(output_path)],
    )

    assert result.exit_code == 0
    assert "高可信" in output_path.read_text(encoding="utf-8")


def test_cli_forwards_repeat_count_to_audit(tmp_path, monkeypatch):
    config_path = tmp_path / "audit.yaml"
    output_path = tmp_path / "report.md"
    config_path.write_text(
        """
selected_endpoint: relay
endpoints:
  - name: relay
    base_url: https://relay.example/v1
    provider: anthropic
    api_shape: openai-compatible
    model: claude-haiku-4-5-20251001
    api_key: TOKEN_PLACEHOLDER
""",
        encoding="utf-8",
    )
    observed_repeat = None

    def fake_run_audit(runtime_config, repeat_count=1):
        nonlocal observed_repeat
        observed_repeat = repeat_count
        return AuditResult(
            target_summary={"base_url_host": "relay.example", "model": runtime_config.endpoint.model},
            probe_results=[],
            rating=Rating.HIGH_TRUST,
            score_breakdown={},
            redacted_config=runtime_config.redacted_config,
        )

    monkeypatch.setattr("tokenverify.cli.run_audit", fake_run_audit)

    result = CliRunner().invoke(
        app,
        ["audit", "--config", str(config_path), "--repeat", "6", "--output", str(output_path)],
    )

    assert result.exit_code == 0
    assert observed_repeat == 6


def test_cli_requires_endpoint_when_config_has_multiple(tmp_path):
    config_path = tmp_path / "audit.yaml"
    config_path.write_text(
        """
endpoints:
  - name: first
    base_url: https://first.example
    model: claude-sonnet-4-5
    api_key: FIRST_TOKEN_PLACEHOLDER
  - name: second
    base_url: https://second.example
    model: claude-sonnet-4-5
    api_key: SECOND_TOKEN_PLACEHOLDER
""",
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["audit", "--config", str(config_path)])

    assert result.exit_code != 0
    assert "select one endpoint" in result.output


def test_cli_returns_one_for_low_trust_audit_result(tmp_path, monkeypatch):
    config_path = tmp_path / "audit.yaml"
    output_path = tmp_path / "report.md"
    config_path.write_text(
        """
selected_endpoint: primary
endpoints:
  - name: primary
    base_url: https://api.anthropic.com
    model: claude-sonnet-4-5
    api_key: TOKEN_PLACEHOLDER
""",
        encoding="utf-8",
    )

    def fake_run_audit(runtime_config, repeat_count=1):
        return AuditResult(
            target_summary={"base_url_host": "api.anthropic.com", "model": runtime_config.endpoint.model},
            probe_results=[],
            rating=Rating.LOW_TRUST,
            score_breakdown={},
            redacted_config=runtime_config.redacted_config,
        )

    monkeypatch.setattr("tokenverify.cli.run_audit", fake_run_audit)

    result = CliRunner().invoke(
        app,
        ["audit", "--config", str(config_path), "--endpoint", "primary", "--output", str(output_path)],
    )

    assert result.exit_code == 1
    assert "Audit completed with rating: 低可信" in result.output
    assert output_path.exists()


def test_cli_returns_three_for_inconclusive_no_key_result(tmp_path, monkeypatch):
    config_path = tmp_path / "audit.yaml"
    output_path = tmp_path / "report.md"
    config_path.write_text(
        """
selected_endpoint: primary
endpoints:
  - name: primary
    base_url: https://api.anthropic.com
    model: claude-sonnet-4-5
""",
        encoding="utf-8",
    )

    def fake_run_audit(runtime_config, repeat_count=1):
        return AuditResult(
            target_summary={"base_url_host": "api.anthropic.com", "model": runtime_config.endpoint.model},
            probe_results=[],
            rating=Rating.INCONCLUSIVE,
            score_breakdown={},
            redacted_config=runtime_config.redacted_config,
        )

    monkeypatch.setattr("tokenverify.cli.run_audit", fake_run_audit)

    result = CliRunner().invoke(
        app,
        ["audit", "--config", str(config_path), "--endpoint", "primary", "--output", str(output_path)],
    )

    assert result.exit_code == 3
    assert "Audit completed with rating: 无法判定" in result.output
    assert "Check API key, network, quota, or unsupported target details in the report." in result.output
    assert output_path.exists()


def test_cli_help_documents_common_examples_and_exit_codes():
    result = CliRunner().invoke(app, ["audit", "--help"])

    assert result.exit_code == 0
    assert "Native Claude example" in result.output
    assert "OpenAI-compatible Claude relay example" in result.output
    assert "Exit code 0: high/medium trust." in result.output
    assert "Exit code 1: low trust." in result.output
    assert "Exit code 2: configuration error." in result.output
    assert "Exit code 3: inconclusive runtime result." in result.output
    assert "--repeat" in result.output
