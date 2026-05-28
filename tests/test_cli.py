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

    def fake_run_audit(runtime_config):
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
