from pathlib import Path

from typer.testing import CliRunner

import tokenverify.cli as cli_module
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
    markdown = output_path.read_text(encoding="utf-8")
    assert "High Trust" in markdown
    assert "Audit Route" in markdown
    assert "provider/model authenticity" in markdown


def test_cli_language_zh_writes_chinese_report_explanation(tmp_path, monkeypatch):
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
            rating=Rating.HIGH_TRUST,
            score_breakdown={},
            redacted_config=runtime_config.redacted_config,
        )

    monkeypatch.setattr("tokenverify.cli.run_audit", fake_run_audit)

    result = CliRunner().invoke(
        app,
        [
            "audit",
            "--config",
            str(config_path),
            "--endpoint",
            "primary",
            "--output",
            str(output_path),
            "--language",
            "zh",
        ],
    )

    assert result.exit_code == 0
    markdown = output_path.read_text(encoding="utf-8")
    assert "本次检测结果：High Trust" in markdown
    assert "## 欺诈场景总结" in markdown
    assert "Audit result:" not in markdown


def test_cli_rejects_unknown_language(tmp_path):
    config_path = tmp_path / "audit.yaml"
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

    result = CliRunner().invoke(app, ["audit", "--config", str(config_path), "--language", "fr"])

    assert result.exit_code == 2
    assert "--language must be en or zh" in result.output


def test_cli_auto_generates_report_path_from_model_and_date(tmp_path, monkeypatch):
    config_path = tmp_path / "audit.yaml"
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

    class FixedDate:
        @classmethod
        def today(cls):
            return "2026-05-29"

    def fake_run_audit(runtime_config, repeat_count=1):
        assert repeat_count == 1
        assert runtime_config.output_path == Path("reports/audit-provider-claude-sonnet-4-5-2026-05-29.md")
        return AuditResult(
            target_summary={"base_url_host": "api.anthropic.com", "model": runtime_config.endpoint.model},
            probe_results=[],
            rating=Rating.HIGH_TRUST,
            score_breakdown={},
            redacted_config=runtime_config.redacted_config,
        )

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli_module, "date", FixedDate)
    monkeypatch.setattr("tokenverify.cli.run_audit", fake_run_audit)

    result = CliRunner().invoke(app, ["audit", "--config", str(config_path), "--endpoint", "primary"])

    expected_path = tmp_path / "reports" / "audit-provider-claude-sonnet-4-5-2026-05-29.md"
    assert result.exit_code == 0
    assert expected_path.exists()
    assert f"Wrote audit report: {expected_path.relative_to(tmp_path)}" in result.output


def test_cli_auto_generated_report_path_avoids_overwriting_existing_file(tmp_path, monkeypatch):
    config_path = tmp_path / "audit.yaml"
    existing_path = tmp_path / "reports" / "audit-provider-gpt-5-1-2026-05-29.md"
    existing_path.parent.mkdir()
    existing_path.write_text("existing", encoding="utf-8")
    config_path.write_text(
        """
selected_endpoint: primary
endpoints:
  - name: primary
    base_url: https://api.openai.com/v1
    provider: openai
    api_shape: openai-compatible
    model: gpt-5.1
    api_key: TOKEN_PLACEHOLDER
""",
        encoding="utf-8",
    )

    class FixedDate:
        @classmethod
        def today(cls):
            return "2026-05-29"

    def fake_run_audit(runtime_config, repeat_count=1):
        assert runtime_config.output_path == Path("reports/audit-provider-gpt-5-1-2026-05-29-2.md")
        return AuditResult(
            target_summary={"base_url_host": "api.openai.com", "model": runtime_config.endpoint.model},
            probe_results=[],
            rating=Rating.HIGH_TRUST,
            score_breakdown={},
            redacted_config=runtime_config.redacted_config,
        )

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli_module, "date", FixedDate)
    monkeypatch.setattr("tokenverify.cli.run_audit", fake_run_audit)

    result = CliRunner().invoke(app, ["audit", "--config", str(config_path), "--endpoint", "primary"])

    assert result.exit_code == 0
    assert existing_path.read_text(encoding="utf-8") == "existing"
    assert (tmp_path / "reports" / "audit-provider-gpt-5-1-2026-05-29-2.md").exists()


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


def test_cli_detail_audit_yes_uses_internal_repeat_count(tmp_path, monkeypatch):
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
        ["audit", "--config", str(config_path), "--detail-audit", "yes", "--output", str(output_path)],
    )

    assert result.exit_code == 0
    assert observed_repeat == 8


def test_cli_detail_audit_no_uses_single_sample(tmp_path, monkeypatch):
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

    def fake_run_audit(runtime_config, repeat_count=1):
        assert repeat_count == 1
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
        ["audit", "--config", str(config_path), "--detail-audit", "no", "--output", str(output_path)],
    )

    assert result.exit_code == 0


def test_cli_rejects_unknown_detail_audit_value(tmp_path):
    config_path = tmp_path / "audit.yaml"
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

    result = CliRunner().invoke(app, ["audit", "--config", str(config_path), "--detail-audit", "maybe"])

    assert result.exit_code == 2
    assert "--detail-audit must be yes or no" in result.output


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
    assert "Audit completed with rating: Low Trust" in result.output
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
    assert "Audit completed with rating: Inconclusive" in result.output
    assert "Check API key, network, quota, or unsupported target details in the report." in result.output
    assert output_path.exists()


def test_cli_help_documents_common_examples_and_exit_codes():
    result = CliRunner().invoke(app, ["audit", "--help"])

    assert result.exit_code == 0
    assert "Native Claude example" in result.output
    assert "Relay contract audit example" in result.output
    assert "Global Options" in result.output
    assert "Provider Audit Options" in result.output
    assert "Relay Audit Options" in result.output
    assert "--config" in result.output
    assert "--base-url" in result.output
    assert "--model" in result.output
    assert "--profile" in result.output
    assert "--detail-audit" in result.output
    assert "--language" in result.output
    assert "Exit code 0:" in result.output
    assert "Exit code 1:" in result.output
    assert "Exit code 2:" in result.output
    assert "Exit code 3: inconclusive runtime result." in result.output
    assert "--repeat" not in result.output
