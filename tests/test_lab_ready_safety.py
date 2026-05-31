from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from tokenverify.audit import AuditObservations, run_audit
from tokenverify.cli import app
from tokenverify.config import load_runtime_config
from tokenverify.models import AuditResult, EvidenceItem, ProbeResult, ProviderEvent, Rating, StreamingMetrics, Verdict
from tokenverify.report import render_markdown


ROOT = Path(__file__).resolve().parents[1]


def write_config(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "audit.yaml"
    path.write_text(content, encoding="utf-8")
    return path


def safe_result() -> AuditResult:
    return AuditResult(
        target_summary={
            "base_url_host": "relay.example",
            "model": "gpt-5.1",
            "endpoint": "relay",
            "claimed_provider": "openai",
            "claimed_api_shape": "openai-compatible",
        },
        probe_results=[
            ProbeResult(
                "openai_model_claim_consistency",
                "failed",
                [
                    EvidenceItem(
                        "openai_model_claim",
                        "strong",
                        False,
                        "Response exposed provider-exclusive metadata under an OpenAI claim.",
                        details={
                            "observed_fields": ["system_fingerprint"],
                            "system_fingerprint": "fp_private_123",
                            "provider_error": "upstream says raw provider secret",
                        },
                        tags=["CROSS_PROVIDER_MODEL_LEAKED"],
                    )
                ],
                errors=["HTTP 401 from https://private-relay.example/v1: raw provider error text TOKEN_SHOULD_NOT_LEAK"],
            ),
            ProbeResult(
                "openai_compatible_streaming",
                "passed",
                [],
                metrics=StreamingMetrics(
                    ttft_seconds=0.123456,
                    total_latency_seconds=1.234567,
                    chunk_intervals=[0.111111, 0.222222, 0.333333],
                    chunk_size_distribution=[10, 20, 30],
                    estimated_tps=48.6,
                    is_synthetic_stream=False,
                ),
            )
        ],
        rating=Rating.LOW_TRUST,
        score_breakdown={"strong_failed": 1},
        verdict=Verdict(
            rating=Rating.LOW_TRUST,
            authenticity_score=39,
            risk_score=0,
            tags=["CROSS_PROVIDER_MODEL_LEAKED"],
        ),
        report_warnings=["raw provider error text TOKEN_SHOULD_NOT_LEAK"],
        redacted_config={
            "endpoint": {
                "name": "relay",
                "base_url": "https://private-relay.example/v1",
                "api_key": "***REDACTED***",
            }
        },
    )


def test_public_markdown_omits_private_observation_fields_and_raw_timing_arrays():
    markdown = render_markdown(safe_result())

    forbidden = [
        "system_fingerprint",
        "fp_private_123",
        "raw provider error text",
        "TOKEN_SHOULD_NOT_LEAK",
        "https://private-relay.example/v1",
        "0.111111",
        "0.222222",
        "0.333333",
        "Chunk intervals:",
    ]
    for value in forbidden:
        assert value not in markdown
    assert "Streaming summary" in markdown


def test_runtime_config_repr_and_redacted_config_hide_api_key_and_raw_endpoint_url(tmp_path):
    config_path = write_config(
        tmp_path,
        """
selected_endpoint: relay
endpoints:
  - name: relay
    base_url: https://private-relay.example/v1
    provider: openai
    api_shape: openai-compatible
    model: gpt-5.1
    api_key: TOKEN_SHOULD_NOT_LEAK
""",
    )

    runtime_config = load_runtime_config(config_path)
    rendered = repr(runtime_config)
    redacted = str(runtime_config.redacted_config)

    for text in (rendered, redacted):
        assert "TOKEN_SHOULD_NOT_LEAK" not in text
        assert "https://private-relay.example/v1" not in text
    assert "base_url_hash" in redacted or "base_url_redacted" in redacted


def test_stream_error_before_non_empty_delta_is_inconclusive_not_failed(tmp_path):
    config_path = write_config(
        tmp_path,
        """
selected_endpoint: deepseek
endpoints:
  - name: deepseek
    base_url: https://api.deepseek.com/v1
    provider: deepseek
    api_shape: openai-compatible
    model: deepseek-r1
    channel_claim: official
    api_key: TOKEN_PLACEHOLDER
""",
    )
    runtime_config = load_runtime_config(config_path)
    observations = AuditObservations(
        stream_events=[
            ProviderEvent(0.0, "auth_error", data={"error": "401 raw provider auth text"}),
        ],
    )

    result = run_audit(runtime_config, observations=observations)

    assert result.rating == Rating.INCONCLUSIVE
    assert result.probe_results[0].status == "error"
    assert result.probe_results[0].name == "stream_runtime"


def test_cli_exception_output_redacts_api_key_endpoint_and_raw_provider_error(tmp_path, monkeypatch):
    config_path = write_config(
        tmp_path,
        """
selected_endpoint: relay
output: report.md
endpoints:
  - name: relay
    base_url: https://private-relay.example/v1
    provider: openai
    api_shape: openai-compatible
    model: gpt-5.1
    api_key: TOKEN_SHOULD_NOT_LEAK
""",
    )

    def fail_audit(runtime_config, repeat_count=1):
        raise RuntimeError(
            "raw provider error text TOKEN_SHOULD_NOT_LEAK https://private-relay.example/v1"
        )

    monkeypatch.setattr("tokenverify.cli.run_audit", fail_audit)

    result = CliRunner().invoke(app, ["audit", "--config", str(config_path)], catch_exceptions=False)

    assert result.exit_code == 3
    assert "TOKEN_SHOULD_NOT_LEAK" not in result.output
    assert "https://private-relay.example/v1" not in result.output
    assert "raw provider error text" not in result.output
    assert "Audit failed before a conclusive result could be produced." in result.output


def test_public_artifacts_do_not_contain_private_lab_observation_material():
    public_paths = [
        ROOT / "README.md",
        ROOT / "README.zh-CN.md",
        ROOT / "CHANGELOG.md",
        ROOT / "docs" / "release-readiness.md",
        ROOT / "docs" / "user-guide.md",
        *sorted((ROOT / "examples" / "reports").glob("*.md")),
    ]
    forbidden = [
        "docs/superpowers",
        "private pack",
        "private-pack",
        "fp_private",
        "system_fingerprint",
        "raw timestamp",
        "raw output",
        "raw model output",
        "raw provider error text",
        "Chunk intervals:",
    ]

    for path in public_paths:
        text = path.read_text(encoding="utf-8")
        for value in forbidden:
            assert value not in text, f"{value} found in {path}"
