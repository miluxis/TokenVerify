from pathlib import Path

from tokenverify.models import AuditResult, EvidenceItem, ProbeResult, Rating, StreamingMetrics
from tokenverify.report import render_markdown


def audit_result() -> AuditResult:
    return AuditResult(
        target_summary={"base_url_host": "api.anthropic.com", "model": "claude-sonnet-4-5", "endpoint": "primary"},
        probe_results=[
            ProbeResult(
                "messages_protocol",
                "passed",
                [EvidenceItem("anthropic_messages_shape", "strong", True, "native shape")],
            ),
            ProbeResult(
                "extended_thinking",
                "passed",
                [EvidenceItem("extended_thinking_expected", "strong", True, "thinking observed")],
            ),
            ProbeResult(
                "streaming_features",
                "warning",
                [EvidenceItem("synthetic_stream_heuristic", "weak", False, "synthetic stream suspected")],
                metrics=StreamingMetrics(0.2, 1.0, [0.1], [3, 7], 10.0, True),
            ),
        ],
        rating=Rating.MEDIUM_TRUST,
        score_breakdown={"strong_passed": 2, "weak_failed": 1},
        report_warnings=["raw logging enabled"],
        raw_log_path=Path("events.jsonl"),
        redacted_config={"endpoint": {"api_key": "***REDACTED***"}},
    )


def test_markdown_contains_required_sections():
    markdown = render_markdown(audit_result())

    assert "# TokenVerify Claude Audit Report" in markdown
    assert "## Overall Rating" in markdown
    assert "## Messages Protocol Probe" in markdown
    assert "## Extended Thinking Probe" in markdown
    assert "## Streaming Metrics" in markdown
    assert "## Configuration Summary" in markdown


def test_markdown_redacts_api_key():
    result = audit_result()
    result.redacted_config["endpoint"]["api_key"] = "***REDACTED***"

    markdown = render_markdown(result)

    assert "TOKEN_SHOULD_BE_REDACTED" not in markdown
    assert "***REDACTED***" in markdown


def test_raw_log_path_is_referenced_not_embedded():
    markdown = render_markdown(audit_result())

    assert "events.jsonl" in markdown
    assert "raw_response_body" not in markdown
