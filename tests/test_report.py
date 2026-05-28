from dataclasses import replace
from pathlib import Path

from tokenverify.models import AuditResult, EvidenceItem, ProbeResult, Rating, StreamingMetrics, Verdict
from tokenverify.report import render_markdown


def audit_result() -> AuditResult:
    return AuditResult(
        target_summary={"base_url_host": "api.anthropic.com", "model": "claude-sonnet-4-5", "endpoint": "primary"},
        probe_results=[
            ProbeResult(
                "messages_protocol",
                "passed",
                [EvidenceItem("anthropic_messages_shape", "strong", True, "native shape", tags=["ANTHROPIC_NATIVE_SHAPE_MATCH"])],
            ),
            ProbeResult(
                "extended_thinking",
                "passed",
                [EvidenceItem("extended_thinking_expected", "strong", True, "thinking observed", tags=["EXTENDED_THINKING_MATCH"])],
            ),
            ProbeResult(
                "streaming_features",
                "warning",
                [
                    EvidenceItem(
                        "synthetic_stream_heuristic",
                        "weak",
                        False,
                        "synthetic stream suspected",
                        tags=["SYNTHETIC_STREAM_SUSPECT"],
                    )
                ],
                metrics=StreamingMetrics(0.2, 1.0, [0.1], [3, 7], 10.0, True),
            ),
        ],
        rating=Rating.MEDIUM_TRUST,
        score_breakdown={"strong_passed": 2, "weak_failed": 1},
        verdict=Verdict(
            rating=Rating.MEDIUM_TRUST,
            authenticity_score=78,
            risk_score=25,
            tags=["ANTHROPIC_NATIVE_SHAPE_MATCH", "EXTENDED_THINKING_MATCH", "SYNTHETIC_STREAM_SUSPECT"],
        ),
        report_warnings=["raw logging enabled"],
        raw_log_path=Path("events.jsonl"),
        redacted_config={"endpoint": {"api_key": "***REDACTED***"}},
    )


def test_markdown_contains_required_sections():
    markdown = render_markdown(audit_result())

    assert "# TokenVerify Claude Audit Report" in markdown
    assert "## Overall Verdict" in markdown
    assert "## Authenticity Assertions" in markdown
    assert "## Heuristic Risk Profile" in markdown
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


def test_markdown_separates_authenticity_assertions_from_risk_profile():
    markdown = render_markdown(audit_result())

    assert "## Authenticity Assertions" in markdown
    assert "## Heuristic Risk Profile" in markdown
    assert markdown.index("## Authenticity Assertions") < markdown.index("## Heuristic Risk Profile")


def test_risk_profile_uses_score_language_not_probability_or_accusation():
    markdown = render_markdown(audit_result())

    assert "Risk score" in markdown
    assert "probability" not in markdown.lower()
    assert "风险概率" not in markdown
    assert "定罪" not in markdown


def test_target_summary_omits_unsupplied_none_values():
    result = audit_result()
    result.target_summary["claimed_region"] = None

    markdown = render_markdown(result)

    assert "claimed_region" not in markdown


def test_markdown_renders_openai_compatible_probe_sections():
    result = replace(
        audit_result(),
        probe_results=[
            ProbeResult(
                "chat_completions_shape",
                "passed",
                [EvidenceItem("openai_compatible_chat_shape", "strong", True, "chat shape")],
            ),
            ProbeResult(
                "claude_claim_consistency",
                "passed",
                [EvidenceItem("claude_model_claim", "strong", True, "model matches")],
            ),
            ProbeResult("reasoning_leakage", "passed", []),
            ProbeResult(
                "openai_compatible_streaming",
                "passed",
                [EvidenceItem("openai_stream_sequence", "strong", True, "finish reason")],
                metrics=StreamingMetrics(0.2, 1.0, [0.1], [2, 2], 4.0, False),
            ),
        ],
    )

    markdown = render_markdown(result)

    assert "## Chat Completions Shape Probe" in markdown
    assert "## Claude Model Claim Consistency Probe" in markdown
    assert "## Reasoning Leakage Probe" in markdown
    assert "## OpenAI-Compatible Streaming Metrics" in markdown
