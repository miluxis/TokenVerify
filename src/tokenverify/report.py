from __future__ import annotations

import json

from tokenverify.models import AuditResult, ProbeResult, RiskTag, StreamingMetrics


def render_markdown(result: AuditResult) -> str:
    lines = [
        "# TokenVerify Claude Audit Report",
        "",
        "## Target Summary",
    ]
    for key, value in result.target_summary.items():
        if value is None:
            continue
        lines.append(f"- **{key}**: {value}")
    lines.extend(
        [
            "",
            "## Overall Verdict",
            "",
            f"- Rating: **{result.rating.value}**",
            f"- Authenticity score: {_authenticity_score_text(result)}",
            f"- Risk score: {_risk_score_text(result)}",
            f"- Tags: {_tags_text(result)}",
            "",
            "Authenticity score measures how well the endpoint matches the claimed provider/API/model behavior.",
            "Risk score measures heuristic channel-health and relay-risk symptoms.",
            "",
            "## Evidence Score Breakdown",
        ]
    )
    for key, value in result.score_breakdown.items():
        lines.append(f"- `{key}`: {value}")
    lines.extend(_authenticity_assertions_section(result.probe_results))
    lines.extend(_heuristic_risk_section(result))
    lines.extend(_probe_section("Messages Protocol Probe", _find_probe(result.probe_results, "messages_protocol")))
    lines.extend(_probe_section("Extended Thinking Probe", _find_probe(result.probe_results, "extended_thinking")))
    lines.extend(_streaming_section(_find_probe(result.probe_results, "streaming_features")))
    lines.extend(["", "## Errors and Warnings"])
    warnings = list(result.report_warnings)
    for probe in result.probe_results:
        warnings.extend(probe.warnings)
        warnings.extend(probe.errors)
    if result.raw_log_path is not None:
        warnings.append(f"Raw event logging enabled. Log path: `{result.raw_log_path}`")
    if warnings:
        lines.extend(f"- {warning}" for warning in warnings)
    else:
        lines.append("- None")
    if result.raw_log_path is not None:
        lines.extend(["", "## Raw Event Log", "", f"Raw event log path: `{result.raw_log_path}`"])
    if result.extension_probe_results:
        lines.extend(["", "## Extension Probe Appendix"])
        for probe in result.extension_probe_results:
            lines.extend([f"### {probe.name}", f"- Status: {probe.status}"])
    lines.extend(
        [
            "",
            "## Configuration Summary",
            "",
            "```json",
            json.dumps(result.redacted_config, ensure_ascii=False, indent=2, default=str),
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def _probe_section(title: str, probe: ProbeResult | None) -> list[str]:
    lines = ["", f"## {title}"]
    if probe is None:
        return lines + ["", "- Not run"]
    lines.extend(["", f"- Status: {probe.status}"])
    for item in probe.evidence:
        state = "pass" if item.passed is True else "fail" if item.passed is False else "neutral"
        lines.append(f"- `{item.key}` ({item.weight}, {state}): {item.message}")
    return lines


def _authenticity_assertions_section(probes: list[ProbeResult]) -> list[str]:
    lines = ["", "## Authenticity Assertions"]
    assertions = [
        item
        for probe in probes
        for item in probe.evidence
        if item.weight in {"strong", "neutral"}
    ]
    if not assertions:
        return lines + ["", "- No strong authenticity assertions were produced."]
    lines.append("")
    for item in assertions:
        state = "pass" if item.passed is True else "fail" if item.passed is False else "neutral"
        tags = f" Tags: {', '.join(item.tags)}." if item.tags else ""
        lines.append(f"- `{item.key}` ({item.weight}, {state}): {item.message}{tags}")
    return lines


def _heuristic_risk_section(result: AuditResult) -> list[str]:
    risk_items = [
        item
        for probe in result.probe_results
        for item in probe.evidence
        if item.weight == "weak"
    ]
    lines = [
        "",
        "## Heuristic Risk Profile",
        "",
        f"- Risk score: {_risk_score_text(result)}",
        f"- Risk tags: {_risk_tags_text(result)}",
        "- These signals are heuristic channel-risk indicators. They can raise operational concern, but they do not by themselves prove provider forgery or unauthorized routing.",
    ]
    if not risk_items:
        return lines + ["- No heuristic risk indicators were produced."]
    for item in risk_items:
        state = "pass" if item.passed is True else "fail" if item.passed is False else "neutral"
        tags = f" Tags: {', '.join(item.tags)}." if item.tags else ""
        lines.append(f"- `{item.key}` ({state}): {item.message}{tags}")
    return lines


def _streaming_section(probe: ProbeResult | None) -> list[str]:
    lines = ["", "## Streaming Metrics"]
    if probe is None or not isinstance(probe.metrics, StreamingMetrics):
        return lines + ["", "- Not run"]
    metrics = probe.metrics
    lines.extend(
        [
            "",
            f"- TTFT seconds: {metrics.ttft_seconds}",
            f"- Total latency seconds: {metrics.total_latency_seconds}",
            f"- Chunk intervals: {metrics.chunk_intervals}",
            f"- Chunk size distribution: {metrics.chunk_size_distribution}",
            f"- Estimated TPS: {metrics.estimated_tps}",
            f"- Synthetic stream heuristic: {metrics.is_synthetic_stream}",
        ]
    )
    return lines


def _authenticity_score_text(result: AuditResult) -> str:
    return str(result.verdict.authenticity_score) if result.verdict else "n/a"


def _risk_score_text(result: AuditResult) -> str:
    return str(result.verdict.risk_score) if result.verdict else "n/a"


def _tags_text(result: AuditResult) -> str:
    if not result.verdict or not result.verdict.tags:
        return "None"
    return ", ".join(result.verdict.tags)


def _risk_tags_text(result: AuditResult) -> str:
    if not result.verdict:
        return "None"
    known_risk_tags = {tag.value for tag in RiskTag}
    risk_tags = [tag for tag in result.verdict.tags if tag in known_risk_tags]
    return ", ".join(risk_tags) if risk_tags else "None"


def _find_probe(probes: list[ProbeResult], name: str) -> ProbeResult | None:
    for probe in probes:
        if probe.name == name:
            return probe
    return None
