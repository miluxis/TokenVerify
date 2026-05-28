from __future__ import annotations

import json

from tokenverify.models import AuditResult, ProbeResult, StreamingMetrics


def render_markdown(result: AuditResult) -> str:
    lines = [
        "# TokenVerify Claude Audit Report",
        "",
        "## Target Summary",
    ]
    for key, value in result.target_summary.items():
        lines.append(f"- **{key}**: {value}")
    lines.extend(
        [
            "",
            "## Overall Rating",
            "",
            f"**{result.rating.value}**",
            "",
            "## Evidence Score Breakdown",
        ]
    )
    for key, value in result.score_breakdown.items():
        lines.append(f"- `{key}`: {value}")
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


def _find_probe(probes: list[ProbeResult], name: str) -> ProbeResult | None:
    for probe in probes:
        if probe.name == name:
            return probe
    return None
