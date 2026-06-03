from __future__ import annotations

from tokenverify.relay_models import RelayAuditMode, RelayAuditProfile, RelayPackSummary, RelayResult
from tokenverify.relay_safety import sanitize_public_relay_text


RISK_LABELS = {
    "prompt_instruction_leakage": "Prompt or instruction leakage",
    "message_rewrite": "System/developer/user message rewrite",
    "context_truncation": "Context truncation",
    "model_substitution": "Model substitution or identity mismatch",
    "streaming_integrity": "Streaming or SSE integrity anomaly",
    "schema_tool_rewrite": "JSON schema or tool-call rewriting",
    "upstream_error_leakage": "Upstream/provider error leakage",
    "latency_or_instability": "Latency variance or unstable relay behavior",
    "infrastructure_fingerprint": "Suspicious relay infrastructure fingerprint",
}


def render_relay_markdown(result: RelayResult) -> str:
    lines = [
        "# TokenVerify Relay Audit Report",
        "",
        "## Plain-Language Summary",
        "",
        f"- Relay verdict: **{result.verdict.value}**",
        f"- Risk level: **{result.risk_level.value}**",
        (
            "- Black-box relay checks cannot prove the true upstream with certainty; "
            "this report shows sanitized contract-level evidence only."
        ),
        "",
        "## Target Summary",
        "",
        f"- Model: {sanitize_public_relay_text(result.model)}",
        f"- Profile: {result.profile.value}",
        f"- Mode: {result.mode.value}",
        f"- Endpoint host: {sanitize_public_relay_text(result.endpoint_host)}",
        f"- Endpoint hash: {sanitize_public_relay_text(result.endpoint_hash)}",
        f"- Challenge pack: {_pack_summary_text(result.pack_summary)}",
        f"- Run ID: {sanitize_public_relay_text(result.run_id)}",
        "",
        "## Relay Verdict",
        "",
        f"- Verdict: **{result.verdict.value}**",
        f"- Risk level: **{result.risk_level.value}**",
    ]
    if result.runtime_category:
        lines.append(f"- Runtime category: {sanitize_public_relay_text(result.runtime_category.value)}")
    lines.extend(["", "## Risk Categories", ""])
    if result.risk_categories:
        for category in result.risk_categories:
            lines.append(f"- {RISK_LABELS[category.value]} (`{category.value}`)")
    else:
        lines.append("- None")
    lines.extend(["", "## Sanitized Evidence", ""])
    for item in result.evidence:
        lines.append(f"### {sanitize_public_relay_text(item.key)}")
        lines.append(f"- Category: {RISK_LABELS[item.category.value]}")
        lines.append(f"- Status: {sanitize_public_relay_text(item.status)}")
        lines.append(f"- Summary: {sanitize_public_relay_text(item.summary)}")
        if item.metrics:
            safe_metrics = ", ".join(
                f"{sanitize_public_relay_text(key)}={sanitize_public_relay_text(value)}"
                for key, value in sorted(item.metrics.items())
            )
            lines.append(f"- Metrics: {safe_metrics}")
    if result.inconclusive_reason:
        lines.extend(
            [
                "",
                "## Inconclusive Explanation",
                "",
                sanitize_public_relay_text(result.inconclusive_reason),
            ]
        )
    lines.extend(
        [
            "",
            "## Retest Guidance",
            "",
            sanitize_public_relay_text(result.retest_guidance),
            "",
            "## Safety Note",
            "",
            _safety_note(result),
            "",
        ]
    )
    return "\n".join(lines)


def _safety_note(result: RelayResult) -> str:
    if result.mode == RelayAuditMode.LIVE:
        if result.profile == RelayAuditProfile.STREAMING:
            return "Live mode made only the approved minimal streaming/SSE integrity request."
        if result.profile == RelayAuditProfile.SCHEMA:
            return "Live mode made only the approved minimal schema/tool preservation request."
        if result.profile == RelayAuditProfile.PRIVACY:
            return "Live mode made only the approved minimal privacy contract request."
        if result.profile == RelayAuditProfile.FULL:
            return (
                "Full profile combines multiple approved checks. A pass means this endpoint satisfied the bounded "
                "checks in this run, not that all relay risks are impossible. Serial execution can make timeout "
                "delays add up across subprofiles when a relay is slow or unavailable."
            )
        return "Live mode made only the approved minimal general connectivity request."
    return "Fake-run mode was deterministic and no live network request was made."


def _pack_summary_text(summary: RelayPackSummary) -> str:
    parts = [summary.label]
    if summary.basename:
        parts.append(f"File: {summary.basename}")
    if summary.pack_id:
        parts.append(f"ID: {summary.pack_id}")
    if summary.version:
        parts.append(f"Version: {summary.version}")
    if summary.pack_hash:
        parts.append(f"Hash: {summary.pack_hash}")
    if summary.profiles:
        parts.append(f"Profiles: {', '.join(summary.profiles)}")
    if summary.categories:
        parts.append(f"Categories: {', '.join(summary.categories)}")
    if summary.challenge_count:
        parts.append(f"Challenges: {summary.challenge_count}")
    for intent in summary.public_intents:
        parts.append(f"Intent: {intent}")
    return sanitize_public_relay_text(" | ".join(parts))
