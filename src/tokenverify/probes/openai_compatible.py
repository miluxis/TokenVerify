from __future__ import annotations

from tokenverify.models import EvidenceItem, EvidenceTag, ProbeResult, ProviderEvent, RiskTag
from tokenverify.probes.streaming import calculate_streaming_metrics


def evaluate_chat_completions_response(response: dict) -> ProbeResult:
    choices = response.get("choices")
    is_openai_shape = isinstance(choices, list) and choices and isinstance(choices[0], dict) and "message" in choices[0]
    if is_openai_shape:
        return ProbeResult(
            "chat_completions_shape",
            "passed",
            [
                EvidenceItem(
                    "openai_compatible_chat_shape",
                    "strong",
                    True,
                    "Response matches OpenAI-compatible Chat Completions shape.",
                    tags=[EvidenceTag.OPENAI_COMPATIBLE_SHAPE_MATCH.value],
                )
            ],
        )
    if response.get("type") == "message" and "content" in response:
        return ProbeResult(
            "chat_completions_shape",
            "failed",
            [
                EvidenceItem(
                    "openai_compatible_chat_shape",
                    "strong",
                    False,
                    "Response is Anthropic native Messages shape despite an OpenAI-compatible claim.",
                    tags=[EvidenceTag.ANTHROPIC_NATIVE_SHAPE_DETECTED.value],
                )
            ],
        )
    return ProbeResult(
        "chat_completions_shape",
        "failed",
        [
            EvidenceItem(
                "openai_compatible_chat_shape",
                "strong",
                False,
                "Response does not match OpenAI-compatible Chat Completions shape.",
                tags=[EvidenceTag.OPENAI_COMPATIBLE_SHAPE_MISMATCH.value],
            )
        ],
    )


def evaluate_claude_claim_consistency(claimed_model: str, response: dict) -> ProbeResult:
    observed = str(response.get("model") or "")
    if not observed:
        return ProbeResult(
            "claude_claim_consistency",
            "skipped",
            [EvidenceItem("claude_model_claim", "strong", None, "No response model field was observed.")],
        )
    normalized_claim = claimed_model.lower().replace("anthropic/", "")
    normalized_observed = observed.lower().replace("anthropic/", "")
    passed = normalized_claim in normalized_observed or normalized_observed in normalized_claim
    return ProbeResult(
        "claude_claim_consistency",
        "passed" if passed else "failed",
        [
            EvidenceItem(
                "claude_model_claim",
                "strong",
                passed,
                f"Observed response model `{observed}` {'matches' if passed else 'contradicts'} claimed model `{claimed_model}`.",
                tags=[
                    EvidenceTag.CLAUDE_MODEL_CLAIM_MATCH.value
                    if passed
                    else EvidenceTag.CLAUDE_MODEL_CLAIM_MISMATCH.value
                ],
            )
        ],
    )


def evaluate_reasoning_leakage(response: dict) -> ProbeResult:
    if _contains_reasoning_content(response):
        return ProbeResult(
            "reasoning_leakage",
            "failed",
            [
                EvidenceItem(
                    "cross_provider_reasoning_leaked",
                    "strong",
                    False,
                    "Response exposed provider-specific reasoning_content in an OpenAI-compatible Claude claim.",
                    tags=[EvidenceTag.CROSS_PROVIDER_REASONING_LEAKED.value],
                )
            ],
        )
    if _contains_fake_thinking_text(response):
        return ProbeResult(
            "reasoning_leakage",
            "warning",
            [
                EvidenceItem(
                    "synthetic_thinking_text",
                    "weak",
                    False,
                    "Thinking-like text was mixed into normal content with scripted prefixes.",
                    tags=[RiskTag.SYNTHETIC_THINKING_SUSPECT.value],
                )
            ],
        )
    return ProbeResult("reasoning_leakage", "passed", [])


def evaluate_openai_streaming_features(events: list[ProviderEvent]) -> ProbeResult:
    metrics = calculate_streaming_metrics(events)
    finish_reasons = [event.data.get("finish_reason") for event in events]
    terminal = next((reason for reason in reversed(finish_reasons) if reason), None)
    evidence: list[EvidenceItem] = []
    if terminal is None and events:
        evidence.append(
            EvidenceItem(
                "openai_stream_sequence",
                "strong",
                False,
                "Stream ended without a terminal finish_reason.",
                tags=[EvidenceTag.STREAM_EVENT_SEQUENCE_MISMATCH.value],
            )
        )
        return ProbeResult("openai_compatible_streaming", "failed", evidence, metrics=metrics)
    if terminal == "content_filter":
        evidence.append(
            EvidenceItem(
                "openai_stream_finish_reason",
                "weak",
                False,
                "Stream ended with content_filter finish_reason for a claimed Claude relay.",
                tags=[RiskTag.CROSS_PROVIDER_FINISH_REASON_SUSPECT.value],
            )
        )
        return ProbeResult("openai_compatible_streaming", "warning", evidence, metrics=metrics)
    if events:
        evidence.append(
            EvidenceItem(
                "openai_stream_sequence",
                "strong",
                True,
                "OpenAI-compatible stream included a terminal finish_reason.",
                tags=[EvidenceTag.OPENAI_STREAM_SEQUENCE_MATCH.value],
            )
        )
    if metrics.is_synthetic_stream:
        evidence.append(
            EvidenceItem(
                "synthetic_stream_heuristic",
                "weak",
                False,
                "Stream chunks were uniformly sized and emitted in a short burst.",
                tags=[RiskTag.SYNTHETIC_STREAM_SUSPECT.value, RiskTag.STREAM_UNIFORMITY_SUSPECT.value],
            )
        )
    return ProbeResult("openai_compatible_streaming", "warning" if metrics.is_synthetic_stream else "passed", evidence, metrics=metrics)


def _contains_reasoning_content(response: dict) -> bool:
    for choice in _choices(response):
        for key in ("delta", "message"):
            value = choice.get(key)
            if isinstance(value, dict) and "reasoning_content" in value:
                return True
    return False


def _contains_fake_thinking_text(response: dict) -> bool:
    markers = (
        "thinking process:",
        "thinking process",
        "### thinking process",
        "[thinking]",
        "{thinking}",
        "analyzing...",
        "1. analyzing",
    )
    for choice in _choices(response):
        message = choice.get("message")
        delta = choice.get("delta")
        content = None
        if isinstance(message, dict):
            content = message.get("content")
        if content is None and isinstance(delta, dict):
            content = delta.get("content")
        normalized = content.strip().lower() if isinstance(content, str) else ""
        if normalized and any(marker in normalized for marker in markers):
            return True
    return False


def _choices(response: dict) -> list[dict]:
    choices = response.get("choices")
    return [choice for choice in choices if isinstance(choice, dict)] if isinstance(choices, list) else []
