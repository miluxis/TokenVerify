from __future__ import annotations

from urllib.parse import urlparse

from tokenverify.models import EvidenceItem, EvidenceTag, ProbeResult, ProviderEvent, RiskTag
from tokenverify.openai_capabilities import OpenAIModelFamily, lookup_openai_model_capability
from tokenverify.probes.streaming import calculate_streaming_metrics


def evaluate_openai_chat_completion_response(response: dict) -> ProbeResult:
    choices = response.get("choices")
    first_choice = choices[0] if isinstance(choices, list) and choices and isinstance(choices[0], dict) else {}
    is_chat_shape = isinstance(first_choice.get("message"), dict) and "finish_reason" in first_choice
    if is_chat_shape:
        return ProbeResult(
            "openai_chat_completions_shape",
            "passed",
            [
                EvidenceItem(
                    "openai_chat_shape",
                    "strong",
                    True,
                    "Response matches OpenAI Chat Completions shape.",
                    tags=[EvidenceTag.OPENAI_CHAT_COMPLETION_SHAPE_MATCH.value],
                )
            ],
        )
    non_openai = response.get("type") == "message" or "content" in response
    return ProbeResult(
        "openai_chat_completions_shape",
        "failed",
        [
            EvidenceItem(
                "openai_chat_shape",
                "strong",
                False,
                "Response does not match OpenAI Chat Completions shape.",
                tags=[
                    EvidenceTag.NON_OPENAI_PROVIDER_SHAPE_DETECTED.value
                    if non_openai
                    else EvidenceTag.OPENAI_CHAT_COMPLETION_SHAPE_MISMATCH.value
                ],
            )
        ],
    )


def evaluate_openai_model_claim(claimed_model: str, response: dict) -> ProbeResult:
    observed = str(response.get("model") or "")
    if not observed:
        return ProbeResult(
            "openai_model_claim_consistency",
            "skipped",
            [EvidenceItem("openai_model_claim", "strong", None, "No response model field was observed.")],
        )

    claimed = lookup_openai_model_capability(claimed_model)
    observed_capability = lookup_openai_model_capability(observed)
    if observed_capability.family == OpenAIModelFamily.NON_OPENAI:
        return ProbeResult(
            "openai_model_claim_consistency",
            "failed",
            [
                EvidenceItem(
                    "openai_model_claim",
                    "strong",
                    False,
                    f"Observed model `{observed}` belongs to a non-OpenAI provider family.",
                    tags=[EvidenceTag.CROSS_PROVIDER_MODEL_LEAKED.value],
                )
            ],
        )

    if _is_structured_downgrade(claimed.family, observed_capability.family):
        return ProbeResult(
            "openai_model_claim_consistency",
            "failed",
            [
                EvidenceItem(
                    "openai_model_claim",
                    "strong",
                    False,
                    f"Observed model `{observed}` is a lower capability tier than claimed model `{claimed_model}`.",
                    tags=[EvidenceTag.OPENAI_MODEL_CLAIM_MISMATCH.value],
                )
            ],
        )

    passed = claimed.family == observed_capability.family or observed_capability.family == OpenAIModelFamily.UNKNOWN_OPENAI
    return ProbeResult(
        "openai_model_claim_consistency",
        "passed" if passed else "failed",
        [
            EvidenceItem(
                "openai_model_claim",
                "strong",
                passed,
                f"Observed model `{observed}` {'matches' if passed else 'contradicts'} claimed model `{claimed_model}`.",
                tags=[
                    EvidenceTag.OPENAI_MODEL_CLAIM_MATCH.value
                    if passed
                    else EvidenceTag.OPENAI_MODEL_CLAIM_MISMATCH.value
                ],
            )
        ],
    )


def evaluate_openai_reasoning_capability(
    model: str,
    accepted_parameters: list[str],
    rejected_parameters: list[str],
    reasoning_tokens: int | None = None,
    is_trivial_prompt: bool = False,
) -> ProbeResult:
    capability = lookup_openai_model_capability(model)
    if capability.supports_reasoning_effort is not True:
        return ProbeResult(
            "openai_reasoning_capability",
            "skipped",
            [
                EvidenceItem(
                    "openai_reasoning_capability",
                    "strong",
                    None,
                    "Reasoning effort is not expected for this OpenAI model tier.",
                )
            ],
        )

    accepted = "reasoning_effort" in accepted_parameters
    rejected = "reasoning_effort" in rejected_parameters
    if rejected or not accepted:
        return ProbeResult(
            "openai_reasoning_capability",
            "failed",
            [
                EvidenceItem(
                    "openai_reasoning_capability",
                    "strong",
                    False,
                    "Reasoning-capable model rejected or stripped reasoning_effort.",
                    tags=[EvidenceTag.OPENAI_REASONING_CAPABILITY_MISMATCH.value],
                )
            ],
        )
    if reasoning_tokens == 0 and is_trivial_prompt:
        return ProbeResult(
            "openai_reasoning_capability",
            "warning",
            [
                EvidenceItem(
                    "openai_reasoning_tokens",
                    "weak",
                    False,
                    "Trivial prompt returned zero reasoning tokens; this is not strong failure evidence.",
                    tags=[EvidenceTag.OPENAI_REASONING_CAPABILITY_MISMATCH.value],
                )
            ],
        )
    if reasoning_tokens is None or reasoning_tokens == 0:
        return ProbeResult(
            "openai_reasoning_capability",
            "failed",
            [
                EvidenceItem(
                    "openai_reasoning_tokens",
                    "strong",
                    False,
                    "Non-trivial reasoning probe returned missing or zero reasoning tokens.",
                    tags=[EvidenceTag.OPENAI_REASONING_CAPABILITY_MISMATCH.value],
                )
            ],
        )
    return ProbeResult(
        "openai_reasoning_capability",
        "passed",
        [
            EvidenceItem(
                "openai_reasoning_capability",
                "strong",
                True,
                "Reasoning-capable model accepted reasoning_effort and reported reasoning tokens.",
                tags=[EvidenceTag.OPENAI_REASONING_CAPABILITY_MATCH.value],
            )
        ],
    )


def evaluate_openai_streaming_features(events: list[ProviderEvent]) -> ProbeResult:
    metrics = calculate_streaming_metrics(events)
    if any(not event.event_type.startswith("chat.completion") for event in events):
        return ProbeResult(
            "openai_compatible_streaming",
            "failed",
            [
                EvidenceItem(
                    "openai_stream_sequence",
                    "strong",
                    False,
                    "Stream emitted non-OpenAI Chat Completions events.",
                    tags=[EvidenceTag.OPENAI_STREAM_SEQUENCE_MISMATCH.value],
                )
            ],
            metrics=metrics,
        )
    terminal = next((event.data.get("finish_reason") for event in reversed(events) if event.data.get("finish_reason")), None)
    if terminal:
        return ProbeResult(
            "openai_compatible_streaming",
            "passed",
            [
                EvidenceItem(
                    "openai_stream_sequence",
                    "strong",
                    True,
                    "OpenAI-compatible stream included a terminal finish_reason.",
                    tags=[EvidenceTag.OPENAI_STREAM_SEQUENCE_MATCH.value],
                )
            ],
            metrics=metrics,
        )
    return ProbeResult(
        "openai_compatible_streaming",
        "failed",
        [
            EvidenceItem(
                "openai_stream_sequence",
                "strong",
                False,
                "Stream ended without a terminal finish_reason.",
                tags=[EvidenceTag.OPENAI_STREAM_SEQUENCE_MISMATCH.value],
            )
        ],
        metrics=metrics,
    )


def evaluate_openai_channel(
    base_url: str,
    channel_claim: str,
    response_headers: dict[str, str] | None = None,
    error_message: str | None = None,
) -> ProbeResult:
    headers = {key.lower(): value.lower() for key, value in (response_headers or {}).items()}
    host = urlparse(base_url).hostname or ""
    evidence: list[EvidenceItem] = []
    official_claim = channel_claim.lower() == "official"

    if official_claim and host != "api.openai.com":
        evidence.append(
            EvidenceItem(
                "openai_official_channel",
                "strong",
                False,
                "Official OpenAI channel was claimed, but base URL host is not api.openai.com.",
                details={"host": host},
                tags=[EvidenceTag.OPENAI_OFFICIAL_CHANNEL_MISMATCH.value],
            )
        )
    elif official_claim:
        evidence.append(
            EvidenceItem(
                "openai_official_channel",
                "strong",
                True,
                "Official OpenAI channel claim matches api.openai.com host.",
                details={"host": host},
                tags=[EvidenceTag.OPENAI_OFFICIAL_CHANNEL_MATCH.value],
            )
        )

    marker_text = " ".join([*headers.keys(), *headers.values(), error_message or ""])
    relay_markers = ("x-openrouter", "x-upstream", "x-relay", "nginx")
    if any(marker in marker_text for marker in relay_markers):
        evidence.append(
            EvidenceItem(
                "openai_relay_header_markers",
                "weak",
                False,
                "Headers or errors exposed relay or self-hosted gateway markers.",
                tags=[RiskTag.RELAY_HEADER_SUSPECT.value, EvidenceTag.OPENAI_OFFICIAL_CHANNEL_MISMATCH.value],
            )
        )

    if not evidence:
        return ProbeResult("openai_channel_risk", "passed", [])
    status = "failed" if any(item.weight == "strong" and item.passed is False for item in evidence) else "warning" if any(item.weight == "weak" for item in evidence) else "passed"
    return ProbeResult("openai_channel_risk", status, evidence)


def _is_structured_downgrade(claimed: OpenAIModelFamily, observed: OpenAIModelFamily) -> bool:
    order = {
        OpenAIModelFamily.GPT_5: 3,
        OpenAIModelFamily.O_SERIES: 2,
        OpenAIModelFamily.GPT_4_1: 1,
        OpenAIModelFamily.GPT_4O: 1,
        OpenAIModelFamily.UNKNOWN_OPENAI: 0,
        OpenAIModelFamily.NON_OPENAI: -1,
    }
    return order.get(observed, 0) < order.get(claimed, 0) and observed != OpenAIModelFamily.UNKNOWN_OPENAI
