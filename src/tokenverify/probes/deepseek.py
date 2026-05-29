from __future__ import annotations

from urllib.parse import urlparse

from tokenverify.deepseek_capabilities import DeepSeekModelFamily, lookup_deepseek_model_capability
from tokenverify.models import EvidenceItem, EvidenceTag, ProbeResult, ProviderEvent, RiskTag
from tokenverify.probes.streaming import calculate_streaming_metrics


def evaluate_deepseek_chat_completion_response(response: dict) -> ProbeResult:
    first_choice = _first_choice(response)
    is_chat_shape = isinstance(first_choice.get("message"), dict) and "finish_reason" in first_choice
    if is_chat_shape:
        return ProbeResult(
            "deepseek_chat_completions_shape",
            "passed",
            [
                EvidenceItem(
                    "deepseek_chat_shape",
                    "strong",
                    True,
                    "Response matches DeepSeek Chat Completions shape.",
                    tags=[EvidenceTag.DEEPSEEK_CHAT_COMPLETION_SHAPE_MATCH.value],
                )
            ],
        )
    non_deepseek = response.get("type") == "message" or "content" in response
    return ProbeResult(
        "deepseek_chat_completions_shape",
        "failed",
        [
            EvidenceItem(
                "deepseek_chat_shape",
                "strong",
                False,
                "Response does not match DeepSeek Chat Completions shape.",
                tags=[
                    EvidenceTag.NON_DEEPSEEK_PROVIDER_SHAPE_DETECTED.value
                    if non_deepseek
                    else EvidenceTag.DEEPSEEK_CHAT_COMPLETION_SHAPE_MISMATCH.value
                ],
            )
        ],
    )


def evaluate_deepseek_model_claim(claimed_model: str, response: dict) -> ProbeResult:
    if _has_cross_provider_metadata(response):
        return _model_claim_failure(
            "Response exposed provider-exclusive metadata under a DeepSeek claim.",
            EvidenceTag.CROSS_PROVIDER_MODEL_LEAKED.value,
        )

    observed = str(response.get("model") or "")
    if not observed:
        return ProbeResult(
            "deepseek_model_claim_consistency",
            "skipped",
            [EvidenceItem("deepseek_model_claim", "strong", None, "No response model field was observed.")],
        )

    claimed = lookup_deepseek_model_capability(claimed_model)
    observed_capability = lookup_deepseek_model_capability(observed)
    if observed_capability.family == DeepSeekModelFamily.NON_DEEPSEEK:
        return _model_claim_failure(
            f"Observed model `{observed}` belongs to a non-DeepSeek provider family.",
            EvidenceTag.CROSS_PROVIDER_MODEL_LEAKED.value,
        )
    if claimed.family == DeepSeekModelFamily.R1 and observed_capability.family != DeepSeekModelFamily.R1:
        return _model_claim_failure(
            f"Observed model `{observed}` is incompatible with claimed R1 model `{claimed_model}`.",
            EvidenceTag.DEEPSEEK_MODEL_CLAIM_MISMATCH.value,
        )

    passed = claimed.family == observed_capability.family or observed_capability.family == DeepSeekModelFamily.UNKNOWN_DEEPSEEK
    return ProbeResult(
        "deepseek_model_claim_consistency",
        "passed" if passed else "failed",
        [
            EvidenceItem(
                "deepseek_model_claim",
                "strong",
                passed,
                f"Observed model `{observed}` {'matches' if passed else 'contradicts'} claimed model `{claimed_model}`.",
                tags=[
                    EvidenceTag.DEEPSEEK_MODEL_CLAIM_MATCH.value
                    if passed
                    else EvidenceTag.DEEPSEEK_MODEL_CLAIM_MISMATCH.value
                ],
            )
        ],
    )


def evaluate_deepseek_reasoning_content(
    model: str,
    response: dict,
    is_trivial_prompt: bool,
) -> ProbeResult:
    capability = lookup_deepseek_model_capability(model)
    if capability.expects_reasoning_content is not True:
        return ProbeResult(
            "deepseek_reasoning_content",
            "skipped",
            [
                EvidenceItem(
                    "deepseek_reasoning_content",
                    "strong",
                    None,
                    "Reasoning content is not expected for this DeepSeek model family.",
                )
            ],
        )
    message = _first_choice(response).get("message")
    reasoning_content = message.get("reasoning_content") if isinstance(message, dict) else None
    if isinstance(reasoning_content, str) and reasoning_content.strip():
        return ProbeResult(
            "deepseek_reasoning_content",
            "passed",
            [
                EvidenceItem(
                    "deepseek_reasoning_content",
                    "strong",
                    True,
                    "R1 response exposed native reasoning_content.",
                    tags=[EvidenceTag.DEEPSEEK_REASONING_CONTENT_MATCH.value],
                )
            ],
        )
    weight = "weak" if is_trivial_prompt else "strong"
    status = "warning" if is_trivial_prompt else "failed"
    return ProbeResult(
        "deepseek_reasoning_content",
        status,
        [
            EvidenceItem(
                "deepseek_reasoning_content",
                weight,
                False,
                "R1 response did not expose native reasoning_content.",
                tags=[EvidenceTag.DEEPSEEK_REASONING_CONTENT_MISSING.value],
            )
        ],
    )


def evaluate_deepseek_streaming_features(model: str, events: list[ProviderEvent]) -> ProbeResult:
    metrics = calculate_streaming_metrics(events)
    evidence: list[EvidenceItem] = []
    if any(not event.event_type.startswith("chat.completion") for event in events):
        evidence.append(
            EvidenceItem(
                "deepseek_stream_sequence",
                "strong",
                False,
                "Stream emitted non-Chat-Completions events under a DeepSeek claim.",
                tags=[EvidenceTag.DEEPSEEK_STREAM_SEQUENCE_MISMATCH.value],
            )
        )
        return ProbeResult("deepseek_compatible_streaming", "failed", evidence, metrics=metrics)

    has_terminal = any(_choice(event).get("finish_reason") for event in events)
    observed_finish_reason_field = any("finish_reason" in _choice(event) for event in events)
    if has_terminal:
        evidence.append(
            EvidenceItem(
                "deepseek_stream_sequence",
                "strong",
                True,
                "DeepSeek-compatible stream included a terminal finish_reason.",
                tags=[EvidenceTag.DEEPSEEK_STREAM_SEQUENCE_MATCH.value],
            )
        )
    elif events and observed_finish_reason_field:
        evidence.append(
            EvidenceItem(
                "deepseek_stream_sequence",
                "strong",
                False,
                "Stream ended without a terminal finish_reason.",
                tags=[EvidenceTag.DEEPSEEK_STREAM_SEQUENCE_MISMATCH.value],
            )
        )

    expects_reasoning = lookup_deepseek_model_capability(model).expects_reasoning_content is True
    saw_reasoning = False
    saw_content = False
    state_disorder = False
    for event in events:
        delta = _choice(event).get("delta")
        if not isinstance(delta, dict):
            continue
        has_reasoning_delta = isinstance(delta.get("reasoning_content"), str) and bool(delta.get("reasoning_content"))
        has_content_delta = isinstance(delta.get("content"), str) and bool(delta.get("content"))
        if has_reasoning_delta and has_content_delta:
            state_disorder = True
        if has_reasoning_delta:
            saw_reasoning = True
            if saw_content:
                state_disorder = True
        if has_content_delta:
            saw_content = True

    if expects_reasoning and saw_reasoning:
        evidence.append(
            EvidenceItem(
                "deepseek_stream_reasoning",
                "strong",
                True,
                "R1 stream exposed native reasoning_content deltas.",
                tags=[EvidenceTag.DEEPSEEK_STREAM_REASONING_MATCH.value],
            )
        )
    elif expects_reasoning and events:
        evidence.append(
            EvidenceItem(
                "deepseek_stream_reasoning",
                "strong",
                False,
                "R1 stream did not expose native reasoning_content deltas.",
                tags=[EvidenceTag.DEEPSEEK_STREAM_REASONING_MISSING.value],
            )
        )
    if state_disorder:
        evidence.append(
            EvidenceItem(
                "deepseek_stream_reasoning_order",
                "weak",
                False,
                "R1 stream interleaved content and reasoning_content in a suspicious order.",
                tags=[RiskTag.SYNTHETIC_THINKING_SUSPECT.value],
            )
        )
    if metrics.is_synthetic_stream:
        evidence.append(
            EvidenceItem(
                "synthetic_stream_heuristic",
                "weak",
                False,
                "Stream chunks look synthetic or overly uniform.",
                tags=[RiskTag.SYNTHETIC_STREAM_SUSPECT.value],
            )
        )

    status = "failed" if any(item.weight == "strong" and item.passed is False for item in evidence) else "warning" if any(
        item.weight == "weak" and item.passed is False for item in evidence
    ) else "passed"
    return ProbeResult("deepseek_compatible_streaming", status, evidence, metrics=metrics)


def evaluate_deepseek_channel(
    base_url: str,
    channel_claim: str,
    response_headers: dict[str, str] | None = None,
    error_message: str | None = None,
) -> ProbeResult:
    headers = {key.lower(): value.lower() for key, value in (response_headers or {}).items()}
    host = urlparse(base_url).hostname or ""
    evidence: list[EvidenceItem] = []
    official_claim = channel_claim.lower() == "official"
    if official_claim and host != "api.deepseek.com":
        evidence.append(
            EvidenceItem(
                "deepseek_official_channel",
                "strong",
                False,
                "Official DeepSeek channel was claimed, but base URL host is not api.deepseek.com.",
                details={"host": host},
                tags=[EvidenceTag.DEEPSEEK_OFFICIAL_CHANNEL_MISMATCH.value],
            )
        )
    elif official_claim:
        evidence.append(
            EvidenceItem(
                "deepseek_official_channel",
                "strong",
                True,
                "Official DeepSeek channel claim matches api.deepseek.com host.",
                details={"host": host},
                tags=[EvidenceTag.DEEPSEEK_OFFICIAL_CHANNEL_MATCH.value],
            )
        )

    marker_text = " ".join([*headers.keys(), *headers.values(), error_message or ""])
    if any(marker in marker_text for marker in ("openrouter", "one-api", "new-api", "nginx", "upstream", "x-relay")):
        evidence.append(
            EvidenceItem(
                "deepseek_relay_markers",
                "weak",
                False,
                "Headers or errors exposed relay or upstream routing markers.",
                tags=[RiskTag.RELAY_HEADER_SUSPECT.value],
            )
        )
    if not evidence:
        return ProbeResult("deepseek_channel_risk", "passed", [])
    status = "failed" if any(item.weight == "strong" and item.passed is False for item in evidence) else "warning" if any(
        item.weight == "weak" and item.passed is False for item in evidence
    ) else "passed"
    return ProbeResult("deepseek_channel_risk", status, evidence)


def _model_claim_failure(message: str, tag: str) -> ProbeResult:
    return ProbeResult(
        "deepseek_model_claim_consistency",
        "failed",
        [EvidenceItem("deepseek_model_claim", "strong", False, message, tags=[tag])],
    )


def _has_cross_provider_metadata(response: dict) -> bool:
    if "system_fingerprint" in response:
        return True
    if response.get("type") == "message":
        return True
    content = response.get("content")
    if isinstance(content, list) and any(isinstance(item, dict) and item.get("type") == "thinking" for item in content):
        return True
    return "candidates" in response


def _first_choice(response: dict) -> dict:
    choices = response.get("choices")
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        return choices[0]
    return {}


def _choice(event: ProviderEvent) -> dict:
    return _first_choice(event.data)
