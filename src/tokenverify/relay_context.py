from __future__ import annotations

import re
import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol

from tokenverify.relay_live import RelayLiveTransportResponse, normalize_live_runtime_error
from tokenverify.relay_models import (
    RelayAuditMode,
    RelayAuditProfile,
    RelayEvidence,
    RelayPackSummary,
    RelayResult,
    RelayRiskCategory,
    RelayRiskLevel,
    RelayRuntimeCategory,
    RelayVerdict,
)
from tokenverify.relay_safety import RelayLiveAuthorization, hash_relay_endpoint, sanitize_public_relay_text, sanitize_to_fqdn


class RelayContextTransport(Protocol):
    def __call__(self, payload: dict[str, Any]) -> RelayLiveTransportResponse:
        ...


class ContextProbeStatus(str, Enum):
    PASS = "pass"
    SUSPICIOUS = "suspicious"
    FAIL = "fail"


@dataclass(frozen=True)
class RelayContextProbe:
    key: str
    expected_answer: str
    messages: list[dict[str, str]]
    max_tokens: int


@dataclass(frozen=True)
class RelayContextObservation:
    probe_key: str
    status: ContextProbeStatus
    exact_answer_observed: bool
    anchor_expected_count: int
    anchor_observed_count: int
    early_anchor_observed: bool
    middle_anchor_observed: bool
    late_anchor_observed: bool
    anchor_order_preserved: bool
    anchor_missing_count: int
    unexpected_anchor_count: int
    middle_anchor_selected: bool
    closing_anchor_wrongly_selected: bool
    separator_degradation_detected: bool
    extra_content_detected: bool
    provider_or_upstream_marker_detected: bool
    provider_or_upstream_marker_count: int
    finish_reason: str | None = None


@dataclass(frozen=True)
class NormalizedRelayContextRuntimeError:
    category: RelayRuntimeCategory
    public_message: str


class RelayContextRuntimeError(RuntimeError):
    def __init__(self, category: RelayRuntimeCategory, public_message: str):
        self.category = category
        self.public_message = sanitize_public_relay_text(public_message)
        super().__init__(self.public_message)


ANCHOR_SEQUENCE = ("TV_CTX_ALPHA", "TV_CTX_BRAVO", "TV_CTX_CHARLIE")
MIDDLE_EXPECTED = "TV_CTX_MIDDLE"
KNOWN_CONTEXT_ANCHORS = ANCHOR_SEQUENCE + ("TV_CTX_OPENING", "TV_CTX_MIDDLE", "TV_CTX_CLOSING")

CONTEXT_PROBES = (
    RelayContextProbe(
        key="context_anchor_retention",
        expected_answer="TV_CTX_ALPHA|TV_CTX_BRAVO|TV_CTX_CHARLIE",
        messages=[
            {
                "role": "system",
                "content": "Public audit task: return only the requested public anchor labels. Do not explain.",
            },
            {"role": "user", "content": "Context block A contains public anchor label TV_CTX_ALPHA."},
            {
                "role": "user",
                "content": (
                    "Context block B contains filler public text about apples, rivers, lamps, and calendars. "
                    "Context block B contains public anchor label TV_CTX_BRAVO."
                ),
            },
            {
                "role": "user",
                "content": (
                    "Context block C contains public anchor label TV_CTX_CHARLIE. "
                    "Return only: TV_CTX_ALPHA|TV_CTX_BRAVO|TV_CTX_CHARLIE"
                ),
            },
        ],
        max_tokens=64,
    ),
    RelayContextProbe(
        key="context_middle_retention",
        expected_answer="TV_CTX_MIDDLE",
        messages=[
            {
                "role": "system",
                "content": "Public audit task: answer with the exact public anchor label requested. Do not explain.",
            },
            {
                "role": "user",
                "content": "Opening public context marker: TV_CTX_OPENING. This marker is not the answer.",
            },
            {
                "role": "user",
                "content": "Middle public context marker: TV_CTX_MIDDLE. This is the requested answer.",
            },
            {
                "role": "user",
                "content": "Closing public context marker: TV_CTX_CLOSING. Return only the middle marker.",
            },
        ],
        max_tokens=32,
    ),
)


def normalize_context_answer(value: object) -> str:
    text = str(value).strip()
    for _ in range(2):
        text = _strip_wrappers(text)
        text = text.strip(" \t\r\n\"'“”‘’")
        text = text.rstrip(" \t\r\n.!?。！？")
    text = re.sub(r"\s*\|\s*", "|", text)
    return text.upper()


def is_exact_context_answer(value: object, expected_answer: str) -> bool:
    return normalize_context_answer(value) == expected_answer.upper()


def classify_context_anchor_sequence(content: object, *, finish_reason: object | None = None) -> RelayContextObservation:
    text = str(content or "")
    normalized = normalize_context_answer(text)
    exact = normalized == "TV_CTX_ALPHA|TV_CTX_BRAVO|TV_CTX_CHARLIE"
    observed = _observed_anchors(normalized)
    missing = [anchor for anchor in ANCHOR_SEQUENCE if anchor not in observed]
    unexpected = [anchor for anchor in observed if anchor not in ANCHOR_SEQUENCE]
    order_preserved = _anchor_order_preserved(normalized, ANCHOR_SEQUENCE)
    separator_degraded = (
        not exact
        and not missing
        and order_preserved
        and bool(re.search(r"(,|;|，|；|\n|\r)", text))
    )
    provider_count = _provider_marker_count(text)
    extra_content = bool(normalized) and not exact and not separator_degraded
    if exact:
        status = ContextProbeStatus.PASS
    elif missing or unexpected or not order_preserved:
        status = ContextProbeStatus.FAIL
    else:
        status = ContextProbeStatus.SUSPICIOUS
    return RelayContextObservation(
        probe_key="context_anchor_retention",
        status=status,
        exact_answer_observed=exact,
        anchor_expected_count=3,
        anchor_observed_count=sum(1 for anchor in ANCHOR_SEQUENCE if anchor in observed),
        early_anchor_observed="TV_CTX_ALPHA" in observed,
        middle_anchor_observed="TV_CTX_BRAVO" in observed,
        late_anchor_observed="TV_CTX_CHARLIE" in observed,
        anchor_order_preserved=order_preserved,
        anchor_missing_count=len(missing),
        unexpected_anchor_count=len(unexpected),
        middle_anchor_selected=False,
        closing_anchor_wrongly_selected=False,
        separator_degradation_detected=separator_degraded,
        extra_content_detected=extra_content,
        provider_or_upstream_marker_detected=provider_count > 0,
        provider_or_upstream_marker_count=provider_count,
        finish_reason=str(finish_reason) if finish_reason is not None else None,
    )


def classify_context_middle_response(content: object, *, finish_reason: object | None = None) -> RelayContextObservation:
    text = str(content or "")
    normalized = normalize_context_answer(text)
    exact = normalized == MIDDLE_EXPECTED
    closing_wrong = "TV_CTX_CLOSING" in normalized and not exact
    observed = _observed_anchors(normalized)
    provider_count = _provider_marker_count(text)
    if exact:
        status = ContextProbeStatus.PASS
    elif closing_wrong or MIDDLE_EXPECTED not in observed:
        status = ContextProbeStatus.FAIL
    else:
        status = ContextProbeStatus.SUSPICIOUS
    return RelayContextObservation(
        probe_key="context_middle_retention",
        status=status,
        exact_answer_observed=exact,
        anchor_expected_count=1,
        anchor_observed_count=1 if MIDDLE_EXPECTED in observed else 0,
        early_anchor_observed=False,
        middle_anchor_observed=MIDDLE_EXPECTED in observed,
        late_anchor_observed=False,
        anchor_order_preserved=True,
        anchor_missing_count=0 if MIDDLE_EXPECTED in observed else 1,
        unexpected_anchor_count=sum(1 for anchor in observed if anchor != MIDDLE_EXPECTED),
        middle_anchor_selected=exact,
        closing_anchor_wrongly_selected=closing_wrong,
        separator_degradation_detected=False,
        extra_content_detected=bool(normalized) and not exact,
        provider_or_upstream_marker_detected=provider_count > 0,
        provider_or_upstream_marker_count=provider_count,
        finish_reason=str(finish_reason) if finish_reason is not None else None,
    )


def build_context_payload(model: str, probe: RelayContextProbe) -> dict[str, Any]:
    return {
        "model": sanitize_public_relay_text(model),
        "messages": list(probe.messages),
        "max_tokens": probe.max_tokens,
        "stream": False,
    }


def normalize_context_response(
    response: RelayLiveTransportResponse,
    *,
    probe: RelayContextProbe,
) -> RelayContextObservation:
    body = response.body if isinstance(response.body, dict) else {}
    choices = body.get("choices")
    choice = choices[0] if isinstance(choices, list) and choices and isinstance(choices[0], dict) else {}
    message = choice.get("message") if isinstance(choice, dict) else {}
    message = message if isinstance(message, dict) else {}
    content = message.get("content")
    finish_reason = choice.get("finish_reason")
    if probe.key == "context_middle_retention":
        return classify_context_middle_response(content if isinstance(content, str) else "", finish_reason=finish_reason)
    return classify_context_anchor_sequence(content if isinstance(content, str) else "", finish_reason=finish_reason)


def normalize_context_runtime_error(exc: BaseException) -> NormalizedRelayContextRuntimeError:
    normalized = normalize_live_runtime_error(RuntimeError(sanitize_public_relay_text(str(exc))))
    return NormalizedRelayContextRuntimeError(
        category=normalized.category,
        public_message=_context_runtime_message(normalized.category),
    )


def run_minimal_context_live_check(
    *,
    authorization: RelayLiveAuthorization,
    endpoint: str,
    model: str,
    api_key: str | None,
    pack_summary: RelayPackSummary,
    transport: RelayContextTransport | None,
) -> RelayResult:
    endpoint_host = sanitize_to_fqdn(endpoint)
    endpoint_hash = hash_relay_endpoint(endpoint)
    if transport is None:
        return _inconclusive_context_result(
            endpoint_host=endpoint_host,
            endpoint_hash=endpoint_hash,
            model=model,
            pack_summary=pack_summary,
            normalized=NormalizedRelayContextRuntimeError(
                RelayRuntimeCategory.UNSUPPORTED_LIVE_TARGET,
                "Relay context live transport is not configured for this execution path.",
            ),
        )
    observations: list[RelayContextObservation] = []
    for probe in CONTEXT_PROBES:
        try:
            response = transport(build_context_payload(model, probe))
        except BaseException as exc:
            normalized = normalize_context_runtime_error(exc)
            return _inconclusive_context_result(
                endpoint_host=endpoint_host,
                endpoint_hash=endpoint_hash,
                model=model,
                pack_summary=pack_summary,
                normalized=normalized,
            )
        status_error = _context_status_error(response.status_code)
        if status_error is not None:
            return _inconclusive_context_result(
                endpoint_host=endpoint_host,
                endpoint_hash=endpoint_hash,
                model=model,
                pack_summary=pack_summary,
                normalized=status_error,
            )
        observations.append(normalize_context_response(response, probe=probe))
    verdict, risk_level = _verdict_from_context_observations(observations)
    evidence = [_evidence_for_context_observation(item) for item in observations]
    return _context_result(
        endpoint_host=endpoint_host,
        endpoint_hash=endpoint_hash,
        model=model,
        pack_summary=pack_summary,
        verdict=verdict,
        risk_level=risk_level,
        evidence=evidence,
    )


def _strip_wrappers(text: str) -> str:
    for wrapper in ("**", "__", "`", "*", "_"):
        if text.startswith(wrapper) and text.endswith(wrapper) and len(text) >= len(wrapper) * 2:
            return text[len(wrapper) : -len(wrapper)].strip()
    return text


def _observed_anchors(text: str) -> list[str]:
    return [anchor for anchor in KNOWN_CONTEXT_ANCHORS if anchor in text]


def _anchor_order_preserved(text: str, anchors: tuple[str, ...]) -> bool:
    positions = [text.find(anchor) for anchor in anchors]
    if any(position < 0 for position in positions):
        return False
    return positions == sorted(positions)


def _provider_marker_count(text: str) -> int:
    lowered = text.lower()
    markers = ("upstream", "provider", "gateway", "bad gateway", "service unavailable")
    return sum(1 for marker in markers if marker in lowered)


def _context_runtime_message(category: RelayRuntimeCategory) -> str:
    messages = {
        RelayRuntimeCategory.AUTH_ERROR: "Provider authentication or authorization error during context retention check.",
        RelayRuntimeCategory.QUOTA_OR_RATE_LIMIT: "Provider quota or rate-limit error during context retention check.",
        RelayRuntimeCategory.TIMEOUT: "Provider timeout before a conclusive context retention result.",
        RelayRuntimeCategory.DISCONNECT: "Provider disconnect before a conclusive context retention result.",
        RelayRuntimeCategory.NETWORK_ERROR: "Provider network error before a conclusive context retention result.",
        RelayRuntimeCategory.UNSUPPORTED_LIVE_TARGET: "Relay context live transport is not configured for this execution path.",
        RelayRuntimeCategory.UNKNOWN_RUNTIME_ERROR: "Provider context runtime error before a conclusive relay result.",
    }
    return messages[category]


def _context_status_error(status_code: int) -> NormalizedRelayContextRuntimeError | None:
    if 200 <= status_code < 300:
        return None
    if status_code in {401, 403}:
        category = RelayRuntimeCategory.AUTH_ERROR
    elif status_code == 429:
        category = RelayRuntimeCategory.QUOTA_OR_RATE_LIMIT
    elif status_code == 504:
        category = RelayRuntimeCategory.TIMEOUT
    elif status_code in {502, 503}:
        category = RelayRuntimeCategory.NETWORK_ERROR
    else:
        category = RelayRuntimeCategory.UNKNOWN_RUNTIME_ERROR
    return NormalizedRelayContextRuntimeError(category=category, public_message=_context_runtime_message(category))


def _verdict_from_context_observations(
    observations: list[RelayContextObservation],
) -> tuple[RelayVerdict, RelayRiskLevel]:
    if any(item.status == ContextProbeStatus.FAIL for item in observations):
        return RelayVerdict.FAIL, RelayRiskLevel.HIGH
    if any(item.status == ContextProbeStatus.SUSPICIOUS for item in observations):
        return RelayVerdict.SUSPICIOUS, RelayRiskLevel.MEDIUM
    return RelayVerdict.PASS, RelayRiskLevel.LOW


def _evidence_for_context_observation(observation: RelayContextObservation) -> RelayEvidence:
    summaries = {
        ContextProbeStatus.PASS: "The context-retention probe preserved the expected public anchors.",
        ContextProbeStatus.SUSPICIOUS: "The context-retention probe kept anchors but showed weak formatting or rewrite symptoms.",
        ContextProbeStatus.FAIL: "The context-retention probe showed missing, wrong, or reordered public anchor evidence.",
    }
    return RelayEvidence(
        key=observation.probe_key,
        category=RelayRiskCategory.CONTEXT_TRUNCATION,
        status=observation.status.value,
        summary=sanitize_public_relay_text(summaries[observation.status]),
        metrics={
            "anchor_expected_count": observation.anchor_expected_count,
            "anchor_observed_count": observation.anchor_observed_count,
            "early_anchor_observed": observation.early_anchor_observed,
            "middle_anchor_observed": observation.middle_anchor_observed,
            "late_anchor_observed": observation.late_anchor_observed,
            "anchor_order_preserved": observation.anchor_order_preserved,
            "anchor_missing_count": observation.anchor_missing_count,
            "unexpected_anchor_count": observation.unexpected_anchor_count,
            "middle_anchor_selected": observation.middle_anchor_selected,
            "closing_anchor_wrongly_selected": observation.closing_anchor_wrongly_selected,
            "separator_degradation_detected": observation.separator_degradation_detected,
            "extra_content_detected": observation.extra_content_detected,
            "provider_or_upstream_marker_detected": observation.provider_or_upstream_marker_detected,
            "provider_or_upstream_marker_count": observation.provider_or_upstream_marker_count,
            "finish_reason": sanitize_public_relay_text(observation.finish_reason)
            if observation.finish_reason is not None
            else None,
        },
    )


def _context_result(
    *,
    endpoint_host: str,
    endpoint_hash: str,
    model: str,
    pack_summary: RelayPackSummary,
    verdict: RelayVerdict,
    risk_level: RelayRiskLevel,
    evidence: list[RelayEvidence],
    inconclusive_reason: str | None = None,
    runtime_category: RelayRuntimeCategory | None = None,
) -> RelayResult:
    return RelayResult(
        run_id=_context_run_id(endpoint_hash, model, verdict.value),
        profile=RelayAuditProfile.CONTEXT,
        scenario=verdict,
        mode=RelayAuditMode.LIVE,
        model=sanitize_public_relay_text(model),
        endpoint_host=endpoint_host,
        endpoint_hash=endpoint_hash,
        pack_summary=pack_summary,
        verdict=verdict,
        risk_level=risk_level,
        risk_categories=[RelayRiskCategory.CONTEXT_TRUNCATION],
        evidence=evidence,
        retest_guidance=(
            "Re-run the context profile after configuration or relay changes. "
            "This is bounded anchor-retention evidence, not a max-context benchmark."
        ),
        inconclusive_reason=inconclusive_reason,
        runtime_category=runtime_category,
    )


def _inconclusive_context_result(
    *,
    endpoint_host: str,
    endpoint_hash: str,
    model: str,
    pack_summary: RelayPackSummary,
    normalized: NormalizedRelayContextRuntimeError,
) -> RelayResult:
    return _context_result(
        endpoint_host=endpoint_host,
        endpoint_hash=endpoint_hash,
        model=model,
        pack_summary=pack_summary,
        verdict=RelayVerdict.INCONCLUSIVE,
        risk_level=RelayRiskLevel.UNKNOWN,
        evidence=[
            RelayEvidence(
                key="context_runtime_inconclusive",
                category=RelayRiskCategory.CONTEXT_TRUNCATION,
                status="inconclusive",
                summary=sanitize_public_relay_text(normalized.public_message),
                metrics={"runtime_category": normalized.category.value, "max_live_request_count": 2},
            )
        ],
        inconclusive_reason=sanitize_public_relay_text(normalized.public_message),
        runtime_category=normalized.category,
    )


def _context_run_id(endpoint_hash: str, model: str, suffix: str) -> str:
    material = "|".join(["context", endpoint_hash, model, suffix])
    return "relay-context-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
