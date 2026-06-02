from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Protocol

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


class RelayLiveTransport(Protocol):
    def __call__(self, payload: dict[str, Any]) -> "RelayLiveTransportResponse":
        ...


@dataclass(frozen=True)
class RelayLiveTransportResponse:
    status_code: int
    body: dict[str, Any]
    headers: dict[str, str] | None = None


@dataclass(frozen=True)
class NormalizedRelayRuntimeError:
    category: RelayRuntimeCategory
    public_message: str

    def raise_for_public_handling(self) -> None:
        raise RelayLiveRuntimeError(self.category, self.public_message) from None


class RelayLiveRuntimeError(RuntimeError):
    def __init__(self, category: RelayRuntimeCategory, public_message: str):
        self.category = category
        self.public_message = public_message
        super().__init__(public_message)


def build_minimal_live_payload(model: str) -> dict[str, Any]:
    return {
        "model": sanitize_public_relay_text(model),
        "messages": [{"role": "user", "content": "Return only: ok"}],
        "max_tokens": 8,
        "stream": False,
    }


def normalize_live_runtime_error(exc: BaseException) -> NormalizedRelayRuntimeError:
    text = str(exc).lower()
    if any(marker in text for marker in ("401", "403", "auth", "authorization", "unauthorized", "forbidden")):
        return NormalizedRelayRuntimeError(
            RelayRuntimeCategory.AUTH_ERROR,
            "Provider authentication or authorization error.",
        )
    if any(marker in text for marker in ("429", "quota", "rate limit", "too many requests", "throttle")):
        return NormalizedRelayRuntimeError(
            RelayRuntimeCategory.QUOTA_OR_RATE_LIMIT,
            "Provider quota or rate-limit error.",
        )
    if "504" in text or "gateway timeout" in text or "timeout" in text or "timed out" in text:
        return NormalizedRelayRuntimeError(
            RelayRuntimeCategory.TIMEOUT,
            "Provider timeout before a conclusive relay result.",
        )
    if any(marker in text for marker in ("connection reset", "disconnect", "incomplete read", "broken stream")):
        return NormalizedRelayRuntimeError(
            RelayRuntimeCategory.DISCONNECT,
            "Provider disconnect before a conclusive relay result.",
        )
    if any(
        marker in text
        for marker in (
            "502",
            "503",
            "bad gateway",
            "service unavailable",
            "dns",
            "connection refused",
            "tls",
            "socket",
            "proxy",
            "network",
        )
    ):
        return NormalizedRelayRuntimeError(
            RelayRuntimeCategory.NETWORK_ERROR,
            "Provider network error before a conclusive relay result.",
        )
    return NormalizedRelayRuntimeError(
        RelayRuntimeCategory.UNKNOWN_RUNTIME_ERROR,
        "Provider runtime error before a conclusive relay result.",
    )


def run_minimal_general_live_check(
    *,
    authorization: RelayLiveAuthorization,
    endpoint: str,
    model: str,
    api_key: str | None,
    pack_summary: RelayPackSummary,
    transport: RelayLiveTransport | None,
) -> RelayResult:
    endpoint_host = sanitize_to_fqdn(endpoint)
    endpoint_hash = hash_relay_endpoint(endpoint)
    if transport is None:
        normalized = NormalizedRelayRuntimeError(
            RelayRuntimeCategory.UNSUPPORTED_LIVE_TARGET,
            "Relay live transport is not configured for this execution path.",
        )
        return _inconclusive_live_result(
            endpoint_host=endpoint_host,
            endpoint_hash=endpoint_hash,
            model=model,
            pack_summary=pack_summary,
            normalized=normalized,
        )
    try:
        response = transport(build_minimal_live_payload(model))
    except BaseException as exc:
        normalized = normalize_live_runtime_error(exc)
        return _inconclusive_live_result(
            endpoint_host=endpoint_host,
            endpoint_hash=endpoint_hash,
            model=model,
            pack_summary=pack_summary,
            normalized=normalized,
        )
    normalized = _runtime_error_for_status(response.status_code)
    if normalized is not None:
        return _inconclusive_live_result(
            endpoint_host=endpoint_host,
            endpoint_hash=endpoint_hash,
            model=model,
            pack_summary=pack_summary,
            normalized=normalized,
        )
    return RelayResult(
        run_id=_live_run_id(endpoint_hash, model, "pass"),
        profile=authorization.profile,
        scenario=RelayVerdict.PASS,
        mode=RelayAuditMode.LIVE,
        model=sanitize_public_relay_text(model),
        endpoint_host=endpoint_host,
        endpoint_hash=endpoint_hash,
        pack_summary=pack_summary,
        verdict=RelayVerdict.PASS,
        risk_level=RelayRiskLevel.LOW,
        risk_categories=[RelayRiskCategory.MODEL_SUBSTITUTION],
        evidence=[
            RelayEvidence(
                key="minimal_live_connectivity",
                category=RelayRiskCategory.MODEL_SUBSTITUTION,
                status="pass",
                summary="Minimal live connectivity check completed with a compatible response envelope.",
                metrics={"status_code": response.status_code},
            )
        ],
        retest_guidance="Run deeper profile-specific probes only after their approved milestones.",
    )


def _runtime_error_for_status(status_code: int) -> NormalizedRelayRuntimeError | None:
    if status_code in {401, 403}:
        return NormalizedRelayRuntimeError(
            RelayRuntimeCategory.AUTH_ERROR,
            "Provider authentication or authorization error.",
        )
    if status_code == 429:
        return NormalizedRelayRuntimeError(
            RelayRuntimeCategory.QUOTA_OR_RATE_LIMIT,
            "Provider quota or rate-limit error.",
        )
    if status_code == 504:
        return NormalizedRelayRuntimeError(
            RelayRuntimeCategory.TIMEOUT,
            "Provider timeout before a conclusive relay result.",
        )
    if status_code in {502, 503}:
        return NormalizedRelayRuntimeError(
            RelayRuntimeCategory.NETWORK_ERROR,
            "Provider network error before a conclusive relay result.",
        )
    if status_code != 200:
        return NormalizedRelayRuntimeError(
            RelayRuntimeCategory.UNKNOWN_RUNTIME_ERROR,
            "Provider runtime error before a conclusive relay result.",
        )
    return None


def _inconclusive_live_result(
    *,
    endpoint_host: str,
    endpoint_hash: str,
    model: str,
    pack_summary: RelayPackSummary,
    normalized: NormalizedRelayRuntimeError,
) -> RelayResult:
    return RelayResult(
        run_id=_live_run_id(endpoint_hash, model, normalized.category.value),
        profile=RelayAuditProfile.GENERAL,
        scenario=RelayVerdict.INCONCLUSIVE,
        mode=RelayAuditMode.LIVE,
        model=sanitize_public_relay_text(model),
        endpoint_host=endpoint_host,
        endpoint_hash=endpoint_hash,
        pack_summary=pack_summary,
        verdict=RelayVerdict.INCONCLUSIVE,
        risk_level=RelayRiskLevel.UNKNOWN,
        risk_categories=[RelayRiskCategory.UPSTREAM_ERROR_LEAKAGE],
        evidence=[
            RelayEvidence(
                key=normalized.category.value,
                category=RelayRiskCategory.UPSTREAM_ERROR_LEAKAGE,
                status="inconclusive",
                summary=normalized.public_message,
            )
        ],
        retest_guidance="Resolve the runtime condition, then rerun with explicit --live.",
        inconclusive_reason=normalized.public_message,
        runtime_category=normalized.category,
    )


def _live_run_id(endpoint_hash: str, model: str, suffix: str) -> str:
    material = "|".join(["live", endpoint_hash, model, suffix])
    return "relay-live-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
