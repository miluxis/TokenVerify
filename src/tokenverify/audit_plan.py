from __future__ import annotations

from dataclasses import dataclass

from tokenverify.models import Claim


class UnsupportedAuditTarget(ValueError):
    pass


@dataclass(frozen=True)
class AuditPlan:
    path: str
    provider: str
    api_shape: str
    probe_names: tuple[str, ...]
    repeat_sampling_min_runs: int = 5
    single_anomaly_policy: str = "A single timing, disconnect, or drift anomaly is not proof of provider substitution."


_ANTHROPIC_NATIVE_PROBES = (
    "messages_protocol",
    "messages_error_schema",
    "extended_thinking",
    "thinking_parameter_compatibility",
    "streaming_features",
)

_ANTHROPIC_OPENAI_COMPATIBLE_PROBES = (
    "chat_completions_shape",
    "claude_claim_consistency",
    "mixed_provider_consistency",
    "claude_version_thinking_capability",
    "reasoning_leakage",
    "channel_risk_observations",
    "repeated_run_variance",
    "openai_compatible_streaming",
)

_OPENAI_COMPATIBLE_PROBES = (
    "openai_chat_completions_shape",
    "openai_model_claim_consistency",
    "openai_reasoning_capability",
    "openai_channel_risk",
    "openai_compatible_streaming",
)


def build_audit_plan(claim: Claim) -> AuditPlan:
    provider = claim.provider.lower()
    api_shape = claim.api_shape.lower()
    if provider == "anthropic" and api_shape == "native":
        return AuditPlan(
            path="anthropic_native",
            provider=provider,
            api_shape=api_shape,
            probe_names=_ANTHROPIC_NATIVE_PROBES,
        )
    if provider == "anthropic" and api_shape == "openai-compatible":
        return AuditPlan(
            path="anthropic_openai_compatible",
            provider=provider,
            api_shape=api_shape,
            probe_names=_ANTHROPIC_OPENAI_COMPATIBLE_PROBES,
        )
    if provider == "openai" and api_shape == "openai-compatible":
        return AuditPlan(
            path="openai_openai_compatible",
            provider=provider,
            api_shape=api_shape,
            probe_names=_OPENAI_COMPATIBLE_PROBES,
        )
    raise UnsupportedAuditTarget(
        f"Audit target provider={claim.provider!r}, api_shape={claim.api_shape!r} is out of scope."
    )
