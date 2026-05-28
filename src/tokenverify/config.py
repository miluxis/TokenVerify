from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import yaml

from tokenverify.models import Claim, EndpointConfig, RuntimeConfig


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class CliOverrides:
    base_url: str | None = None
    model: str | None = None
    api_key: str | None = None
    api_key_env: str | None = None
    endpoint: str | None = None
    output: str | None = None
    raw_log_path: str | None = None


SECRET_KEYS = {"api_key", "authorization", "x-api-key", "anthropic-api-key"}


def load_runtime_config(
    path: str | Path,
    overrides: CliOverrides | None = None,
    env: Mapping[str, str] | None = None,
) -> RuntimeConfig:
    overrides = overrides or CliOverrides()
    env = env or os.environ
    raw = _load_yaml(Path(path))
    endpoints = raw.get("endpoints") or []
    if not isinstance(endpoints, list) or not endpoints:
        raise ConfigError("Configuration must define at least one endpoint.")

    selected_name = overrides.endpoint or raw.get("selected_endpoint")
    if selected_name is None and len(endpoints) > 1:
        raise ConfigError("Configuration has multiple endpoints; select one endpoint.")

    endpoint_data = _select_endpoint(endpoints, selected_name)
    endpoint = _build_endpoint(endpoint_data, overrides, env)
    output = Path(overrides.output or raw.get("output") or "tokenverify-audit.md")
    raw_logs = raw.get("raw_logs") or {}
    raw_log_path = Path(overrides.raw_log_path) if overrides.raw_log_path else _optional_path(raw_logs.get("path"))
    raw_logs_enabled = bool(raw_logs.get("enabled", False) or raw_log_path)

    effective = {
        **raw,
        "selected_endpoint": endpoint.name,
        "endpoint": {
            "name": endpoint.name,
            "base_url": endpoint.base_url,
            "model": endpoint.model,
            "api_key": endpoint.api_key,
            "headers": endpoint.headers,
            "claim": {
                "provider": endpoint.claim.provider if endpoint.claim else "anthropic",
                "api_shape": endpoint.claim.api_shape if endpoint.claim else "native",
                "model": endpoint.claim.model if endpoint.claim else endpoint.model,
                "channel_claim": endpoint.claim.channel_claim if endpoint.claim else "unknown",
                "region_claim": endpoint.claim.region_claim if endpoint.claim else None,
            },
        },
        "output": str(output),
        "raw_logs": {"enabled": raw_logs_enabled, "path": str(raw_log_path) if raw_log_path else None},
    }

    return RuntimeConfig(
        endpoint=endpoint,
        output_path=output,
        raw_logs_enabled=raw_logs_enabled,
        raw_log_path=raw_log_path,
        extension_probes=list(raw.get("extension_probes") or []),
        redacted_config=redact_secrets(effective),
    )


def redact_secrets(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[Any, Any] = {}
        for key, item in value.items():
            if str(key).lower() in SECRET_KEYS:
                redacted[key] = "***REDACTED***"
            else:
                redacted[key] = redact_secrets(item)
        return redacted
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    if isinstance(value, str) and value.lower().startswith("bearer "):
        return "***REDACTED***"
    return value


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise ConfigError(f"Configuration file not found: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ConfigError("Configuration root must be a mapping.")
    return data


def _select_endpoint(endpoints: list[dict[str, Any]], selected_name: str | None) -> dict[str, Any]:
    if selected_name is None:
        return endpoints[0]
    for endpoint in endpoints:
        if endpoint.get("name") == selected_name:
            return endpoint
    raise ConfigError(f"Selected endpoint not found: {selected_name}")


def _build_endpoint(
    data: dict[str, Any],
    overrides: CliOverrides,
    env: Mapping[str, str],
) -> EndpointConfig:
    api_key_env = overrides.api_key_env or data.get("api_key_env")
    api_key = overrides.api_key or (env.get(api_key_env) if api_key_env else None) or data.get("api_key")
    name = str(data.get("name") or "primary")
    base_url = overrides.base_url or data.get("base_url")
    model = overrides.model or data.get("model")
    if not base_url:
        raise ConfigError(f"Endpoint {name} must define base_url.")
    if not model:
        raise ConfigError(f"Endpoint {name} must define model.")
    normalized_base_url = str(base_url).rstrip("/")
    normalized_model = str(model)
    claim = _build_claim(data, normalized_model, normalized_base_url)
    return EndpointConfig(
        name=name,
        base_url=normalized_base_url,
        model=normalized_model,
        api_key=api_key,
        headers=dict(data.get("headers") or {}),
        claim=claim,
    )


def _optional_path(value: Any) -> Path | None:
    return Path(value) if value else None


def _build_claim(data: dict[str, Any], model: str, base_url: str) -> Claim:
    provider = str(data.get("provider") or "anthropic")
    api_shape = str(data.get("api_shape") or _infer_api_shape(base_url))
    return Claim(
        provider=provider,
        api_shape=api_shape,
        model=model,
        channel_claim=str(data.get("channel_claim") or "unknown"),
        region_claim=str(data["region_claim"]) if data.get("region_claim") else None,
    )


def _infer_api_shape(base_url: str) -> str:
    lower = base_url.lower().rstrip("/")
    if "/v1/chat/completions" in lower:
        return "openai-compatible"
    if lower.endswith("/v1") and "anthropic.com" not in lower:
        return "openai-compatible"
    return "native"
