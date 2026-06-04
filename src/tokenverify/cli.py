from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, replace
from datetime import date
from enum import Enum
from pathlib import Path
from typing import Any

import typer
import yaml

from tokenverify.config import CliOverrides, ConfigError, load_runtime_config
from tokenverify.dynamic_challenges import ChallengePackError
from tokenverify.audit import run_audit
from tokenverify.models import Rating
from tokenverify.report import render_markdown
from tokenverify.relay_audit import RelayAuditRequest, exit_code_for_relay_verdict, run_relay_audit
from tokenverify.relay_live import RelayLiveTransportResponse
from tokenverify.relay_models import RelayAuditConfigError, RelayAuditProfile, parse_relay_profile, parse_relay_scenario
from tokenverify.relay_report import render_relay_markdown
from tokenverify.relay_safety import RelayAuditSecurityViolation, basename_only, guard_api_key_env_name, sanitize_public_relay_text
from tokenverify.relay_streaming import RelayStreamEvent, normalize_stream_event
from tokenverify.security import public_error_summary

AUDIT_HELP = """Run a TokenVerify audit and write a Markdown report.

Provider authenticity example:
  tokenverify audit --config examples/claude-audit.yaml --endpoint primary

Native Claude example:
  tokenverify audit --config examples/claude-audit.yaml --endpoint primary

Relay contract audit example:
  tokenverify audit --base-url https://relay.example/v1 --model example-model --profile full --api-key-env RELAY_API_KEY --live

Routing:
  --config routes to provider audit unless the YAML declares route: relay.
  --base-url plus --model routes to relay audit.

Exit code 0: positive or cautionary non-terminal result.
Exit code 1: conclusive negative result.
Exit code 2: configuration, argument, routing, pack, live-gate, or security error.
Exit code 3: inconclusive runtime result.
"""

RELAY_AUDIT_HELP = """Run a deterministic TokenVerify Relay Audit fake-run or guarded live request.

Fake-run example:
  tokenverify relay-audit --base-url https://relay.example/v1 --model example-model --profile general --fake-run suspicious

Live execution is limited to approved minimal general connectivity, streaming/SSE integrity, schema/tool preservation, privacy contract, and full composite paths.

Exit code 0: fake-run verdict pass or suspicious.
Exit code 1: fake-run verdict fail.
Exit code 2: CLI argument, configuration, pack metadata, or live-gate error.
Exit code 3: fake-run verdict inconclusive.
"""

app = typer.Typer(no_args_is_help=True)


class AuditRoute(str, Enum):
    AUTO = "auto"
    PROVIDER = "provider"
    RELAY = "relay"


@dataclass(frozen=True)
class AuditRouteSelection:
    route: AuditRoute
    parsed_config: dict[str, Any] | None = None


@app.callback()
def main() -> None:
    """TokenVerify audit commands."""


@app.command("audit", help=AUDIT_HELP)
def audit(
    config: Path | None = typer.Option(
        None,
        "--config",
        exists=True,
        readable=True,
        rich_help_panel="Provider Audit Options",
    ),
    endpoint: str | None = typer.Option(None, "--endpoint", rich_help_panel="Provider Audit Options"),
    output: str | None = typer.Option(None, "--output", rich_help_panel="Global Options"),
    base_url: str | None = typer.Option(None, "--base-url", rich_help_panel="Relay Audit Options"),
    model: str | None = typer.Option(None, "--model", rich_help_panel="Relay Audit Options"),
    api_key: str | None = typer.Option(None, "--api-key", rich_help_panel="Relay Audit Options"),
    api_key_env: str | None = typer.Option(None, "--api-key-env", rich_help_panel="Relay Audit Options"),
    profile: str = typer.Option("general", "--profile", rich_help_panel="Relay Audit Options"),
    fake_run: str | None = typer.Option(None, "--fake-run", rich_help_panel="Relay Audit Options"),
    pack_path: str | None = typer.Option(None, "--pack-path", rich_help_panel="Relay Audit Options"),
    live: bool = typer.Option(False, "--live", rich_help_panel="Relay Audit Options"),
    route: str = typer.Option("auto", "--route", rich_help_panel="Global Options"),
    raw_log_path: str | None = typer.Option(None, "--raw-log-path", rich_help_panel="Provider Audit Options"),
    language: str = typer.Option(
        "en",
        "--language",
        help="Report explanation language: en or zh.",
        rich_help_panel="Global Options",
    ),
    detail_audit: str = typer.Option(
        "no",
        "--detail-audit",
        help="Run provider deep sampling: yes/no.",
        rich_help_panel="Provider Audit Options",
    ),
    repeat: int | None = typer.Option(None, "--repeat", min=1, max=10, hidden=True),
    challenge_pack: str | None = typer.Option(
        None,
        "--challenge-pack",
        help="Run a local Dynamic Challenge Suite YAML pack.",
        rich_help_panel="Provider Audit Options",
    ),
    challenge_level: str = typer.Option(
        "basic",
        "--challenge-level",
        help="Dynamic challenge level: basic, standard, or strict.",
        rich_help_panel="Provider Audit Options",
    ),
) -> None:
    try:
        route_selection = _determine_audit_route(
            config=config,
            endpoint=endpoint,
            base_url=base_url,
            model=model,
            profile=profile,
            fake_run=fake_run,
            pack_path=pack_path,
            route=route,
        )
        selected_route = route_selection.route
        repeat_count = _repeat_count_for_detail_audit(detail_audit, repeat)
        report_language = _normalize_language(language)
        normalized_challenge_level = _normalize_challenge_level(challenge_level)
    except ConfigError as exc:
        typer.echo(str(exc))
        raise typer.Exit(2) from exc

    if selected_route == AuditRoute.RELAY:
        if detail_audit.strip().lower() == "yes":
            typer.echo("Relay repeated full-profile audit is not part of the current release.")
            raise typer.Exit(2)
        if config is not None:
            try:
                relay_config = _load_relay_config(route_selection.parsed_config)
            except RelayAuditConfigError as exc:
                typer.echo(sanitize_public_relay_text(exc))
                raise typer.Exit(2) from exc
            base_url = relay_config["base_url"]
            model = relay_config["model"]
            profile = relay_config["profile"]
            fake_run = relay_config["fake_run"]
            api_key_env = relay_config["api_key_env"]
            pack_path = relay_config["pack_path"]
            live = relay_config["live"]
        _run_relay_audit_cli_flow(
            base_url=base_url or "",
            model=model or "",
            profile=profile,
            fake_run=fake_run,
            output=output,
            language=report_language,
            api_key=api_key,
            api_key_env=api_key_env,
            pack_path=pack_path,
            live=live,
        )
        return

    if config is None:
        typer.echo("Provider audit requires --config.")
        raise typer.Exit(2)

    try:
        runtime_config = load_runtime_config(
            config,
            overrides=CliOverrides(
                endpoint=endpoint,
                output=output,
                base_url=base_url,
                model=model,
                api_key=api_key,
                api_key_env=api_key_env,
                raw_log_path=raw_log_path,
                challenge_pack=challenge_pack,
                challenge_level=normalized_challenge_level,
            ),
        )
    except ConfigError as exc:
        typer.echo(str(exc))
        raise typer.Exit(2) from exc

    if output is None:
        runtime_config = _with_auto_output_path(runtime_config)

    try:
        result = run_audit(runtime_config, repeat_count=repeat_count)
    except ChallengePackError as exc:
        typer.echo(str(exc))
        raise typer.Exit(2) from exc
    except Exception as exc:
        typer.echo("Audit failed before a conclusive result could be produced.")
        typer.echo(public_error_summary(exc))
        raise typer.Exit(3) from exc
    markdown = render_markdown(result, language=report_language)
    runtime_config.output_path.parent.mkdir(parents=True, exist_ok=True)
    runtime_config.output_path.write_text(markdown, encoding="utf-8")
    typer.echo(f"Wrote audit report: {runtime_config.output_path}")
    typer.echo(f"Audit completed with rating: {result.rating.value}")
    exit_code = _exit_code_for_rating(result.rating)
    if exit_code:
        if exit_code == 3:
            typer.echo("Check API key, network, quota, or unsupported target details in the report.")
        raise typer.Exit(exit_code)


@app.command("relay-audit", help=RELAY_AUDIT_HELP)
def relay_audit(
    base_url: str = typer.Option(..., "--base-url"),
    model: str = typer.Option(..., "--model"),
    profile: str = typer.Option("general", "--profile"),
    fake_run: str | None = typer.Option(None, "--fake-run"),
    output: str | None = typer.Option(None, "--output"),
    language: str = typer.Option("en", "--language"),
    api_key: str | None = typer.Option(None, "--api-key"),
    api_key_env: str | None = typer.Option(None, "--api-key-env"),
    pack_path: str | None = typer.Option(None, "--pack-path"),
    live: bool = typer.Option(False, "--live"),
) -> None:
    _run_relay_audit_cli_flow(
        base_url=base_url,
        model=model,
        profile=profile,
        fake_run=fake_run,
        output=output,
        language=language,
        api_key=api_key,
        api_key_env=api_key_env,
        pack_path=pack_path,
        live=live,
        compatibility_notice=True,
    )


def _run_relay_audit_cli_flow(
    *,
    base_url: str,
    model: str,
    profile: str,
    fake_run: str | None,
    output: str | None,
    language: str,
    api_key: str | None,
    api_key_env: str | None,
    pack_path: str | None,
    live: bool,
    compatibility_notice: bool = False,
) -> None:
    if compatibility_notice:
        typer.echo(
            "Compatibility notice: tokenverify relay-audit remains supported; tokenverify audit is the primary entry.",
            err=True,
        )
    try:
        api_key_env = guard_api_key_env_name(api_key_env)
        report_language = _normalize_language(language)
        relay_profile = parse_relay_profile(profile)
        relay_scenario = parse_relay_scenario(fake_run) if fake_run else None
        resolved_api_key = _resolve_relay_api_key(
            api_key=api_key,
            api_key_env=api_key_env,
            require_env=live and relay_scenario is None,
        )
        request = RelayAuditRequest(
            base_url=base_url,
            model=model,
            profile=relay_profile,
            fake_scenario=relay_scenario,
            pack_path=Path(pack_path) if pack_path else None,
            live=live,
            api_key=resolved_api_key,
        )
        request = _with_relay_live_transports(request, relay_profile, relay_scenario)
        result = run_relay_audit(request)
    except RelayAuditConfigError as exc:
        typer.echo(sanitize_public_relay_text(exc))
        raise typer.Exit(2) from exc
    except RelayAuditSecurityViolation as exc:
        typer.echo(sanitize_public_relay_text(exc))
        raise typer.Exit(2) from exc
    except Exception as exc:
        typer.echo("Relay audit failed before a public result could be produced.")
        typer.echo(sanitize_public_relay_text(exc))
        raise typer.Exit(1) from exc

    output_path = Path(output) if output else _next_available_relay_report_path(model, date.today())
    markdown = render_relay_markdown(result, language=report_language)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(markdown, encoding="utf-8")
    typer.echo(f"Wrote relay audit report: {basename_only(output_path)}")
    typer.echo(f"Relay audit completed with verdict: {result.verdict.value}")
    exit_code = exit_code_for_relay_verdict(result.verdict)
    if exit_code:
        raise typer.Exit(exit_code)


def _with_relay_live_transports(
    request: RelayAuditRequest,
    relay_profile: RelayAuditProfile,
    relay_scenario,
) -> RelayAuditRequest:
    if not request.live or relay_scenario is not None:
        return request
    if relay_profile == RelayAuditProfile.STREAMING:
        return replace(request, stream_transport_factory=_default_relay_stream_transport_factory(request))
    if relay_profile == RelayAuditProfile.SCHEMA:
        return replace(request, schema_transport_factory=_default_relay_schema_transport_factory(request))
    if relay_profile == RelayAuditProfile.PRIVACY:
        return replace(request, privacy_transport_factory=_default_relay_privacy_transport_factory(request))
    if relay_profile == RelayAuditProfile.FULL:
        return replace(
            request,
            live_transport_factory=_default_relay_live_transport_factory(request),
            stream_transport_factory=_default_relay_stream_transport_factory(request),
            schema_transport_factory=_default_relay_schema_transport_factory(request),
            privacy_transport_factory=_default_relay_privacy_transport_factory(request),
        )
    return replace(request, live_transport_factory=_default_relay_live_transport_factory(request))


def _default_relay_live_transport_factory(request: RelayAuditRequest):
    def factory():
        return _default_relay_live_transport(request)

    return factory


def _default_relay_live_transport(request: RelayAuditRequest):
    import httpx

    def transport(payload):
        headers = {"Authorization": f"Bearer {request.api_key}"} if request.api_key else {}
        url = request.base_url.rstrip("/")
        post_url = url if url.endswith("/chat/completions") else f"{url}/chat/completions"
        with httpx.Client(timeout=30.0) as client:
            response = client.post(post_url, json=payload, headers=headers)
        try:
            body = response.json()
        except ValueError:
            body = {}
        return RelayLiveTransportResponse(
            status_code=response.status_code,
            body=body,
            headers=dict(response.headers),
        )

    return transport


def _default_relay_schema_transport_factory(request: RelayAuditRequest):
    def factory():
        return _default_relay_live_transport(request)

    return factory


def _default_relay_privacy_transport_factory(request: RelayAuditRequest):
    def factory():
        return _default_relay_live_transport(request)

    return factory


def _default_relay_stream_transport_factory(request: RelayAuditRequest):
    def factory():
        return _default_relay_stream_transport(request)

    return factory


def _default_relay_stream_transport(request: RelayAuditRequest):
    import httpx

    def transport(payload):
        headers = {"Authorization": f"Bearer {request.api_key}"} if request.api_key else {}
        url = request.base_url.rstrip("/")
        post_url = url if url.endswith("/chat/completions") else f"{url}/chat/completions"
        events: list[RelayStreamEvent] = []
        with httpx.Client(timeout=30.0) as client:
            with client.stream("POST", post_url, json=payload, headers=headers) as response:
                response.raise_for_status()
                index = 0
                for raw_line in response.iter_lines():
                    parsed = _parse_stream_json_line(raw_line)
                    if parsed is None:
                        continue
                    events.append(normalize_stream_event(parsed, index=index))
                    index += 1
        return events

    return transport


def _parse_stream_json_line(raw_line: object) -> dict | None:
    if isinstance(raw_line, bytes):
        text = raw_line.decode("utf-8", errors="ignore").strip()
    else:
        text = str(raw_line).strip()
    if not text:
        return None
    if text.startswith("data:"):
        text = text[5:].strip()
    if text == "[DONE]":
        return None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        raise RuntimeError("Malformed streaming event envelope.") from None
    return parsed if isinstance(parsed, dict) else None


def _exit_code_for_rating(rating: Rating) -> int:
    if rating == Rating.LOW_TRUST:
        return 1
    if rating == Rating.INCONCLUSIVE:
        return 3
    return 0


def _repeat_count_for_detail_audit(detail_audit: str, repeat: int | None) -> int:
    if repeat is not None:
        return repeat
    normalized = detail_audit.strip().lower()
    if normalized == "yes":
        return 8
    if normalized == "no":
        return 1
    raise ConfigError("--detail-audit must be yes or no.")


def _normalize_language(language: str) -> str:
    normalized = language.strip().lower()
    if normalized in {"en", "zh"}:
        return normalized
    raise ConfigError("--language must be en or zh.")


def _normalize_challenge_level(level: str) -> str:
    normalized = level.strip().lower()
    if normalized in {"basic", "standard", "strict"}:
        return normalized
    raise ConfigError("--challenge-level must be basic, standard, or strict.")


def _normalize_audit_route(route: str) -> AuditRoute:
    normalized = route.strip().lower()
    try:
        return AuditRoute(normalized)
    except ValueError:
        raise ConfigError("--route must be auto, provider, or relay.") from None


def _load_config_for_routing(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except OSError:
        raise ConfigError(f"Configuration file could not be read: {basename_only(path)}") from None
    except yaml.YAMLError:
        raise ConfigError(f"Configuration file is not valid YAML: {basename_only(path)}") from None
    if not isinstance(data, dict):
        raise ConfigError("Configuration root must be a mapping.")
    return data


def _route_from_parsed_config(data: dict[str, Any] | None) -> AuditRoute | None:
    if data is None:
        return None
    raw_route = data.get("route")
    if raw_route is None:
        return None
    normalized = str(raw_route).strip().lower()
    if normalized == "provider":
        return AuditRoute.PROVIDER
    if normalized == "relay":
        return AuditRoute.RELAY
    raise ConfigError("Configuration route must be provider or relay.")


def _has_relay_cli_inputs(
    *,
    base_url: str | None,
    model: str | None,
    profile: str,
    fake_run: str | None,
    pack_path: str | None,
) -> bool:
    return any(
        (
            base_url,
            model,
            profile != "general",
            fake_run,
            pack_path,
        )
    )


def _determine_audit_route(
    *,
    config: Path | None,
    endpoint: str | None,
    base_url: str | None,
    model: str | None,
    profile: str,
    fake_run: str | None,
    pack_path: str | None,
    route: str,
) -> AuditRouteSelection:
    requested = _normalize_audit_route(route)
    parsed_config = _load_config_for_routing(config)
    relay_cli_inputs = _has_relay_cli_inputs(
        base_url=base_url,
        model=model,
        profile=profile,
        fake_run=fake_run,
        pack_path=pack_path,
    )
    if config is not None and relay_cli_inputs:
        raise ConfigError("--config cannot be combined with direct relay options like --base-url or --profile.")
    if endpoint and config is None:
        raise ConfigError("Detected --endpoint, but provider audit endpoint selection requires --config.")
    if base_url and not model:
        raise ConfigError("Detected --base-url; relay audit also requires --model.")
    if model and not base_url:
        raise ConfigError("Detected --model; relay audit also requires --base-url.")
    if profile != "general" and not (base_url and model):
        raise ConfigError("Detected --profile; relay audit profiles require --base-url and --model.")
    if fake_run and not (base_url and model):
        raise ConfigError("Detected --fake-run; relay audit fake-runs require --base-url and --model.")
    config_route = _route_from_parsed_config(parsed_config)
    inferred = config_route or (AuditRoute.PROVIDER if config is not None else None)
    if inferred is None and base_url and model:
        inferred = AuditRoute.RELAY
    if inferred is None:
        raise ConfigError("Provide either --config for provider audit, or --base-url and --model for relay audit.")
    if requested != AuditRoute.AUTO and requested != inferred:
        raise ConfigError(f"--route {requested.value} conflicts with inferred {inferred.value} audit inputs.")
    return AuditRouteSelection(route=inferred, parsed_config=parsed_config)


def _load_relay_config(data: dict[str, Any] | None) -> dict[str, Any]:
    if data is None:
        raise RelayAuditConfigError("Relay config route requires a parsed configuration mapping.")
    relay = data.get("relay") or {}
    if not isinstance(relay, dict):
        raise RelayAuditConfigError("Relay config must define a relay mapping.")
    base_url = relay.get("base_url")
    model = relay.get("model")
    if not base_url:
        raise RelayAuditConfigError("Relay config route requires relay.base_url.")
    if not model:
        raise RelayAuditConfigError("Relay config route requires relay.model.")
    return {
        "base_url": str(base_url),
        "model": str(model),
        "profile": str(relay.get("profile") or "general"),
        "fake_run": str(relay["fake_run"]) if relay.get("fake_run") else None,
        "api_key_env": str(relay["api_key_env"]) if relay.get("api_key_env") else None,
        "pack_path": str(relay["pack_path"]) if relay.get("pack_path") else None,
        "live": bool(relay.get("live", False)),
    }


def _resolve_relay_api_key(*, api_key: str | None, api_key_env: str | None, require_env: bool) -> str | None:
    if api_key:
        return api_key
    if not api_key_env:
        return None
    if require_env and api_key_env not in os.environ:
        raise RelayAuditConfigError(
            f"Detected --api-key-env {api_key_env}, but that variable was not found in the current environment. "
            f"Set it first, for example: export {api_key_env}=<your-relay-key>"
        )
    return os.environ.get(api_key_env)


def _with_auto_output_path(runtime_config):
    output_path = _next_available_report_path(runtime_config.endpoint.model, date.today())
    redacted_config = dict(runtime_config.redacted_config)
    redacted_config["output"] = str(output_path)
    return replace(runtime_config, output_path=output_path, redacted_config=redacted_config)


def _next_available_report_path(model: str, today) -> Path:
    model_slug = _slugify_model_name(model)
    base_path = Path("reports") / f"audit-provider-{model_slug}-{today}.md"
    if not base_path.exists():
        return base_path
    for index in range(2, 1000):
        candidate = base_path.with_name(f"{base_path.stem}-{index}{base_path.suffix}")
        if not candidate.exists():
            return candidate
    raise ConfigError("Could not find an available report filename.")


def _next_available_relay_report_path(model: str, today) -> Path:
    model_slug = _slugify_model_name(model)
    base_path = Path("reports") / f"audit-relay-{model_slug}-{today}.md"
    if not base_path.exists():
        return base_path
    for index in range(2, 1000):
        candidate = base_path.with_name(f"{base_path.stem}-{index}{base_path.suffix}")
        if not candidate.exists():
            return candidate
    raise RelayAuditConfigError("Could not find an available relay report filename.")


def _slugify_model_name(model: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "-", model.strip().lower()).strip("-")
    return slug or "model"


if __name__ == "__main__":
    app()
