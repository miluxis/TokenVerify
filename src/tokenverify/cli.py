from __future__ import annotations

import json
import os
import re
from dataclasses import replace
from datetime import date
from pathlib import Path

import typer

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

Native Claude example:
  tokenverify audit --config examples/claude-audit.yaml --endpoint primary

OpenAI-compatible Claude relay example:
  tokenverify audit --config examples/claude-openai-compatible-audit.yaml --endpoint claude-openai-compatible --detail-audit yes

Exit code 0: high/medium trust.
Exit code 1: low trust.
Exit code 2: configuration error.
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


@app.callback()
def main() -> None:
    """TokenVerify audit commands."""


@app.command("audit", help=AUDIT_HELP)
def audit(
    config: Path = typer.Option(..., "--config", exists=True, readable=True),
    endpoint: str | None = typer.Option(None, "--endpoint"),
    output: str | None = typer.Option(None, "--output"),
    base_url: str | None = typer.Option(None, "--base-url"),
    model: str | None = typer.Option(None, "--model"),
    api_key: str | None = typer.Option(None, "--api-key"),
    api_key_env: str | None = typer.Option(None, "--api-key-env"),
    raw_log_path: str | None = typer.Option(None, "--raw-log-path"),
    language: str = typer.Option(
        "en",
        "--language",
        help="Report explanation language: en or zh.",
    ),
    detail_audit: str = typer.Option(
        "no",
        "--detail-audit",
        help="Run a deeper audit for relay, account-pool, and reverse-channel risk signals: yes/no.",
    ),
    repeat: int | None = typer.Option(None, "--repeat", min=1, max=10, hidden=True),
    challenge_pack: str | None = typer.Option(
        None,
        "--challenge-pack",
        help="Run a local Dynamic Challenge Suite YAML pack.",
    ),
    challenge_level: str = typer.Option(
        "basic",
        "--challenge-level",
        help="Dynamic challenge level: basic, standard, or strict.",
    ),
) -> None:
    try:
        repeat_count = _repeat_count_for_detail_audit(detail_audit, repeat)
        report_language = _normalize_language(language)
        normalized_challenge_level = _normalize_challenge_level(challenge_level)
    except ConfigError as exc:
        typer.echo(str(exc))
        raise typer.Exit(2) from exc

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
    api_key: str | None = typer.Option(None, "--api-key"),
    api_key_env: str | None = typer.Option(None, "--api-key-env"),
    pack_path: str | None = typer.Option(None, "--pack-path"),
    live: bool = typer.Option(False, "--live"),
) -> None:
    try:
        api_key_env = guard_api_key_env_name(api_key_env)
        relay_profile = parse_relay_profile(profile)
        relay_scenario = parse_relay_scenario(fake_run) if fake_run else None
        resolved_api_key = api_key or (os.environ.get(api_key_env) if api_key_env else None)
        request = RelayAuditRequest(
            base_url=base_url,
            model=model,
            profile=relay_profile,
            fake_scenario=relay_scenario,
            pack_path=Path(pack_path) if pack_path else None,
            live=live,
            api_key=resolved_api_key,
        )
        if live and relay_scenario is None:
            if relay_profile == RelayAuditProfile.STREAMING:
                request = replace(
                    request,
                    stream_transport_factory=_default_relay_stream_transport_factory(request),
                )
            elif relay_profile == RelayAuditProfile.SCHEMA:
                request = replace(
                    request,
                    schema_transport_factory=_default_relay_schema_transport_factory(request),
                )
            elif relay_profile == RelayAuditProfile.PRIVACY:
                request = replace(
                    request,
                    privacy_transport_factory=_default_relay_privacy_transport_factory(request),
                )
            elif relay_profile == RelayAuditProfile.FULL:
                request = replace(
                    request,
                    live_transport_factory=_default_relay_live_transport_factory(request),
                    stream_transport_factory=_default_relay_stream_transport_factory(request),
                    schema_transport_factory=_default_relay_schema_transport_factory(request),
                    privacy_transport_factory=_default_relay_privacy_transport_factory(request),
                )
            else:
                request = replace(request, live_transport_factory=_default_relay_live_transport_factory(request))
        result = run_relay_audit(
            request
        )
    except RelayAuditConfigError as exc:
        typer.echo(sanitize_public_relay_text(exc))
        raise typer.Exit(2) from exc
    except RelayAuditSecurityViolation as exc:
        typer.echo(sanitize_public_relay_text(exc))
        raise typer.Exit(2) from exc
    except Exception as exc:
        typer.echo("Relay audit failed before a public result could be produced.")
        typer.echo(sanitize_public_relay_text(exc))
        raise typer.Exit(2) from exc

    output_path = Path(output) if output else _next_available_relay_report_path(model, date.today())
    markdown = render_relay_markdown(result)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(markdown, encoding="utf-8")
    typer.echo(f"Wrote relay audit report: {basename_only(output_path)}")
    typer.echo(f"Relay audit completed with verdict: {result.verdict.value}")
    exit_code = exit_code_for_relay_verdict(result.verdict)
    if exit_code:
        raise typer.Exit(exit_code)


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


def _with_auto_output_path(runtime_config):
    output_path = _next_available_report_path(runtime_config.endpoint.model, date.today())
    redacted_config = dict(runtime_config.redacted_config)
    redacted_config["output"] = str(output_path)
    return replace(runtime_config, output_path=output_path, redacted_config=redacted_config)


def _next_available_report_path(model: str, today) -> Path:
    model_slug = _slugify_model_name(model)
    base_path = Path("reports") / f"audit-{model_slug}-{today}.md"
    if not base_path.exists():
        return base_path
    for index in range(2, 1000):
        candidate = base_path.with_name(f"{base_path.stem}-{index}{base_path.suffix}")
        if not candidate.exists():
            return candidate
    raise ConfigError("Could not find an available report filename.")


def _next_available_relay_report_path(model: str, today) -> Path:
    model_slug = _slugify_model_name(model)
    base_path = Path("reports") / f"relay-audit-{model_slug}-{today}.md"
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
