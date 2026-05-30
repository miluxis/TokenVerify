from __future__ import annotations

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


def _slugify_model_name(model: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "-", model.strip().lower()).strip("-")
    return slug or "model"


if __name__ == "__main__":
    app()
