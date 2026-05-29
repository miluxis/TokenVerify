from __future__ import annotations

from pathlib import Path

import typer

from tokenverify.config import CliOverrides, ConfigError, load_runtime_config
from tokenverify.audit import run_audit
from tokenverify.models import Rating
from tokenverify.report import render_markdown

AUDIT_HELP = """Run a TokenVerify audit and write a Markdown report.

Native Claude example:
  tokenverify audit --config examples/claude-audit.yaml --endpoint primary --output reports/claude-audit.md

OpenAI-compatible Claude relay example:
  tokenverify audit --config examples/claude-openai-compatible-audit.yaml --endpoint claude-openai-compatible --repeat 3 --output reports/claude-relay-audit.md

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
    repeat: int = typer.Option(1, "--repeat", min=1, max=10, help="Repeat live Chat Completions sampling 1-10 times."),
) -> None:
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
            ),
        )
    except ConfigError as exc:
        typer.echo(str(exc))
        raise typer.Exit(2) from exc

    result = run_audit(runtime_config, repeat_count=repeat)
    markdown = render_markdown(result)
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


if __name__ == "__main__":
    app()
