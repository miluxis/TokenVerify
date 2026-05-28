from __future__ import annotations

from pathlib import Path

import typer

from tokenverify.config import CliOverrides, ConfigError, load_runtime_config
from tokenverify.audit import run_audit
from tokenverify.report import render_markdown

app = typer.Typer(no_args_is_help=True)


@app.callback()
def main() -> None:
    """TokenVerify audit commands."""


@app.command("audit")
def audit(
    config: Path = typer.Option(..., "--config", exists=True, readable=True),
    endpoint: str | None = typer.Option(None, "--endpoint"),
    output: str | None = typer.Option(None, "--output"),
    base_url: str | None = typer.Option(None, "--base-url"),
    model: str | None = typer.Option(None, "--model"),
    api_key: str | None = typer.Option(None, "--api-key"),
    api_key_env: str | None = typer.Option(None, "--api-key-env"),
    raw_log_path: str | None = typer.Option(None, "--raw-log-path"),
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

    result = run_audit(runtime_config)
    markdown = render_markdown(result)
    runtime_config.output_path.parent.mkdir(parents=True, exist_ok=True)
    runtime_config.output_path.write_text(markdown, encoding="utf-8")
    typer.echo(f"Wrote audit report: {runtime_config.output_path}")
if __name__ == "__main__":
    app()
