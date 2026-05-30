# TokenVerify Release Readiness

This checklist covers local package readiness and publishable user-facing artifacts.

## Versioning Policy

TokenVerify uses SemVer-style versions while the project is pre-1.0:

- Patch updates fix bugs, wording, packaging metadata, or documentation without changing CLI behavior.
- Minor updates add provider paths, probes, report sections, or CLI flags.
- Major version `1.0.0` should wait until the CLI, report schema, and scoring semantics are stable enough for external automation.

Current package version is defined in `pyproject.toml`.

## Packaging Check

Run the packaging check without downloading dependencies. Use `--no-build-isolation` when the local environment already has the build backend, so pip does not try to fetch build dependencies:

```bash
python3 -m pip wheel . --no-deps --no-build-isolation --wheel-dir /tmp/tokenverify-wheel
```

Then verify the installed command exposes help in a clean environment:

```bash
tokenverify audit --help
```

In this workspace, the offline wheel check can use the bundled Python runtime if the system Python does not have `setuptools` installed locally.

Before publishing or handing off an archive:

- Do not include API keys, raw event logs, or local scratch files.
- Keep example configs on environment-variable placeholders.
- Keep real-network tests opt-in.
- Run `PYTHONPATH=src python3 -m pytest -v`.
- Run `git diff --check`.

## User-Facing Artifacts

The user-facing handoff should include:

- `README.md` for install, configuration, CLI usage, exit codes, and safety policy.
- `docs/user-guide.md` for supported audit paths and report interpretation.
- `examples/*.yaml` for safe configuration templates.
- `examples/reports/*.md` for offline mock reports that can be inspected without live provider requests.

## GitHub Release Checklist

Use `v0.2.0-preview` for the Dynamic Challenge Suite preview release.

Before creating the GitHub release:

- Confirm `git status --short` contains only intended release files.
- Run `PYTHONPATH=src python3 -m pytest -v`.
- Run `git diff --check`.
- Confirm `README.md`, `README.zh-CN.md`, `LICENSE`, `CLA.md`, and
  `CHANGELOG.md` are present.
- Confirm `.github/ISSUE_TEMPLATE/*` and `.github/PULL_REQUEST_TEMPLATE.md` are
  present.
- Confirm no API keys, raw event logs, customer secrets, or local scratch files
  are staged.

Suggested GitHub About description:

```text
Black-box LLM endpoint audit CLI for provider, model, reasoning, and relay-risk signals.
```

Suggested GitHub About topics:

```text
llm, ai, audit, security, openai, anthropic, claude, deepseek, model-routing, llmops, agpl
```

Suggested release title:

```text
TokenVerify v0.2.0-preview
```

Use the `CHANGELOG.md` `v0.2.0-preview` section as the release notes base.
