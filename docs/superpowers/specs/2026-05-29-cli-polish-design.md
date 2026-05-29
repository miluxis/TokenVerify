# CLI Polish Design Spec

Date: 2026-05-29
Status: Implemented

## Purpose

CLI polish makes TokenVerify usable from scripts and by users who do not read source code. The command should show common audit examples, write a report before exiting, and return stable exit codes that automation can interpret.

## Scope

In scope:

- Add native Claude and OpenAI-compatible Claude relay examples to CLI help.
- Define exit-code policy for completed audits, low-trust findings, configuration errors, and inconclusive runtime results.
- Document no-key/offline behavior as an inconclusive runtime result.
- Keep `--repeat` constrained to 1..10 and documented as repeat sampling.

Out of scope:

- No provider expansion.
- No scoring changes.
- No live-network tests.
- No JSON output or dashboard behavior.

## Exit-Code Policy

- `0`: audit report was written and the rating is high or medium trust.
- `1`: audit report was written and the rating is low trust.
- `2`: configuration or CLI argument error.
- `3`: audit report was written, but the runtime result is inconclusive, such as missing API key, quota/auth failure, network failure, or unsupported target.

## Implementation Plan

1. Add failing CLI tests for low-trust exit code, inconclusive exit code, and help examples.
2. Implement rating-to-exit-code mapping after report writing.
3. Update README usage, exit-code, and no-key/offline notes.
4. Update roadmap checklist after targeted tests pass.
