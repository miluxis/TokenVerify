# CLI Report Output And Detail Audit Design

Date: 2026-05-29
Status: Implemented

## Purpose

TokenVerify should hide implementation details from ordinary users. Users should not need to choose report filenames or tune repeat-sampling counts to get useful channel-risk coverage.

## Decisions

- If `--output` is not provided, `tokenverify audit` writes to `reports/audit-[model-name]-[date].md`.
- `[model-name]` comes directly from the configured or overridden model name, normalized into a safe lowercase filename slug.
- If the generated path already exists, TokenVerify appends a numeric suffix such as `-2`.
- `--output` remains available as an advanced backward-compatible override.
- Public detailed scanning uses `--detail-audit yes/no`.
- `--detail-audit yes` maps to 8 internal samples.
- `--detail-audit no` maps to 1 sample.
- `--repeat` remains as a hidden compatibility override for advanced automation.

## Scope

This change is CLI-only. It does not change scoring, provider probes, report content, or live-network test policy.
