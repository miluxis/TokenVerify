# TokenVerify Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Claude Anthropic-native authenticity audit MVP as a tested Python package with a thin CLI and Markdown report output.

**Architecture:** Layered audit core: config -> provider -> probes -> evidence -> scoring -> Markdown report -> CLI. Core scoring uses built-in Claude Messages, Extended Thinking, and streaming physical-feature probes; user YAML probes are appendix-only. No business logic belongs in the CLI.

**Tech Stack:** Python 3.11+, `pytest`, `httpx`, `PyYAML`, `typer` or `argparse` with the default choice of `typer`, `ruff` optional for checks only after approval.

---

## Summary

This plan should be saved to `docs/superpowers/plans/2026-05-25-tokenverify-implementation-plan.md` after Plan Mode allows mutation. It must not initialize git, scaffold code, or commit business logic until the user explicitly approves the plan.

The confirmed Spec additions are included:

- Extended Thinking manual-budget payloads must keep `thinking.budget_tokens < max_tokens`, defaulting to `budget_tokens=1024` and `max_tokens=2048`.
- Streaming weak evidence includes `chunk_size_distribution` and `is_synthetic_stream` heuristics for fixed-size deltas or short-burst fake streaming.

## File Path Design

Create these implementation files after approval:

- `pyproject.toml`: package metadata, console script, dependencies, pytest config.
- `src/tokenverify/__init__.py`: package version.
- `src/tokenverify/config.py`: YAML loading, CLI override merge, secret redaction, endpoint selection.
- `src/tokenverify/models.py`: dataclasses/enums for config, events, probe results, evidence, scores, audit result.
- `src/tokenverify/model_capabilities.py`: Claude capability table and lookup.
- `src/tokenverify/providers/anthropic.py`: Anthropic Messages request builder, streaming parser, provider error normalization.
- `src/tokenverify/probes/messages.py`: Anthropic Messages protocol structure probe.
- `src/tokenverify/probes/thinking.py`: Extended Thinking probe with payload validity guard.
- `src/tokenverify/probes/streaming.py`: TTFT/TPS/chunk interval/chunk size/synthetic stream sampling.
- `src/tokenverify/scoring.py`: overall rating and evidence score computation.
- `src/tokenverify/report.py`: Markdown renderer.
- `src/tokenverify/cli.py`: `tokenverify audit` CLI orchestration only.
- `tests/`: mirrored test modules for each production module.
- `examples/claude-audit.yaml`: safe example config using environment variable references, not plaintext keys.

## Phase 1 Checklist: Project Foundation, Types, Config

- [ ] Create package scaffold files listed above, without adding network behavior yet.
- [ ] Add `pyproject.toml` with package name `tokenverify`, console script `tokenverify=tokenverify.cli:app`, dependencies `httpx`, `PyYAML`, `typer`, and test dependency `pytest`.
- [ ] Define core types in `src/tokenverify/models.py`.
- [ ] Implement config loading in `src/tokenverify/config.py`.
- [ ] Add and pass config/model tests.

## Phase 2 Checklist: Anthropic Provider and Built-In Probes

- [ ] Implement `src/tokenverify/model_capabilities.py`.
- [ ] Implement `src/tokenverify/providers/anthropic.py`.
- [ ] Implement Messages protocol probe.
- [ ] Implement Extended Thinking probe.
- [ ] Implement streaming feature probe.
- [ ] Add and pass provider/probe tests with mocked network only.

## Phase 3 Checklist: Scoring, Markdown Report, Raw Logs, CLI

- [ ] Implement `src/tokenverify/scoring.py`.
- [ ] Implement `src/tokenverify/report.py`.
- [ ] Implement raw log behavior.
- [ ] Implement `src/tokenverify/cli.py`.
- [ ] Add and pass scoring/report/CLI tests.

## Phase 4 Checklist: End-to-End Hardening and Plan Review Gate

- [ ] Add `examples/claude-audit.yaml`.
- [ ] Add mocked end-to-end audit flow test.
- [ ] Add optional real-network test marker skipped by default.
- [ ] Run full verification.
- [ ] Self-review against Spec.

## Acceptance Criteria

- All unit tests pass with no real network access.
- CLI help works and exposes only the Phase 1 interface.
- Markdown report includes all required sections and never leaks API keys.
- Thinking probe payload construction enforces `budget_tokens < max_tokens`.
- Streaming metrics include chunk size distribution and synthetic stream detection.
- Scoring keeps streaming anomalies as weak evidence.
- Extension probes appear only in the appendix and never alter the core rating.

## Assumptions

- Python 3.11+ is acceptable for Phase 1.
- `typer` is the default CLI framework unless dependency minimization later overrides it.
- The first implementation can keep the Claude capability table in source code, provided it is isolated in `model_capabilities.py`.
