# Suspected Upstream Signals Design Spec

Date: 2026-05-29
Status: Implemented

## Purpose

Suspected Upstream Signals is an auxiliary explanation layer for TokenVerify reports. It translates observed cross-provider fingerprints, model strings, and response structures into plain-language hints such as "疑似 OpenAI 风格上游或兼容层", "疑似 Claude/Anthropic 风格上游或兼容层", or "疑似 DeepSeek/R1 风格上游或兼容层".

This layer must not assert the real official upstream. It explains observable style clues only.

## Scope

In scope:

- Read existing `AuditResult` target summary, claim, probe evidence, evidence details, and stable tags.
- Render a Markdown section named `Suspected Upstream Signals / 疑似上游特征`.
- Show only auxiliary hints with observed evidence labels.
- Treat weak model-name-only strings as hints, not official-provider assertions.
- Mark Gemini, Seed, Qwen, Doubao, or similar unimplemented families only as unmodeled vendor-style clues.

Out of scope:

- No scoring changes.
- No new hard-fail tags.
- No Gemini, Seed, Qwen, Doubao provider auditing.
- No live-network behavior.

## Implementation Plan

1. Add focused report tests that expect suspected upstream hints for Claude, OpenAI, and DeepSeek claims.
2. Create `src/tokenverify/upstream_signals.py` with a small extractor returning neutral report entries.
3. Call the extractor from `report.py` and render the new section after Channel Risk Profile.
4. Update the roadmap checklist only after the related tests pass.
