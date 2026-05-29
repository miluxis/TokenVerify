# Test And Safety Policy Design Spec

Date: 2026-05-29
Status: Implemented

## Purpose

TokenVerify tests must remain safe by default. Normal test runs must not send real provider requests, and every provider/probe expansion must add regression coverage before implementation is considered complete.

## Policy

- Normal pytest runs exclude `real_network` tests through `pyproject.toml`.
- Real-network tests are opt-in only and must be explicitly marked with `pytest.mark.real_network`.
- Provider HTTP behavior must use `httpx.MockTransport`.
- Probe behavior should use direct probe inputs or mock observations.
- Every new provider or probe module must add regression tests in the matching `tests/providers/` or `tests/probes/` area.
- No provider expansion is complete until the full default test suite passes without live network access.

## Verification

The policy is enforced by `tests/test_safety_policy.py`, which checks pytest marker configuration, README documentation, and regression-test coverage for current provider/probe modules.
