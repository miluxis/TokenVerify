## Summary

- 

## Checklist

- [ ] I have read and agree to the CLA in `CLA.md`.
- [ ] I ran `PYTHONPATH=src python3 -m pytest -v`.
- [ ] I ran `git diff --check`.
- [ ] No live network requests are added to the default test suite.
- [ ] Provider HTTP tests use `httpx.MockTransport`.
- [ ] No API keys, raw event logs, or customer secrets are included.
- [ ] New provider or probe behavior includes regression tests.

## Notes

TokenVerify is a black-box audit tool. Avoid wording that claims certainty about the true upstream provider unless the code has direct server-provided evidence.
