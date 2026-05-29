from __future__ import annotations

from typing import Protocol

from tokenverify.models import ProviderEvent


class ProviderAdapter(Protocol):
    def create_probe_response(self, model: str, prompt: str, max_tokens: int = 64) -> dict:
        """Run a minimal non-streaming probe request."""

    def stream_probe_events(self, model: str, prompt: str, max_tokens: int = 64) -> list[ProviderEvent]:
        """Run a minimal streaming probe request and return normalized provider events."""
