"""Exception hierarchy for compcopilot."""

from __future__ import annotations


class CopilotError(Exception):
    """Base class for errors raised deliberately by this package."""


class ConfigurationError(CopilotError):
    """Settings or a configuration file are missing or invalid."""


class EvidenceError(CopilotError):
    """Evidence, policy or exception files cannot be read or fail validation."""


class ReportError(CopilotError):
    """A report could not be rendered or written."""


class ProviderError(CopilotError):
    """An external model provider returned an error or an unusable response."""


class TransientProviderError(ProviderError):
    """A provider failure worth retrying (timeouts, rate limits, 5xx)."""
