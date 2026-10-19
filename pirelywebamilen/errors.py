"""Exceptions raised by the open shell."""
from __future__ import annotations


class ConfigurationError(ValueError):
    """The shield was configured with something it cannot honour."""


class CoreUnavailable(RuntimeError):
    """The closed scoring core is not installed.

    The shell still works in observe mode; nothing is blocked without a core.
    """

    def __init__(self, message: str = "closed core (pwa_core) is not installed") -> None:
        super().__init__(message)
