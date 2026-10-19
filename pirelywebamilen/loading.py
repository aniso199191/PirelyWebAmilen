"""Closed-core loader.

The scoring core ships as a compiled extension module named ``pwa_core``.
It is deliberately not part of this repository. This module is the only place
that knows how to reach it, so an alternative core can be dropped in without
touching the shell.

Contract (v1)::

    pwa_core.evaluate(fields: dict) -> dict
        {
          "action": "allow" | "challenge" | "block",
          "score": float,          # 0..100
          "reason": str,           # short machine-ish label
          "labels": list[str],     # optional signal names
        }
        pwa_core.VERSION: str
"""
from __future__ import annotations

import os

_core = None
_tried = False


def load():
    """Return the core module, or None when it is not installed."""
    global _core, _tried
    if _tried:
        return _core
    _tried = True
    path = os.environ.get("PWA_CORE_PATH")
    if path:
        # An explicit path wins, so operators can pin a specific build.
        import importlib.util

        spec = importlib.util.spec_from_file_location("pwa_core", path)
        if spec and spec.loader:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            _core = module
            return _core
    try:
        import pwa_core  # type: ignore

        _core = pwa_core
    except Exception:
        _core = None
    return _core


def reset() -> None:
    """Forget the loaded core (tests, hot reload)."""
    global _core, _tried
    _core, _tried = None, False
