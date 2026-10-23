"""Bounded, local ZIP quarantine for a deliberately narrow filename profile."""

from .core import ArchiveGuard, Limits, read_snapshot

__all__ = ["ArchiveGuard", "Limits", "read_snapshot"]
__version__ = "0.1.0"
