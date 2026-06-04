"""Acquisition layer protocol.

A source provides parsers with paths to artifacts. The same parser code works
regardless of whether the source is a mounted drive, a live system, or an image.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable


@runtime_checkable
class ArtifactSource(Protocol):
    """Abstract source of Windows forensic artifacts."""

    def get_system_hive(self) -> Path | None:
        """Path to SYSTEM registry hive, or None if unavailable."""
        ...

    def get_software_hive(self) -> Path | None:
        """Path to SOFTWARE registry hive."""
        ...

    def get_user_hives(self) -> list[tuple[str, Path]]:
        """List of (username, path to NTUSER.DAT) for each user profile."""
        ...

    def get_user_class_hives(self) -> list[tuple[str, Path]]:
        """List of (username, path to UsrClass.dat) — needed for shellbags."""
        ...

    def get_evtx_files(self) -> dict[str, Path]:
        """Mapping of channel name (file stem) → path to .evtx file."""
        ...

    def get_setupapi_log(self) -> Path | None:
        """Path to Windows/INF/setupapi.dev.log."""
        ...

    def get_amcache_hive(self) -> Path | None:
        """Path to Amcache.hve."""
        ...

    def get_prefetch_dir(self) -> Path | None:
        """Path to Windows/Prefetch directory."""
        ...

    def get_recent_lnk_dirs(self) -> list[tuple[str, Path]]:
        """List of (username, path to Recent items directory) per user."""
        ...

    def get_search_db(self) -> Path | None:
        """Path to Windows.edb (Windows Search index)."""
        ...
