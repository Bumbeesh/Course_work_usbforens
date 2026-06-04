"""Reads artifacts from a regular filesystem path.

Used for:
- mounted disks attached as secondary drives (E:\\, F:\\)
- mounted disk images (Arsenal Image Mounter etc.)
- KAPE-style extracted artifact directories that preserve Windows paths

Expects a standard Windows layout under the provided root:
    <root>/Windows/System32/config/SYSTEM, SOFTWARE
    <root>/Windows/System32/winevt/Logs/*.evtx
    <root>/Windows/INF/setupapi.dev.log
    <root>/Windows/AppCompat/Programs/Amcache.hve
    <root>/Windows/Prefetch/*.pf
    <root>/Users/<name>/NTUSER.DAT
    <root>/Users/<name>/AppData/Local/Microsoft/Windows/UsrClass.dat
    <root>/Users/<name>/AppData/Roaming/Microsoft/Windows/Recent/*.lnk
    <root>/ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.edb
"""

from __future__ import annotations

import logging
from pathlib import Path

from .base import ArtifactSource

logger = logging.getLogger(__name__)

_SKIP_PROFILE_NAMES = frozenset(
    {"Default", "Default User", "Public", "All Users", "DefaultAppPool", "WDAGUtilityAccount"}
)


class MountedDriveSource(ArtifactSource):
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        if not self.root.exists():
            raise ValueError(f"Root path does not exist: {self.root}")
        if not self.root.is_dir():
            raise ValueError(f"Root path is not a directory: {self.root}")

    # ----- registry hives -----

    def get_system_hive(self) -> Path | None:
        return self._exists(self.root / "Windows" / "System32" / "config" / "SYSTEM")

    def get_software_hive(self) -> Path | None:
        return self._exists(self.root / "Windows" / "System32" / "config" / "SOFTWARE")

    def get_user_hives(self) -> list[tuple[str, Path]]:
        return self._collect_user_files("NTUSER.DAT")

    def get_user_class_hives(self) -> list[tuple[str, Path]]:
        return self._collect_user_files(
            "AppData/Local/Microsoft/Windows/UsrClass.dat"
        )

    # ----- event logs -----

    def get_evtx_files(self) -> dict[str, Path]:
        evtx_dir = self.root / "Windows" / "System32" / "winevt" / "Logs"
        if not evtx_dir.exists():
            return {}
        return {p.stem: p for p in evtx_dir.glob("*.evtx")}

    # ----- text logs -----

    def get_setupapi_log(self) -> Path | None:
        return self._exists(self.root / "Windows" / "INF" / "setupapi.dev.log")

    # ----- AmCache, Prefetch -----

    def get_amcache_hive(self) -> Path | None:
        return self._exists(
            self.root / "Windows" / "AppCompat" / "Programs" / "Amcache.hve"
        )

    def get_prefetch_dir(self) -> Path | None:
        d = self.root / "Windows" / "Prefetch"
        return d if d.is_dir() else None

    # ----- per-user user-activity artifacts -----

    def get_recent_lnk_dirs(self) -> list[tuple[str, Path]]:
        users_dir = self.root / "Users"
        if not users_dir.exists():
            return []
        result = []
        for user_dir in users_dir.iterdir():
            if not self._is_real_user(user_dir):
                continue
            recent = user_dir / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent"
            if recent.is_dir():
                result.append((user_dir.name, recent))
        return result

    # ----- search index -----

    def get_search_db(self) -> Path | None:
        return self._exists(
            self.root
            / "ProgramData"
            / "Microsoft"
            / "Search"
            / "Data"
            / "Applications"
            / "Windows"
            / "Windows.edb"
        )

    # ----- helpers -----

    @staticmethod
    def _exists(p: Path) -> Path | None:
        return p if p.exists() else None

    @staticmethod
    def _is_real_user(user_dir: Path) -> bool:
        return user_dir.is_dir() and user_dir.name not in _SKIP_PROFILE_NAMES

    def _collect_user_files(self, relative: str) -> list[tuple[str, Path]]:
        users_dir = self.root / "Users"
        if not users_dir.exists():
            return []
        result = []
        for user_dir in users_dir.iterdir():
            if not self._is_real_user(user_dir):
                continue
            candidate = user_dir / relative
            if candidate.exists():
                result.append((user_dir.name, candidate))
            else:
                logger.debug("No %s for user %s", relative, user_dir.name)
        return result
