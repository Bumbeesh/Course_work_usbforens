"""Parser for Windows shortcut (.lnk) files in a user's Recent folder.

Windows auto-creates a .lnk under
    Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\
each time the user opens a file via Explorer. Each shortcut embeds the target's
path, size, and MAC timestamps, and — when the target lived on a non-fixed
volume — a volume block with the drive type, volume serial number (VSN) and
volume label.

This parser emits one FILE_ACCESSED RawEvent per shortcut, carrying whatever the
shortcut records. It deliberately does NOT decide whether the file relates to a
USB device — that is the correlation layer's job, which links a file event to a
connection session either directly (target on a removable volume / VSN matches a
device volume) or by temporal overlap (the file timestamp falls inside a session
window).

Timestamp note: the timestamps embedded in a .lnk are FILETIME (UTC). pylnk3
surfaces them as naive *local* datetimes (converted using the analyst machine's
timezone). We convert back to UTC by treating the naive value as local — correct
only when the analyst and source machines share a timezone (same caveat as the
setupapi parser). The .lnk file's own filesystem MAC times are intentionally
ignored: artifact extraction (a plain copy) resets them to the extraction time.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

from ..core.enums import EventType, SourceKind, TimestampKind, TimestampPrecision
from ..core.models import FileRef, RawEvent, UserRef, VolumeRef
from ..sources.base import ArtifactSource

logger = logging.getLogger(__name__)

try:
    import pylnk3
except ImportError:  # optional dependency (extra "lnk")
    pylnk3 = None


# DRIVE_TYPE values from the LNK VolumeID structure (and pylnk3's string forms)
_REMOVABLE_DRIVE_TYPES = frozenset({2, "DRIVE_REMOVABLE", "Removable"})


class LnkParser:
    """Parses Recent\\*.lnk shortcuts into FILE_ACCESSED events."""

    name = "lnk"

    def parse(self, source: ArtifactSource) -> Iterator[RawEvent]:
        if pylnk3 is None:
            logger.warning(
                "pylnk3 not installed; skipping lnk parser (install extra 'lnk')"
            )
            return

        recent_dirs = source.get_recent_lnk_dirs()
        if not recent_dirs:
            logger.warning("No Recent folders found; skipping lnk parser")
            return

        total = emitted = 0
        for username, recent in recent_dirs:
            for lnk_path in sorted(recent.glob("*.lnk")):
                total += 1
                try:
                    lnk = pylnk3.parse(str(lnk_path))
                except Exception as exc:  # noqa: BLE001
                    logger.debug("Could not parse %s: %s", lnk_path.name, exc)
                    continue
                event = self._build_event(lnk, lnk_path, username)
                if event is not None:
                    emitted += 1
                    yield event

        logger.info("lnk: scanned %d shortcuts, %d emitted", total, emitted)

    def _build_event(self, lnk, lnk_path: Path, username: str) -> RawEvent | None:
        target = (
            _get(lnk, "path")
            or _get(lnk, "local_base_path")
            or _get(lnk, "relative_path")
        )
        if not target:
            return None

        ts = (
            _to_utc(_get(lnk, "modification_time"))
            or _to_utc(_get(lnk, "creation_time"))
            or _to_utc(_get(lnk, "access_time"))
        )
        if ts is None:
            return None  # no usable embedded timestamp

        drive_type = _get(lnk, "drive_type")
        vsn = _get(lnk, "drive_serial_number")
        label = _get(lnk, "volume_label")
        drive_letter = target[:2] if len(target) >= 2 and target[1] == ":" else None

        file_ref = FileRef(
            path=target,
            name=_basename(target),
            size=_get(lnk, "file_size") or None,
        )

        volume_ref = None
        if vsn or label or drive_type in _REMOVABLE_DRIVE_TYPES:
            volume_ref = VolumeRef(
                vsn=_fmt_vsn(vsn),
                drive_letter=drive_letter,
                label=label or None,
            )

        return RawEvent(
            ts=ts,
            ts_kind=TimestampKind.MTIME,
            ts_precision=TimestampPrecision.SECOND,
            source=SourceKind.LNK,
            source_artifact=str(lnk_path),
            event_type=EventType.FILE_ACCESSED,
            file_ref=file_ref,
            volume_ref=volume_ref,
            user_ref=UserRef(username=username),
            raw={
                "lnk_name": lnk_path.name,
                "drive_type": str(drive_type) if drive_type is not None else None,
                "drive_serial_number": _fmt_vsn(vsn),
                "volume_label": label or None,
                "local_base_path": _get(lnk, "local_base_path"),
                "relative_path": _get(lnk, "relative_path"),
                "working_dir": _get(lnk, "working_dir"),
                "target_modified": _iso(_to_utc(_get(lnk, "modification_time"))),
                "target_created": _iso(_to_utc(_get(lnk, "creation_time"))),
                "target_accessed": _iso(_to_utc(_get(lnk, "access_time"))),
                "removable": drive_type in _REMOVABLE_DRIVE_TYPES,
            },
        )


# ----------------------------------------------------------------------------
# Pure helpers (module-level for unit testing without a .lnk fixture)
# ----------------------------------------------------------------------------


def _get(lnk, attr):
    """Read an attribute from a pylnk3 object, swallowing access errors."""
    try:
        return getattr(lnk, attr, None)
    except Exception:  # noqa: BLE001 — pylnk3 raises on absent structures
        return None


def _to_utc(dt: datetime | None) -> datetime | None:
    """Normalize a pylnk3 datetime to UTC-aware.

    pylnk3 yields naive local datetimes; treat naive as local and convert. Aware
    datetimes are converted to UTC directly.
    """
    if not isinstance(dt, datetime):
        return None
    # A zero/epoch time means "not set": the FILETIME epoch (1601) or the FAT/DOS
    # epoch (1980) both appear for unset target timestamps. USB Mass Storage
    # predates neither, so anything before 1990 is treated as absent.
    if dt.year < 1990:
        return None
    return dt.astimezone(timezone.utc)


def _iso(dt: datetime | None) -> str | None:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


def _fmt_vsn(vsn) -> str | None:
    """Format a 32-bit volume serial number as 'XXXX-XXXX' (uppercase hex)."""
    if vsn in (None, 0, ""):
        return None
    try:
        n = int(vsn)
    except (TypeError, ValueError):
        return str(vsn)
    return f"{(n >> 16) & 0xFFFF:04X}-{n & 0xFFFF:04X}"


def _basename(path: str) -> str:
    return path.replace("/", "\\").rstrip("\\").split("\\")[-1]
