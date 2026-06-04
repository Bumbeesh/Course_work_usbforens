"""Parser for shellbags in UsrClass.dat.

    UsrClass.dat\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU

Explorer records, per user, every folder ever browsed as a tree of "shell item"
entries under BagMRU. Each node's numbered values hold the shell items of its
children; the matching numbered subkeys recurse into those children. Walking the
tree and concatenating the decoded item names reconstructs full browsed paths
such as `E:\\course\\bogdan\\Downloads`.

Unlike Recent shortcuts (which give a temporal hint), a shellbag under a volume
is *direct* evidence that the user navigated that folder. We emit one
FILE_IN_SHELLBAG RawEvent per folder/file entry that sits under a drive volume,
carrying the reconstructed path, the browsing user, and the node's last-write
time (≈ when the folder was last browsed). The correlation engine links an entry
to a device by matching its drive letter to one of the device's volumes.

Timestamp note: the node last-write time is a FILETIME (UTC). The FAT timestamps
embedded in each shell item (folder MAC) are LOCAL; we convert them to UTC the
same way (and with the same caveat) as the lnk parser.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from datetime import datetime, timezone

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.registry import RegistryHive

from ..core.enums import EventType, SourceKind, TimestampKind, TimestampPrecision
from ..core.models import FileRef, RawEvent, UserRef, VolumeRef
from ..sources.base import ArtifactSource
from ._registry_utils import normalize_timestamp
from ._shellbag_utils import parse_shell_item

logger = logging.getLogger(__name__)

BAGMRU_PATH = r"\Local Settings\Software\Microsoft\Windows\Shell\BagMRU"

_SKIP_VALUES = frozenset({"MRUListEx", "NodeSlot", "NodeSlots"})


class ShellbagsParser:
    """Parses each user's UsrClass.dat BagMRU into FILE_IN_SHELLBAG events."""

    name = "shellbags"

    def parse(self, source: ArtifactSource) -> Iterator[RawEvent]:
        class_hives = source.get_user_class_hives()
        if not class_hives:
            logger.warning("No UsrClass.dat hives found; skipping shellbags parser")
            return

        total = 0
        for username, hive_path in class_hives:
            count = 0
            for event in self._parse_hive(username, hive_path):
                count += 1
                yield event
            logger.info("shellbags [%s]: %d folder entries", username, count)
            total += count

        logger.info("shellbags: %d entries across users", total)

    def _parse_hive(self, username: str, hive_path) -> Iterator[RawEvent]:
        try:
            hive = RegistryHive(str(hive_path))
            root = hive.get_key(BAGMRU_PATH)
        except RegistryKeyNotFoundException:
            logger.debug("BagMRU not found in %s", hive_path)
            return
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not open UsrClass.dat %s: %s", hive_path, exc)
            return

        yield from self._walk(root, drive=None, parts=[], username=username,
                              hive_path=str(hive_path))

    def _walk(
        self, node, drive: str | None, parts: list[str], username: str, hive_path: str
    ) -> Iterator[RawEvent]:
        items = self._child_items(node)
        for name, sub in self._child_subkeys(node):
            data = items.get(name)
            if data is None:
                continue
            item = parse_shell_item(data)
            if item is None:
                continue

            new_drive, new_parts = drive, parts
            if item["kind"] == "volume":
                new_drive = item["name"]  # e.g. "E:"
                new_parts = []
            elif item["kind"] == "file" and item["name"]:
                new_parts = parts + [item["name"]]
                if new_drive:
                    yield self._build_event(
                        item, sub, new_drive, new_parts, username, hive_path
                    )
            # "root"/"other": no path component, just recurse

            yield from self._walk(sub, new_drive, new_parts, username, hive_path)

    def _build_event(self, item, sub, drive, parts, username, hive_path) -> RawEvent:
        full_path = drive + "\\" + "\\".join(parts)
        ts = normalize_timestamp(sub.header.last_modified)
        return RawEvent(
            ts=ts,
            ts_kind=TimestampKind.OBSERVED,  # node last-write ≈ last browsed
            ts_precision=TimestampPrecision.SECOND,
            source=SourceKind.SHELLBAG,
            source_artifact=hive_path,
            event_type=EventType.FILE_IN_SHELLBAG,
            file_ref=FileRef(path=full_path, name=item["name"]),
            volume_ref=VolumeRef(drive_letter=drive),
            user_ref=UserRef(username=username),
            raw={
                "short_name": item.get("short_name"),
                "long_name": item.get("long_name"),
                "folder_modified": _iso(_to_utc(item.get("modified"))),
                "folder_created": _iso(_to_utc(item.get("created"))),
                "folder_accessed": _iso(_to_utc(item.get("accessed"))),
            },
        )

    @staticmethod
    def _child_items(node) -> dict[str, bytes]:
        out: dict[str, bytes] = {}
        for v in node.iter_values(trim_values=False):
            if v.name in _SKIP_VALUES:
                continue
            out[v.name] = _coerce_bytes(v.value)
        return out

    @staticmethod
    def _child_subkeys(node):
        return [(s.name, s) for s in node.iter_subkeys() if s.name.isdigit()]


def _coerce_bytes(value) -> bytes:
    """regipy returns REG_BINARY as a hex string; normalize to raw bytes."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        try:
            return bytes.fromhex(value)
        except ValueError:
            return b""
    return b""


def _to_utc(dt: datetime | None) -> datetime | None:
    if not isinstance(dt, datetime):
        return None
    return dt.astimezone(timezone.utc)


def _iso(dt: datetime | None) -> str | None:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None
