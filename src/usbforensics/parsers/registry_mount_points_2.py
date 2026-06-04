"""Parser for per-user MountPoints2 in NTUSER.DAT.

    NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2

Windows records, per user, every volume mount point the user has accessed via
Explorer. The subkeys are:

    {GUID}              — a mounted volume, identified by its volume GUID. For a
                          USB Mass Storage device this is the same volume GUID
                          seen in SYSTEM\\MountedDevices (\\??\\Volume{GUID}).
    ##server#share      — a network share (not USB — skipped here)
    CPC, _??_...         — special / non-volume entries (skipped)

The subkey's last-write time approximates the *last* time that user mounted that
volume. This is the artifact that attributes a USB volume mount to a specific
user account — something the system-wide registry/EVTX sources cannot do.

We emit one VOLUME_USER_MOUNT RawEvent per volume-GUID subkey, carrying the
volume GUID and the username. The correlation engine links it to a device by
matching the volume GUID against that device's volumes.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.registry import RegistryHive

from ..core.enums import EventType, SourceKind, TimestampKind, TimestampPrecision
from ..core.models import RawEvent, UserRef, VolumeRef
from ..sources.base import ArtifactSource
from ._registry_utils import normalize_timestamp

logger = logging.getLogger(__name__)


MOUNTPOINTS2_PATH = (
    r"\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"
)

# A volume mount subkey is a bare volume GUID: {8-4-4-4-12}
_VOLUME_GUID_RE = re.compile(
    r"^\{[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}$"
)


class RegistryMountPoints2Parser:
    """Parses each user's NTUSER.DAT MountPoints2 for volume mounts."""

    name = "registry_mount_points_2"

    def parse(self, source: ArtifactSource) -> Iterator[RawEvent]:
        user_hives = source.get_user_hives()
        if not user_hives:
            logger.warning("No NTUSER.DAT hives found; skipping mount_points_2 parser")
            return

        total = 0
        for username, hive_path in user_hives:
            count = 0
            for event in self._parse_hive(username, hive_path):
                count += 1
                yield event
            logger.info("MountPoints2 [%s]: %d volume mount(s)", username, count)
            total += count

        logger.info("registry_mount_points_2: %d volume mount(s) across users", total)

    def _parse_hive(self, username: str, hive_path) -> Iterator[RawEvent]:
        try:
            hive = RegistryHive(str(hive_path))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not open NTUSER.DAT %s: %s", hive_path, exc)
            return

        try:
            key = hive.get_key(MOUNTPOINTS2_PATH)
        except RegistryKeyNotFoundException:
            logger.debug("MountPoints2 not found in %s", hive_path)
            return

        for sub in key.iter_subkeys():
            name = sub.name
            if not _VOLUME_GUID_RE.match(name):
                logger.debug("Skipping non-volume MountPoints2 subkey: %s", name)
                continue

            ts = normalize_timestamp(sub.header.last_modified)
            if ts is None:
                continue

            yield RawEvent(
                ts=ts,
                ts_kind=TimestampKind.OBSERVED,
                ts_precision=TimestampPrecision.SECOND,
                source=SourceKind.REGISTRY_MOUNT_POINTS_2,
                source_artifact=str(hive_path),
                event_type=EventType.VOLUME_USER_MOUNT,
                volume_ref=VolumeRef(volume_guid=name),
                user_ref=UserRef(username=username),
                raw={"mount_point": name, "username": username},
            )
