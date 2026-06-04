"""Parser for SYSTEM\\MountedDevices.

MountedDevices is a single registry key whose values bind a mount point to the
storage device that backed it at the time the binding was last written:

    \\DosDevices\\E:            -> binary "unique id" of whatever was E: last
    \\??\\Volume{GUID}          -> binary "unique id" of that volume mount point

The binary "unique id" comes in two shapes relevant to USB Mass Storage:

1. UTF-16LE device instance string (typical for removable devices), e.g.:
       _??_USBSTOR#Disk&Ven_General&Prod_UDisk&Rev_5.00#2307301544295453676514&0#{53f5...}
   This is the gold bridge: it ties a drive letter / volume GUID *directly* to a
   USBSTOR iSerial with no further correlation needed.

2. 12-byte MBR binding: 4-byte NT disk signature + 8-byte partition start offset
   (both little-endian). No iSerial is embedded; it can only be linked to a device
   by matching the disk signature against other artifacts — deferred to the
   correlation layer. We still emit it so that bridge is available downstream.

Caveats:
- MountedDevices keeps only the *last* binding for each \\DosDevices\\X: letter.
  A letter reused across devices reflects only the most recent one. The
  \\??\\Volume{GUID} entries are more stable (one per volume ever mounted).
- Individual values are not timestamped; only the parent key carries a last-write
  time. All emitted events use that as an OBSERVED timestamp.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.registry import RegistryHive

from ..core.enums import EventType, SourceKind, TimestampKind, TimestampPrecision
from ..core.models import DeviceRef, RawEvent, VolumeRef
from ..sources.base import ArtifactSource
from ._registry_utils import normalize_timestamp

logger = logging.getLogger(__name__)


MOUNTED_DEVICES_PATH = r"\MountedDevices"

# Value-name classification
_DOSDEV_RE = re.compile(r"^\\DosDevices\\(?P<letter>[A-Za-z]:)$")
_VOLUME_RE = re.compile(r"^\\\?\?\\Volume(?P<guid>\{[0-9A-Fa-f-]+\})$")

# USBSTOR instance string embedded in a UTF-16LE "unique id" blob.
# Same identity shape as setupapi / kernel_pnp, but '#'-separated.
_USBSTOR_BIN_RE = re.compile(
    r"USBSTOR#"
    r"Disk&Ven_(?P<vendor>[^#&]+)&Prod_(?P<product>[^#&]+)&Rev_(?P<rev>[^#&]+)"
    r"#(?P<iserial_raw>[^#]+)"
)


class RegistryMountedDevicesParser:
    """Parses SYSTEM\\MountedDevices for volume / drive-letter -> device bindings."""

    name = "registry_mounted_devices"

    def parse(self, source: ArtifactSource) -> Iterator[RawEvent]:
        hive_path = source.get_system_hive()
        if hive_path is None:
            logger.warning("SYSTEM hive not available; skipping registry_mounted_devices")
            return

        logger.info("Parsing MountedDevices in %s", hive_path)
        hive = RegistryHive(str(hive_path))
        hive_path_str = str(hive_path)

        try:
            key = hive.get_key(MOUNTED_DEVICES_PATH)
        except RegistryKeyNotFoundException:
            logger.warning("MountedDevices key not found (%s)", MOUNTED_DEVICES_PATH)
            return

        key_ts = normalize_timestamp(key.header.last_modified)

        usb_bindings = 0
        other_bindings = 0
        # trim_values=False is critical: regipy's default (True) hexlifies REG_BINARY
        # and truncates it to MAX_LEN (128 bytes), which silently cuts long device
        # instance strings mid-iSerial. With False we get the full raw bytes.
        for value in key.iter_values(trim_values=False):
            name = value.name
            data = _coerce_bytes(value.value)

            mount = _classify_mount_point(name)
            if mount is None:
                logger.debug("Unrecognized MountedDevices value name: %r", name)
                continue
            kind, drive_letter, volume_guid = mount

            decoded = _decode_unique_id(data)
            logger.debug(
                "MountedDevices %s (len=%d) -> %s", name, len(data), decoded.get("kind")
            )

            volume_ref = VolumeRef(drive_letter=drive_letter, volume_guid=volume_guid)
            raw_common = {
                "mount_point": name,
                "mount_point_kind": kind,
                "unique_id_kind": decoded.get("kind"),
                "unique_id_len": len(data),
            }

            if decoded["kind"] == "usbstor":
                usb_bindings += 1
                yield RawEvent(
                    ts=key_ts,
                    ts_kind=TimestampKind.OBSERVED,
                    ts_precision=TimestampPrecision.SECOND,
                    source=SourceKind.REGISTRY_MOUNTED_DEVICES,
                    source_artifact=hive_path_str,
                    event_type=EventType.VOLUME_ASSIGNED_LETTER,
                    device_ref=DeviceRef(iserial=decoded["iserial"]),
                    volume_ref=volume_ref,
                    raw={
                        **raw_common,
                        "vendor": decoded["vendor"],
                        "product": decoded["product"],
                        "revision": decoded["revision"],
                        "device_instance": decoded["device_instance"],
                    },
                )
            else:
                # MBR signature binding or unrecognized blob: no iSerial, but the
                # volume binding is still worth emitting for the correlation layer.
                other_bindings += 1
                yield RawEvent(
                    ts=key_ts,
                    ts_kind=TimestampKind.OBSERVED,
                    ts_precision=TimestampPrecision.SECOND,
                    source=SourceKind.REGISTRY_MOUNTED_DEVICES,
                    source_artifact=hive_path_str,
                    event_type=EventType.VOLUME_ASSIGNED_LETTER,
                    device_ref=None,
                    volume_ref=volume_ref,
                    raw={
                        **raw_common,
                        "disk_signature": decoded.get("disk_signature"),
                        "partition_offset": decoded.get("partition_offset"),
                    },
                )

        logger.info(
            "MountedDevices: %d USBSTOR bindings, %d other/MBR bindings",
            usb_bindings,
            other_bindings,
        )


# ----------------------------------------------------------------------------
# Pure helpers (module-level for unit testing without a hive fixture)
# ----------------------------------------------------------------------------


def _classify_mount_point(name: str) -> tuple[str, str | None, str | None] | None:
    """Classify a MountedDevices value name.

    Returns (kind, drive_letter, volume_guid) or None if the name is neither a
    DOS drive-letter nor a volume mount point.
    """
    m = _DOSDEV_RE.match(name)
    if m:
        return ("drive_letter", m.group("letter"), None)
    m = _VOLUME_RE.match(name)
    if m:
        return ("volume_guid", None, m.group("guid"))
    return None


def _coerce_bytes(value) -> bytes:
    """Normalize a regipy REG_BINARY value to raw bytes.

    regipy returns REG_BINARY as a hex *string* (e.g. "5f003f00..."), not bytes.
    Accept that, raw bytes, or bytearray; anything else yields empty bytes.
    """
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        try:
            return bytes.fromhex(value.strip().replace(" ", ""))
        except ValueError:
            return b""
    return b""


def _decode_unique_id(data: bytes) -> dict:
    """Decode a MountedDevices "unique id" blob.

    Recognizes:
        - UTF-16LE device instance strings containing a USBSTOR component
        - 12-byte MBR bindings (4-byte disk signature + 8-byte partition offset)
    Anything else is returned as kind="unknown".
    """
    # Attempt UTF-16LE text decode (USBSTOR / volume device instance strings)
    text = data.decode("utf-16-le", errors="ignore").rstrip("\x00")
    if "USBSTOR" in text:
        m = _USBSTOR_BIN_RE.search(text)
        if m:
            iserial = m.group("iserial_raw").split("&")[0].split("#")[0]
            return {
                "kind": "usbstor",
                "iserial": iserial,
                "vendor": _unescape(m.group("vendor")),
                "product": _unescape(m.group("product")),
                "revision": _unescape(m.group("rev")),
                "device_instance": text,
            }

    # 12-byte MBR binding: 4-byte signature (LE) + 8-byte partition offset (LE)
    if len(data) == 12:
        return {
            "kind": "mbr",
            "disk_signature": data[:4].hex(),
            "partition_offset": int.from_bytes(data[4:12], "little"),
        }

    return {"kind": "unknown"}


def _unescape(s: str) -> str:
    """USBSTOR strings use underscores in place of spaces from the SCSI inquiry."""
    return s.replace("_", " ").strip()
