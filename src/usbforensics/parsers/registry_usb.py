"""Parser for USB Mass Storage device data in the SYSTEM hive.

Reads two parallel registry subtrees:

1. \\ControlSet00X\\Enum\\USB\\VID_xxxx&PID_yyyy\\<iSerial>
       Authoritative VID, PID, iSerial.

2. \\ControlSet00X\\Enum\\USBSTOR\\Disk&Ven_X&Prod_Y&Rev_Z\\<iSerial>&0
       Identity: vendor/product/revision strings, FriendlyName, ContainerID, etc.
       Timestamps: under Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\<pid>:
           0064 = DEVPKEY_Device_InstallDate      (last install/reinstall)
           0065 = DEVPKEY_Device_FirstInstallDate (first ever install)
           0066 = DEVPKEY_Device_LastArrivalDate  (last plug-in)
           0067 = DEVPKEY_Device_LastRemovalDate  (last unplug)

The two subtrees are joined by iSerial to produce a coherent DeviceRef
with full VID/PID/iSerial identity. The active ControlSet number is resolved
dynamically via \\Select\\Current.

Emitted RawEvents per USBSTOR instance:
    DEVICE_SEEN           — registry key last-write time (OBSERVED kind)
    DEVICE_FIRST_INSTALL  — from Properties pid 0064 and/or 0065
    DEVICE_LAST_ARRIVAL   — from Properties pid 0066
    DEVICE_LAST_REMOVAL   — from Properties pid 0067
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from datetime import datetime

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.registry import RegistryHive

from ..core.enums import EventType, SourceKind, TimestampKind, TimestampPrecision
from ..core.models import DeviceRef, RawEvent
from ..sources.base import ArtifactSource
from ._registry_utils import find_subkey, normalize_timestamp, resolve_current_control_set

logger = logging.getLogger(__name__)


USBSTOR_CLASS_RE = re.compile(
    r"^Disk&Ven_(?P<vendor>[^&]+)&Prod_(?P<product>[^&]+)&Rev_(?P<rev>[^&]+)$"
)

USB_VIDPID_RE = re.compile(r"^VID_(?P<vid>[0-9A-Fa-f]{4})&PID_(?P<pid>[0-9A-Fa-f]{4})$")


# DEVPROPKEY fmtid grouping device install/arrival/removal timestamps.
# This GUID and the pid values below are Microsoft-defined constants stable
# across Windows 10/11.
TIMESTAMPS_FMTID = "{83da6326-97a6-4088-9453-a1923f573b29}"

# Mapping from on-disk pid (4-digit hex) to (event_type, timestamp_kind).
# 0064 and 0065 both indicate installation; 0064 may be updated on reinstall
# while 0065 is the original first install. We tag both as FIRST_INSTALL and
# let the aggregation layer pick the earliest.
PROPERTY_MAP: dict[str, tuple[EventType, TimestampKind]] = {
    "0064": (EventType.DEVICE_FIRST_INSTALL, TimestampKind.FIRST_INSTALL),
    "0065": (EventType.DEVICE_FIRST_INSTALL, TimestampKind.FIRST_INSTALL),
    "0066": (EventType.DEVICE_LAST_ARRIVAL, TimestampKind.LAST_ARRIVAL),
    "0067": (EventType.DEVICE_LAST_REMOVAL, TimestampKind.LAST_REMOVAL),
}


class RegistryUsbParser:
    """Parses Enum\\USB and Enum\\USBSTOR (with its Properties subtree)."""

    name = "registry_usb"

    def parse(self, source: ArtifactSource) -> Iterator[RawEvent]:
        hive_path = source.get_system_hive()
        if hive_path is None:
            logger.warning("SYSTEM hive not available; skipping registry_usb parser")
            return

        logger.info("Parsing SYSTEM hive: %s", hive_path)
        hive = RegistryHive(str(hive_path))
        hive_path_str = str(hive_path)

        cs_number = resolve_current_control_set(hive)
        logger.info("Active control set: ControlSet%03d", cs_number)
        usb_path = rf"\ControlSet{cs_number:03d}\Enum\USB"
        usbstor_path = rf"\ControlSet{cs_number:03d}\Enum\USBSTOR"

        usb_index = self._index_usb_devices(hive, usb_path)
        logger.info("Indexed %d devices from USB key", len(usb_index))

        seen = 0
        ts_events = 0
        for event in self._iter_usbstor_events(hive, hive_path_str, usbstor_path, usb_index):
            if event.event_type == EventType.DEVICE_SEEN:
                seen += 1
            else:
                ts_events += 1
            yield event

        logger.info(
            "USBSTOR: %d instances (DEVICE_SEEN events), %d timestamp events",
            seen,
            ts_events,
        )

    # ------------------------------------------------------------------
    # USB\VID_xxxx&PID_yyyy\<iSerial>  →  iSerial → (VID, PID)
    # ------------------------------------------------------------------

    def _index_usb_devices(self, hive: RegistryHive, usb_path: str) -> dict[str, "_UsbInfo"]:
        out: dict[str, _UsbInfo] = {}
        try:
            usb_key = hive.get_key(usb_path)
        except RegistryKeyNotFoundException:
            logger.warning("USB enum key not found (%s)", usb_path)
            return out

        for vidpid_subkey in usb_key.iter_subkeys():
            m = USB_VIDPID_RE.match(vidpid_subkey.name)
            if not m:
                continue
            vid, pid = m.group("vid").upper(), m.group("pid").upper()
            for iserial_subkey in vidpid_subkey.iter_subkeys():
                iserial = iserial_subkey.name
                ts = normalize_timestamp(iserial_subkey.header.last_modified)
                out[iserial] = _UsbInfo(vid=vid, pid=pid, last_write=ts)
        return out

    # ------------------------------------------------------------------
    # USBSTOR walk: emit DEVICE_SEEN + timestamps from Properties
    # ------------------------------------------------------------------

    def _iter_usbstor_events(
        self,
        hive: RegistryHive,
        hive_path: str,
        usbstor_path: str,
        usb_index: dict[str, "_UsbInfo"],
    ) -> Iterator[RawEvent]:
        try:
            usbstor_key = hive.get_key(usbstor_path)
        except RegistryKeyNotFoundException:
            logger.warning("USBSTOR key not found (%s)", usbstor_path)
            return

        for class_subkey in usbstor_key.iter_subkeys():
            class_match = USBSTOR_CLASS_RE.match(class_subkey.name)
            if not class_match:
                logger.debug("Unrecognized USBSTOR class key: %s", class_subkey.name)
                continue

            vendor = _unescape(class_match.group("vendor"))
            product = _unescape(class_match.group("product"))
            revision = _unescape(class_match.group("rev"))

            for inst_subkey in class_subkey.iter_subkeys():
                inst_name = inst_subkey.name
                iserial = inst_name.split("&")[0] if "&" in inst_name else inst_name

                friendly_name = _get_value(inst_subkey, "FriendlyName")
                container_id = _get_value(inst_subkey, "ContainerID")

                usb_info = usb_index.get(iserial)
                device_ref = DeviceRef(
                    vid=usb_info.vid if usb_info else None,
                    pid=usb_info.pid if usb_info else None,
                    iserial=iserial,
                )

                raw_common = {
                    "vendor": vendor,
                    "product": product,
                    "revision": revision,
                    "friendly_name": friendly_name,
                    "container_id": container_id,
                    "instance_key": inst_name,
                    "class_key": class_subkey.name,
                    "joined_with_usb_key": usb_info is not None,
                }

                # ---- DEVICE_SEEN from the instance key last-write time ----
                last_write = normalize_timestamp(inst_subkey.header.last_modified)
                if last_write is not None:
                    yield RawEvent(
                        ts=last_write,
                        ts_kind=TimestampKind.OBSERVED,
                        ts_precision=TimestampPrecision.SECOND,
                        source=SourceKind.REGISTRY_USBSTOR,
                        source_artifact=hive_path,
                        event_type=EventType.DEVICE_SEEN,
                        device_ref=device_ref,
                        raw=raw_common,
                    )

                # ---- Timestamp events from Properties\{83da6326-...}\<pid> ----
                yield from self._iter_property_timestamps(
                    inst_subkey, hive_path, device_ref, raw_common
                )

    @staticmethod
    def _iter_property_timestamps(
        instance_key,
        hive_path: str,
        device_ref: DeviceRef,
        raw_common: dict,
    ) -> Iterator[RawEvent]:
        """Walk Properties\\<TIMESTAMPS_FMTID>\\<pid> and emit RawEvents per pid."""
        props_key = find_subkey(instance_key, "Properties")
        if props_key is None:
            return

        fmtid_key = find_subkey(props_key, TIMESTAMPS_FMTID)
        if fmtid_key is None:
            return

        for pid_subkey in fmtid_key.iter_subkeys():
            mapping = PROPERTY_MAP.get(pid_subkey.name)
            if mapping is None:
                continue
            event_type, ts_kind = mapping

            ts = _read_filetime_value(pid_subkey)
            if ts is None:
                continue

            yield RawEvent(
                ts=ts,
                ts_kind=ts_kind,
                ts_precision=TimestampPrecision.SECOND,
                source=SourceKind.REGISTRY_USBSTOR,
                source_artifact=hive_path,
                event_type=event_type,
                device_ref=device_ref,
                raw={**raw_common, "property_pid": pid_subkey.name},
            )


# ----------------------------------------------------------------------------
# Helpers local to this parser
# ----------------------------------------------------------------------------


class _UsbInfo:
    __slots__ = ("vid", "pid", "last_write")

    def __init__(self, vid: str, pid: str, last_write) -> None:
        self.vid = vid
        self.pid = pid
        self.last_write = last_write


def _get_value(key, name: str) -> str | None:
    try:
        for v in key.iter_values():
            if v.name == name:
                return str(v.value) if v.value is not None else None
    except Exception as exc:  # noqa: BLE001
        logger.debug("Could not read values from %s: %s", key.name, exc)
    return None


def _read_filetime_value(key) -> datetime | None:
    """Find the first usable timestamp value in `key` and return it as UTC."""
    try:
        for v in key.iter_values():
            ts = normalize_timestamp(v.value)
            if ts is not None:
                return ts
    except Exception as exc:  # noqa: BLE001
        logger.debug("Error reading values of %s: %s", key.name, exc)
    return None


def _unescape(s: str) -> str:
    """USBSTOR strings have underscores in place of spaces from SCSI inquiry."""
    return s.replace("_", " ").strip()
