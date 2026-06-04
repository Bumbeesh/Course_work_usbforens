"""Parser for Microsoft-Windows-Kernel-PnP/Configuration events.

This channel records PnP CONFIGURATION events — driver install and device
start — for every device on the system. For USB Mass Storage we care about
two event IDs:

    400 — Device configured (driver newly installed for this device)
    410 — Device started (driver attached and device is ready)

NOTE on Event 430: in this channel, 430 means *"device requires further
installation"* — it is NOT a device removal/unplug event. Empirically, on
Win10/11 it commonly fires for SWD\\WPDBUSENUM child nodes that fail to
fully install (which is harmless for mass storage). It is deliberately NOT
emitted by this parser.

True unplug events live in a different channel — most commonly
`Microsoft-Windows-DriverFrameworks-UserMode/Operational` (events 2003 =
arrival, 2005 = removal), which is disabled by default on client Windows.

Device hierarchy and filtering: when a USB flash drive is plugged in,
Windows enumerates a PnP tree:

    USB\\VID_X&PID_Y\\<iSerial>              ← USB device
      USBSTOR\\Disk&Ven_X&Prod_Y&Rev_Z\\...   ← canonical storage device  (we keep this)
        STORAGE\\Volume\\_??_USBSTOR#...      ← volume layer              (skipped)
        SWD\\WPDBUSENUM\\_??_USBSTOR#...      ← WPD wrapper               (skipped)

Each layer fires its own 400/410 events. To produce one event per physical
plug-in, we filter to the canonical USBSTOR\\Disk root and skip the
STORAGE\\Volume and SWD\\WPDBUSENUM child nodes (their instance paths
contain "USBSTOR" as a substring but do not start with it).

The .evtx file lives at:
    Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Kernel-PnP%4Configuration.evtx
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from datetime import datetime, timezone

from Evtx.Evtx import Evtx

from ..core.enums import EventType, SourceKind, TimestampKind, TimestampPrecision
from ..core.models import DeviceRef, RawEvent
from ..sources.base import ArtifactSource

logger = logging.getLogger(__name__)


EVTX_CHANNEL_STEM = "Microsoft-Windows-Kernel-PnP%4Configuration"

# Standard XML namespace used by Windows event records
_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

# Mapping from EventID to (event_type, timestamp_kind).
# Event 430 ("device requires further installation") is deliberately omitted —
# see module docstring.
_EVENT_MAP: dict[int, tuple[EventType, TimestampKind]] = {
    400: (EventType.DEVICE_FIRST_INSTALL, TimestampKind.FIRST_INSTALL),
    410: (EventType.DEVICE_CONNECTED, TimestampKind.CONNECTION),
}

# Cheap pre-filter substrings — match either of our two EventIDs
_EVENT_ID_MARKERS = tuple(f">{eid}</EventID>" for eid in _EVENT_MAP)

# Identity regex — matches the same USBSTOR patterns as setupapi parser.
# Handles both backslash and hash separators.
_USBSTOR_PATH_RE = re.compile(
    r"USBSTOR[\\#]"
    r"Disk&Ven_(?P<vendor>[^\\#&]+)&Prod_(?P<product>[^\\#&]+)&Rev_(?P<rev>[^\\#&]+)"
    r"[\\#](?P<iserial_raw>[^\\#]+)"
)

# Field names that may carry the device instance path across PnP event versions
_INSTANCE_FIELD_NAMES = ("DeviceInstanceId", "DeviceInstancePath", "InstanceId")


class KernelPnpParser:
    """Parses Microsoft-Windows-Kernel-PnP/Configuration for USB plug/unplug events."""

    name = "kernel_pnp"

    def parse(self, source: ArtifactSource) -> Iterator[RawEvent]:
        evtx_files = source.get_evtx_files()
        evtx_path = evtx_files.get(EVTX_CHANNEL_STEM)
        if evtx_path is None:
            logger.warning(
                "%s.evtx not available; skipping kernel_pnp parser",
                EVTX_CHANNEL_STEM,
            )
            return

        logger.info("Parsing %s", evtx_path)
        evtx_path_str = str(evtx_path)

        total = 0
        matched = 0
        emitted = 0

        try:
            with Evtx(evtx_path_str) as log:
                for record in log.records():
                    total += 1
                    try:
                        xml_str = record.xml()
                    except Exception as exc:  # noqa: BLE001
                        logger.debug("Skipping record (xml decode failed): %s", exc)
                        continue

                    if not any(m in xml_str for m in _EVENT_ID_MARKERS):
                        continue
                    matched += 1

                    event = self._parse_record(xml_str, evtx_path_str)
                    if event is not None:
                        emitted += 1
                        yield event
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to parse EVTX file %s: %s", evtx_path, exc)
            return

        logger.info(
            "kernel_pnp: scanned %d records, %d matched 400/410, %d emitted "
            "(filtered to USBSTOR\\Disk root device only)",
            total,
            matched,
            emitted,
        )

    # ------------------------------------------------------------------

    def _parse_record(self, xml_str: str, source_path: str) -> RawEvent | None:
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError as exc:
            logger.debug("Could not parse record XML: %s", exc)
            return None

        system = root.find(f"{_NS}System")
        if system is None:
            return None

        # EventID with optional Qualifiers attribute
        event_id_elem = system.find(f"{_NS}EventID")
        if event_id_elem is None:
            return None
        try:
            event_id = int((event_id_elem.text or "").strip())
        except ValueError:
            return None

        mapping = _EVENT_MAP.get(event_id)
        if mapping is None:
            return None
        event_type, ts_kind = mapping

        # TimeCreated
        time_elem = system.find(f"{_NS}TimeCreated")
        if time_elem is None:
            return None
        ts = self._parse_systemtime(time_elem.get("SystemTime", ""))
        if ts is None:
            return None

        record_id_elem = system.find(f"{_NS}EventRecordID")
        record_id = record_id_elem.text if record_id_elem is not None else None

        # EventData — find a field that has the device instance path
        event_data = root.find(f"{_NS}EventData")
        if event_data is None:
            return None

        instance_id = ""
        data: dict[str, str] = {}
        for d in event_data.findall(f"{_NS}Data"):
            name = d.get("Name")
            value = (d.text or "").strip()
            if name:
                data[name] = value
                if name in _INSTANCE_FIELD_NAMES and not instance_id:
                    instance_id = value

        if not instance_id:
            return None

        # Filter to the canonical USBSTOR\Disk root device.
        # STORAGE\Volume\_??_USBSTOR#... and SWD\WPDBUSENUM\_??_USBSTOR#... contain
        # "USBSTOR" as a substring but represent child PnP nodes of the same
        # physical plug-in; we skip them to produce one event per physical event.
        if not instance_id.upper().startswith("USBSTOR\\DISK"):
            return None

        usbstor_match = _USBSTOR_PATH_RE.search(instance_id)
        if usbstor_match is None:
            return None

        iserial_raw = usbstor_match.group("iserial_raw")
        iserial = iserial_raw.split("&")[0].split("#")[0]

        vendor = _unescape(usbstor_match.group("vendor"))
        product = _unescape(usbstor_match.group("product"))
        revision = _unescape(usbstor_match.group("rev"))

        return RawEvent(
            ts=ts,
            ts_kind=ts_kind,
            ts_precision=TimestampPrecision.SECOND,
            source=SourceKind.EVTX_KERNEL_PNP,
            source_artifact=source_path,
            event_type=event_type,
            device_ref=DeviceRef(iserial=iserial),
            raw={
                "event_id": event_id,
                "device_instance_id": instance_id,
                "vendor": vendor,
                "product": product,
                "revision": revision,
                "driver_name": data.get("DriverName"),
                "class_guid": data.get("ClassGuid"),
                "event_record_id": record_id,
            },
        )

    @staticmethod
    def _parse_systemtime(ts_str: str) -> datetime | None:
        if not ts_str:
            return None
        normalized = ts_str.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(normalized)
        except ValueError:
            pass
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
            try:
                return datetime.strptime(normalized, fmt)
            except ValueError:
                continue
        logger.debug("Could not parse SystemTime %r", ts_str)
        return None


def _unescape(s: str) -> str:
    return s.replace("_", " ").strip()
