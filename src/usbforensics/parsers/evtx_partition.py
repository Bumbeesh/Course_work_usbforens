"""Parser for Microsoft-Windows-Partition/Diagnostic.evtx event 1006.

Event 1006 is logged by Windows every time a partitioned storage device is
connected (USB Mass Storage, SD card, eSATA, etc.). For USB devices specifically,
the event payload contains:

    TimeCreated      — UTC timestamp of the physical connection
    Manufacturer     — USB device's manufacturer string
    Model            — device's product string
    Revision         — device's revision string
    SerialNumber     — iSerial of the device
    ParentId         — USB\\VID_xxxx&PID_yyyy\\iSerial path
    DiskId           — Volume GUID assigned to this connection
    Capacity         — size in bytes
    DiskNumber       — disk number assigned at this connection
    PartitionCount   — number of partitions detected
    + per-partition data tables

This is the primary source for building a full connection-history timeline of
USB Mass Storage devices. Unlike registry-based timestamps (which only retain
the *last* arrival/removal), the event log preserves *every* connection until
the log rotates.

The .evtx file lives at:
    Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Partition%4Diagnostic.evtx
(the %4 is Windows' percent-encoding of '/' in the channel name)
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


EVTX_CHANNEL_STEM = "Microsoft-Windows-Partition%4Diagnostic"
TARGET_EVENT_ID = 1006

# Standard XML namespace used by Windows event records
_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

# Quick byte-level pre-filter to avoid full XML parse on non-1006 records.
# Windows can emit EventID with optional attributes:
#   <EventID>1006</EventID>
#   <EventID Qualifiers="0">1006</EventID>
# Both contain the substring `>1006</EventID>`, which is what we test for.
_EVENT_ID_MARKER = f">{TARGET_EVENT_ID}</EventID>"

# ParentId extracts VID/PID/iSerial from the USB enumeration path
# Example: "USB\VID_ABCD&PID_1234\2307301544295453676514"
_PARENT_ID_RE = re.compile(
    r"USB\\VID_(?P<vid>[0-9A-Fa-f]{4})&PID_(?P<pid>[0-9A-Fa-f]{4})\\(?P<iserial>[^\\]+)"
)


class EvtxPartitionParser:
    """Parses Microsoft-Windows-Partition/Diagnostic.evtx for USB connection events."""

    name = "evtx_partition"

    def parse(self, source: ArtifactSource) -> Iterator[RawEvent]:
        evtx_files = source.get_evtx_files()
        evtx_path = evtx_files.get(EVTX_CHANNEL_STEM)
        if evtx_path is None:
            logger.warning(
                "%s.evtx not available; skipping evtx_partition parser",
                EVTX_CHANNEL_STEM,
            )
            return

        logger.info("Parsing %s", evtx_path)
        evtx_path_str = str(evtx_path)

        total_records = 0
        matched_records = 0
        emitted = 0

        try:
            with Evtx(evtx_path_str) as log:
                for record in log.records():
                    total_records += 1
                    try:
                        xml_str = record.xml()
                    except Exception as exc:  # noqa: BLE001
                        logger.debug("Skipping record (xml decode failed): %s", exc)
                        continue

                    # Cheap pre-filter
                    if _EVENT_ID_MARKER not in xml_str:
                        continue
                    matched_records += 1

                    event = self._parse_record(xml_str, evtx_path_str)
                    if event is not None:
                        emitted += 1
                        yield event
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to parse EVTX file %s: %s", evtx_path, exc)
            return

        logger.info(
            "evtx_partition: scanned %d records, %d matched EventID %d, %d emitted",
            total_records,
            matched_records,
            TARGET_EVENT_ID,
            emitted,
        )

    # ------------------------------------------------------------------

    def _parse_record(self, xml_str: str, source_path: str) -> RawEvent | None:
        """Convert a single 1006 record's XML into a RawEvent.

        Returns None if the record doesn't look like a USB-attached device
        (e.g., it could be SATA or some other partitioned storage).
        """
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError as exc:
            logger.debug("Could not parse record XML: %s", exc)
            return None

        system = root.find(f"{_NS}System")
        if system is None:
            return None

        # Belt-and-suspenders: the marker-string check already filtered most
        # non-1006 records, but a precise check guards against XML quirks.
        event_id_elem = system.find(f"{_NS}EventID")
        if event_id_elem is None or (event_id_elem.text or "").strip() != str(TARGET_EVENT_ID):
            return None

        # TimeCreated
        time_elem = system.find(f"{_NS}TimeCreated")
        if time_elem is None:
            return None
        ts = self._parse_systemtime(time_elem.get("SystemTime", ""))
        if ts is None:
            return None

        # EventRecordID (for traceability)
        record_id_elem = system.find(f"{_NS}EventRecordID")
        record_id = record_id_elem.text if record_id_elem is not None else None

        # EventData
        event_data = root.find(f"{_NS}EventData")
        if event_data is None:
            return None

        data: dict[str, str] = {}
        for d in event_data.findall(f"{_NS}Data"):
            name = d.get("Name")
            if name:
                data[name] = (d.text or "").strip()

        serial = data.get("SerialNumber", "")
        if not serial:
            return None

        # Filter to USB-attached devices via ParentId pattern
        parent_id = data.get("ParentId", "")
        parent_match = _PARENT_ID_RE.search(parent_id)
        if parent_match is None:
            # Not USB-attached (could be SATA disk getting a 1006 too)
            return None

        device_ref = DeviceRef(
            vid=parent_match.group("vid").upper(),
            pid=parent_match.group("pid").upper(),
            iserial=serial,
        )

        return RawEvent(
            ts=ts,
            ts_kind=TimestampKind.CONNECTION,
            ts_precision=TimestampPrecision.SECOND,
            source=SourceKind.EVTX_PARTITION,
            source_artifact=source_path,
            event_type=EventType.DEVICE_CONNECTED,
            device_ref=device_ref,
            raw={
                "manufacturer": data.get("Manufacturer", ""),
                "model": data.get("Model", ""),
                "revision": data.get("Revision", ""),
                "parent_id": parent_id,
                "disk_id": data.get("DiskId", ""),
                "capacity": data.get("Capacity"),
                "disk_number": data.get("DiskNumber"),
                "partition_count": data.get("PartitionCount"),
                "event_record_id": record_id,
            },
        )

    @staticmethod
    def _parse_systemtime(ts_str: str) -> datetime | None:
        """Parse SystemTime attribute from <TimeCreated SystemTime="...">.

        Format is ISO 8601 UTC with 'Z' suffix, e.g., '2026-05-29T09:22:08.123456Z'.
        Fractional seconds may have varying precision; some events omit them.
        """
        if not ts_str:
            return None

        # Python 3.11 supports 'Z' in fromisoformat directly; for 3.10 we
        # normalize it manually. Also handle absence of fractional seconds.
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
