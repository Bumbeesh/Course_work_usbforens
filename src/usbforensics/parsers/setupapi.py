"""Parser for Windows\\INF\\setupapi.dev.log.

setupapi.dev.log is a plain-text log written by SetupAPI for every PnP device
installation. For USB Mass Storage devices, the relevant block looks like:

    >>>  [Device Install (Hardware initiated) - USBSTOR\\Disk&Ven_X&Prod_Y&Rev_Z\\IS&0]
    >>>  Section start 2026/05/29 12:22:08.123
         ... details ...
    <<<  Section end 2026/05/29 12:22:08.456
    <<<  [Exit status: SUCCESS]

The file is appended-only and typically retains records back to OS install,
making it a robust secondary source for first-install timestamps that survives
most anti-forensics attempts targeting USBSTOR registry keys (clearing the
registry doesn't clean this log).

Timestamp note: setupapi.dev.log writes LOCAL system time, not UTC. This parser
interprets the parsed naive datetime as local time of the *analyst's* machine
and converts to UTC. This is correct only when the source and analysis machines
share a timezone (which is the case for self-triage). For cross-timezone
forensics, Phase 2 should read TimeZoneInformation from the SOFTWARE hive.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

from ..core.enums import EventType, SourceKind, TimestampKind, TimestampPrecision
from ..core.models import DeviceRef, RawEvent
from ..sources.base import ArtifactSource

logger = logging.getLogger(__name__)


# Header line examples:
#   >>>  [Device Install (Hardware initiated) - USBSTOR\Disk&Ven_X&Prod_Y&Rev_Z\IS&0]
#   >>>  [Device Install (Hardware initiated) - SWD\WPDBUSENUM\_??_USBSTOR#Disk&Ven_X...]
HEADER_RE = re.compile(
    r"^>>>\s+\[Device Install\s+\([^)]+\)\s*-\s*(?P<path>.+?)\]\s*$"
)

# Section start: ">>>  Section start YYYY/MM/DD HH:MM:SS.fff"
SECTION_START_RE = re.compile(
    r"^>>>\s+Section start\s+(?P<ts>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s*$"
)

# Extract identity from any path containing a USBSTOR component.
# Handles both backslash (direct device IDs) and hash (WPDBUSENUM-wrapped IDs).
USBSTOR_PATH_RE = re.compile(
    r"USBSTOR[\\#]"
    r"Disk&Ven_(?P<vendor>[^\\#&]+)&Prod_(?P<product>[^\\#&]+)&Rev_(?P<rev>[^\\#&]+)"
    r"[\\#](?P<iserial_raw>[^\\#]+)"
)

_TS_FORMATS = ("%Y/%m/%d %H:%M:%S.%f", "%Y/%m/%d %H:%M:%S")


class SetupApiParser:
    """Parses setupapi.dev.log for USBSTOR first-install events."""

    name = "setupapi"

    def parse(self, source: ArtifactSource) -> Iterator[RawEvent]:
        log_path = source.get_setupapi_log()
        if log_path is None:
            logger.warning("setupapi.dev.log not available; skipping")
            return

        logger.info("Parsing %s", log_path)

        text = self._read_text(log_path)
        if text is None:
            return

        yield from self._iter_events(text, str(log_path))

    # ------------------------------------------------------------------
    # File reading: setupapi.dev.log encoding varies by OS build / locale
    # ------------------------------------------------------------------

    @staticmethod
    def _read_text(log_path: Path) -> str | None:
        """Read setupapi.dev.log with proper encoding detection.

        On Windows, this file can be UTF-8 (with or without BOM) or UTF-16 LE
        (with or without BOM, depending on Windows build). Naively trying UTF-8
        first doesn't work — UTF-16 LE bytes are *valid UTF-8 sequences*
        (NUL is a valid Python char), so decoding succeeds silently and yields
        a string with embedded NULs that splitlines() can't parse correctly.

        We detect UTF-16 LE without BOM by checking the proportion of NUL bytes
        at odd byte positions: UTF-16 LE ASCII text has 0x00 at every second
        byte, while UTF-8 ASCII has no NULs at all.
        """
        try:
            raw = log_path.read_bytes()
        except OSError as exc:
            logger.warning("Could not read %s: %s", log_path, exc)
            return None

        # Explicit BOMs
        if raw.startswith(b"\xff\xfe"):
            return raw.decode("utf-16-le", errors="replace")
        if raw.startswith(b"\xfe\xff"):
            return raw.decode("utf-16-be", errors="replace")
        if raw.startswith(b"\xef\xbb\xbf"):
            return raw[3:].decode("utf-8", errors="replace")

        # No BOM: detect UTF-16 LE by NUL-at-odd-positions ratio in a sample
        sample = raw[: min(len(raw), 4096)]
        odd_positions = len(sample) // 2
        if odd_positions > 0:
            nul_at_odd = sum(1 for i in range(1, len(sample), 2) if sample[i] == 0)
            if nul_at_odd / odd_positions > 0.7:
                logger.info("Detected UTF-16 LE without BOM by NUL-byte heuristic")
                return raw.decode("utf-16-le", errors="replace")

        # Default: UTF-8 (modern Windows convention)
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.decode("utf-8", errors="replace")

    # ------------------------------------------------------------------
    # State-machine over lines: header -> Section start -> event
    # ------------------------------------------------------------------

    def _iter_events(self, text: str, source_path: str) -> Iterator[RawEvent]:
        pending_path: str | None = None

        for line in text.splitlines():
            if pending_path is None:
                header = HEADER_RE.match(line)
                if header:
                    pending_path = header.group("path")
                continue

            section = SECTION_START_RE.match(line)
            if section:
                ts = self._parse_ts(section.group("ts"))
                if ts is not None:
                    event = self._build_event(pending_path, ts, source_path)
                    if event is not None:
                        yield event
                pending_path = None
                continue

            # Another header before we saw a Section start — reset to new header
            next_header = HEADER_RE.match(line)
            if next_header:
                pending_path = next_header.group("path")

    @staticmethod
    def _parse_ts(ts_str: str) -> datetime | None:
        """Parse 'YYYY/MM/DD HH:MM:SS[.fff]' string.

        Returns a UTC-aware datetime by treating the naive string as local time
        of the analyst's system (see module docstring for the timezone caveat).
        """
        for fmt in _TS_FORMATS:
            try:
                naive = datetime.strptime(ts_str, fmt)
            except ValueError:
                continue
            # Treat as local time, then convert to UTC. astimezone() on a
            # naive datetime interprets it as local since Python 3.6.
            return naive.astimezone(timezone.utc)
        logger.debug("Could not parse setupapi timestamp: %r", ts_str)
        return None

    @staticmethod
    def _build_event(device_path: str, ts: datetime, source_path: str) -> RawEvent | None:
        """Build a DEVICE_FIRST_INSTALL event from a USBSTOR-containing device path."""
        match = USBSTOR_PATH_RE.search(device_path)
        if not match:
            return None  # Not a USB Mass Storage install record

        iserial_raw = match.group("iserial_raw")
        # Strip "&0" suffix (instance discriminator) and any trailing "#{guid}"
        iserial = iserial_raw.split("&")[0].split("#")[0]

        vendor = _unescape(match.group("vendor"))
        product = _unescape(match.group("product"))
        revision = _unescape(match.group("rev"))

        return RawEvent(
            ts=ts,
            ts_kind=TimestampKind.FIRST_INSTALL,
            ts_precision=TimestampPrecision.SECOND,
            source=SourceKind.SETUPAPI_LOG,
            source_artifact=source_path,
            event_type=EventType.DEVICE_FIRST_INSTALL,
            device_ref=DeviceRef(iserial=iserial),
            raw={
                "vendor": vendor,
                "product": product,
                "revision": revision,
                "device_path": device_path,
                "timezone_note": (
                    "Parsed from local time of analyst system; "
                    "may be off if source system has a different timezone."
                ),
            },
        )


def _unescape(s: str) -> str:
    return s.replace("_", " ").strip()
