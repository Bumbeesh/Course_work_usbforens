"""Two-layer data model.

Layer 1: RawEvent — atomic facts emitted by parsers, immutable, attributable.
Layer 2: Entities (Device, Volume, Session) — canonical objects built by correlation.

Per project decision, Layer 3 (Hypothesis with confidence scoring) is intentionally
omitted: the tool aggregates and presents facts; interpretation is left to the analyst.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from .enums import EventType, SourceKind, TimestampKind, TimestampPrecision


# ----------------------------------------------------------------------------
# Entity references — partial pointers used inside RawEvent
# ----------------------------------------------------------------------------


class DeviceRef(BaseModel):
    """Partial or canonical reference to a USB device.

    Parsers fill in whatever they know. Correlation engine matches and merges
    refs into canonical Device entities.
    """

    model_config = ConfigDict(frozen=True)

    vid: str | None = None
    pid: str | None = None
    iserial: str | None = None

    @property
    def canonical_id(self) -> str | None:
        """Stable identifier across all data sources, if enough info is present."""
        if self.vid and self.pid and self.iserial:
            return f"{self.vid.upper()}_{self.pid.upper()}_{self.iserial}"
        return None


class VolumeRef(BaseModel):
    model_config = ConfigDict(frozen=True)

    vsn: str | None = None  # 4-byte Volume Serial Number, hex like "1A2B-3C4D"
    volume_guid: str | None = None  # Windows {GUID}
    drive_letter: str | None = None  # "E:"
    label: str | None = None


class FileRef(BaseModel):
    model_config = ConfigDict(frozen=True)

    path: str | None = None
    name: str | None = None
    size: int | None = None
    sha1: str | None = None


class UserRef(BaseModel):
    model_config = ConfigDict(frozen=True)

    sid: str | None = None
    username: str | None = None


# ----------------------------------------------------------------------------
# Layer 1: RawEvent
# ----------------------------------------------------------------------------


class RawEvent(BaseModel):
    """A single atomic fact extracted by a parser.

    Every claim in the final report must trace back to one or more RawEvents.
    """

    event_id: UUID = Field(default_factory=uuid4)
    ts: datetime  # ALWAYS UTC. Naive datetimes are a bug.
    ts_kind: TimestampKind
    ts_precision: TimestampPrecision = TimestampPrecision.SECOND

    source: SourceKind
    source_artifact: str  # path/identifier of artifact, for forensic traceability
    event_type: EventType

    # Any subset of references may be filled in
    device_ref: DeviceRef | None = None
    volume_ref: VolumeRef | None = None
    file_ref: FileRef | None = None
    user_ref: UserRef | None = None

    # Original parsed data, for verifiability and debugging
    raw: dict[str, Any] = Field(default_factory=dict)


# ----------------------------------------------------------------------------
# Layer 2: Entities (built by correlation, not by parsers)
# ----------------------------------------------------------------------------


class Device(BaseModel):
    """Canonical USB Mass Storage device.

    Identity key: (VID, PID, iSerial). All RawEvents whose DeviceRef resolves to
    the same canonical_id are merged into one Device.
    """

    canonical_id: str
    vid: str
    pid: str
    iserial: str

    friendly_names: list[str] = Field(default_factory=list)
    vendor: str | None = None
    product: str | None = None
    revision: str | None = None

    first_seen: datetime | None = None
    last_seen: datetime | None = None

    volume_serial_numbers: list[str] = Field(default_factory=list)

    evidence_event_ids: list[UUID] = Field(default_factory=list)


class Volume(BaseModel):
    """A volume (typically a partition on a USB device)."""

    vsn: str | None = None
    volume_guid: str | None = None
    drive_letter: str | None = None
    label: str | None = None
    filesystem: str | None = None
    device_canonical_id: str | None = None

    evidence_event_ids: list[UUID] = Field(default_factory=list)


class Session(BaseModel):
    """A single connection session: device was plugged at start_ts, removed at end_ts."""

    session_id: UUID = Field(default_factory=uuid4)
    device_canonical_id: str
    start_ts: datetime
    end_ts: datetime | None = None  # None = no removal evidence in window

    # Provenance of end_ts. There is no clean event-log unplug source on Windows
    # (DriverFrameworks is off by default; Kernel-PnP 430 != unplug), so end_ts is
    # either the exact registry Last Removal (only valid for the most recent
    # session) or an inferred trailing Partition/Diagnostic 1006 observation.
    end_ts_source: str | None = None  # "registry_last_removal" | "evtx_partition"
    end_ts_inferred: bool = False  # True when end_ts is a heuristic, not exact

    drive_letter: str | None = None
    user_sid: str | None = None
    username: str | None = None

    plug_evidence_ids: list[UUID] = Field(default_factory=list)
    unplug_evidence_ids: list[UUID] = Field(default_factory=list)
