"""Correlation engine.

Takes the flat list of RawEvents emitted by parsers and builds canonical
entities (Device, Volume, Session). This is the single place where
cross-source correlation happens — parsers stay correlation-free.

Three steps, per device (grouped by iSerial):
    1. canonicalize  — merge all RawEvents sharing an iSerial into one Device,
                       filling VID/PID/identity strings from whatever source has them.
    2. link volumes  — fold MountedDevices bindings into Volume entities, unifying
                       a drive letter and a volume GUID that point to the same
                       device instance into a single Volume.
    3. build sessions — pair each Kernel-PnP 410 arrival with a removal boundary:
                        the most recent session is closed by the exact registry
                        Last Removal; earlier sessions are closed by an *inferred*
                        trailing Partition/Diagnostic 1006 observation (or left open).

Per project decision the engine produces facts and provenance, not verdicts.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from uuid import UUID

from pydantic import BaseModel, Field

from ..core.enums import EventType, SourceKind, TimestampKind
from ..core.models import Device, RawEvent, Session, Volume

# ±window for temporal file-to-session correlation. Absorbs unplug-time
# imprecision (registry Last Removal granularity) and minor clock skew between
# artifacts. Chosen by project decision.
GRACE = timedelta(seconds=60)

# Two arrival signals (Kernel-PnP 410 vs registry Last Arrival) within this gap
# describe the same physical connection and must not become two sessions.
SESSION_DEDUP = timedelta(minutes=5)


class LinkedFile(BaseModel):
    """A file-access event tied to a connection session."""

    event: RawEvent
    session_id: UUID | None = None
    link_type: str  # "direct" (on USB volume) | "temporal" (active during session)
    inferred: bool  # True for temporal links (no direct volume evidence)


class CorrelatedDevice(BaseModel):
    """A Device with all entities and raw evidence correlated to it."""

    device: Device
    volumes: list[Volume] = Field(default_factory=list)
    sessions: list[Session] = Field(default_factory=list)
    events: list[RawEvent] = Field(default_factory=list)
    file_activity: list[LinkedFile] = Field(default_factory=list)
    user_mounts: list[RawEvent] = Field(default_factory=list)
    shellbag_activity: list[RawEvent] = Field(default_factory=list)

    @property
    def usernames(self) -> list[str]:
        names = [
            ev.user_ref.username
            for ev in self.user_mounts
            if ev.user_ref and ev.user_ref.username
        ]
        return sorted(set(names))


class CorrelationResult(BaseModel):
    devices: list[CorrelatedDevice] = Field(default_factory=list)
    orphan_events: list[RawEvent] = Field(default_factory=list)
    unlinked_file_events: list[RawEvent] = Field(default_factory=list)
    unlinked_shellbags: list[RawEvent] = Field(default_factory=list)

    @property
    def all_events(self) -> list[RawEvent]:
        out: list[RawEvent] = (
            list(self.orphan_events)
            + list(self.unlinked_file_events)
            + list(self.unlinked_shellbags)
        )
        for cd in self.devices:
            out.extend(cd.events)
            out.extend(lf.event for lf in cd.file_activity)
            out.extend(cd.user_mounts)
            out.extend(cd.shellbag_activity)
        return out


def correlate(events: list[RawEvent]) -> CorrelationResult:
    """Build canonical entities from a flat list of RawEvents."""
    file_events = [e for e in events if e.event_type == EventType.FILE_ACCESSED]
    mount_events = [e for e in events if e.event_type == EventType.VOLUME_USER_MOUNT]
    shellbag_events = [e for e in events if e.event_type == EventType.FILE_IN_SHELLBAG]
    _special = {
        EventType.FILE_ACCESSED,
        EventType.VOLUME_USER_MOUNT,
        EventType.FILE_IN_SHELLBAG,
    }
    device_events = [e for e in events if e.event_type not in _special]

    by_iserial: dict[str, list[RawEvent]] = defaultdict(list)
    orphans: list[RawEvent] = []
    for ev in device_events:
        if ev.device_ref and ev.device_ref.iserial:
            by_iserial[ev.device_ref.iserial].append(ev)
        else:
            orphans.append(ev)

    devices: list[CorrelatedDevice] = []
    for iserial, group in sorted(by_iserial.items()):
        device = _build_device(iserial, group)
        volumes = _build_volumes(group, device.canonical_id)
        sessions = _build_sessions(group, device.canonical_id, volumes)
        devices.append(
            CorrelatedDevice(
                device=device, volumes=volumes, sessions=sessions, events=group
            )
        )

    # Link per-user volume mounts to a device by matching the volume GUID.
    for me in mount_events:
        cd = _link_user_mount(me, devices)
        if cd is not None:
            cd.user_mounts.append(me)
        else:
            orphans.append(me)

    # Link shellbag folder navigation to a device by matching the drive letter.
    unlinked_bags: list[RawEvent] = []
    for sb in shellbag_events:
        cd = _link_by_drive_letter(sb, devices)
        if cd is not None:
            cd.shellbag_activity.append(sb)
        else:
            unlinked_bags.append(sb)

    # Link file-access events to the connection session whose (grace-padded)
    # window contains the file timestamp.
    unlinked: list[RawEvent] = []
    for fe in file_events:
        link = _link_file(fe, devices)
        if link is None:
            unlinked.append(fe)
        else:
            cd, linked_file = link
            cd.file_activity.append(linked_file)

    return CorrelationResult(
        devices=devices,
        orphan_events=orphans,
        unlinked_file_events=unlinked,
        unlinked_shellbags=unlinked_bags,
    )


def _link_by_drive_letter(
    ev: RawEvent, devices: list[CorrelatedDevice]
) -> CorrelatedDevice | None:
    """Match an event to a device whose volume holds the event's drive letter."""
    letter = ev.volume_ref.drive_letter if ev.volume_ref else None
    if not letter:
        return None
    for cd in devices:
        for vol in cd.volumes:
            if vol.drive_letter and vol.drive_letter.upper() == letter.upper():
                return cd
    return None


def _link_user_mount(
    me: RawEvent, devices: list[CorrelatedDevice]
) -> CorrelatedDevice | None:
    """Match a VOLUME_USER_MOUNT event to a device by volume GUID."""
    guid = me.volume_ref.volume_guid if me.volume_ref else None
    if not guid:
        return None
    for cd in devices:
        for vol in cd.volumes:
            if vol.volume_guid and vol.volume_guid.lower() == guid.lower():
                return cd
    return None


# ----------------------------------------------------------------------------
# File-to-session correlation
# ----------------------------------------------------------------------------


def _link_file(
    fe: RawEvent, devices: list[CorrelatedDevice]
) -> tuple[CorrelatedDevice, LinkedFile] | None:
    """Link a FILE_ACCESSED event to the first session whose window contains it."""
    for cd in devices:
        for sess, lo, hi in _session_windows(cd.sessions):
            if fe.ts < lo:
                continue
            if hi is not None and fe.ts > hi:
                continue
            inferred, link_type = True, "temporal"
            if _volume_corroborates(fe, cd):
                inferred, link_type = False, "direct"
            return cd, LinkedFile(
                event=fe,
                session_id=sess.session_id,
                link_type=link_type,
                inferred=inferred,
            )
    return None


def _session_windows(
    sessions: list[Session],
) -> list[tuple[Session, datetime, datetime | None]]:
    """For each session, the grace-padded [lo, hi] window used for file linking.

    Open sessions (no end_ts) are bounded above by the next session's start, or
    left unbounded (hi=None) if there is no later session.
    """
    ordered = sorted(sessions, key=lambda s: s.start_ts)
    out: list[tuple[Session, datetime, datetime | None]] = []
    for i, sess in enumerate(ordered):
        lo = sess.start_ts - GRACE
        if sess.end_ts is not None:
            hi: datetime | None = sess.end_ts + GRACE
        elif i + 1 < len(ordered):
            hi = ordered[i + 1].start_ts  # open session bounded by next arrival
        else:
            hi = None  # last, open-ended
        out.append((sess, lo, hi))
    return out


def _volume_corroborates(fe: RawEvent, cd: CorrelatedDevice) -> bool:
    """True if the file's volume or its target path matches a device volume.

    Any of three signals makes the link 'direct': the shortcut's volume serial
    (VSN), its volume drive letter, or the drive letter of the target path itself
    — a target on ``E:\\`` while the device held ``E:`` means the file was on the
    device, not merely active during the connection.
    """
    dev_letters = {v.drive_letter.upper() for v in cd.volumes if v.drive_letter}
    dev_vsns = {v.vsn for v in cd.volumes if v.vsn}

    fv = fe.volume_ref
    if fv is not None:
        if fv.vsn and fv.vsn in dev_vsns:
            return True
        if fv.drive_letter and fv.drive_letter.upper() in dev_letters:
            return True

    path = fe.file_ref.path if fe.file_ref else None
    if path and len(path) >= 2 and path[1] == ":" and path[:2].upper() in dev_letters:
        return True
    return False


# ----------------------------------------------------------------------------
# Step 1: device canonicalization
# ----------------------------------------------------------------------------


def _build_device(iserial: str, events: list[RawEvent]) -> Device:
    vid = pid = vendor = product = revision = None
    friendly_names: list[str] = []

    for ev in events:
        ref = ev.device_ref
        if ref is not None:
            vid = vid or ref.vid
            pid = pid or ref.pid
        raw = ev.raw or {}
        vendor = vendor or raw.get("vendor") or raw.get("manufacturer")
        product = product or raw.get("product") or raw.get("model")
        revision = revision or raw.get("revision")
        fn = raw.get("friendly_name")
        if fn and fn not in friendly_names:
            friendly_names.append(fn)

    timestamps = [ev.ts for ev in events if ev.ts is not None]
    canonical_id = f"{vid}_{pid}_{iserial}" if vid and pid else iserial

    return Device(
        canonical_id=canonical_id,
        vid=vid or "",
        pid=pid or "",
        iserial=iserial,
        friendly_names=friendly_names,
        vendor=vendor,
        product=product,
        revision=revision,
        first_seen=min(timestamps) if timestamps else None,
        last_seen=max(timestamps) if timestamps else None,
        evidence_event_ids=[ev.event_id for ev in events],
    )


# ----------------------------------------------------------------------------
# Step 2: volume linking
# ----------------------------------------------------------------------------


def _build_volumes(events: list[RawEvent], canonical_id: str) -> list[Volume]:
    """Fold MountedDevices bindings into Volume entities.

    A drive letter (\\DosDevices\\E:) and a volume GUID (\\??\\Volume{...}) that
    decode to the *same* device instance string are the same volume — merge them.
    """
    by_instance: dict[str, Volume] = {}
    for ev in events:
        if ev.source != SourceKind.REGISTRY_MOUNTED_DEVICES or ev.volume_ref is None:
            continue
        raw = ev.raw or {}
        # Group by the decoded device instance so the two MountedDevices values
        # for one volume collapse into a single entity.
        key = raw.get("device_instance") or raw.get("mount_point") or ""
        vol = by_instance.get(key)
        if vol is None:
            vol = Volume(device_canonical_id=canonical_id)
            by_instance[key] = vol
        vol.drive_letter = vol.drive_letter or ev.volume_ref.drive_letter
        vol.volume_guid = vol.volume_guid or ev.volume_ref.volume_guid
        vol.evidence_event_ids.append(ev.event_id)

    return list(by_instance.values())


# ----------------------------------------------------------------------------
# Step 3: session building (heuristic chosen by project decision)
# ----------------------------------------------------------------------------


def _build_sessions(
    events: list[RawEvent], canonical_id: str, volumes: list[Volume]
) -> list[Session]:
    """Reconstruct connection sessions from arrival and removal signals.

    Arrivals: strict Kernel-PnP 410 events, plus the registry Last Arrival when it
    is not already covered by a 410 (the event log can miss a re-plug of an
    already-installed device, which otherwise merges two distant connections into
    one session). Each arrival is closed by the registry Last Removal if it falls
    inside the arrival's window (exact), otherwise by the last trailing
    Partition/Diagnostic 1006 observation in that window (inferred), otherwise it
    is left open.
    """
    arrivals_410 = sorted(
        (
            ev
            for ev in events
            if ev.source == SourceKind.EVTX_KERNEL_PNP
            and ev.event_type == EventType.DEVICE_CONNECTED
        ),
        key=lambda e: e.ts,
    )

    last_arrival_evs = [ev for ev in events if ev.ts_kind == TimestampKind.LAST_ARRIVAL]
    last_arrival = max(last_arrival_evs, key=lambda e: e.ts) if last_arrival_evs else None

    arrivals = list(arrivals_410)
    if last_arrival is not None and not any(
        abs((a.ts - last_arrival.ts).total_seconds()) <= SESSION_DEDUP.total_seconds()
        for a in arrivals_410
    ):
        arrivals.append(last_arrival)
    arrivals.sort(key=lambda e: e.ts)

    if not arrivals:
        return []

    part_obs = sorted(
        (ev for ev in events if ev.source == SourceKind.EVTX_PARTITION),
        key=lambda e: e.ts,
    )

    removal_events = [ev for ev in events if ev.ts_kind == TimestampKind.LAST_REMOVAL]
    last_removal = max(removal_events, key=lambda e: e.ts) if removal_events else None

    default_letter = volumes[0].drive_letter if len(volumes) == 1 else None

    sessions: list[Session] = []
    for i, arr in enumerate(arrivals):
        start = arr.ts
        next_start = arrivals[i + 1].ts if i + 1 < len(arrivals) else None

        window_obs = [
            o
            for o in part_obs
            if o.ts > start and (next_start is None or o.ts < next_start)
        ]

        end_ts: datetime | None = None
        end_source: str | None = None
        inferred = False
        unplug_ids = []

        removal_in_window = (
            last_removal is not None
            and last_removal.ts >= start
            and (next_start is None or last_removal.ts < next_start)
        )
        if removal_in_window:
            end_ts = last_removal.ts
            end_source = "registry_last_removal"
            inferred = False
            unplug_ids = [last_removal.event_id] + [o.event_id for o in window_obs]
        elif window_obs:
            end_ts = window_obs[-1].ts
            end_source = "evtx_partition"
            inferred = True
            unplug_ids = [window_obs[-1].event_id]

        sessions.append(
            Session(
                device_canonical_id=canonical_id,
                start_ts=start,
                end_ts=end_ts,
                end_ts_source=end_source,
                end_ts_inferred=inferred,
                drive_letter=default_letter,
                plug_evidence_ids=[arr.event_id],
                unplug_evidence_ids=unplug_ids,
            )
        )

    return sessions
