"""Taxonomies used throughout the data model.

These enums are the closed vocabulary for source attribution, event classification,
and timestamp semantics. New items get added here, not invented ad-hoc by parsers.
"""

from enum import StrEnum


class SourceKind(StrEnum):
    """Identifies the type of artifact a RawEvent came from."""

    # Registry sources
    REGISTRY_USB = "registry_usb"  # SYSTEM\...\Enum\USB
    REGISTRY_USBSTOR = "registry_usbstor"  # SYSTEM\...\Enum\USBSTOR
    REGISTRY_MOUNTED_DEVICES = "registry_mounted_devices"  # SYSTEM\MountedDevices
    REGISTRY_DEVICE_CLASSES = "registry_device_classes"  # SYSTEM\...\DeviceClasses\{GUID}
    REGISTRY_MOUNT_POINTS_2 = "registry_mount_points_2"  # NTUSER\...\MountPoints2
    REGISTRY_PROFILE_LIST = "registry_profile_list"  # SOFTWARE\...\ProfileList
    REGISTRY_WPD = "registry_wpd"  # SOFTWARE\...\Windows Portable Devices

    # File-based sources
    SETUPAPI_LOG = "setupapi_log"  # Windows\INF\setupapi.dev.log

    # Event log sources
    EVTX_PARTITION = "evtx_partition"  # Microsoft-Windows-Partition/Diagnostic
    EVTX_KERNEL_PNP = "evtx_kernel_pnp"  # Microsoft-Windows-Kernel-PnP/Configuration
    EVTX_SYSTEM = "evtx_system"  # System.evtx

    # User-activity artifacts
    LNK = "lnk"
    JUMPLIST = "jumplist"
    PREFETCH = "prefetch"
    AMCACHE = "amcache"
    SHELLBAG = "shellbag"
    SEARCH_INDEX = "search_index"  # Windows.edb

    # NTFS-level
    MFT = "mft"
    USN_JOURNAL = "usn_journal"


class EventType(StrEnum):
    """Taxonomy of facts a parser can emit."""

    # Device lifecycle
    DEVICE_FIRST_INSTALL = "device_first_install"
    DEVICE_SEEN = "device_seen"  # Generic "registry has a record" event
    DEVICE_CONNECTED = "device_connected"
    DEVICE_DISCONNECTED = "device_disconnected"
    DEVICE_LAST_ARRIVAL = "device_last_arrival"
    DEVICE_LAST_REMOVAL = "device_last_removal"

    # Volume / drive letter binding
    VOLUME_ASSIGNED_LETTER = "volume_assigned_letter"
    VOLUME_USER_MOUNT = "volume_user_mount"

    # File interaction associated with USB
    FILE_ACCESSED = "file_accessed"  # Recent LNK / jumplist: user opened a file (location-neutral)
    FILE_OPENED_FROM_USB = "file_opened_from_usb"
    FILE_EXECUTED_FROM_USB = "file_executed_from_usb"
    FILE_IN_SEARCH_INDEX = "file_in_search_index"
    FILE_IN_SHELLBAG = "file_in_shellbag"
    FILE_SAVE_DIALOG_USB = "file_save_dialog_usb"

    # Local FS activity (correlated by timing, not by direct link)
    FILE_CREATED_LOCAL = "file_created_local"
    FILE_MODIFIED_LOCAL = "file_modified_local"
    FILE_DELETED_LOCAL = "file_deleted_local"


class TimestampKind(StrEnum):
    """Semantics of the `ts` field in a RawEvent — what kind of moment it captures."""

    FIRST_INSTALL = "first_install"
    LAST_ARRIVAL = "last_arrival"
    LAST_REMOVAL = "last_removal"
    CONNECTION = "connection"
    DISCONNECTION = "disconnection"
    OBSERVED = "observed"  # e.g., registry key's last-write time
    BTIME = "btime"  # filesystem birth/creation time
    MTIME = "mtime"
    ATIME = "atime"
    CTIME = "ctime"  # NTFS MFT change time
    EXECUTION = "execution"
    LOGGED = "logged"  # event log record time


class TimestampPrecision(StrEnum):
    """Precision of the timestamp — important when correlating across sources."""

    SECOND = "second"
    MINUTE = "minute"
    HOUR = "hour"
    DAY = "day"
    UNKNOWN = "unknown"
