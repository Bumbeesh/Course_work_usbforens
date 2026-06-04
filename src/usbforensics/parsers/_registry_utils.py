"""Shared helpers for parsers that work with Windows registry hives.

Centralizes:
- Resolving the active ControlSet via \\Select\\Current
- Navigating subkeys by name (regipy doesn't have a get_subkey convenience)
- Normalizing various FILETIME representations to UTC datetime
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from regipy.exceptions import RegistryKeyNotFoundException
from regipy.registry import RegistryHive

logger = logging.getLogger(__name__)

SELECT_PATH = r"\Select"

# Windows FILETIME epoch offset (seconds between 1601-01-01 and 1970-01-01)
_FILETIME_EPOCH_DIFF = 11_644_473_600


def resolve_current_control_set(hive: RegistryHive) -> int:
    """Return N such that ControlSet00N is the active control set.

    Reads \\Select\\Current REG_DWORD. Falls back to 1 if unavailable, with
    a logged warning — old hives or unusual cases may lack this key.
    """
    try:
        select_key = hive.get_key(SELECT_PATH)
    except RegistryKeyNotFoundException:
        logger.warning("\\Select key not found; falling back to ControlSet001")
        return 1

    for value in select_key.iter_values():
        if value.name == "Current":
            return int(value.value)

    logger.warning("\\Select\\Current value not present; falling back to ControlSet001")
    return 1


def find_subkey(parent_key, name: str):
    """Return the immediate child key with the given name, or None.

    regipy's NKRecord does not expose a direct get_subkey method, so we
    linearly scan. Cost is negligible for the small fanouts we deal with.
    """
    try:
        for sk in parent_key.iter_subkeys():
            if sk.name == name:
                return sk
    except Exception as exc:  # noqa: BLE001
        logger.debug("Error iterating subkeys of %r: %s", parent_key.name, exc)
    return None


def filetime_to_utc(ft_int: int) -> datetime:
    """Convert raw Windows FILETIME (100-ns since 1601-01-01 UTC) to UTC datetime."""
    unix_seconds = ft_int / 10_000_000 - _FILETIME_EPOCH_DIFF
    return datetime.fromtimestamp(unix_seconds, tz=timezone.utc)


def normalize_timestamp(value) -> datetime | None:
    """Best-effort conversion to UTC-aware datetime.

    Accepts:
        - datetime (returned as-is, made UTC-aware if naive)
        - bytes of length 8 — treated as little-endian FILETIME
        - int large enough to be a FILETIME
    Returns None for unrecognized values.
    """
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, bytes) and len(value) == 8:
        return filetime_to_utc(int.from_bytes(value, byteorder="little"))
    if isinstance(value, int) and value > 100_000_000_000_000_000:
        # Plausible FILETIME range; anything smaller is not interpretable as such
        return filetime_to_utc(value)
    return None
