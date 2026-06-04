"""Shell-item decoding for the shellbags parser.

A shellbag stores, per browsed folder, a binary "shell item" describing one path
component. The relevant item classes for USB folder navigation:

    0x2F            volume / drive root — ASCII drive string at offset 3 ("E:\\")
    0x31            directory entry (ASCII 8.3 name)
    0x32            file entry (ASCII 8.3 name)
    0x35 / 0xB1     directory/file entry with a UTF-16 primary name
    0x1F            root folder (This PC / Desktop) — a GUID, no path component

File/dir entries embed a FAT modified date/time at offset 8 and, in a trailing
BEEF0004 extension block, the FAT creation/access times plus a UTF-16 long name.

FAT timestamps are LOCAL time; callers convert to UTC (see the lnk parser's
timezone caveat — correct only when analyst and source share a timezone).
"""

from __future__ import annotations

import re
from datetime import datetime

_BEEF0004 = b"\x04\x00\xef\xbe"
# Characters that never appear in a Windows file/dir name — used to trim long names.
_NAME_RUN = re.compile(r'[^\x00-\x1f<>:"/\\|?*]{2,}')


def parse_shell_item(b: bytes) -> dict | None:
    """Decode a single shell item. Returns a dict with at least 'kind' and 'name'."""
    if len(b) < 3:
        return None
    typ = b[2]

    if typ == 0x2F:  # volume / drive root
        drive = b[3:].split(b"\x00")[0].decode("ascii", "replace")
        return {"kind": "volume", "name": drive.rstrip("\\"), "drive": drive}

    if typ == 0x1F:  # root folder (This PC, Desktop) — GUID, no path component
        return {"kind": "root", "name": None}

    if (typ & 0x70) == 0x30 or typ in (0xB1,):  # file/dir entry
        modified = _fat(b, 8)
        unicode_name = typ in (0x35, 0xB1)
        short = _primary_name(b, 0x0E, unicode_name)
        long_name, created, accessed = _beef(b)
        # The 8.3 / primary name is reliable; the BEEF0004 long name is best-effort
        # (its exact offset is version-dependent) so it is kept only for reference.
        return {
            "kind": "file",
            "name": short or long_name,
            "short_name": short,
            "long_name": long_name,
            "modified": modified,
            "created": created,
            "accessed": accessed,
        }

    return {"kind": "other", "name": None}


def _primary_name(b: bytes, off: int, unicode_name: bool) -> str:
    if off >= len(b):
        return ""
    if unicode_name:
        end = off
        while end + 1 < len(b) and b[end:end + 2] != b"\x00\x00":
            end += 2
        return b[off:end].decode("utf-16-le", "replace")
    nul = b.find(b"\x00", off)
    return b[off:nul if nul >= 0 else len(b)].decode("latin-1", "replace")


def _beef(b: bytes) -> tuple[str | None, datetime | None, datetime | None]:
    """Return (long_name, created, accessed) from the BEEF0004 extension block."""
    i = b.find(_BEEF0004)
    if i < 0:
        return None, None, None
    created = _fat(b, i + 4)
    accessed = _fat(b, i + 8)
    # The UTF-16 long name follows the fixed fields; its exact offset is version-
    # dependent, so we take the longest printable UTF-16LE run after the times.
    text = b[i + 12:].decode("utf-16-le", "ignore")
    runs = _NAME_RUN.findall(text)
    long_name = max(runs, key=len).strip() if runs else None
    return (long_name or None), created, accessed


def _fat(b: bytes, off: int) -> datetime | None:
    """Decode a 4-byte FAT (DOS) date+time at `off` into a naive (local) datetime."""
    if off + 4 > len(b):
        return None
    date = int.from_bytes(b[off:off + 2], "little")
    time = int.from_bytes(b[off + 2:off + 4], "little")
    if date == 0:
        return None
    day = date & 0x1F
    month = (date >> 5) & 0x0F
    year = 1980 + ((date >> 9) & 0x7F)
    sec = (time & 0x1F) * 2
    minute = (time >> 5) & 0x3F
    hour = (time >> 11) & 0x1F
    try:
        return datetime(year, month, day, hour, minute, sec)
    except ValueError:
        return None
