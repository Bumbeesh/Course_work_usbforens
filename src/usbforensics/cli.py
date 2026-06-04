"""Command-line interface for usbforensics.

Subcommands map to the three acquisition modes:
    drive  — analyze a mounted drive or extracted artifacts directory
    self   — analyze the active Windows system  (TODO: Phase 4)
    image  — analyze a raw or .E01 disk image   (TODO: Phase 4)

Phase 1.1 status: drive mode runs registry_usb and registry_device_classes parsers,
groups events by iSerial, and prints a per-device summary including first install /
last arrival / last removal timestamps. Markdown report rendering still TODO.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

import typer

from . import __version__
from .core.models import RawEvent
from .correlation.engine import CorrelationResult, correlate
from .parsers.evtx_partition import EvtxPartitionParser
from .parsers.kernel_pnp import KernelPnpParser
from .parsers.lnk import LnkParser
from .parsers.registry_mount_points_2 import RegistryMountPoints2Parser
from .parsers.registry_mounted_devices import RegistryMountedDevicesParser
from .parsers.registry_usb import RegistryUsbParser
from .parsers.setupapi import SetupApiParser
from .parsers.shellbags import ShellbagsParser
from .reporting.markdown import MarkdownReporter
from .sources.base import ArtifactSource
from .sources.mounted import MountedDriveSource

app = typer.Typer(
    name="usbforensics",
    help="USB Mass Storage forensic analysis for Windows.",
    no_args_is_help=True,
    add_completion=False,
)


# ----------------------------------------------------------------------------
# Subcommands
# ----------------------------------------------------------------------------


@app.command("drive")
def cmd_drive(
    path: Path = typer.Option(
        ...,
        "--path",
        help="Root of a mounted drive or extracted artifacts directory.",
    ),
    output: Path = typer.Option(
        Path("usbforensics_report.md"),
        "--output",
        help="Output report path.",
    ),
    since: str = typer.Option(
        None,
        "--since",
        help="Keep only events at/after this UTC time "
        "(YYYY-MM-DD[ HH:MM[:SS]]). Date-only = start of day.",
    ),
    until: str = typer.Option(
        None,
        "--until",
        help="Keep only events at/before this UTC time "
        "(YYYY-MM-DD[ HH:MM[:SS]]). Date-only = end of day.",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Analyze a mounted drive (non-active filesystem) or extracted artifacts."""
    _setup_logging(verbose)
    try:
        since_dt = _parse_bound(since, end=False) if since else None
        until_dt = _parse_bound(until, end=True) if until else None
    except ValueError as exc:
        typer.echo(f"Error: {exc}")
        raise typer.Exit(2) from exc
    if since_dt and until_dt and since_dt > until_dt:
        typer.echo("Error: --since is later than --until")
        raise typer.Exit(2)
    source = MountedDriveSource(path)
    _run_pipeline(
        source, output, source_root=str(path), mode="drive",
        since=since_dt, until=until_dt,
    )


@app.command("self")
def cmd_self(
    output: Path = typer.Option(
        Path("usbforensics_report.md"), "--output", help="Output report path."
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Analyze the active Windows system (requires admin)."""
    _setup_logging(verbose)
    typer.echo("[TODO Phase 4] self mode requires LiveSystemSource (pytsk3 raw read).")
    raise typer.Exit(2)


@app.command("image")
def cmd_image(
    path: Path = typer.Option(..., "--path", help="Path to disk image (.dd or .E01)"),
    output: Path = typer.Option(
        Path("usbforensics_report.md"), "--output", help="Output report path."
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Analyze a raw or .E01 disk image."""
    _setup_logging(verbose)
    typer.echo("[TODO Phase 4] image mode requires ImageFileSource (pytsk3 + libewf).")
    raise typer.Exit(2)


@app.command("version")
def cmd_version() -> None:
    """Print version and exit."""
    typer.echo(f"usbforensics {__version__}")


# ----------------------------------------------------------------------------
# Pipeline orchestration (will move to core/pipeline.py once it grows)
# ----------------------------------------------------------------------------


_PARSERS = [
    RegistryUsbParser(),
    RegistryMountedDevicesParser(),
    RegistryMountPoints2Parser(),
    SetupApiParser(),
    EvtxPartitionParser(),
    KernelPnpParser(),
    LnkParser(),
    ShellbagsParser(),
]


# ----------------------------------------------------------------------------
# Time-window filtering
# ----------------------------------------------------------------------------

_DT_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d")


def _parse_bound(value: str, *, end: bool) -> datetime:
    """Parse a --since/--until bound into a UTC-aware datetime.

    Accepts 'YYYY-MM-DD', 'YYYY-MM-DD HH:MM', 'YYYY-MM-DD HH:MM:SS' and the ISO
    'T'-separated variants. A date-only bound spans the whole day: start of day
    for --since, end of day (23:59:59) for --until. Bounds are interpreted as UTC,
    matching the UTC timestamps the parsers emit.
    """
    v = value.strip().replace("T", " ")
    for fmt in _DT_FORMATS:
        try:
            dt = datetime.strptime(v, fmt)
        except ValueError:
            continue
        if fmt == "%Y-%m-%d" and end:
            dt = dt.replace(hour=23, minute=59, second=59)
        return dt.replace(tzinfo=timezone.utc)
    raise ValueError(
        f"unrecognized date/time {value!r}; expected YYYY-MM-DD[ HH:MM[:SS]]"
    )


def _filter_window(
    events: list[RawEvent], since: datetime | None, until: datetime | None
) -> list[RawEvent]:
    """Keep events whose timestamp falls within [since, until] (open-ended sides)."""
    out: list[RawEvent] = []
    for e in events:
        if since is not None and e.ts < since:
            continue
        if until is not None and e.ts > until:
            continue
        out.append(e)
    return out


def _window_label(since: datetime | None, until: datetime | None) -> str:
    lo = since.strftime("%Y-%m-%d %H:%M:%S UTC") if since else "−∞"
    hi = until.strftime("%Y-%m-%d %H:%M:%S UTC") if until else "+∞"
    return f"[{lo} … {hi}]"


def _run_pipeline(
    source: ArtifactSource,
    output: Path,
    source_root: str,
    mode: str,
    since: datetime | None = None,
    until: datetime | None = None,
) -> None:
    """Run all parsers, render Markdown report, write to output, print summary."""
    all_events: list[RawEvent] = []

    for parser in _PARSERS:
        events = list(parser.parse(source))
        typer.echo(f"Parser '{parser.name}': {len(events)} events")
        all_events.extend(events)

    # Optional time-window filter (applied to the raw event stream before correlation)
    if since or until:
        before = len(all_events)
        all_events = _filter_window(all_events, since, until)
        typer.echo(
            f"\nTime filter {_window_label(since, until)}: "
            f"{len(all_events)}/{before} events kept"
        )

    typer.echo("")

    # Correlate raw events into canonical entities (Device/Volume/Session)
    result = correlate(all_events)

    # Render and save report
    reporter = MarkdownReporter()
    report_text = reporter.render(
        result,
        source_root=source_root,
        mode=mode,
        tool_version=__version__,
        run_started=datetime.now(timezone.utc),
        time_window=(since, until) if (since or until) else None,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report_text, encoding="utf-8")

    # Brief stdout summary
    _print_summary(result, output)


# ----------------------------------------------------------------------------
# Lightweight correlation preview
# ----------------------------------------------------------------------------


def _print_summary(result: CorrelationResult, output: Path) -> None:
    """Brief stdout summary; the full detail lives in the markdown report."""
    total_events = len(result.all_events)
    total_sessions = sum(len(cd.sessions) for cd in result.devices)
    total_files = sum(len(cd.file_activity) for cd in result.devices)
    total_bags = sum(len(cd.shellbag_activity) for cd in result.devices)
    typer.echo(
        f"Summary: {len(result.devices)} unique device(s), "
        f"{total_events} total events, "
        f"{total_sessions} session(s), "
        f"{total_files} file(s) linked, "
        f"{total_bags} folder(s) browsed on device "
        f"({len(result.orphan_events)} orphan, "
        f"{len(result.unlinked_file_events)} uncorrelated files, "
        f"{len(result.unlinked_shellbags)} non-device shellbags)"
    )
    for cd in result.devices:
        d = cd.device
        name = " ".join(x for x in (d.vendor, d.product) if x) or "<unknown>"
        typer.echo(
            f"  - {name}  VID/PID={d.vid or '?'}/{d.pid or '?'}  "
            f"iSerial={d.iserial}  events={len(cd.events)}  "
            f"sessions={len(cd.sessions)}  files={len(cd.file_activity)}  "
            f"folders={len(cd.shellbag_activity)}"
        )

    typer.echo("")
    typer.echo(f"Report written to: {output}")


# ----------------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------------


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    # regipy is chatty at INFO level about DEVPROP structure decoding —
    # informative but noisy in normal runs. Keep warnings/errors only unless
    # the user explicitly asked for verbose output.
    if not verbose:
        logging.getLogger("regipy").setLevel(logging.WARNING)


if __name__ == "__main__":
    app()
