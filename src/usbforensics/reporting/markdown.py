"""Markdown report renderer.

Produces a human-readable forensic report grouping evidence by device, with
explicit source attribution for every claim. Designed to read well both as
raw text and when rendered as Markdown (e.g., in IDE preview, GitHub, or pandoc).

Design principles:
- One section per device, ordered by first appearance
- Every fact lists its source artifact(s)
- Tables for tabular data (timelines, identity), prose for context
- Notes called out via blockquote
- Raw event counts available for cross-checking with stdout summary
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from io import StringIO

from ..core.enums import SourceKind, TimestampKind
from ..core.models import RawEvent
from ..correlation.engine import CorrelationResult

# VIDs that are not registered with USB-IF — they show up on generic/no-name devices
_SUSPECT_VIDS = frozenset({"ABCD", "1234", "0000", "FFFF"})


class MarkdownReporter:
    """Renders a list of RawEvents into a structured Markdown report."""

    def render(
        self,
        result: CorrelationResult,
        *,
        source_root: str,
        mode: str,
        tool_version: str,
        run_started: datetime | None = None,
        time_window: tuple[datetime | None, datetime | None] | None = None,
    ) -> str:
        if run_started is None:
            run_started = datetime.now(timezone.utc)

        all_events = result.all_events

        out = StringIO()
        self._header(out, mode, source_root, tool_version, run_started, time_window)
        self._summary(out, result.devices, all_events)
        self._source_inventory(out, all_events)
        if result.devices:
            self._devices(out, result.devices)
        if result.orphan_events:
            self._orphan_events(out, result.orphan_events)
        self._footer(out)
        return out.getvalue()

    # ------------------------------------------------------------------
    # Sections
    # ------------------------------------------------------------------

    def _header(self, out, mode, source_root, tool_version, run_started,
                time_window=None) -> None:
        out.write("# Отчёт об анализе USB-устройств\n\n")
        out.write(f"- **Сформирован**: {_fmt_dt(run_started)}\n")
        out.write(f"- **Инструмент**: usbforensics {tool_version}\n")
        out.write(f"- **Режим**: `{mode}`\n")
        out.write(f"- **Корень артефактов**: `{source_root}`\n")
        if time_window:
            since, until = time_window
            lo = _fmt_dt(since) if since else "−∞"
            hi = _fmt_dt(until) if until else "+∞"
            out.write(
                f"- **Период анализа**: {lo} … {hi} "
                f"(показаны только события в этом окне)\n"
            )
        out.write("\n")
        out.write(
            "Отчёт агрегирует следы активности USB Mass Storage устройств, "
            "извлечённые из артефактов Windows (куст реестра SYSTEM, "
            "`setupapi.dev.log`, журналы событий, кусты пользователей и ярлыки). "
            "Все временны́е метки приведены в UTC. Каждый факт сопровождается "
            "источником, из которого он извлечён. Инструмент агрегирует факты; "
            "их интерпретация и выводы — ответственность аналитика.\n\n"
        )

    def _summary(self, out, devices, events) -> None:
        out.write("## Сводка\n\n")
        out.write(f"- **Обнаружено устройств**: {len(devices)}\n")
        out.write(f"- **Всего извлечено событий**: {len(events)}\n")
        total_sessions = sum(len(cd.sessions) for cd in devices)
        total_files = sum(len(cd.file_activity) for cd in devices)
        total_bags = sum(len(cd.shellbag_activity) for cd in devices)
        out.write(f"- **Восстановлено сессий подключения**: {total_sessions}\n")
        out.write(f"- **Файлов привязано к сессиям**: {total_files}\n")
        out.write(f"- **Папок просмотрено на устройствах (shellbags)**: {total_bags}\n")

        timestamps = [ev.ts for ev in events if ev.ts]
        if timestamps:
            out.write(f"- **Самое раннее событие**: {_fmt_dt(min(timestamps))}\n")
            out.write(f"- **Самое позднее событие**: {_fmt_dt(max(timestamps))}\n")

        if devices:
            out.write("\n### Устройства (обзор)\n\n")
            out.write(
                "| # | Вендор / Продукт | VID/PID | iSerial | Сессии | Файлы | События |\n"
            )
            out.write("|---|---|---|---|---|---|---|\n")
            for idx, cd in enumerate(devices, 1):
                d = cd.device
                name = " ".join(x for x in (d.vendor, d.product) if x) or "—"
                vidpid = f"`{d.vid or '?'}/{d.pid or '?'}`"
                out.write(
                    f"| {idx} | {name} | {vidpid} | `{d.iserial}` "
                    f"| {len(cd.sessions)} | {len(cd.file_activity)} | {len(cd.events)} |\n"
                )
        out.write("\n")

    def _source_inventory(self, out, events) -> None:
        per_source: dict[SourceKind, set[str]] = defaultdict(set)
        per_source_count: dict[SourceKind, int] = defaultdict(int)
        for ev in events:
            per_source[ev.source].add(ev.source_artifact)
            per_source_count[ev.source] += 1

        if not per_source:
            return

        out.write("## Обработанные источники\n\n")
        out.write("| Тип источника | Путь к артефакту | События |\n")
        out.write("|---|---|---|\n")
        for source_kind in sorted(per_source, key=lambda s: s.value):
            for path in sorted(per_source[source_kind]):
                out.write(
                    f"| `{source_kind.value}` | `{path}` | {per_source_count[source_kind]} |\n"
                )
        out.write("\n")

    def _devices(self, out, devices) -> None:
        out.write("## Устройства\n\n")
        for idx, cd in enumerate(devices, 1):
            self._device_section(out, idx, cd)

    def _device_section(self, out, idx: int, cd) -> None:
        iserial = cd.device.iserial
        group = cd.events
        s = _summarize(group)
        title = " ".join(x for x in (s["vendor"], s["product"]) if x) or "Unknown device"
        out.write(f"### Устройство {idx}: {title}\n\n")

        # --- Synthesis (who / when / what, for quick reading) ---
        self._device_synthesis(out, cd, title)

        # --- Identity ---
        out.write("**Идентификация**\n\n")
        out.write("| Свойство | Значение | Источники |\n|---|---|---|\n")
        out.write(
            f"| VID | `{s['vid'] or '?'}` | "
            f"{_sources_for_ref_field(group, 'vid')} |\n"
        )
        out.write(
            f"| PID | `{s['pid'] or '?'}` | "
            f"{_sources_for_ref_field(group, 'pid')} |\n"
        )
        out.write(
            f"| iSerial | `{iserial}` | "
            f"{_sources_for_ref_field(group, 'iserial')} |\n"
        )
        if s["vendor"]:
            out.write(
                f"| Вендор | {s['vendor']} | "
                f"{_sources_for_raw_field(group, 'vendor', 'manufacturer')} |\n"
            )
        if s["product"]:
            out.write(
                f"| Продукт | {s['product']} | "
                f"{_sources_for_raw_field(group, 'product', 'model')} |\n"
            )
        if s["friendly_name"]:
            out.write(f"| FriendlyName | {s['friendly_name']} | `registry_usbstor` |\n")
        out.write("\n")

        # VID-IF registration note
        if s["vid"] and s["vid"].upper() in _SUSPECT_VIDS:
            out.write(
                f"> **Примечание**: VID `{s['vid']}` не соответствует ни одному "
                f"зарегистрированному в USB-IF идентификатору вендора. Обычно это "
                f"признак generic / безымянного / контрафактного устройства.\n\n"
            )

        # --- Volume / drive-letter bindings (from MountedDevices) ---
        self._volume_bindings(out, group)

        # --- User attribution (from per-user MountPoints2) ---
        self._user_mounts(out, cd)

        # --- Connection sessions (correlation engine) ---
        self._sessions(out, cd.sessions)

        # --- Files correlated to sessions (file attribution) ---
        self._file_activity(out, cd)

        # --- Folders browsed on the device (shellbags) ---
        self._shellbags(out, cd)

        # --- Timeline summary ---
        rows = _timeline_rows(group, s)
        if rows:
            out.write("**Сводная хронология**\n\n")
            out.write("| Событие | Время (UTC) | Источник(и) |\n|---|---|---|\n")
            for label, ts, sources in rows:
                out.write(f"| {label} | {_fmt_dt(ts)} | {', '.join(sources)} |\n")
            out.write("\n")

        # --- PnP lifecycle events (Kernel-PnP detail) ---
        pnp_events = sorted(
            (ev for ev in group if ev.source == SourceKind.EVTX_KERNEL_PNP),
            key=lambda e: e.ts,
        )
        if pnp_events:
            out.write("**События жизненного цикла PnP** (из `Microsoft-Windows-Kernel-PnP/Configuration`)\n\n")
            out.write("| # | Время (UTC) | EventID | Действие | Record ID |\n")
            out.write("|---|---|---|---|---|\n")
            for n, ev in enumerate(pnp_events, 1):
                raw = ev.raw or {}
                eid = raw.get("event_id", "?")
                action = _pnp_action(eid)
                out.write(
                    f"| {n} | {_fmt_dt(ev.ts)} | {eid} | {action} | "
                    f"{raw.get('event_record_id') or '—'} |\n"
                )
            out.write("\n")
            out.write(
                "> События 400/410 в `Kernel-PnP/Configuration` фиксируют установку "
                "драйвера и запуск устройства соответственно. Они срабатывают при "
                "подключении, но **не при отключении** — этот канал не журналирует "
                "извлечение устройства. Каноническое время отключения см. в строке "
                "`Последнее отключение (реестр)` сводной хронологии выше.\n\n"
            )

        # --- Partition observation events (EVTX detail) ---
        evtx_events = sorted(
            (ev for ev in group if ev.source == SourceKind.EVTX_PARTITION),
            key=lambda e: e.ts,
        )
        if evtx_events:
            out.write("**События наблюдения разделов** (из `Microsoft-Windows-Partition/Diagnostic`)\n\n")
            out.write("| # | Время (UTC) | Диск № | Ёмкость | Record ID |\n")
            out.write("|---|---|---|---|---|\n")
            for n, ev in enumerate(evtx_events, 1):
                raw = ev.raw or {}
                out.write(
                    f"| {n} | {_fmt_dt(ev.ts)} | {raw.get('disk_number') or '—'} "
                    f"| {_fmt_capacity(raw.get('capacity'))} "
                    f"| {raw.get('event_record_id') or '—'} |\n"
                )
            out.write("\n")
            out.write(
                "> Событие 1006 этого канала срабатывает при *любом* наблюдении "
                "таблицы разделов — как при подключении, так и при изменении "
                "состояния (например, отключении). Несколько записей для одного "
                "устройства могут отражать один цикл подключение-отключение. "
                "Строгое разделение подключения и отключения требует сопоставления "
                "с событиями 410 канала `Microsoft-Windows-Kernel-PnP/Configuration`.\n\n"
            )

        # --- Total events ---
        sources_used = sorted({ev.source.value for ev in group})
        out.write(
            f"**Всего фактов по устройству**: {len(group)} "
            f"(источники: {', '.join(f'`{s}`' for s in sources_used)})\n\n"
        )
        out.write("---\n\n")

    def _device_synthesis(self, out, cd, title: str) -> None:
        """A short who/when/what synthesis at the head of each device section."""
        d = cd.device
        out.write("**Сводка**\n\n")
        out.write(
            f"**{title}** — VID/PID `{d.vid or '?'}/{d.pid or '?'}`, "
            f"iSerial `{d.iserial}`.\n\n"
        )

        bullets: list[str] = []
        if cd.usernames:
            who = ", ".join(f"`{u}`" for u in cd.usernames)
            bullets.append(f"Монтировал пользователь: {who}.")
        if cd.sessions:
            ordered = sorted(cd.sessions, key=lambda s: s.start_ts)
            first = ordered[0].start_ts
            last_end = max((s.end_ts or s.start_ts) for s in ordered)
            bullets.append(
                f"Сессий подключения: {len(cd.sessions)}; активность охватывает "
                f"{_fmt_dt(first)} → {_fmt_dt(last_end)}."
            )
        else:
            bullets.append(
                "Сессии подключения не восстановлены "
                "(не зафиксировано событие Kernel-PnP 410)."
            )
        if cd.file_activity:
            names = ", ".join(
                f"`{lf.event.file_ref.name}`"
                for lf in cd.file_activity[:5]
                if lf.event.file_ref and lf.event.file_ref.name
            )
            n_inf = sum(1 for lf in cd.file_activity if lf.inferred)
            bullets.append(
                f"Файлов активно во время сессий: {len(cd.file_activity)} ({names}) — "
                f"из них {n_inf} привязано по времени (предположительно)."
            )
        if cd.shellbag_activity:
            paths = ", ".join(
                f"`{ev.file_ref.path}`"
                for ev in cd.shellbag_activity[:5]
                if ev.file_ref and ev.file_ref.path
            )
            bullets.append(
                f"Папок просмотрено на устройстве: {len(cd.shellbag_activity)} "
                f"({paths}) — прямое свидетельство навигации."
            )
        for b in bullets:
            out.write(f"- {b}\n")
        out.write("\n")
        out.write(
            "> Только факты; квалификацию действий выполняет аналитик.\n\n"
        )

    def _volume_bindings(self, out, group: list[RawEvent]) -> None:
        """Render drive-letter / volume-GUID bindings from MountedDevices."""
        bindings = [
            ev
            for ev in group
            if ev.source == SourceKind.REGISTRY_MOUNTED_DEVICES and ev.volume_ref is not None
        ]
        if not bindings:
            return

        out.write("**Привязки тома** (из `SYSTEM\\MountedDevices`)\n\n")
        out.write("| Точка монтирования | Буква диска | Volume GUID |\n|---|---|---|\n")
        for ev in bindings:
            ref = ev.volume_ref
            raw = ev.raw or {}
            out.write(
                f"| `{raw.get('mount_point') or '—'}` "
                f"| {ref.drive_letter or '—'} "
                f"| {('`' + ref.volume_guid + '`') if ref.volume_guid else '—'} |\n"
            )
        out.write("\n")
        out.write(
            "> MountedDevices хранит только *последнюю* привязку для каждой буквы "
            "диска. Переиспользованная буква отражает лишь самое недавнее "
            "устройство; записи `\\??\\Volume{GUID}` устойчивее.\n\n"
        )

    def _user_mounts(self, out, cd) -> None:
        """Render per-user volume mounts (who mounted this device's volume)."""
        if not cd.user_mounts:
            return

        out.write("**Монтировал пользователь** (из `NTUSER.DAT\\...\\MountPoints2`)\n\n")
        out.write("| Пользователь | Volume GUID | Последнее монтирование (UTC) |\n|---|---|---|\n")
        for ev in sorted(cd.user_mounts, key=lambda e: e.ts):
            user = (ev.user_ref.username if ev.user_ref else None) or "—"
            guid = (ev.volume_ref.volume_guid if ev.volume_ref else None) or "—"
            out.write(f"| {user} | `{guid}` | {_fmt_dt(ev.ts)} |\n")
        out.write("\n")
        out.write(
            "> MountPoints2 связывает монтирование тома с конкретной учётной записью "
            "пользователя. Время — last-write подключа реестра, то есть примерно "
            "момент последнего монтирования тома этим пользователем.\n\n"
        )

    def _sessions(self, out, sessions) -> None:
        """Render reconstructed connection sessions (410 arrival -> removal)."""
        if not sessions:
            return

        out.write("**Сессии подключения** (восстановлено)\n\n")
        out.write("| # | Начало (UTC) | Конец (UTC) | Длительность | Источник конца | Диск |\n")
        out.write("|---|---|---|---|---|---|\n")
        any_inferred = False
        for n, s in enumerate(sorted(sessions, key=lambda x: x.start_ts), 1):
            end = _fmt_dt(s.end_ts) if s.end_ts else "— (открыта)"
            duration = _fmt_duration(s.start_ts, s.end_ts)
            if s.end_ts_inferred:
                any_inferred = True
            out.write(
                f"| {n} | {_fmt_dt(s.start_ts)} | {end} | {duration} "
                f"| {_end_source_label(s)} | {s.drive_letter or '—'} |\n"
            )
        out.write("\n")
        out.write(
            "> Начало сессии — событие Kernel-PnP 410 (строгое подключение). Чистого "
            "событийного источника отключения на Windows нет, поэтому конец — это "
            "либо точный реестровый **Last Removal** (достоверен только для самой "
            "недавней сессии), либо *предположительное* хвостовое наблюдение "
            "Partition/Diagnostic 1006.\n\n"
        )
        if any_inferred:
            out.write(
                "> ⚠ У сессий с пометкой *предположительно* время конца эвристическое; "
                "их длительность следует считать приблизительной.\n\n"
            )

    def _file_activity(self, out, cd) -> None:
        """Render files correlated to this device's connection sessions."""
        if not cd.file_activity:
            return

        # Map session_id -> ordinal for human-readable references
        ordered = sorted(cd.sessions, key=lambda s: s.start_ts)
        sess_num = {s.session_id: i for i, s in enumerate(ordered, 1)}

        out.write("**Файлы, привязанные к сессиям** (из ярлыков Recent)\n\n")
        out.write("| Файл | Путь | Время файла (UTC) | Сессия | Связь |\n")
        out.write("|---|---|---|---|---|\n")
        for lf in sorted(cd.file_activity, key=lambda x: x.event.ts):
            ev = lf.event
            fr = ev.file_ref
            name = (fr.name if fr else None) or "—"
            path = (fr.path if fr else None) or "—"
            sn = sess_num.get(lf.session_id, "—")
            link = (
                "временна́я (в окне сессии) — предположительно"
                if lf.inferred
                else "прямая (на томе устройства)"
            )
            out.write(
                f"| `{name}` | `{path}` | {_fmt_dt(ev.ts)} | {sn} | {link} |\n"
            )
        out.write("\n")
        out.write(
            "> *Прямая* связь означает, что серийный номер тома / буква диска ярлыка "
            "совпали с томом устройства. *Временна́я* связь означает лишь, что время "
            "файла попадает в окно подключения (±60 с) — файл был активен, пока "
            "устройство было подключено, что согласуется с переносом на устройство "
            "или с него (но само по себе его не доказывает).\n\n"
        )

    def _shellbags(self, out, cd) -> None:
        """Render folders browsed on this device's volume (shellbag navigation)."""
        if not cd.shellbag_activity:
            return

        ordered = sorted(cd.sessions, key=lambda s: s.start_ts)

        def during_session(ts) -> str:
            for i, s in enumerate(ordered, 1):
                end = s.end_ts or ts  # open session: treat as ongoing
                if s.start_ts <= ts <= max(end, s.start_ts):
                    return str(i)
            return "—"

        out.write("**Папки, просмотренные на устройстве** (из shellbags)\n\n")
        out.write("| Путь | Просмотрено (UTC) | В сессии |\n|---|---|---|\n")
        for ev in sorted(cd.shellbag_activity, key=lambda e: e.ts):
            fr = ev.file_ref
            path = (fr.path if fr else None) or "—"
            out.write(f"| `{path}` | {_fmt_dt(ev.ts)} | {during_session(ev.ts)} |\n")
        out.write("\n")
        out.write(
            "> Shellbag — *прямое* свидетельство того, что пользователь открывал эту "
            "папку в Проводнике. Путь сопоставлен с устройством по букве диска; "
            "время — last-write записи (≈ последний просмотр папки). Буквы дисков "
            "переиспользуются между устройствами, поэтому просмотр вне какой-либо "
            "сессии подключения может относиться к другому устройству с той же "
            "буквой.\n\n"
        )

    def _orphan_events(self, out, orphans) -> None:
        out.write("## События без привязки к устройству\n\n")
        out.write(
            f"{len(orphans)} событие(й) не удалось связать с конкретным устройством, "
            "так как их источник не содержал iSerial. Обычно такие записи приходят "
            "из артефактов с частичными или некорректными ссылками на устройство.\n\n"
        )

    def _footer(self, out) -> None:
        out.write(
            "*Отчёт сформирован usbforensics — "
            "инструмент криминалистического анализа USB Mass Storage устройств.*\n"
        )


# ----------------------------------------------------------------------------
# Helpers (module-level for reuse and testability)
# ----------------------------------------------------------------------------


def _summarize(events: list[RawEvent]) -> dict:
    """Aggregate identity fields and timestamps across a device's events.

    Distinguishes timestamps by both ts_kind and source — e.g., a CONNECTION
    event from evtx_partition (partition observation, fires on plug AND unplug)
    is semantically different from a CONNECTION from kernel_pnp (strict arrival).
    """
    out: dict = {
        "vid": None,
        "pid": None,
        "vendor": None,
        "product": None,
        "friendly_name": None,
        "first_install": None,
        "last_arrival": None,
        "last_removal": None,
        "last_observed": None,
        # Partition/Diagnostic observations (fires on both plug and unplug)
        "first_partition_obs": None,
        "last_partition_obs": None,
        # Kernel-PnP — strict semantics
        "first_pnp_arrival": None,
        "last_pnp_arrival": None,
        "first_pnp_removal": None,
        "last_pnp_removal": None,
    }

    for ev in events:
        ref = ev.device_ref
        if ref is not None:
            out["vid"] = out["vid"] or ref.vid
            out["pid"] = out["pid"] or ref.pid

        raw = ev.raw or {}
        out["vendor"] = out["vendor"] or raw.get("vendor") or raw.get("manufacturer")
        out["product"] = out["product"] or raw.get("product") or raw.get("model")
        out["friendly_name"] = out["friendly_name"] or raw.get("friendly_name")

        if ev.ts_kind == TimestampKind.FIRST_INSTALL:
            cur = out["first_install"]
            out["first_install"] = ev.ts if cur is None or ev.ts < cur else cur
        elif ev.ts_kind == TimestampKind.LAST_ARRIVAL:
            cur = out["last_arrival"]
            out["last_arrival"] = ev.ts if cur is None or ev.ts > cur else cur
        elif ev.ts_kind == TimestampKind.LAST_REMOVAL:
            cur = out["last_removal"]
            out["last_removal"] = ev.ts if cur is None or ev.ts > cur else cur
        elif ev.ts_kind == TimestampKind.OBSERVED:
            cur = out["last_observed"]
            out["last_observed"] = ev.ts if cur is None or ev.ts > cur else cur
        elif ev.ts_kind == TimestampKind.CONNECTION:
            if ev.source == SourceKind.EVTX_KERNEL_PNP:
                # Strict plug-in semantics
                cur_first = out["first_pnp_arrival"]
                out["first_pnp_arrival"] = (
                    ev.ts if cur_first is None or ev.ts < cur_first else cur_first
                )
                cur_last = out["last_pnp_arrival"]
                out["last_pnp_arrival"] = (
                    ev.ts if cur_last is None or ev.ts > cur_last else cur_last
                )
            else:
                # Partition observation (may also fire on unplug)
                cur_first = out["first_partition_obs"]
                out["first_partition_obs"] = (
                    ev.ts if cur_first is None or ev.ts < cur_first else cur_first
                )
                cur_last = out["last_partition_obs"]
                out["last_partition_obs"] = (
                    ev.ts if cur_last is None or ev.ts > cur_last else cur_last
                )
        elif ev.ts_kind == TimestampKind.DISCONNECTION:
            cur_first = out["first_pnp_removal"]
            out["first_pnp_removal"] = (
                ev.ts if cur_first is None or ev.ts < cur_first else cur_first
            )
            cur_last = out["last_pnp_removal"]
            out["last_pnp_removal"] = (
                ev.ts if cur_last is None or ev.ts > cur_last else cur_last
            )

    return out


def _timeline_rows(group: list[RawEvent], s: dict) -> list[tuple[str, datetime, list[str]]]:
    """Build (label, ts, sources) tuples for the timeline table."""
    rows: list[tuple[str, datetime, list[str]]] = []

    if s["first_install"]:
        sources = sorted({
            ev.source.value
            for ev in group
            if ev.ts_kind == TimestampKind.FIRST_INSTALL
        })
        rows.append(("Первая установка", s["first_install"], sources))

    if s["last_arrival"]:
        sources = sorted({
            ev.source.value
            for ev in group
            if ev.ts_kind == TimestampKind.LAST_ARRIVAL
        })
        rows.append(("Последнее подключение (реестр)", s["last_arrival"], sources))

    if s["last_removal"]:
        sources = sorted({
            ev.source.value
            for ev in group
            if ev.ts_kind == TimestampKind.LAST_REMOVAL
        })
        rows.append(("Последнее отключение (реестр)", s["last_removal"], sources))

    if s["first_pnp_arrival"]:
        rows.append(
            ("Первое подключение PnP (событие 410)", s["first_pnp_arrival"], ["evtx_kernel_pnp"])
        )
    if s["last_pnp_arrival"] and s["last_pnp_arrival"] != s["first_pnp_arrival"]:
        rows.append(
            ("Последнее подключение PnP (событие 410)", s["last_pnp_arrival"], ["evtx_kernel_pnp"])
        )

    if s["first_pnp_removal"]:
        rows.append(
            ("Первое отключение PnP (событие 430)", s["first_pnp_removal"], ["evtx_kernel_pnp"])
        )
    if s["last_pnp_removal"] and s["last_pnp_removal"] != s["first_pnp_removal"]:
        rows.append(
            ("Последнее отключение PnP (событие 430)", s["last_pnp_removal"], ["evtx_kernel_pnp"])
        )

    return rows


def _pnp_action(event_id) -> str:
    """Human-readable description of a Kernel-PnP event ID."""
    try:
        eid = int(event_id)
    except (ValueError, TypeError):
        return str(event_id)
    return {
        400: "Первая установка / настройка",
        410: "Запущено (драйвер подключён)",
    }.get(eid, f"Неизвестно ({eid})")


def _sources_for_ref_field(events: list[RawEvent], field: str) -> str:
    """Return comma-separated sources whose DeviceRef had a non-None value for `field`."""
    sources: set[str] = set()
    for ev in events:
        if ev.device_ref is None:
            continue
        if getattr(ev.device_ref, field, None) is not None:
            sources.add(ev.source.value)
    return ", ".join(f"`{s}`" for s in sorted(sources)) or "—"


def _sources_for_raw_field(events: list[RawEvent], *field_names: str) -> str:
    """Return comma-separated sources that had any of `field_names` populated in raw."""
    sources: set[str] = set()
    for ev in events:
        raw = ev.raw or {}
        if any(raw.get(name) for name in field_names):
            sources.add(ev.source.value)
    return ", ".join(f"`{s}`" for s in sorted(sources)) or "—"


def _fmt_dt(dt: datetime) -> str:
    """Format datetime as 'YYYY-MM-DD HH:MM:SS UTC' (microseconds dropped for readability)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _fmt_duration(start: datetime, end: datetime | None) -> str:
    """Human-readable duration between start and end, or '—' if end is unknown."""
    if end is None:
        return "—"
    total = int((end - start).total_seconds())
    if total < 0:
        return "—"
    h, rem = divmod(total, 3600)
    m, sec = divmod(rem, 60)
    parts = []
    if h:
        parts.append(f"{h} ч")
    if m:
        parts.append(f"{m} мин")
    parts.append(f"{sec} с")
    return " ".join(parts)


def _end_source_label(session) -> str:
    """Describe where a session's end timestamp came from."""
    if session.end_ts is None:
        return "— (открыта)"
    if session.end_ts_source == "registry_last_removal":
        return "реестровый Last Removal (точно)"
    if session.end_ts_source == "evtx_partition":
        return "хвостовое 1006 (предположительно)"
    return session.end_ts_source or "—"


def _fmt_capacity(value) -> str:
    """Pretty-print a byte count from the EVTX `Capacity` field."""
    if value in (None, "", "-"):
        return "—"
    try:
        n = int(value)
    except (ValueError, TypeError):
        return str(value)

    if n >= 1024 ** 4:
        return f"{n / 1024 ** 4:.2f} ТБ ({n:,} байт)"
    if n >= 1024 ** 3:
        return f"{n / 1024 ** 3:.2f} ГБ ({n:,} байт)"
    if n >= 1024 ** 2:
        return f"{n / 1024 ** 2:.2f} МБ ({n:,} байт)"
    return f"{n:,} байт"
