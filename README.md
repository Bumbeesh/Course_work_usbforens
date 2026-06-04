# usbforensics

Утилита криминалистического анализа истории подключений USB Mass Storage устройств и связанной с ними файловой активности на Windows 10.

## Назначение

Tool агрегирует следы работы USB-носителей из артефактов Windows и формирует человеко-читаемый отчёт в Markdown. Решения о квалификации действий (копирование, хищение, и т.п.) принимает эксперт-аналитик, читающий отчёт.

## Требования

- Python 3.12+
- Windows 10 (для self-режима) или любая ОС, способная читать смонтированный NTFS (для drive-режима)
- `uv` для управления зависимостями

## Установка

```powershell
# Установка uv
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

# Зависимости проекта
cd usbforensics
uv sync
```

## Использование

```powershell
# Анализ распакованных артефактов (рабочий режим)
uv run usbforensics drive --path C:\path\to\artifacts --output report.md

# Подробный лог хода парсинга
uv run usbforensics drive --path C:\path\to\artifacts -v
```

`--path` указывает на корень со стандартной раскладкой Windows. Tool прогоняет
все парсеры, коррелирует факты в сущности `Device`/`Volume`/`Session` и пишет
Markdown-отчёт (по умолчанию `usbforensics_report.md`).

### Ожидаемая раскладка артефактов под `--path`

```
Windows/System32/config/SYSTEM                         # реестр: USB/USBSTOR, MountedDevices
Windows/System32/winevt/Logs/*.evtx                    # Partition/Diagnostic, Kernel-PnP
Windows/INF/setupapi.dev.log                           # первая установка
Windows/Prefetch/*.pf                                  # (для будущего prefetch-парсера)
Users/<user>/NTUSER.DAT                                # MountPoints2 (атрибуция пользователя)
Users/<user>/AppData/Local/Microsoft/Windows/UsrClass.dat            # shellbags
Users/<user>/AppData/Roaming/Microsoft/Windows/Recent/*.lnk          # открытые файлы
```

Кусты реестра (`SYSTEM`, `NTUSER.DAT`, `UsrClass.dat`) на живой системе
заблокированы — доставать их следует из VSS-снапшота. `.lnk`/`.evtx`/`.pf` —
обычные файлы.

### Режимы

```
usbforensics drive --path <dir>          # распакованные артефакты / смонтированный диск (работает)
usbforensics self                        # self-triage активной системы (TODO, Phase 4)
usbforensics image --path image.E01      # анализ образа диска (TODO, Phase 4)
```

## Архитектура

Четырёхслойный pipeline:

1. **Acquisition** (`sources/`) — чтение артефактов: `MountedDriveSource` (готов), `LiveSystemSource`/`ImageFileSource` (TODO)
2. **Parsing** (`parsers/`) — извлечение атомарных `RawEvent`-ов из каждого артефакта (корреляцию не делают)
3. **Correlation** (`correlation/engine.py`) — построение `Device`/`Volume`/`Session`; привязка файлов и папок к сессиям; атрибуция пользователя
4. **Reporting** (`reporting/`) — рендеринг Markdown-отчёта со сводкой по каждому устройству

## Реализованные парсеры

| Парсер | Артефакт | Что даёт |
|---|---|---|
| `registry_usb` | SYSTEM: Enum\USB, USBSTOR + Properties | VID/PID/iSerial, install/arrival/removal |
| `registry_mounted_devices` | SYSTEM: MountedDevices | мост том ↔ буква диска / Volume GUID |
| `registry_mount_points_2` | NTUSER: MountPoints2 | атрибуция: какой пользователь монтировал том |
| `setupapi` | setupapi.dev.log | дата первой установки |
| `evtx_partition` | Partition/Diagnostic 1006 | подключения, ёмкость, том |
| `kernel_pnp` | Kernel-PnP 400/410 | строгие arrival-события (границы сессий) |
| `lnk` | Recent\*.lnk | файлы, открытые пользователем (временна́я привязка) |
| `shellbags` | UsrClass: BagMRU | папки, по которым лазили (прямая привязка по букве) |

Корреляция собирает из этого по каждому устройству сводку **кто / когда / что**:
пользователь, сессии подключения, файлы, активные в окне сессии, и папки,
просмотренные на самом устройстве. Tool агрегирует факты; квалификацию действий
(копирование, хищение и т.п.) делает аналитик.

## Тесты

```powershell
uv run --extra dev pytest -q
```

## Сборка автономного .exe

Собирает единый исполняемый файл `dist/usbforensics.exe`, не требующий
установленного Python или зависимостей:

```powershell
uv run --extra dev pyinstaller --onefile --name usbforensics `
  --collect-all pydantic --collect-all regipy `
  --collect-submodules Evtx --collect-submodules pylnk3 --collect-submodules usbforensics `
  --distpath dist --workpath build_pyi --specpath build_pyi -y pyi_entry.py
```

Запуск собранного файла:

```powershell
.\dist\usbforensics.exe drive --path C:\path\to\artifacts
```

## Дальнейшие планы

- **prefetch / amcache** — следы запуска программ (в т.ч. с USB)
- **Phase 4 (NTFS)** — `LiveSystemSource`/`ImageFileSource` через `pytsk3`, парсеры `$MFT`/`$UsnJrnl`; включает режимы `self` и `image`
- **Phase 5** — сборка автономного `.exe` через PyInstaller
