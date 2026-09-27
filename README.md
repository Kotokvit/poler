# POLER — суверенный стриминговый архиватор

**`.poler`**: гигабайты и терабайты → один файл, **без сырой выгрузки на
диск**. Поток (stdin / сеть / tar) нарезается content-defined чанками
(FastCDC), дедуплицируется по BLAKE3, сжимается zstd (3/15) и пишет
файловую таблицу в трейлер — RAM-дисциплина ~1.1 МБ независимо от объёма.

Извлечено из [poler-engine](https://github.com/poler-engine-org/poler-engine)
v0.61.0 как самостоятельные модули — **без зависимости от движка**
(доказательство: `docs/INDEPENDENCE.md`, включая интероп обеих сторон).

```
tar -c ~/Документы | poler create backup.poler -     # конвейер: 0 temp-файлов
poler create backup.poler ~/Документы                # каталог
poler verify backup.poler                            # SHA-256: поток + каждая запись
poler extract backup.poler ~/restore                 # с защитой от zip-slip
poler cat backup.poler Документы/notes.md            # запись в stdout
poler patch backup.poler --ops 'add config/app.cfg=файл; delete stale.bin'
poler rollback backup.poler                          # откат к .polerbak
```

## POLER BOX — коробка без ОС

`poler-box` — нативная замена Docker'у для исполнения недоверенного
содержимого архивов: userns → pivot_root(tmpfs) → seccomp-белый список →
netns/pidns → губернатор RSS/CPU → `execveat(memfd)`. Образа ОС нет: rootfs
стримится прямо из `.poler`.

```
poler-box safe-extract чужой.poler dir/       # бомба-фильтр + zip-slip
poler-box run чужой.poler payload --rss-mb 512 --cpu-s 60
```

## Формат

FastCDC-чанки 64 КиБ–1 МиБ (цель 256 КиБ) · BLAKE3-дедуп (24 Б/чанк в RAM)
· zstd STORE/ZFAST/ZDEEP · логический индекс 24 Б/чанк · файловая таблица
(имя/смещение/SHA-256) · трейлер 104 Б `POLEREND` · crash-safe
(`.part` → атомарный rename). Полная спецификация: `docs/FORMAT.md`.

## Интеграция в проводники (GUI без GUI-кода)

| Платформа | Как | Файлы |
|---|---|---|
| **Linux: Dolphin / KDE** | ServiceMenus (Extract/Verify/Mount/Box) | `integrations/linux/poler-servicemenu.desktop` |
| **Linux: Nautilus** | скрипты контекстного меню | `install.sh` |
| **Linux: Nemo** | `.nemo_action` | `install.sh` |
| **Linux: Thunar** | uca.xml (custom actions) | `install.sh` |
| **Linux: ВСЕ проводники** | **FUSE: `.poler` = папка** (Dolphin/Nautilus/Nemo/Thunar/PCManFM/Caja/mc/ranger/yazi) | `crates/poler-fuse` |
| **Linux: GUI** | `poler-gui` (yad/zenity: сжать/извлечь/проверить/смонтировать) | `gui/poler-gui` |
| **Windows: Проводник** | контекстное меню (.reg + PowerShell-мост) | `integrations/windows/POLER-Explorer.reg` |
| **Windows: Total Commander** | WCX-плагин: Enter открывает `.poler` | `integrations/windows/poler-wcx` |
| **macOS: Finder** | Quick Action + duti | `integrations/macos/install-macos.sh` |
| **Android** | JNI-библиотека (cargo-ndk) | `integrations/android/README.md` |

Установка на Linux — одна команда:

```bash
git clone https://github.com/Kotokvit/poler && cd poler
cargo build --release
sudo apt install yad libfuse3-dev   # опционально: диалоги + FUSE
bash integrations/linux/install.sh
```

## Сборка и тесты

```bash
cargo build --release              # poler + poler-box (без libfuse)
cargo test -p poler-archive        # 33 теста: round-trip, дедуп, порча, патчинг
cargo build -p poler-fuse          # при наличии libfuse + /dev/fuse
```

Зависимости: zstd, blake3, flate2 (pure-Rust backend), serde, memmap2,
libc — все кроссплатформенные, ноль системных библиотек кроме libfuse для
опционального FUSE.

## Документация

- `docs/FORMAT.md` — байтовая спецификация v1
- `docs/INDEPENDENCE.md` — доказательство автономии от движка + интероп
- `docs/SECURITY.md` — модель угроз: zip-slip, бомбы, недоверенный код

## Статус

- v0.1.0: create/list/info/verify/extract/cat/patch/rollback + BOX
  (run/safe-extract) + интеграции Linux/Windows/macOS/Android
- Roadmap: FUSE-автомаунт в Dolphin, шифрование записей (AES), dual-магия
  чанков для сканирования повреждений хвост-вперёд, feature `winpe`
  (исполнение PE32+ внутри BOX), мобильный просмотрщик на JNI.

---

**POLER Engineering Core** · формат унаследован байт-в-байт от
poler-engine v0.61.0 · лицензия: `LICENSE.md`
