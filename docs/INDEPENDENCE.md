# Доказательство независимости от poler-engine

**Утверждение.** Крейты `poler-archive` и `poler-box` собираются и работают
полностью отдельно от poler-engine: ни одного пути к движку в дереве
зависимостей, ни одной строчки кода движка вне пяти скопированных файлов.

## Происхождение кода

| Файл этого репо | Файл poler-engine v0.61.0 | Правки |
|---|---|---|
| `src/dedup.rs` | `src/archive/dedup.rs` | только пути `use` |
| `src/stream_writer.rs` | `src/archive/stream_writer.rs` | пути `use` |
| `src/reader.rs` | `src/archive/reader.rs` | пути `use` |
| `src/patcher.rs` | `src/archive/patcher.rs` | пути `use` |
| `src/sha256.rs` | `src/pqc/sha256.rs` | ноль правок |
| `poler-box/src/lib.rs` | `src/boxenv/mod.rs` | пути `use` + winpe-shim |
| `poler-box/src/seccomp.rs` | `src/boxenv/seccomp.rs` | ноль правок |

Новый код: `src/ustar.rs` (FS→tar-генератор), CLI-бины, интеграции, тесты.

## Зависимости (весь внешне-крейтовый след)

| Крейт | Версия | Зачем | Движок использует |
|---|---|---|---|
| zstd | 0.13 | сжатие чанков (ярусы 3/15) | да (0.13.3) |
| blake3 | 1.5 | хэш-дедуп чанков | да (1.8.7) |
| flate2 | 1.0 (rust_backend) | CoW-патчер | да (1.1.9) |
| serde/serde_json | 1.0 | JSON-отчёты | да |
| memmap2 | 0.9 | mmap-чтение | да (0.9.11) |
| libc | 0.2 | syscall (pread, box) | да |

fuser (poler-fuse) — опционально, вне default-members.

Ни одна зависимость не ссылается на poler-engine; `Cargo.toml` не содержит
path/git-ссылок на движок. `cargo tree` подтверждает:

```text
poler-archive v0.1.0
├── blake3 v1.x ├── flate2 v1.x ├── libc v0.2 ├── memmap2 v0.9
├── serde v1.0 ├── serde_json v1.0 └── zstd v0.13
```

## Проверки (воспроизводимы)

1. `cargo build` в этом репо — без движка в системе (движок даже не
   установлен в CI-контейнере).
2. `cargo test -p poler-archive` — 27 юнит-тестов движка (переехали вместе
   с файлами) + 7 интеграционных (включая CLI-транскодинг .tar.gz/.tar.zst/
   .tar через реальный бинарник): **34 passed**.
3. **Интероп, обе стороны**:
   - `poler list/verify` на архиве, созданном бинарником
     `poler-engine v0.61.0 --stream-file - --output-archive` → `all_ok: true`;
   - `poler-engine --archive-list` читает архив, созданный standalone
     `poler create` → все записи видны;
   - `poler-engine --poler-extract` распаковывает standalone-архив →
     `files_ok == files`, содержимое бит-в-бит.
4. Магия формата: `MAGIC_START == "POLERARC"`, `MAGIC_END == "POLEREND"`,
   `TRAILER_SIZE == 104` — константы общие с движком (тест
   `magic_bytes_match_engine`).

## Что НЕ вошло (и почему)

- `src/archive/mod.rs` (сканер zip/tar/gz/zst чужих форматов) — это
  компетенция поискового движка, не архиватора; у poler CLI свой листинг.
- `src/winpe/*` (5.7K строк Win64-субстрата) — MVP-детект PE32+ включён,
  полное исполнение PE внутри BOX — feature `winpe` (roadmap).
- License Gate — в v2.0 движка уже удалён; здесь его нет по определению.
