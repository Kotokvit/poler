//! POLER — суверенный стриминговый архиватор формата `.poler`.
//!
//! Крейт извлечён из poler-engine v0.61.0 (`src/archive/{dedup,
//! stream_writer, reader, patcher}.rs` + `src/pqc/sha256.rs`) и собирается
//! полностью самостоятельно: **ноль зависимостей от движка**, только
//! общедоступные крейты (zstd/blake3/flate2/memmap2/serde/libc).
//!
//! Формат v1 (байт-точно как у движка):
//! ```text
//! [0..8)   magic "POLERARC"
//! [8..)    физические чанки: blake3[32] raw_len u32 stored_len u32
//!          method u8 pad[3] payload[stored_len]   (method: 0 store,
//!          1 zstd-3, 2 zstd-15)
//! ...      логический индекс (24 Б/чанк): raw_off u64 stored_off u64
//!          raw_len u32 pad u32
//! ...      файловая таблица: name_len u16 name raw_off u64 raw_len u64
//!          sha256[32]
//! [конец-104..конец) трейлер "POLEREND"
//! ```
//! Все числа little-endian. Запись crash-safe: `.poler.part` → атомарный
//! rename. Чтение: mmap, O(log n) доступ к любому байту. Распаковка:
//! защита от zip-slip (`safe_rel_path`) + SHA-256 каждой записи.

pub mod dedup;
pub mod patcher;
pub mod reader;
pub mod sha256;
pub mod stream_writer;
pub mod ustar;

pub use dedup::{chunk_hash, cut_point, split_chunks, ChunkDedup, CdcParams};
pub use patcher::{
    bak_path, patch_archive, rollback_archive, PatchKind, PatchOp, PatchOptions, PatchReport,
    RollbackReport,
};
pub use reader::{ExtractReport, PolerFile, PolerInfo, PolerLayout, PolerReader, VerifyReport};
pub use ustar::FsTarReader;
pub use stream_writer::{
    fmt_bytes, peak_rss_kb, write_stream, CompressTier, StreamWriteConfig, StreamWriteStats,
    StreamWriter, SyntheticStream, MAGIC_END, MAGIC_START, TRAILER_SIZE,
};
