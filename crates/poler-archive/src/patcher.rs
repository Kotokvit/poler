//! In-place CoW-патчер `.poler`: замена/добавление/удаление записей
//! БЕЗ распаковки архива на диск (zero-disk constraint).
//!
//! ## Принцип Copy-on-Write
//!
//! Физические чанки иммутабельны. Новые данные нарезаются FastCDC,
//! сжимаются и **аппендятся поверх старого трейлера**; логический
//! индекс и файловая таблица переливаются заново следом; трейлер
//! перезаписывается последним (104 Б в самом конце файла). Заменённые
//! старые чанки остаются в потоке «мёртвыми» байтами — читатель их
//! не видит, а дедупликация будущих патчей может найти и оживить.
//!
//! ## Инварианты формата (сохраняются патчем)
//!
//! 1. Логический индекс отсортирован по `raw_off` и непрерывен:
//!    новые чанки продолжают сырой поток от `old_total_raw`.
//! 2. Каждая запись файловой таблицы указывает внутрь `[0, total_raw)`.
//! 3. `stream_sha256` в трейлере — честный SHA256 всего логического
//!    потока (старые чанки, включая мёртвые, + новые данные):
//!    пересчитывается при каждом патче, `--poler-verify` сходится.
//!
//! ## Откат
//!
//! Перед мутацией пишется `<archive>.polerbak` (120 Б: magic POLERBAK,
//! старая длина, старый трейлер). `--poler-rollback` восстанавливает
//! трейлер и усекает файл: байты исходника возвращаются дословно.

use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::dedup::{chunk_hash, split_chunks, ChunkDedup, CdcParams};
use crate::reader::PolerReader;
use crate::stream_writer::{
    peak_rss_kb, StreamWriter, CHUNK_HEADER_SIZE, CompressTier, MAGIC_END, METHOD_STORE,
    METHOD_ZFAST, METHOD_ZDEEP, POLER_VERSION, TRAILER_SIZE, INDEX_ENTRY_SIZE,
};
use crate::sha256::{hex, sha256, Sha256};

pub const BAK_MAGIC: &[u8; 8] = b"POLERBAK";
pub const BAK_RECORD_SIZE: usize = 8 + 8 + TRAILER_SIZE;

// ────────────────────────── Операции ──────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchKind {
    Replace,
    Add,
    Delete,
}

#[derive(Debug, Clone)]
pub struct PatchOp {
    pub kind: PatchKind,
    pub name: String,
    /// Новое содержимое (Replace/Add). У Delete — пусто.
    pub data: Vec<u8>,
}

impl PatchOp {
    pub fn replace(name: impl Into<String>, data: Vec<u8>) -> PatchOp {
        PatchOp { kind: PatchKind::Replace, name: name.into(), data }
    }
    pub fn add(name: impl Into<String>, data: Vec<u8>) -> PatchOp {
        PatchOp { kind: PatchKind::Add, name: name.into(), data }
    }
    pub fn delete(name: impl Into<String>) -> PatchOp {
        PatchOp { kind: PatchKind::Delete, name: name.into(), data: Vec::new() }
    }
}

#[derive(Debug, Clone)]
pub struct PatchOptions {
    pub cdc: CdcParams,
    pub tier: CompressTier,
    /// Перезаписать существующий `.polerbak` вместо отказа.
    pub force_bak: bool,
}

impl Default for PatchOptions {
    fn default() -> Self {
        PatchOptions {
            cdc: CdcParams::default(),
            tier: CompressTier::Auto,
            force_bak: false,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PatchReport {
    pub archive: String,
    pub ops_applied: u64,
    pub files_before: u64,
    pub files_after: u64,
    pub new_chunks_written: u64,
    pub new_chunks_deduped: u64,
    pub logical_chunks: u64,
    pub physical_chunks: u64,
    pub total_raw: u64,
    pub old_len: u64,
    pub new_len: u64,
    pub stream_sha256_hex: String,
    pub rehashed_bytes: u64,
    pub elapsed_ms: u64,
    pub peak_rss_kb: u64,
    pub backup: String,
}

pub fn bak_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".polerbak");
    PathBuf::from(s)
}

// ────────────────────────── Патч ──────────────────────────

/// Применить операции in-place (Copy-on-Write). Все проверки — до
/// первой мутации: невалидный манифест не трогает ни одного байта.
pub fn patch_archive(
    path: &Path,
    ops: &[PatchOp],
    opts: &PatchOptions,
) -> Result<PatchReport, String> {
    let started = std::time::Instant::now();
    if ops.is_empty() {
        return Err("пустой список операций".to_string());
    }

    let reader = PolerReader::open(path)?;
    let layout = reader.layout();
    let files_before = reader.info().files;

    // ── валидация (до мутации) ──
    let mut seen = HashSet::new();
    for op in ops {
        if op.name.is_empty() {
            return Err("пустое имя записи".to_string());
        }
        if op.name.len() > u16::MAX as usize {
            return Err(format!("имя длиннее {}: {}", u16::MAX, op.name));
        }
        if !seen.insert(op.name.clone()) {
            return Err(format!("дубль операции над {}", op.name));
        }
        let exists = reader.find_file(&op.name).is_some();
        match op.kind {
            PatchKind::Replace => {
                if !exists {
                    return Err(format!("replace: записи {} нет в архиве", op.name));
                }
            }
            PatchKind::Add => {
                if exists {
                    return Err(format!("add: запись {} уже существует", op.name));
                }
                if op.name.starts_with('/') || op.name.split('/').any(|c| c == "..") {
                    return Err(format!("add: небезопасное имя {}", op.name));
                }
            }
            PatchKind::Delete => {
                if !exists {
                    return Err(format!("delete: записи {} нет в архиве", op.name));
                }
            }
        }
    }

    // ── бэкап точки отката ──
    let bak = bak_path(path);
    if bak.exists() && !opts.force_bak {
        return Err(format!(
            "{} существует: сначала --poler-rollback или --force-bak",
            bak.display()
        ));
    }
    let old_trailer = reader
        .raw_region(layout.file_len - TRAILER_SIZE as u64, TRAILER_SIZE as u64)
        .ok_or("mmap: трейлер вне файла")?;
    {
        let mut b = Vec::with_capacity(BAK_RECORD_SIZE);
        b.extend_from_slice(BAK_MAGIC);
        b.extend_from_slice(&layout.file_len.to_le_bytes());
        b.extend_from_slice(old_trailer);
        std::fs::write(&bak, &b).map_err(|e| format!("bak: {e}"))?;
    }

    // ── write-хендл + ОТДЕЛЬНЫЙ read-хендл для дедуп-верификации ──
    // КРИТИЧНО: позиционированное чтение (Windows seek_read) двигает файловый
    // курсор — pread через write-хендл затирал бы записанное (BufWriter пишет
    // по курсору). Поэтому дедуп-верификация читает через отдельный
    // read-only хендл того же файла.
    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| format!("open w {}: {e}", path.display()))?;
    file.seek(SeekFrom::Start(layout.file_len - TRAILER_SIZE as u64))
        .map_err(|e| format!("seek: {e}"))?;
    let mut out = BufWriter::with_capacity(1024 * 1024, file);
    let readback = std::fs::File::open(path)
        .map_err(|e| format!("open r {}: {e}", path.display()))?;

    // ── дедуп-реестр старых физических чанков ──
    let mut dedup = ChunkDedup::new();
    {
        let mut uniq = HashSet::new();
        for (_, stored_off, _) in reader.logical_entries() {
            if uniq.insert(stored_off) {
                let hash = reader
                    .physical_blake3(stored_off)
                    .ok_or_else(|| format!("заголовок чанка {stored_off} вне файла"))?;
                dedup.insert(&hash, stored_off);
            }
        }
    }
    let old_physical = layout.physical_chunks;

    // ── новые данные: CDC + сжатие + дедуп ──
    struct NewFile {
        name: String,
        raw_off: u64,
        raw_len: u64,
        sha256: [u8; 32],
    }
    let mut next_raw = layout.total_raw;
    let mut write_pos = layout.file_len - TRAILER_SIZE as u64;
    let mut logical_new: Vec<(u64, u64, u32)> = Vec::new();
    let mut new_files: Vec<NewFile> = Vec::new();
    let mut physical_new: u64 = 0;
    let mut deduped_new: u64 = 0;

    let mut fast: Option<zstd::bulk::Compressor<'static>> = None;
    let mut deep: Option<zstd::bulk::Compressor<'static>> = None;
    let compress = |raw: &[u8],
                    tier: CompressTier,
                    fast: &mut Option<zstd::bulk::Compressor<'static>>,
                    deep: &mut Option<zstd::bulk::Compressor<'static>>|
     -> Result<(u8, Vec<u8>), String> {
        if raw.len() < 512 {
            return Ok((METHOD_STORE, raw.to_vec()));
        }
        let z = |lvl: i32,
                 slot: &mut Option<zstd::bulk::Compressor<'static>>,
                 m: &str|
         -> Result<Vec<u8>, String> {
            if slot.is_none() {
                *slot = Some(
                    zstd::bulk::Compressor::new(lvl)
                        .map_err(|e| format!("zstd {lvl} {m}: {e}"))?,
                );
            }
            slot.as_mut().unwrap().compress(raw).map_err(|e| format!("zstd: {e}"))
        };
        match tier {
            CompressTier::Fast => {
                let c = z(3, fast, "fast")?;
                Ok(if c.len() < raw.len() * 15 / 16 {
                    (METHOD_ZFAST, c)
                } else {
                    (METHOD_STORE, raw.to_vec())
                })
            }
            CompressTier::Deep => {
                let c = z(15, deep, "deep")?;
                Ok(if c.len() < raw.len() * 15 / 16 {
                    (METHOD_ZDEEP, c)
                } else {
                    (METHOD_STORE, raw.to_vec())
                })
            }
            CompressTier::Auto => {
                let c3 = z(3, fast, "fast")?;
                if c3.len() >= raw.len() * 15 / 16 {
                    return Ok((METHOD_STORE, raw.to_vec()));
                }
                if c3.len() <= raw.len() / 2 {
                    let c15 = z(15, deep, "deep")?;
                    if c15.len() < c3.len() {
                        return Ok((METHOD_ZDEEP, c15));
                    }
                }
                Ok((METHOD_ZFAST, c3))
            }
        }
    };

    let _ = &out; // write-хендл больше не читается: дедуп-верификация — через отдельный readback
    for op in ops {
        if op.kind == PatchKind::Delete {
            continue;
        }
        let file_raw_off = next_raw;
        for chunk in split_chunks(&op.data, &opts.cdc) {
            let hash = chunk_hash(chunk);
            let raw_len = chunk.len() as u32;
            let raw_off = next_raw;
            next_raw += chunk.len() as u64;
            if let Some(stored_off) = dedup.lookup(&hash, &readback) {
                logical_new.push((raw_off, stored_off, raw_len));
                deduped_new += 1;
                continue;
            }
            let (method, payload) =
                compress(chunk, opts.tier, &mut fast, &mut deep)?;
            let stored_off = write_pos;
            let mut hdr = [0u8; CHUNK_HEADER_SIZE];
            hdr[0..32].copy_from_slice(&hash);
            hdr[32..36].copy_from_slice(&raw_len.to_le_bytes());
            hdr[36..40].copy_from_slice(&(payload.len() as u32).to_le_bytes());
            hdr[40] = method;
            out.write_all(&hdr).map_err(|e| format!("write hdr: {e}"))?;
            out.write_all(&payload).map_err(|e| format!("write payload: {e}"))?;
            write_pos += (CHUNK_HEADER_SIZE + payload.len()) as u64;
            logical_new.push((raw_off, stored_off, raw_len));
            dedup.insert(&hash, stored_off);
            physical_new += 1;
        }
        new_files.push(NewFile {
            name: op.name.clone(),
            raw_off: file_raw_off,
            raw_len: op.data.len() as u64,
            sha256: sha256(&op.data),
        });
    }

    // ── новый логический индекс: старые entries + новые ──
    let index_off_new = write_pos;
    {
        let region = reader
            .raw_region(layout.index_off, layout.index_len)
            .ok_or("mmap: старый индекс вне файла")?;
        for block in region.chunks(256 * 1024) {
            out.write_all(block).map_err(|e| format!("copy index: {e}"))?;
        }
    }
    let mut entry_buf = [0u8; 24];
    for (raw_off, stored_off, raw_len) in &logical_new {
        entry_buf[0..8].copy_from_slice(&raw_off.to_le_bytes());
        entry_buf[8..16].copy_from_slice(&stored_off.to_le_bytes());
        entry_buf[16..20].copy_from_slice(&raw_len.to_le_bytes());
        out.write_all(&entry_buf).map_err(|e| format!("write index: {e}"))?;
    }
    let index_len_new = layout.index_len + (logical_new.len() as u64) * INDEX_ENTRY_SIZE as u64;
    write_pos = index_off_new + index_len_new;

    // ── новая файловая таблица (стримингово) ──
    let files_off_new = write_pos;
    let mut files_len_new: u64 = 0;
    {
        let region = reader
            .raw_region(layout.files_off, layout.files_len)
            .ok_or("mmap: старая таблица вне файла")?;
        let by_name: HashMap<&str, &NewFile> =
            new_files.iter().map(|f| (f.name.as_str(), f)).collect();
        let delete_set: HashSet<&str> = ops
            .iter()
            .filter(|o| o.kind == PatchKind::Delete)
            .map(|o| o.name.as_str())
            .collect();

        let mut p = 0usize;
        let mut rec = Vec::with_capacity(4096);
        while p < region.len() {
            let rec_start = p;
            if p + 2 > region.len() {
                return Err("таблица: обрыв name_len".to_string());
            }
            let name_len = u16::from_le_bytes([region[p], region[p + 1]]) as usize;
            p += 2;
            if p + name_len + 48 > region.len() {
                return Err("таблица: обрыв записи".to_string());
            }
            let name = String::from_utf8_lossy(&region[p..p + name_len]).to_string();
            p += name_len + 48; // raw_off + raw_len + sha256
            if delete_set.contains(name.as_str()) {
                continue; // удаление: запись не переносится
            }
            if let Some(nf) = by_name.get(name.as_str()) {
                // замена: новая запись с тем же именем
                rec.clear();
                rec.extend_from_slice(&(nf.name.len() as u16).to_le_bytes());
                rec.extend_from_slice(nf.name.as_bytes());
                rec.extend_from_slice(&nf.raw_off.to_le_bytes());
                rec.extend_from_slice(&nf.raw_len.to_le_bytes());
                rec.extend_from_slice(&nf.sha256);
                out.write_all(&rec).map_err(|e| format!("write rec: {e}"))?;
                files_len_new += rec.len() as u64;
            } else {
                // нетронутая запись: сырые байты как есть
                let bytes = &region[rec_start..p];
                out.write_all(bytes).map_err(|e| format!("copy rec: {e}"))?;
                files_len_new += bytes.len() as u64;
            }
        }
        // добавленные записи — в конец таблицы
        for op in ops {
            if op.kind != PatchKind::Add {
                continue;
            }
            let nf = new_files
                .iter()
                .find(|f| f.name == op.name)
                .expect("add-файл записан выше");
            rec.clear();
            rec.extend_from_slice(&(nf.name.len() as u16).to_le_bytes());
            rec.extend_from_slice(nf.name.as_bytes());
            rec.extend_from_slice(&nf.raw_off.to_le_bytes());
            rec.extend_from_slice(&nf.raw_len.to_le_bytes());
            rec.extend_from_slice(&nf.sha256);
            out.write_all(&rec).map_err(|e| format!("write add rec: {e}"))?;
            files_len_new += rec.len() as u64;
        }
    }
    write_pos += files_len_new;

    // ── честный пересчёт SHA256 логического потока ──
    let mut h = Sha256::new();
    let mut rehashed: u64 = 0;
    reader.for_each_chunk(|_, data| {
        h.update(data);
        rehashed += data.len() as u64;
        Ok(())
    })?;
    for op in ops {
        if op.kind != PatchKind::Delete {
            h.update(&op.data);
            rehashed += op.data.len() as u64;
        }
    }
    let stream_digest = h.finalize();

    // ── новый трейлер ──
    let logical_total = layout.logical_chunks + logical_new.len() as u64;
    let physical_total = old_physical + physical_new;
    let total_raw_new = next_raw;
    let final_len = write_pos + TRAILER_SIZE as u64;
    let mut trailer = [0u8; TRAILER_SIZE];
    trailer[0..8].copy_from_slice(MAGIC_END);
    trailer[8..10].copy_from_slice(&POLER_VERSION.to_le_bytes());
    let mut flags: u16 = 0;
    if layout.dedup {
        flags |= 1;
    }
    if layout.tar_mode {
        flags |= 2;
    }
    trailer[10..12].copy_from_slice(&flags.to_le_bytes());
    trailer[12..16].copy_from_slice(&(logical_total as u32).to_le_bytes());
    trailer[16..20].copy_from_slice(&(physical_total as u32).to_le_bytes());
    trailer[20..28].copy_from_slice(&index_off_new.to_le_bytes());
    trailer[28..36].copy_from_slice(&index_len_new.to_le_bytes());
    trailer[36..44].copy_from_slice(&files_off_new.to_le_bytes());
    trailer[44..52].copy_from_slice(&files_len_new.to_le_bytes());
    trailer[52..60].copy_from_slice(&total_raw_new.to_le_bytes());
    trailer[60..68].copy_from_slice(&final_len.to_le_bytes());
    trailer[68..100].copy_from_slice(&stream_digest);
    out.write_all(&trailer).map_err(|e| format!("write trailer: {e}"))?;
    let file = out.into_inner().map_err(|e| format!("flush: {e}"))?;
    file.set_len(final_len).map_err(|e| format!("truncate: {e}"))?;
    file.sync_all().map_err(|e| format!("sync: {e}"))?;
    drop(file);
    drop(reader);

    let files_after = (files_before as i64
        + ops.iter().filter(|o| o.kind == PatchKind::Add).count() as i64
        - ops.iter().filter(|o| o.kind == PatchKind::Delete).count() as i64)
        .max(0) as u64;

    Ok(PatchReport {
        archive: path.display().to_string(),
        ops_applied: ops.len() as u64,
        files_before,
        files_after,
        new_chunks_written: physical_new,
        new_chunks_deduped: deduped_new,
        logical_chunks: logical_total,
        physical_chunks: physical_total,
        total_raw: total_raw_new,
        old_len: layout.file_len,
        new_len: final_len,
        stream_sha256_hex: hex(&stream_digest),
        rehashed_bytes: rehashed,
        elapsed_ms: started.elapsed().as_millis() as u64,
        peak_rss_kb: peak_rss_kb(),
        backup: bak.display().to_string(),
    })
}

// ────────────────────────── Откат ──────────────────────────

#[derive(Debug, Clone, serde::Serialize)]
pub struct RollbackReport {
    pub archive: String,
    pub restored_len: u64,
}

/// Откатить последний патч: трейлер из `.polerbak` + усечение.
pub fn rollback_archive(path: &Path) -> Result<RollbackReport, String> {
    let bak = bak_path(path);
    let buf = std::fs::read(&bak).map_err(|e| format!("{}: {e}", bak.display()))?;
    if buf.len() != BAK_RECORD_SIZE || &buf[0..8] != BAK_MAGIC {
        return Err(format!("{}: не является бэкапом .poler", bak.display()));
    }
    let old_len = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| format!("open w {}: {e}", path.display()))?;
    file.seek(SeekFrom::Start(old_len - TRAILER_SIZE as u64))
        .map_err(|e| format!("seek: {e}"))?;
    file.write_all(&buf[16..])
        .map_err(|e| format!("write trailer: {e}"))?;
    file.set_len(old_len).map_err(|e| format!("truncate: {e}"))?;
    file.sync_all().map_err(|e| format!("sync: {e}"))?;
    drop(file);
    std::fs::remove_file(&bak).map_err(|e| format!("remove bak: {e}"))?;
    Ok(RollbackReport { archive: path.display().to_string(), restored_len: old_len })
}

// ────────────────────────── Чтение записи (cat) ──────────────────────────

/// Содержимое записи в Vec (для CLI `--poler-cat` и тестов).
pub fn cat_file(path: &Path, name: &str, out: &mut Vec<u8>) -> Result<u64, String> {
    let reader = PolerReader::open(path)?;
    let f = reader.find_file(name).ok_or_else(|| format!("записи {name} нет в архиве"))?;
    let mut off = f.raw_off;
    let end = f.raw_off + f.raw_len;
    // read_range очищает свой буфер на каждом вызове — копим отдельно.
    let mut piece = Vec::new();
    while off < end {
        let step = ((end - off) as usize).min(1024 * 1024);
        piece.clear();
        reader.read_range(off, step, &mut piece)?;
        if piece.len() != step {
            return Err(format!(
                "{name}: прочитано {} из {} на смещении {off}",
                piece.len(),
                step
            ));
        }
        out.extend_from_slice(&piece);
        off += step as u64;
    }
    Ok(f.raw_len)
}

// ────────────────────────── Ремукс: tar.gz-блоб → tar_mode ──────────────────────────

/// io::Read-адаптер над записью `.poler`: последовательные куски
/// `read_range` по 256 КиБ (разжимаются только покрывающие чанки,
/// RAM ≈ 256 КиБ + 1 чанк на любую длину записи).
pub struct EntryStreamReader<'a> {
    reader: &'a PolerReader,
    off: u64,
    end: u64,
    buf: Vec<u8>,
    pos: usize,
}

impl<'a> EntryStreamReader<'a> {
    pub fn new(reader: &'a PolerReader, off: u64, len: u64) -> Self {
        EntryStreamReader { reader, off, end: off + len, buf: Vec::new(), pos: 0 }
    }
}

impl std::io::Read for EntryStreamReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.buf.len() {
            if self.off >= self.end {
                return Ok(0);
            }
            let want = ((self.end - self.off) as usize).min(256 * 1024);
            self.reader
                .read_range(self.off, want, &mut self.buf)
                .map_err(|e| std::io::Error::other(e))?;
            self.pos = 0;
            self.off += want as u64;
        }
        let n = (self.buf.len() - self.pos).min(out.len());
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// Ремукс `.poler` с единственной gzip-записью (tar.gz) в `.poler`
/// с файловой таблицей tar_mode: сырой tar-поток нарезается CDC,
/// дедуплицируется и сжимается заново. Zero-disk: ни распаковки на
/// диск, ни полной загрузки в RAM. После ремукса патчи отдельных
/// файлов становятся CoW-операциями за секунды.
pub fn remux_archive(
    src: &Path,
    out: &Path,
    cfg: crate::stream_writer::StreamWriteConfig,
) -> Result<crate::stream_writer::StreamWriteStats, String> {
    let reader = PolerReader::open(src)?;
    if reader.files().len() != 1 {
        return Err(format!(
            "remux: ожидается одна gzip-запись, найдено {} (см. --poler-list)",
            reader.files().len()
        ));
    }
    let f = &reader.files()[0];
    let mut magic = Vec::new();
    reader.read_range(f.raw_off, 2usize.min(f.raw_len as usize), &mut magic)?;
    let gz = magic.len() == 2 && magic[0] == 0x1f && magic[1] == 0x8b;
    if !gz {
        return Err(format!(
            "remux: запись {} не является gzip (магия {:02x?})",
            f.name, magic
        ));
    }

    let mut w = StreamWriter::open(out, cfg).map_err(|e| format!("open out: {e}"))?;
    let entry = EntryStreamReader::new(&reader, f.raw_off, f.raw_len);
    let mut stream: Box<dyn std::io::Read> =
        Box::new(flate2::read::MultiGzDecoder::new(entry));
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = stream
            .read(&mut buf)
            .map_err(|e| format!("gunzip: {e}"))?;
        if n == 0 {
            break;
        }
        w.push_bytes(&buf[..n]).map_err(|e| format!("push: {e}"))?;
    }
    let hint = f.name.trim_end_matches(".gz").to_string();
    w.finish(&hint).map_err(|e| format!("finish: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream_writer::{StreamWriter, StreamWriteConfig};

    fn tmp_tag() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let pid = std::process::id();
        format!("polerpatch-{}-{}", pid, N.fetch_add(1, Ordering::SeqCst))
    }

    /// ustar-заголовок (512 Б) для тестового tar.
    fn tar_header(name: &str, size: usize) -> Vec<u8> {
        let mut h = vec![0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..108].copy_from_slice(b"0000644\0"); // mode
        h[108..116].copy_from_slice(b"0000000\0"); // uid
        h[116..124].copy_from_slice(b"0000000\0"); // gid
        let mut oct = format!("{:011o}\0", size);
        oct.truncate(12);
        h[124..136].copy_from_slice(oct.as_bytes()); // size
        h[136..148].copy_from_slice(b"00000000000\0"); // mtime
        h[148..156].copy_from_slice(b"        "); // checksum placeholder
        h[156] = b'0'; // typeflag: regular
        h[257..263].copy_from_slice(b"ustar\0"); // magic
        h[263..265].copy_from_slice(b"00"); // version
        // checksum: сумма всех байт при нулёвых 148..156, 6 цифр + NUL + пробел
        let sum: u32 = h.iter().map(|&b| b as u32).sum();
        let cs = format!("{:06o}\0 ", sum);
        h[148..156].copy_from_slice(cs.as_bytes());
        h
    }

    fn make_tar(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut tar = Vec::new();
        for (name, data) in files {
            tar.extend_from_slice(&tar_header(name, data.len()));
            tar.extend_from_slice(data);
            let pad = (512 - data.len() % 512) % 512;
            tar.extend(std::iter::repeat(0u8).take(pad));
        }
        tar.extend(std::iter::repeat(0u8).take(1024)); // конец архива
        tar
    }

    fn build_archive(dir: &std::path::Path, files: &[(&str, &[u8])]) -> PathBuf {
        let tar = make_tar(files);
        let out = dir.join("test.poler");
        let mut w = StreamWriter::open(&out, StreamWriteConfig::default()).unwrap();
        w.push_bytes(&tar).unwrap();
        w.finish("main.tar").unwrap();
        out
    }

    fn tmpdir() -> PathBuf {
        let d = std::env::temp_dir().join(tmp_tag());
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn read_entry(path: &Path, name: &str) -> Vec<u8> {
        let mut v = Vec::new();
        cat_file(path, name, &mut v).unwrap();
        v
    }

    fn text(len: usize, seed: u8) -> Vec<u8> {
        (0..len).map(|i| b'a' + ((i as u32 * (seed as u32 + 7)) % 26) as u8).collect()
    }

    #[test]
    fn replace_grow_and_shrink() {
        let d = tmpdir();
        let a = text(50_000, 1);
        let b = text(150_000, 2);
        let c = text(3_000, 3);
        let arch = build_archive(&d, &[("dir/a.txt", &a), ("dir/b.bin", &b), ("c.txt", &c)]);

        let bigger = text(400_000, 9);
        let rep = patch_archive(
            &arch,
            &[PatchOp::replace("dir/b.bin", bigger.clone())],
            &PatchOptions::default(),
        )
        .unwrap();
        assert_eq!(rep.ops_applied, 1);
        assert_eq!(rep.files_before, 3);
        assert_eq!(rep.files_after, 3);
        assert!(rep.new_chunks_written > 0);

        assert_eq!(read_entry(&arch, "dir/b.bin"), bigger);
        assert_eq!(read_entry(&arch, "dir/a.txt"), a);
        assert_eq!(read_entry(&arch, "c.txt"), c);

        let reader = PolerReader::open(&arch).unwrap();
        let vr = reader.verify().unwrap();
        assert!(vr.all_ok, "verify после replace: {:?}", vr.files_bad);

        // повторная замена — меньшим файлом
        let smaller = text(10, 4);
        patch_archive(
            &arch,
            &[PatchOp::replace("dir/b.bin", smaller.clone())],
            &PatchOptions { force_bak: true, ..Default::default() },
        )
        .unwrap();
        assert_eq!(read_entry(&arch, "dir/b.bin"), smaller);
        let reader = PolerReader::open(&arch).unwrap();
        assert!(reader.verify().unwrap().all_ok);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn add_and_delete() {
        let d = tmpdir();
        let a = text(1000, 1);
        let arch = build_archive(&d, &[("a.txt", &a)]);

        let new_data = text(200_000, 5);
        patch_archive(
            &arch,
            &[
                PatchOp::add("sub/new.txt", new_data.clone()),
                PatchOp::delete("a.txt"),
            ],
            &PatchOptions::default(),
        )
        .unwrap();

        let reader = PolerReader::open(&arch).unwrap();
        assert_eq!(reader.files().len(), 1);
        assert_eq!(reader.files()[0].name, "sub/new.txt");
        assert!(reader.verify().unwrap().all_ok);
        assert_eq!(read_entry(&arch, "sub/new.txt"), new_data);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn dedup_identical_content_writes_nothing() {
        let d = tmpdir();
        let a = text(300_000, 3);
        let arch = build_archive(&d, &[("a.txt", &a)]);

        // Дедуп работает на уровне CDC-чанков: повторная запись тех же
        // данных тем же патчем находит все чанки предыдущей замены.
        let payload = text(300_000, 9);
        let opts = PatchOptions::default();
        patch_archive(&arch, &[PatchOp::replace("a.txt", payload.clone())], &opts).unwrap();
        let rep = patch_archive(
            &arch,
            &[PatchOp::replace("a.txt", payload.clone())],
            &PatchOptions { force_bak: true, ..Default::default() },
        )
        .unwrap();
        assert_eq!(rep.new_chunks_written, 0, "повторный патч не пишет ни чанка");
        assert!(rep.new_chunks_deduped > 0);
        assert_eq!(read_entry(&arch, "a.txt"), payload);
        let reader = PolerReader::open(&arch).unwrap();
        assert!(reader.verify().unwrap().all_ok);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rollback_restores_bytes() {
        let d = tmpdir();
        let a = text(80_000, 1);
        let arch = build_archive(&d, &[("a.txt", &a)]);
        let before = std::fs::read(&arch).unwrap();

        patch_archive(
            &arch,
            &[PatchOp::replace("a.txt", text(120_000, 7))],
            &PatchOptions::default(),
        )
        .unwrap();
        assert!(bak_path(&arch).exists());

        let rb = rollback_archive(&arch).unwrap();
        assert_eq!(rb.restored_len, before.len() as u64);
        let after = std::fs::read(&arch).unwrap();
        assert_eq!(before, after, "откат восстанавливает байты дословно");
        assert!(!bak_path(&arch).exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn bak_guard_refuses_second_patch() {
        let d = tmpdir();
        let a = text(1000, 1);
        let arch = build_archive(&d, &[("a.txt", &a)]);

        patch_archive(
            &arch,
            &[PatchOp::replace("a.txt", text(1000, 2))],
            &PatchOptions::default(),
        )
        .unwrap();
        let err = patch_archive(
            &arch,
            &[PatchOp::replace("a.txt", text(1000, 3))],
            &PatchOptions::default(),
        )
        .unwrap_err();
        assert!(err.contains("polerbak"), "отказ при существующем bak: {err}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn multichunk_replacement_of_large_file() {
        let d = tmpdir();
        let a = text(64 * 1024, 1);
        let big = text(3 * 1024 * 1024, 2); // > cdc.max → несколько чанков
        let arch = build_archive(&d, &[("small.txt", &a), ("big.bin", &big)]);

        let rep = patch_archive(
            &arch,
            &[PatchOp::replace("big.bin", big.clone())],
            &PatchOptions::default(),
        )
        .unwrap();
        assert!(rep.logical_chunks > 6, "ожидается нарезка на чанки");

        // replace на полностью новое содержимое
        let fresh = text(5 * 1024 * 1024, 4);
        patch_archive(
            &arch,
            &[PatchOp::replace("big.bin", fresh.clone())],
            &PatchOptions { force_bak: true, ..Default::default() },
        )
        .unwrap();
        assert_eq!(read_entry(&arch, "big.bin"), fresh);
        assert_eq!(read_entry(&arch, "small.txt"), a);
        let reader = PolerReader::open(&arch).unwrap();
        assert!(reader.verify().unwrap().all_ok);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn remux_tar_gz_blob_to_file_table() {
        let d = tmpdir();
        let a = text(80_000, 1);
        let b = text(250_000, 2);
        let tar = make_tar(&[("src/a.cc", &a), ("docs/b.txt", &b)]);
        // gzip-упаковка (как main.tar.gz в реальном архиве пользователя)
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&tar).unwrap();
        let tgz = enc.finish().unwrap();

        let blob = d.join("blob.poler");
        let mut w = StreamWriter::open(&blob, StreamWriteConfig::default()).unwrap();
        w.push_bytes(&tgz).unwrap();
        w.finish("main.tar.gz").unwrap();

        let out = d.join("remuxed.poler");
        let stats = remux_archive(&blob, &out, StreamWriteConfig::default()).unwrap();
        assert!(stats.tar_mode, "ремукс должен включить tar_mode");
        assert!(stats.files >= 2);

        let reader = PolerReader::open(&out).unwrap();
        let vr = reader.verify().unwrap();
        assert!(vr.all_ok, "verify ремукса: {:?}", vr.files_bad);
        assert_eq!(read_entry(&out, "src/a.cc"), a);
        assert_eq!(read_entry(&out, "docs/b.txt"), b);

        // после ремукса — CoW-патч отдельного файла
        let patched = text(120_000, 7);
        patch_archive(
            &out,
            &[PatchOp::replace("src/a.cc", patched.clone())],
            &PatchOptions::default(),
        )
        .unwrap();
        assert_eq!(read_entry(&out, "src/a.cc"), patched);
        assert_eq!(read_entry(&out, "docs/b.txt"), b);
        assert!(PolerReader::open(&out).unwrap().verify().unwrap().all_ok);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn invalid_ops_reject_before_mutation() {
        let d = tmpdir();
        let a = text(1000, 1);
        let arch = build_archive(&d, &[("a.txt", &a)]);
        let before = std::fs::read(&arch).unwrap();

        assert!(patch_archive(&arch, &[PatchOp::replace("нет.txt", a.clone())], &PatchOptions::default()).is_err());
        assert!(patch_archive(&arch, &[PatchOp::add("a.txt", a.clone())], &PatchOptions::default()).is_err());
        assert!(patch_archive(&arch, &[PatchOp::delete("нет.txt")], &PatchOptions::default()).is_err());
        assert!(patch_archive(&arch, &[PatchOp::add("/abs/path.txt", a.clone())], &PatchOptions::default()).is_err());
        assert!(patch_archive(
            &arch,
            &[PatchOp::replace("a.txt", a.clone()), PatchOp::delete("a.txt")],
            &PatchOptions::default()
        )
        .is_err());

        let after = std::fs::read(&arch).unwrap();
        assert_eq!(before, after, "невалидный манифест не меняет ни байта");
        assert!(!bak_path(&arch).exists());
        let _ = std::fs::remove_dir_all(&d);
    }
}
