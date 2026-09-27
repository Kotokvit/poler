//! Streaming-компрессор `.poler`: сетевой поток → чанки FastCDC →
//! BLAKE3-дедупликация → многоярусный zstd — БЕЗ сырой выгрузки на диск
//! (директива docs/DIRECTIVE_STREAMING_INGESTION_PIPELINE.md, §2B).
//!
//! RAM-дисциплина: буфер нарезки ≤ max+64 KiB (~1.1 МБ), реестр
//! дедупа ~24 Б/чанк, логический индекс 24 Б/чанк, таблица файлов
//! льётся в sidecar-файл метаданных (имена/смещения/SHA256 — никогда
//! сырые данные), zstd-контексты создаются один раз. Пик RSS
//! сообщается в статистике (VmHWM из /proc/self/status).
//!
//! Crash-safety: запись идёт в `<out>.poler.part`, атомарный rename
//! в конце; брошенный без finish() писатель удаляет свои temporaries.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use crate::dedup::{chunk_hash, cut_point, ChunkDedup, CdcParams};
use crate::sha256::{hex, Sha256};

// ────────────────────────── Формат .poler v1 ──────────────────────────
// Все числа little-endian. Раскладка файла:
//   [0..8)                  magic "POLERARC"
//   [8..)                   физические чанки подряд:
//                             blake3[32] raw_len u32 stored_len u32
//                             method u8 pad[3]  payload[stored_len]
//   ...                     логический индекс (24 Б/чанк):
//                             raw_off u64 stored_off u64 raw_len u32 pad u32
//   ...                     файловая таблица:
//                             name_len u16 name[..] raw_off u64
//                             raw_len u64 sha256[32]
//   [len-104..len)          трейлер "POLEREND"
pub const MAGIC_START: &[u8; 8] = b"POLERARC";
pub const MAGIC_END: &[u8; 8] = b"POLEREND";
pub const POLER_VERSION: u16 = 1;
pub const TRAILER_SIZE: usize = 104;
pub const CHUNK_HEADER_SIZE: usize = 44;
pub const INDEX_ENTRY_SIZE: usize = 24;
pub const FILE_ENTRY_FIXED: usize = 2 + 8 + 8 + 32; // + имя переменной длины

pub const METHOD_STORE: u8 = 0;
pub const METHOD_ZFAST: u8 = 1; // zstd ~3
pub const METHOD_ZDEEP: u8 = 2; // zstd ~15

/// Ярус сжатия.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressTier {
    /// Только быстрый уровень (zstd-3): максимум скорости.
    Fast,
    /// Только глубокий (zstd-15): максимум плотности.
    Deep,
    /// Авто: zstd-3; если чанк сжимается лучше 2:1 — пробуем zstd-15
    /// и берём меньший результат. Дефолт директивы.
    Auto,
}

impl Default for CompressTier {
    fn default() -> Self {
        CompressTier::Auto
    }
}

/// Конфигурация потоковой записи.
#[derive(Debug, Clone)]
pub struct StreamWriteConfig {
    pub cdc: CdcParams,
    /// BLAKE3-дедупликация чанков (true по умолчанию).
    pub dedup: bool,
    pub tier: CompressTier,
    /// Размер чтения из источника (сеть/файл), байт.
    pub read_chunk: usize,
    /// Прогресс в stderr каждые N сырых байт (0 = молчать).
    pub progress_bytes: u64,
}

impl Default for StreamWriteConfig {
    fn default() -> Self {
        StreamWriteConfig {
            cdc: CdcParams::default(),
            dedup: true,
            tier: CompressTier::Auto,
            read_chunk: 64 * 1024,
            progress_bytes: 256 * 1024 * 1024,
        }
    }
}

/// Итог потоковой записи (serde: JSON в stdout CLI).
#[derive(Debug, Clone, serde::Serialize)]
pub struct StreamWriteStats {
    pub output: String,
    pub total_raw: u64,
    pub total_stored: u64,
    pub ratio: f64,
    pub logical_chunks: u64,
    pub physical_chunks: u64,
    pub dedup_chunks: u64,
    pub dedup_bytes: u64,
    pub stored_chunks: u64,
    pub fast_chunks: u64,
    pub deep_chunks: u64,
    pub files: u64,
    pub tar_mode: bool,
    pub stream_sha256_hex: String,
    pub elapsed_ms: u64,
    pub throughput_mbs: f64,
    /// Пик RSS процесса (VmHWM), КБ — критерий ≤ 48 МБ.
    pub peak_rss_kb: u64,
}

/// Пик RSS процесса (VmHWM /proc/self/status; вне Linux — 0).
pub fn peak_rss_kb() -> u64 {
    if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
        for line in s.lines() {
            if let Some(rest) = line.strip_prefix("VmHWM:") {
                return rest
                    .trim()
                    .trim_end_matches("kB")
                    .trim()
                    .parse()
                    .unwrap_or(0);
            }
        }
    }
    0
}

// ────────────────────────── Логический индекс ─────────────────────────

#[derive(Debug, Clone, Copy)]
struct LogicalEntry {
    raw_off: u64,
    stored_off: u64,
    raw_len: u32,
}

impl LogicalEntry {
    fn to_bytes(self) -> [u8; INDEX_ENTRY_SIZE] {
        let mut b = [0u8; INDEX_ENTRY_SIZE];
        b[0..8].copy_from_slice(&self.raw_off.to_le_bytes());
        b[8..16].copy_from_slice(&self.stored_off.to_le_bytes());
        b[16..20].copy_from_slice(&self.raw_len.to_le_bytes());
        b[20..24].copy_from_slice(&0u32.to_le_bytes());
        b
    }
}

// ────────────────────────── tar-наблюдатель ───────────────────────────

/// Завершённый файл tar-потока.
pub struct TarFileDone {
    pub name: String,
    pub raw_off: u64,
    pub raw_len: u64,
    pub sha256: [u8; 32],
}

/// Наблюдатель tar-потока: байты не меняются, распознаются только
/// границы файлов (ustar + GNU longname 'L'/'K' + base-256 размеры)
/// и их SHA256. Сломавшийся заголовок выключает трекинг; целостность
/// потока не страдает.
struct TarObserver {
    /// Абсолютная позиция в сыром потоке.
    pos: u64,
    /// Абсолютное начало текущего 512-блока (заголовка):
    /// pos отстаёт на незасчитанный кусок среза.
    block_start: u64,
    /// Накопитель текущего 512-байтного блока заголовка.
    block: [u8; 512],
    filled: usize,
    state: ObsState,
    /// Текущий файл (имя, raw_off) — hash живёт в state.
    current: Option<(String, u64)>,
    /// Имя, отложенное записью GNU 'L'.
    long_name: Option<String>,
    /// Паддинг данных текущей записи (до кратности 512).
    pending_pad: u64,
    tar_detected: bool,
    files: u64,
}

enum ObsState {
    /// Первый блок ещё не проверен.
    Probing,
    /// Копим 512-байтный блок заголовка.
    Header,
    /// Идут данные файла: осталось байт, sha256.
    FileData(u64, Sha256),
    /// Данные нерегулярной записи — пропустить байт.
    Skip(u64),
    /// Данные записи 'L'/'K': осталось байт, буфер имени.
    LongName(u64, Vec<u8>),
    /// tar кончился (или не он): поток больше не разбирается.
    Done,
}

impl TarObserver {
    fn new() -> Self {
        TarObserver {
            pos: 0,
            block_start: 0,
            block: [0u8; 512],
            filled: 0,
            state: ObsState::Probing,
            current: None,
            long_name: None,
            pending_pad: 0,
            tar_detected: false,
            files: 0,
        }
    }

    fn tracking(&self) -> bool {
        !matches!(self.state, ObsState::Done)
    }

    fn is_tar(&self) -> bool {
        self.tar_detected
    }

    /// Скармливаем очередные сырые байты (в порядке потока);
    /// завершённые файлы возвращаются вектор (не callback —
    /// чтобы не воевать с borrow-чекером за &mut self).
    fn feed(&mut self, bytes: &[u8], out: &mut Vec<TarFileDone>) {
        let mut rest = bytes;
        while !rest.is_empty() && self.tracking() {
            let state = std::mem::replace(&mut self.state, ObsState::Done);
            let take;
            match state {
                ObsState::Done => return,
                ObsState::FileData(mut left, mut hash) => {
                    take = (left as usize).min(rest.len());
                    hash.update(&rest[..take]);
                    left -= take as u64;
                    if left == 0 {
                        if let Some((name, raw_off)) = self.current.take() {
                            out.push(TarFileDone {
                                name,
                                raw_off,
                                raw_len: self.pos + take as u64 - raw_off,
                                sha256: hash.finalize(),
                            });
                            self.files += 1;
                        }
                        let pad = self.pending_pad;
                        self.state = if pad > 0 { ObsState::Skip(pad) } else { ObsState::Header };
                    } else {
                        self.state = ObsState::FileData(left, hash);
                    }
                }
                ObsState::Skip(mut left) => {
                    take = (left as usize).min(rest.len());
                    left -= take as u64;
                    self.state = if left == 0 { ObsState::Header } else { ObsState::Skip(left) };
                }
                ObsState::LongName(mut left, mut buf) => {
                    take = (left as usize).min(rest.len());
                    buf.extend_from_slice(&rest[..take]);
                    left -= take as u64;
                    if left == 0 {
                        let mut name = String::from_utf8_lossy(&buf).to_string();
                        while name.ends_with('\0') {
                            name.pop();
                        }
                        self.long_name = Some(name);
                        let pad = self.pending_pad;
                        self.state = if pad > 0 { ObsState::Skip(pad) } else { ObsState::Header };
                    } else {
                        self.state = ObsState::LongName(left, buf);
                    }
                }
                ObsState::Probing | ObsState::Header => {
                    // копим блок заголовка; state восстанавливаем ДО
                    // on_header — он различает Probing/Tracking
                    let need = 512 - self.filled;
                    if self.filled == 0 {
                        self.block_start = self.pos;
                    }
                    take = need.min(rest.len());
                    self.block[self.filled..self.filled + take].copy_from_slice(&rest[..take]);
                    self.filled += take;
                    self.state = state;
                    if self.filled == 512 {
                        let block = self.block;
                        self.filled = 0;
                        self.on_header(block, out);
                    }
                }
            }
            self.pos += take as u64;
            rest = &rest[take..];
        }
    }

    /// Разбор заголовка.
    fn on_header(&mut self, b: [u8; 512], out: &mut Vec<TarFileDone>) {
        let all_zero = b.iter().all(|&x| x == 0);
        let probing = matches!(self.state, ObsState::Probing);
        self.state = ObsState::Header;

        if all_zero {
            if probing {
                self.state = ObsState::Done; // пустой поток/не tar
                return;
            }
            self.state = ObsState::Done; // хвост tar
            return;
        }
        if !Self::valid_magic(&b) {
            if probing {
                self.state = ObsState::Done; // не tar — обычный поток
                return;
            }
            self.state = ObsState::Done; // сломанный заголовок
            return;
        }
        if probing {
            self.tar_detected = true;
        }

        let size = Self::size_field(&b[124..136]).unwrap_or(0);
        let typeflag = b[156];
        let pad = (512 - (size % 512)) % 512;
        self.pending_pad = pad;

        match typeflag {
            b'L' | b'K' => {
                self.state = ObsState::LongName(size, Vec::with_capacity(size as usize));
            }
            b'0' | 0 | b' ' | b'7' => {
                let name = match self.long_name.take() {
                    Some(long) => long,
                    None => {
                        let n = b[..100].iter().position(|&c| c == 0).unwrap_or(100);
                        let mut name = String::from_utf8_lossy(&b[..n]).to_string();
                        let pn = b[345..500].iter().position(|&c| c == 0).unwrap_or(155);
                        if pn > 0 {
                            let prefix = String::from_utf8_lossy(&b[345..345 + pn]).to_string();
                            name = format!("{prefix}/{name}");
                        }
                        name
                    }
                };
                if size == 0 {
                    out.push(TarFileDone {
                        name,
                        raw_off: self.block_start + 512,
                        raw_len: 0,
                        sha256: Sha256::new().finalize(),
                    });
                    self.files += 1;
                    self.state = ObsState::Header;
                } else {
                    self.current = Some((name, self.block_start + 512));
                    self.state = ObsState::FileData(size, Sha256::new());
                }
            }
            _ => {
                // каталоги/симлинки/прочее: данные (если есть) пропускаем
                self.long_name = None;
                self.state = if size + pad > 0 {
                    ObsState::Skip(size + pad)
                } else {
                    ObsState::Header
                };
            }
        }
    }

    /// EOF: закрыть незавершённый файл (усечённый tar — честно
    /// отдаём то, что видели; верификация вскроет обрыв).
    fn finish(&mut self, out: &mut Vec<TarFileDone>) {
        if let ObsState::FileData(_, hash) = std::mem::replace(&mut self.state, ObsState::Done) {
            if let Some((name, raw_off)) = self.current.take() {
                out.push(TarFileDone {
                    name,
                    raw_off,
                    raw_len: self.pos - raw_off,
                    sha256: hash.finalize(),
                });
                self.files += 1;
            }
        }
        self.state = ObsState::Done;
    }

    fn valid_magic(b: &[u8; 512]) -> bool {
        &b[257..262] == b"ustar"
    }

    /// Размер записи: восьмеричное поле ИЛИ GNU base-256
    /// (старший бит первого байта) — для файлов > 8 GiB.
    fn size_field(field: &[u8]) -> Option<u64> {
        if field[0] & 0x80 != 0 {
            let mut v: u128 = (field[0] & 0x7f) as u128;
            for &b in &field[1..] {
                v = (v << 8) | b as u128;
            }
            return Some(v.min(u64::MAX as u128) as u64);
        }
        let s: String = field
            .iter()
            .take_while(|&&c| c != 0 && c != b' ')
            .map(|&c| c as char)
            .collect();
        u64::from_str_radix(s.trim(), 8).ok()
    }
}

// ────────────────────────── StreamWriter ──────────────────────────────

/// Потоковый писатель .poler-контейнера.
pub struct StreamWriter {
    cfg: StreamWriteConfig,
    file: File,
    part_path: PathBuf,
    final_path: PathBuf,
    /// Sidecar файлой таблицы (только метаданные, не сырые данные).
    files_spill: File,
    files_spill_path: PathBuf,
    files_count: u64,
    logical: Vec<LogicalEntry>,
    dedup: ChunkDedup,
    /// Позиции.
    raw_pos: u64,
    stored_pos: u64,
    /// Буфер нарезки (ёмкость ≤ max + slack).
    buf: Vec<u8>,
    observer: TarObserver,
    stream_hash: Sha256,
    fast: Option<zstd::bulk::Compressor<'static>>,
    deep: Option<zstd::bulk::Compressor<'static>>,
    /// Статистика.
    dedup_chunks: u64,
    dedup_bytes: u64,
    stored_chunks: u64,
    fast_chunks: u64,
    deep_chunks: u64,
    started: std::time::Instant,
    last_progress: u64,
    finished: bool,
}

impl StreamWriter {
    /// Открыть запись: создаётся `<out>.poler.part`, атомарное
    /// переименование в `<out>` — в [`StreamWriter::finish`].
    pub fn open(out: &Path, cfg: StreamWriteConfig) -> io::Result<StreamWriter> {
        let part_path = sidecar_path(out, "part");
        let files_spill_path = sidecar_path(out, "part.files");
        // read+write: дедуп-верификация читает заголовки только что
        // записанных чанков через read_exact_at из page cache
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&part_path)?;
        file.write_all(MAGIC_START)?;
        let files_spill = File::create(&files_spill_path)?;
        let cap = cfg.cdc.max + cfg.read_chunk;
        Ok(StreamWriter {
            cfg,
            file,
            part_path,
            final_path: out.to_path_buf(),
            files_spill,
            files_spill_path,
            files_count: 0,
            logical: Vec::new(),
            dedup: ChunkDedup::new(),
            raw_pos: 0,
            stored_pos: MAGIC_START.len() as u64,
            buf: Vec::with_capacity(cap),
            observer: TarObserver::new(),
            stream_hash: Sha256::new(),
            fast: None,
            deep: None,
            dedup_chunks: 0,
            dedup_bytes: 0,
            stored_chunks: 0,
            fast_chunks: 0,
            deep_chunks: 0,
            started: std::time::Instant::now(),
            last_progress: 0,
            finished: false,
        })
    }

    /// Скармливать сырой поток порциями любого размера (сеть, сокеты,
    /// страницы краула). Границы чанков зависят только от содержимого.
    pub fn push_bytes(&mut self, bytes: &[u8]) -> io::Result<()> {
        let mut rest = bytes;
        let mut done_files = Vec::new();
        while !rest.is_empty() {
            let want = self.cfg.cdc.max;
            while self.buf.len() < want && !rest.is_empty() {
                let take = (want - self.buf.len()).min(rest.len());
                let chunk = &rest[..take];
                self.observer.feed(chunk, &mut done_files);
                self.stream_hash.update(chunk);
                self.buf.extend_from_slice(chunk);
                rest = &rest[take..];
            }
            for d in done_files.drain(..) {
                self.append_tar_file(d);
            }
            self.cut_ready(false)?;
        }
        Ok(())
    }

    /// Завершить поток: финализировать таблицу файлов, индекс и
    /// трейлер, атомарно переименовать `.part` → выход.
    pub fn finish(mut self, name_hint: &str) -> io::Result<StreamWriteStats> {
        self.cut_ready(true)?; // хвостовые чанки
        let mut done_files = Vec::new();
        self.observer.finish(&mut done_files);
        for d in done_files {
            self.append_tar_file(d);
        }

        let tar_mode = self.observer.is_tar();
        // Финализируем sha256 потока РОВНО ОДИН раз — после него
        // новых сырых байт не будет.
        let stream_digest = std::mem::replace(&mut self.stream_hash, Sha256::new()).finalize();
        if !tar_mode {
            // одиночная запись: весь поток — один «файл»
            self.append_file_record(
                &sanitize_hint(name_hint),
                0,
                self.raw_pos,
                stream_digest,
            );
        }

        // логический индекс
        let index_off = self.stored_pos;
        let mut index_buf = Vec::with_capacity(self.logical.len() * INDEX_ENTRY_SIZE);
        for e in &self.logical {
            index_buf.extend_from_slice(&e.to_bytes());
        }
        self.file.write_all(&index_buf)?;
        self.stored_pos += index_buf.len() as u64;

        // файловая таблица: длина sidecar известна ДО вливания
        let files_off = self.stored_pos;
        let files_len = std::fs::metadata(&self.files_spill_path)?.len();
        let mut spill_read = File::open(&self.files_spill_path)?;
        let mut copy_buf = vec![0u8; 64 * 1024];
        loop {
            let n = spill_read.read(&mut copy_buf)?;
            if n == 0 {
                break;
            }
            self.file.write_all(&copy_buf[..n])?;
        }
        drop(spill_read);
        let _ = std::fs::remove_file(&self.files_spill_path);
        let final_len = files_off + files_len + TRAILER_SIZE as u64;

        // трейлер
        let mut trailer = [0u8; TRAILER_SIZE];
        trailer[0..8].copy_from_slice(MAGIC_END);
        trailer[8..10].copy_from_slice(&POLER_VERSION.to_le_bytes());
        let mut flags: u16 = 0;
        if self.cfg.dedup {
            flags |= 1;
        }
        if tar_mode {
            flags |= 2;
        }
        trailer[10..12].copy_from_slice(&flags.to_le_bytes());
        trailer[12..16].copy_from_slice(&(self.logical.len() as u32).to_le_bytes());
        trailer[16..20].copy_from_slice(&(self.dedup.misses as u32).to_le_bytes());
        trailer[20..28].copy_from_slice(&index_off.to_le_bytes());
        trailer[28..36]
            .copy_from_slice(&((self.logical.len() as u64) * (INDEX_ENTRY_SIZE as u64)).to_le_bytes());
        trailer[36..44].copy_from_slice(&files_off.to_le_bytes());
        trailer[44..52].copy_from_slice(&files_len.to_le_bytes());
        trailer[52..60].copy_from_slice(&self.raw_pos.to_le_bytes());
        trailer[60..68].copy_from_slice(&final_len.to_le_bytes());
        trailer[68..100].copy_from_slice(&stream_digest);
        self.file.write_all(&trailer)?;
        self.file.sync_all()?;
        // дескриптор закроется в Drop: rename с открытым хендлом
        // валиден на Linux

        std::fs::rename(&self.part_path, &self.final_path)?;
        self.finished = true;
        let total_stored = std::fs::metadata(&self.final_path)?.len();
        let elapsed = self.started.elapsed().as_millis() as u64;
        Ok(StreamWriteStats {
            output: self.final_path.display().to_string(),
            total_raw: self.raw_pos,
            total_stored,
            ratio: if self.raw_pos > 0 {
                total_stored as f64 / self.raw_pos as f64
            } else {
                0.0
            },
            logical_chunks: self.logical.len() as u64,
            physical_chunks: self.dedup.misses,
            dedup_chunks: self.dedup_chunks,
            dedup_bytes: self.dedup_bytes,
            stored_chunks: self.stored_chunks,
            fast_chunks: self.fast_chunks,
            deep_chunks: self.deep_chunks,
            files: if tar_mode { self.files_count } else { 1 },
            tar_mode,
            stream_sha256_hex: hex(&stream_digest),
            elapsed_ms: elapsed,
            throughput_mbs: if elapsed > 0 {
                self.raw_pos as f64 / 1024.0 / 1024.0 / (elapsed as f64 / 1000.0)
            } else {
                0.0
            },
            peak_rss_kb: peak_rss_kb(),
        })
    }

    /// Вырезать все готовые чанки из буфера. `eof` — источник исчерпан:
    /// тогда остаток режется как хвост (граница может быть < max).
    fn cut_ready(&mut self, eof: bool) -> io::Result<()> {
        // buf вынимается: process_chunk(&mut self) не может заимствовать
        // срез самого себя
        let mut buf = std::mem::take(&mut self.buf);
        loop {
            if buf.is_empty() {
                break;
            }
            if !eof && buf.len() < self.cfg.cdc.max {
                break; // ждём данных для детерминированной границы
            }
            let cut = cut_point(&buf, &self.cfg.cdc);
            self.process_chunk(&buf[..cut])?;
            buf.drain(..cut);
            self.maybe_progress();
        }
        self.buf = buf;
        Ok(())
    }

    fn process_chunk(&mut self, raw: &[u8]) -> io::Result<()> {
        let hash = chunk_hash(raw);
        let raw_off = self.raw_pos;
        let raw_len = raw.len() as u32;
        self.raw_pos += raw.len() as u64;

        if self.cfg.dedup {
            if let Some(stored_off) = self.dedup.lookup(&hash, &self.file) {
                self.logical.push(LogicalEntry { raw_off, stored_off, raw_len });
                self.dedup.record_hit();
                self.dedup_chunks += 1;
                self.dedup_bytes += raw.len() as u64;
                return Ok(());
            }
        }

        let (method, payload) = self.compress(raw)?;
        let stored_off = self.stored_pos;
        let mut hdr = [0u8; CHUNK_HEADER_SIZE];
        hdr[0..32].copy_from_slice(&hash);
        hdr[32..36].copy_from_slice(&raw_len.to_le_bytes());
        hdr[36..40].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        hdr[40] = method;
        self.file.write_all(&hdr)?;
        self.file.write_all(&payload)?;
        self.stored_pos += (CHUNK_HEADER_SIZE + payload.len()) as u64;
        self.logical.push(LogicalEntry { raw_off, stored_off, raw_len });
        self.dedup.insert(&hash, stored_off);
        match method {
            METHOD_STORE => self.stored_chunks += 1,
            METHOD_ZFAST => self.fast_chunks += 1,
            _ => self.deep_chunks += 1,
        }
        Ok(())
    }

    /// Многоярусное сжатие одного чанка.
    fn compress(&mut self, raw: &[u8]) -> io::Result<(u8, Vec<u8>)> {
        if raw.len() < 512 {
            return Ok((METHOD_STORE, raw.to_vec()));
        }
        match self.cfg.tier {
            CompressTier::Fast => {
                let c = self.zfast(raw)?;
                if c.len() < raw.len() * 15 / 16 {
                    Ok((METHOD_ZFAST, c))
                } else {
                    Ok((METHOD_STORE, raw.to_vec()))
                }
            }
            CompressTier::Deep => {
                let c = self.zdeep(raw)?;
                if c.len() < raw.len() * 15 / 16 {
                    Ok((METHOD_ZDEEP, c))
                } else {
                    Ok((METHOD_STORE, raw.to_vec()))
                }
            }
            CompressTier::Auto => {
                let c3 = self.zfast(raw)?;
                if c3.len() >= raw.len() * 15 / 16 {
                    return Ok((METHOD_STORE, raw.to_vec()));
                }
                if c3.len() <= raw.len() / 2 {
                    // хорошо сжимается — глубокий ярус может дать кратно
                    let c15 = self.zdeep(raw)?;
                    if c15.len() < c3.len() {
                        return Ok((METHOD_ZDEEP, c15));
                    }
                }
                Ok((METHOD_ZFAST, c3))
            }
        }
    }

    fn zfast(&mut self, raw: &[u8]) -> io::Result<Vec<u8>> {
        if self.fast.is_none() {
            self.fast = Some(zstd_compressor(3)?);
        }
        self.fast.as_mut().unwrap().compress(raw)
    }

    fn zdeep(&mut self, raw: &[u8]) -> io::Result<Vec<u8>> {
        if self.deep.is_none() {
            self.deep = Some(zstd_compressor(15)?);
        }
        self.deep.as_mut().unwrap().compress(raw)
    }

    /// Завершённый tar-файл → sidecar-таблица.
    fn append_tar_file(&mut self, done: TarFileDone) {
        self.append_file_record(&done.name, done.raw_off, done.raw_len, done.sha256);
    }

    fn append_file_record(
        &mut self,
        name: &str,
        raw_off: u64,
        raw_len: u64,
        sha256: [u8; 32],
    ) {
        let mut b = Vec::with_capacity(FILE_ENTRY_FIXED + name.len());
        b.extend_from_slice(&(name.len() as u16).to_le_bytes());
        b.extend_from_slice(name.as_bytes());
        b.extend_from_slice(&raw_off.to_le_bytes());
        b.extend_from_slice(&raw_len.to_le_bytes());
        b.extend_from_slice(&sha256);
        if self.files_spill.write_all(&b).is_ok() {
            self.files_count += 1;
        }
    }

    fn maybe_progress(&mut self) {
        if self.cfg.progress_bytes > 0
            && self.raw_pos - self.last_progress >= self.cfg.progress_bytes
        {
            self.last_progress = self.raw_pos;
            eprintln!(
                "stream: {} raw → {} stored, {} чанков (дедуп {})",
                fmt_bytes(self.raw_pos),
                fmt_bytes(self.stored_pos),
                self.logical.len(),
                self.dedup_chunks
            );
        }
    }
}

impl Drop for StreamWriter {
    fn drop(&mut self) {
        if !self.finished {
            let _ = std::fs::remove_file(&self.part_path);
            let _ = std::fs::remove_file(&self.files_spill_path);
        }
    }
}

fn sidecar_path(out: &Path, suffix: &str) -> PathBuf {
    let mut s = out.as_os_str().to_os_string();
    s.push(format!(".{suffix}"));
    PathBuf::from(s)
}

fn sanitize_hint(hint: &str) -> String {
    let base = hint.rsplit('/').next().unwrap_or("stream");
    let base = base.trim();
    if base.is_empty() {
        "stream".to_string()
    } else {
        base.chars().take(180).collect()
    }
}

fn zstd_compressor(level: i32) -> io::Result<zstd::bulk::Compressor<'static>> {
    zstd::bulk::Compressor::new(level)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("zstd: {e}")))
}

pub fn fmt_bytes(b: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = b as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{b} B")
    } else {
        format!("{v:.2} {}", UNITS[u])
    }
}

/// Целостный поток: источник → .poler одной командой.
pub fn write_stream<R: Read>(
    src: R,
    out: &Path,
    cfg: StreamWriteConfig,
    name_hint: &str,
) -> io::Result<StreamWriteStats> {
    let mut w = StreamWriter::open(out, cfg)?;
    let mut reader = src;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        w.push_bytes(&buf[..n])?;
    }
    w.finish(name_hint)
}

// ─────────────────────── Синтетика для бенчей ─────────────────────────

/// Детерминированный синтетический поток для бенчей и тестов RAM:
/// текстоподобные блоки (сжимаются, фразы повторяются → дедуп CDC)
/// и каждый 8-й блок псевдослучайный (несжимаем → ярус STORE).
pub struct SyntheticStream {
    total: u64,
    produced: u64,
    state: u64,
    block: Vec<u8>,
    block_pos: usize,
    block_no: u64,
}

impl SyntheticStream {
    pub fn new(total: u64, seed: u64) -> Self {
        SyntheticStream {
            total,
            produced: 0,
            state: seed | 1,
            block: Vec::new(),
            block_pos: 0,
            block_no: 0,
        }
    }

    fn next_u64(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    fn refill(&mut self) {
        self.block.clear();
        self.block_pos = 0;
        const PHRASES: [&str; 12] = [
            "the kernel scheduler keeps fairness across run queues",
            "мозг мухи держит ритм мысли в живом вихре",
            "memory ordering guarantees require acquire-release semantics",
            "квантовая решётка тритов живёт без умножения",
            "zero-copy parsing avoids intermediate buffer allocations",
            "энтропия фильтра отделяет смысл от шума страницы",
            "the piece tree balances insertions in logarithmic time",
            "суверенный архиватор льёт поток прямо в кристалл",
            "content defined chunking resists insertion shifts",
            "резонанс смысла растёт при совпадении контекста",
            "mmap backed readers achieve constant time open latency",
            "дедупликация blake3 находит повторяющиеся блоки кода",
        ];
        if self.block_no % 8 == 7 {
            // несжимаемый блок
            self.block.reserve(64 * 1024);
            for _ in 0..(64 * 1024 / 8) {
                let w = self.next_u64();
                self.block.extend_from_slice(&w.to_le_bytes());
            }
        } else {
            let mut seed = self.next_u64();
            self.block.reserve(64 * 1024);
            while self.block.len() < 64 * 1024 {
                let p = PHRASES[(seed as usize) % PHRASES.len()];
                self.block.extend_from_slice(p.as_bytes());
                self.block.push(b'\n');
                seed = seed
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
            }
        }
        self.block_no += 1;
    }
}

impl Read for SyntheticStream {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.produced >= self.total {
            return Ok(0);
        }
        let want = out.len().min((self.total - self.produced) as usize);
        let mut filled = 0;
        while filled < want {
            if self.block_pos >= self.block.len() {
                self.refill();
            }
            let take = (self.block.len() - self.block_pos).min(want - filled);
            out[filled..filled + take]
                .copy_from_slice(&self.block[self.block_pos..self.block_pos + take]);
            self.block_pos += take;
            filled += take;
        }
        self.produced += filled as u64;
        Ok(filled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("poler-sw-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d.join(name)
    }

    #[test]
    fn roundtrip_small_stream() {
        let path = tmp("small.poler");
        let data: Vec<u8> = (0..300_000u32).map(|i| (i * 7 + i / 251) as u8).collect();
        let stats =
            write_stream(&data[..], &path, StreamWriteConfig::default(), "probe.bin").unwrap();
        assert_eq!(stats.total_raw, 300_000);
        assert_eq!(stats.files, 1);
        assert!(!stats.tar_mode);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn incremental_push_equals_write_stream() {
        // Один и тот же поток через write_stream и push_bytes нечётными
        // порциями: байты .poler обязаны совпасть (детерминизм границ).
        let mut data = Vec::new();
        let mut st = 12345u64;
        for _ in 0..(2 * 1024 * 1024 / 8) {
            st = st.wrapping_mul(6364136223846793005).wrapping_add(1);
            data.extend_from_slice(&st.to_le_bytes());
        }
        let p1 = tmp("inc1.poler");
        let p2 = tmp("inc2.poler");
        write_stream(&data[..], &p1, StreamWriteConfig::default(), "x.bin").unwrap();
        let mut w = StreamWriter::open(&p2, StreamWriteConfig::default()).unwrap();
        let mut off = 0;
        for step in [1usize, 3, 7, 61, 4096, 65537, 13] {
            let end = (off + step).min(data.len());
            w.push_bytes(&data[off..end]).unwrap();
            off = end;
            if off >= data.len() {
                break;
            }
        }
        while off < data.len() {
            let end = (off + 100_000).min(data.len());
            w.push_bytes(&data[off..end]).unwrap();
            off = end;
        }
        w.finish("x.bin").unwrap();
        let b1 = std::fs::read(&p1).unwrap();
        let b2 = std::fs::read(&p2).unwrap();
        assert_eq!(b1, b2, "push_bytes порциями == write_stream");
        let _ = std::fs::remove_file(&p1);
        let _ = std::fs::remove_file(&p2);
    }

    #[test]
    fn dedup_drops_repeated_blocks() {
        // 12 ДОСЛОВНЫХ блоков по 256 КиБ подряд (3 МиБ периодического
        // содержимого) + уникальный хвост: CDC-сеть кандидатов
        // сходится к периодической решётке → внутренние чанки повторяются.
        let mut block: Vec<u8> = Vec::with_capacity(256 * 1024);
        let mut st = 777u64;
        while block.len() < 256 * 1024 {
            st = st.wrapping_mul(2862933555777941757).wrapping_add(3037000493);
            for b in (st as u32).to_le_bytes() {
                block.push(b);
                if block.len() == 256 * 1024 {
                    break;
                }
            }
        }
        let mut stream = Vec::new();
        for _ in 0..12 {
            stream.extend_from_slice(&block);
        }
        // уникальный хвост (несжимаемый, чтобы заодно проверить STORE)
        let mut tail = Vec::with_capacity(512 * 1024);
        let mut t = 4242u64;
        while tail.len() < 512 * 1024 {
            t = t.wrapping_mul(6364136223846793005).wrapping_add(1);
            tail.extend_from_slice(&t.to_le_bytes());
        }
        stream.extend_from_slice(&tail);
        let p = tmp("dedup.poler");
        let cfg = StreamWriteConfig { progress_bytes: 0, ..Default::default() };
        let stats = write_stream(&stream[..], &p, cfg, "rep.bin").unwrap();
        assert!(
            stats.dedup_chunks >= 3,
            "дедуп не сработал: {} (логических {})",
            stats.dedup_chunks,
            stats.logical_chunks
        );
        assert!(stats.total_stored < stream.len() as u64 / 2, "архив не ужался");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn synthetic_stream_is_deterministic() {
        let mut a = SyntheticStream::new(1_000_000, 5);
        let mut b = SyntheticStream::new(1_000_000, 5);
        let mut ra = Vec::new();
        let mut rb = Vec::new();
        a.read_to_end(&mut ra).unwrap();
        b.read_to_end(&mut rb).unwrap();
        assert_eq!(ra, rb);
        assert_eq!(ra.len(), 1_000_000);
    }

    #[test]
    fn peak_rss_reports_something() {
        let v = peak_rss_kb();
        assert!(v == 0 || v > 1000, "VmHWM = {v} КБ выглядит неразумно");
    }
}

