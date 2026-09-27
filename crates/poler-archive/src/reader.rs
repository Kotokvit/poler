//! Zero-copy читатель `.poler`: mmap всего файла, трейлер читается
//! за одно обращение (открытие < 1 мс — критерий директивы §5),
//! логический индекс даёт O(log n) поиск чанка по raw-смещению,
//! разжатие — по требованию, только покрывающие чанки.
//!
//! RAM-дисциплина: индекс 24 Б/чанк в Vec, разжатые чанки — по одному
//! (≤ 1 MiB) в переиспользуемом скрэтче; кэш декомпрессии намеренно
//! отсутствует (приоритет — пик RSS, а не повторные чтения).

use std::fs::File;
use std::io::Write;
use std::path::Path;

use memmap2::Mmap;

use crate::stream_writer::{
    CHUNK_HEADER_SIZE, INDEX_ENTRY_SIZE, MAGIC_END, MAGIC_START, METHOD_STORE, METHOD_ZDEEP,
    METHOD_ZFAST, POLER_VERSION, TRAILER_SIZE,
};
use crate::sha256::{hex, Sha256};

/// Запись файловой таблицы контейнера.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PolerFile {
    pub name: String,
    pub raw_off: u64,
    pub raw_len: u64,
    pub sha256_hex: String,
}

/// Метаданные контейнера (из трейлера).
#[derive(Debug, Clone, serde::Serialize)]
pub struct PolerInfo {
    pub version: u16,
    pub dedup: bool,
    pub tar_mode: bool,
    pub logical_chunks: u64,
    pub physical_chunks: u64,
    pub files: u64,
    pub total_raw: u64,
    pub total_stored: u64,
    pub ratio: f64,
    pub stream_sha256_hex: String,
}

/// Отчёт верификации.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VerifyReport {
    pub stream_ok: bool,
    pub stream_sha256_hex: String,
    pub expected_stream_sha256_hex: String,
    pub files_checked: u64,
    pub files_ok: u64,
    pub files_bad: Vec<String>,
    pub all_ok: bool,
}

/// Отчёт распаковки.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ExtractReport {
    pub dir: String,
    pub files_written: u64,
    pub files_skipped_unsafe: Vec<String>,
    pub files_ok: u64,
    pub files_bad: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
struct IndexEntry {
    raw_off: u64,
    stored_off: u64,
    raw_len: u32,
}

/// Геометрия контейнера для in-place патчера.
#[derive(Debug, Clone, Copy)]
pub struct PolerLayout {
    pub file_len: u64,
    pub index_off: u64,
    pub index_len: u64,
    pub files_off: u64,
    pub files_len: u64,
    pub logical_chunks: u64,
    pub physical_chunks: u64,
    pub total_raw: u64,
    pub dedup: bool,
    pub tar_mode: bool,
}

/// Развёрнутый mmap-читатель `.poler`.
pub struct PolerReader {
    mmap: Mmap,
    index: Vec<IndexEntry>,
    files: Vec<PolerFile>,
    info: PolerInfo,
    stream_sha256: [u8; 32],
    index_off: u64,
    index_len: u64,
    files_off: u64,
    files_len: u64,
}

impl PolerReader {
    /// O(1)-открытие: mmap (ленивый) + разбор трейлера/индекса/таблицы.
    pub fn open(path: &Path) -> Result<PolerReader, String> {
        let file = File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
        let file_len = file
            .metadata()
            .map_err(|e| format!("stat {}: {e}", path.display()))?
            .len();
        if file_len < (MAGIC_START.len() + TRAILER_SIZE) as u64 {
            return Err(format!(
                "{}: слишком мал для .poler ({file_len} Б)",
                path.display()
            ));
        }
        // SAFETY: mmap только для чтения; файл не мутирует никто, кроме
        // нас самих (контейнер immutable by design).
        let mmap = unsafe { Mmap::map(&file) }.map_err(|e| format!("mmap: {e}"))?;
        let bytes = &mmap[..];
        if &bytes[0..8] != MAGIC_START {
            return Err(format!("{}: magic POLERARC не найден", path.display()));
        }
        let t = &bytes[bytes.len() - TRAILER_SIZE..];
        if &t[0..8] != MAGIC_END {
            return Err(format!("{}: трейлер POLEREND не найден (обрыв?)", path.display()));
        }
        let version = u16::from_le_bytes([t[8], t[9]]);
        if version != POLER_VERSION {
            return Err(format!("{}: версия .poler {version} не поддерживается", path.display()));
        }
        let flags = u16::from_le_bytes([t[10], t[11]]);
        let logical_chunks = u32::from_le_bytes([t[12], t[13], t[14], t[15]]) as u64;
        let physical_chunks = u32::from_le_bytes([t[16], t[17], t[18], t[19]]) as u64;
        let index_off = le_u64(&t[20..28]);
        let index_len = le_u64(&t[28..36]);
        let files_off = le_u64(&t[36..44]);
        let files_len = le_u64(&t[44..52]);
        let total_raw = le_u64(&t[52..60]);
        let total_stored = le_u64(&t[60..68]);
        let mut stream_sha256 = [0u8; 32];
        stream_sha256.copy_from_slice(&t[68..100]);

        // валидация границ
        let end = |off: u64, len: u64, what: &str| -> Result<(), String> {
            let sum = off
                .checked_add(len)
                .ok_or_else(|| format!("{what}: переполнение границ"))?;
            if sum > bytes.len() as u64 {
                return Err(format!("{what}: [{off}..{sum}] вне файла {}", bytes.len()));
            }
            Ok(())
        };
        end(index_off, index_len, "индекс")?;
        if index_len != logical_chunks * INDEX_ENTRY_SIZE as u64 {
            return Err(format!(
                "индекс: длина {index_len} != {logical_chunks}×{INDEX_ENTRY_SIZE}"
            ));
        }
        end(files_off, files_len, "файлы")?;
        if index_off < MAGIC_START.len() as u64 || files_off < index_off {
            return Err("раскладка регионов нарушена".to_string());
        }

        // индекс
        let mut index = Vec::with_capacity(logical_chunks as usize);
        let mut p = index_off as usize;
        for _ in 0..logical_chunks {
            index.push(IndexEntry {
                raw_off: le_u64(&bytes[p..p + 8]),
                stored_off: le_u64(&bytes[p + 8..p + 16]),
                raw_len: u32::from_le_bytes([bytes[p + 16], bytes[p + 17], bytes[p + 18], bytes[p + 19]]),
            });
            p += INDEX_ENTRY_SIZE;
        }

        // файловая таблица
        let mut files = Vec::new();
        let mut p = files_off as usize;
        let files_end = (files_off + files_len) as usize;
        while p < files_end {
            let name_len = u16::from_le_bytes([bytes[p], bytes[p + 1]]) as usize;
            p += 2;
            if p + name_len + 48 > files_end {
                return Err("файловая таблица: обрыв записи".to_string());
            }
            let name = String::from_utf8_lossy(&bytes[p..p + name_len]).to_string();
            p += name_len;
            let raw_off = le_u64(&bytes[p..p + 8]);
            p += 8;
            let raw_len = le_u64(&bytes[p..p + 8]);
            p += 8;
            let mut sha = [0u8; 32];
            sha.copy_from_slice(&bytes[p..p + 32]);
            p += 32;
            files.push(PolerFile {
                name,
                raw_off,
                raw_len,
                sha256_hex: hex(&sha),
            });
        }

        Ok(PolerReader {
            mmap,
            index,
            stream_sha256,
            index_off,
            index_len,
            files_off,
            files_len,
            info: PolerInfo {
                version,
                dedup: flags & 1 != 0,
                tar_mode: flags & 2 != 0,
                logical_chunks,
                physical_chunks,
                files: files.len() as u64,
                total_raw,
                total_stored,
                ratio: if total_raw > 0 {
                    total_stored as f64 / total_raw as f64
                } else {
                    0.0
                },
                stream_sha256_hex: hex(&stream_sha256),
            },
            files,
        })
    }

    pub fn info(&self) -> &PolerInfo {
        &self.info
    }

    pub fn files(&self) -> &[PolerFile] {
        &self.files
    }

    pub fn find_file(&self, name: &str) -> Option<&PolerFile> {
        self.files.iter().find(|f| f.name == name)
    }

    /// Снимок логического индекса: (raw_off, stored_off, raw_len) всех
    /// чанков в порядке сырого потока. Для CoW-патчера, который
    /// переливает индекс в хвост контейнера.
    pub fn logical_entries(&self) -> Vec<(u64, u64, u32)> {
        self.index
            .iter()
            .map(|e| (e.raw_off, e.stored_off, e.raw_len))
            .collect()
    }

    /// blake3-хеш физического чанка по stored_off (первые 32 Б заголовка).
    /// Дедуп-реестр патчера строится по этим хешам без декомпрессии.
    pub fn physical_blake3(&self, stored_off: u64) -> Option<[u8; 32]> {
        let off = stored_off as usize;
        if off + 32 > self.mmap.len() {
            return None;
        }
        let mut h = [0u8; 32];
        h.copy_from_slice(&self.mmap[off..off + 32]);
        Some(h)
    }

    /// Сырой срез mmap-отображения [off, off+len) — для потокового
    /// копирования метаданных (индекс, файловая таблица) без RAM-копий.
    pub fn raw_region(&self, off: u64, len: u64) -> Option<&[u8]> {
        let start = off as usize;
        let end = start.checked_add(len as usize)?;
        if end > self.mmap.len() {
            return None;
        }
        Some(&self.mmap[start..end])
    }

    /// Геометрия контейнера для in-place патчера.
    pub fn layout(&self) -> PolerLayout {
        PolerLayout {
            file_len: self.mmap.len() as u64,
            index_off: self.index_off,
            index_len: self.index_len,
            files_off: self.files_off,
            files_len: self.files_len,
            logical_chunks: self.info.logical_chunks,
            physical_chunks: self.info.physical_chunks,
            total_raw: self.info.total_raw,
            dedup: self.info.dedup,
            tar_mode: self.info.tar_mode,
        }
    }

    /// Физический чанк по stored_off: (method, raw_len, payload).
    fn physical(&self, stored_off: u64) -> Result<(u8, u32, &[u8]), String> {
        let off = stored_off as usize;
        if off + CHUNK_HEADER_SIZE > self.mmap.len() {
            return Err(format!("чанк {stored_off}: заголовок вне файла"));
        }
        let h = &self.mmap[off..off + CHUNK_HEADER_SIZE];
        let raw_len = u32::from_le_bytes([h[32], h[33], h[34], h[35]]) as usize;
        let stored_len = u32::from_le_bytes([h[36], h[37], h[38], h[39]]) as usize;
        let method = h[40];
        let payload_off = off + CHUNK_HEADER_SIZE;
        if payload_off + stored_len > self.mmap.len() {
            return Err(format!("чанк {stored_off}: payload вне файла"));
        }
        Ok((method, raw_len as u32, &self.mmap[payload_off..payload_off + stored_len]))
    }

    /// Разжать чанк в скрэтч (переиспользуемый буфер).
    fn decompress_into(&self, stored_off: u64, scratch: &mut Vec<u8>) -> Result<(), String> {
        let (method, raw_len, payload) = self.physical(stored_off)?;
        match method {
            METHOD_STORE => {
                scratch.clear();
                scratch.extend_from_slice(payload);
            }
            METHOD_ZFAST | METHOD_ZDEEP => {
                let out =
                    zstd::bulk::decompress(payload, raw_len as usize).map_err(|e| format!("zstd: {e}"))?;
                if out.len() != raw_len as usize {
                    return Err(format!(
                        "чанк {stored_off}: разжато {} Б, ожидалось {raw_len}",
                        out.len()
                    ));
                }
                *scratch = out;
            }
            m => return Err(format!("чанк {stored_off}: неизвестный метод {m}")),
        }
        if scratch.len() != raw_len as usize {
            return Err(format!(
                "чанк {stored_off}: длина {} != заголовок {raw_len}",
                scratch.len()
            ));
        }
        Ok(())
    }

    /// O(log n) поиск чанка, покрывающего raw_off (индекс отсортирован).
    fn chunk_covering(&self, raw_off: u64) -> Result<usize, String> {
        if self.index.is_empty() {
            return Err("контейнер пуст".to_string());
        }
        let mut lo = 0usize;
        let mut hi = self.index.len();
        while lo + 1 < hi {
            let mid = (lo + hi) / 2;
            if self.index[mid].raw_off <= raw_off {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        if self.index[lo].raw_off > raw_off {
            return Err(format!("смещение {raw_off} до первого чанка"));
        }
        Ok(lo)
    }

    /// Прочитать диапазон сырого потока [raw_off, raw_off+len).
    /// Разжимаются только покрывающие чанки. RAM ≈ len + 1 чанк.
    pub fn read_range(&self, raw_off: u64, len: usize, out: &mut Vec<u8>) -> Result<(), String> {
        out.clear();
        if len == 0 {
            return Ok(());
        }
        let end_off = raw_off + len as u64;
        if end_off > self.info.total_raw {
            return Err(format!(
                "диапазон [{raw_off}..{end_off}] вне потока {}",
                self.info.total_raw
            ));
        }
        let mut i = self.chunk_covering(raw_off)?;
        let mut scratch = Vec::new();
        let mut pos = raw_off;
        while pos < end_off {
            let e = self.index[i];
            if e.raw_off > pos {
                return Err("дыра в индексе".to_string());
            }
            self.decompress_into(e.stored_off, &mut scratch)?;
            let in_chunk = (pos - e.raw_off) as usize;
            let take = ((e.raw_off + e.raw_len as u64) - pos).min(end_off - pos) as usize;
            out.extend_from_slice(&scratch[in_chunk..in_chunk + take]);
            pos += take as u64;
            i += 1;
            if i >= self.index.len() && pos < end_off {
                return Err("индекс кончился раньше потока".to_string());
            }
        }
        Ok(())
    }

    /// Последовательный обход логических чанков (разжатых).
    /// Страницы payload сбрасываются MADV_DONTNEED после разжатия —
    /// резидентность mmap не копится в RSS на гигабайтных контейнерах
    /// (страницы подчитаются из page cache при повторном чтении).
    pub fn for_each_chunk(
        &self,
        mut f: impl FnMut(u64, &[u8]) -> Result<(), String>,
    ) -> Result<(), String> {
        let mut scratch = Vec::new();
        for e in &self.index {
            self.decompress_into(e.stored_off, &mut scratch)?;
            f(e.raw_off, &scratch)?;
            self.drop_payload_pages(e.stored_off);
        }
        Ok(())
    }

    /// MADV_DONTNEED на диапазоне payload чанка: страницы возвращаются
    /// ядру, RSS не растёт с размером контейнера; заголовок 44 Б
    /// остаётся резидентным (дедуп-верификатор перечитывает его).
    /// memmap2 0.9 не экспортирует MADV_DONTNEED — прямой libc-вызов
    /// с выравниванием границ до страниц.
    fn drop_payload_pages(&self, stored_off: u64) {
        #[cfg(target_os = "linux")]
        {
            const PAGE_MASK: usize = 4096 - 1; // x86_64/aarch64: 4 КиБ
            let off = stored_off as usize;
            if off + CHUNK_HEADER_SIZE > self.mmap.len() {
                return;
            }
            let h = &self.mmap[off..off + CHUNK_HEADER_SIZE];
            let stored_len = u32::from_le_bytes([h[36], h[37], h[38], h[39]]) as usize;
            let payload_off = off + CHUNK_HEADER_SIZE;
            let end = (payload_off + stored_len).min(self.mmap.len());
            if end <= payload_off {
                return;
            }
            let base = self.mmap.as_ptr() as usize;
            let lo = (base + payload_off) & !PAGE_MASK;
            let hi = (base + end + PAGE_MASK) & !PAGE_MASK;
            if hi > lo {
                let ret = unsafe {
                    libc::madvise(
                        lo as *mut libc::c_void,
                        hi - lo,
                        libc::MADV_DONTNEED,
                    )
                };
                let _ = ret; // отказ не фатален: страницы останутся резидентными
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = stored_off; // вне Linux residency не трогаем
        }
    }

    /// Полный сырой поток → Writer (sha256/извлечение/сравнение).
    pub fn stream_out<W: Write>(&self, w: &mut W) -> Result<u64, String> {
        let mut written = 0u64;
        self.for_each_chunk(|_, data| {
            w.write_all(data).map_err(|e| format!("write: {e}"))?;
            written += data.len() as u64;
            Ok(())
        })?;
        Ok(written)
    }

    /// Верификация: SHA256 всего потока + каждой записи таблицы.
    pub fn verify(&self) -> Result<VerifyReport, String> {
        let mut h = Sha256::new();
        let n = {
            let mut hw = HashWriter { h: &mut h, n: 0 };
            self.stream_out(&mut hw)?
        };
        if n != self.info.total_raw {
            return Err(format!(
                "длина потока {n} != трейлер {}",
                self.info.total_raw
            ));
        }
        let got = h.finalize();
        let mut report = VerifyReport {
            stream_ok: got == self.stream_sha256,
            stream_sha256_hex: hex(&got),
            expected_stream_sha256_hex: hex(&self.stream_sha256),
            files_checked: 0,
            files_ok: 0,
            files_bad: Vec::new(),
            all_ok: false,
        };
        // per-file
        let mut buf = Vec::new();
        for f in &self.files {
            report.files_checked += 1;
            let mut h = Sha256::new();
            let mut off = f.raw_off;
            let end = f.raw_off + f.raw_len;
            let mut ok = true;
            while off < end {
                let step = ((end - off) as usize).min(1024 * 1024);
                match self.read_range(off, step, &mut buf) {
                    Ok(()) => h.update(&buf),
                    Err(e) => {
                        report.files_bad.push(format!("{}: {e}", f.name));
                        ok = false;
                        break;
                    }
                }
                off += step as u64;
            }
            if ok {
                let digest = h.finalize();
                let want = match decode_hex(&f.sha256_hex) {
                    Some(v) => v,
                    None => {
                        report.files_bad.push(format!("{}: битая hex-запись sha256", f.name));
                        continue;
                    }
                };
                if digest == want {
                    report.files_ok += 1;
                } else {
                    report.files_bad
                        .push(format!("{}: sha256 не совпал", f.name));
                }
            }
        }
        report.all_ok = report.stream_ok
            && report.files_bad.is_empty()
            && report.files_ok == report.files_checked;
        Ok(report)
    }

    /// Распаковка в каталог. Пути санитизируются: абсолютные и `..`
    /// пропускаются с пометкой (не молча).
    pub fn extract_all(&self, dir: &Path) -> Result<ExtractReport, String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
        let mut report = ExtractReport {
            dir: dir.display().to_string(),
            files_written: 0,
            files_skipped_unsafe: Vec::new(),
            files_ok: 0,
            files_bad: Vec::new(),
        };
        let mut buf = Vec::new();
        for f in &self.files {
            let safe = safe_rel_path(&f.name);
            let Some(rel) = safe else {
                report.files_skipped_unsafe.push(f.name.clone());
                continue;
            };
            let out_path = dir.join(&rel);
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
            }
            let mut out = File::create(&out_path).map_err(|e| format!("create: {e}"))?;
            let mut off = f.raw_off;
            let end = f.raw_off + f.raw_len;
            while off < end {
                let step = ((end - off) as usize).min(1024 * 1024);
                self.read_range(off, step, &mut buf)?;
                out.write_all(&buf).map_err(|e| format!("write: {e}"))?;
                off += step as u64;
            }
            drop(out);
            report.files_written += 1;
            // sha256-контроль на месте
            let got = file_sha256(&out_path)?;
            if got == f.sha256_hex {
                report.files_ok += 1;
            } else {
                report.files_bad.push(f.name.clone());
            }
        }
        Ok(report)
    }

    /// JSON для --poler-list.
    pub fn list_json(&self) -> serde_json::Value {
        serde_json::json!({
            "info": self.info,
            "files": self.files,
        })
    }
}

/// Writer, одновременно кормящий SHA-256 (для verify потока).
struct HashWriter<'a> {
    h: &'a mut Sha256,
    n: u64,
}

impl Write for HashWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.h.update(buf);
        self.n += buf.len() as u64;
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn le_u64(b: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[..8]);
    u64::from_le_bytes(a)
}

fn decode_hex(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = (s.as_bytes()[i * 2] as char).to_digit(16)?;
        let lo = (s.as_bytes()[i * 2 + 1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

fn safe_rel_path(name: &str) -> Option<std::path::PathBuf> {
    let p = Path::new(name);
    if p.is_absolute() {
        return None;
    }
    for comp in p.components() {
        use std::path::Component;
        match comp {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    let s = name.trim_start_matches("./");
    if s.is_empty() {
        return None;
    }
    Some(Path::new(s).to_path_buf())
}

fn file_sha256(path: &Path) -> Result<String, String> {
    let mut f = File::open(path).map_err(|e| format!("open: {e}"))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    use std::io::Read;
    loop {
        let n = f.read(&mut buf).map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex(&h.finalize()))
}

#[cfg(test)]
mod tests {
    use crate::stream_writer::{write_stream, StreamWriter, StreamWriteConfig};
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("poler-rd-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d.join(name)
    }

    /// Смешанные данные: 2+2 МиБ ПОДРЯД идентичного текста (back-to-back
    /// периодичность → гарантированный дедуп), затем случайные блоки
    /// (STORE-ярус) с разными сидами.
    fn mixed_data(total: usize) -> Vec<u8> {
        let text = b"the quick brown fox learns the kernel scheduler and the resonant memory lives in trits\n";
        let unit = 2 * 1024 * 1024;
        let mut u = Vec::with_capacity(unit);
        while u.len() < unit {
            u.extend_from_slice(text);
        }
        u.truncate(unit);
        let rand_block = |seed: u64, len: usize| -> Vec<u8> {
            let mut v = Vec::with_capacity(len);
            let mut st = seed;
            while v.len() < len {
                st = st.wrapping_mul(6364136223846793005).wrapping_add(1);
                v.extend_from_slice(&st.to_le_bytes());
            }
            v
        };
        let segs: Vec<Vec<u8>> = vec![
            u.clone(),
            u,
            rand_block(0xABCD, 512 * 1024),
            rand_block(0x1234, 512 * 1024),
            rand_block(0x7777, 2 * 1024 * 1024),
        ];
        let mut v = Vec::with_capacity(total);
        for s in &segs {
            if v.len() >= total {
                break;
            }
            v.extend_from_slice(s);
        }
        if v.len() < total {
            v.extend_from_slice(&rand_block(0xBEEF, total - v.len()));
        }
        v.truncate(total);
        v
    }

    #[test]
    fn open_read_verify_roundtrip() {
        let data = mixed_data(5 * 1024 * 1024);
        let p = tmp("rt.poler");
        let stats = write_stream(
            &data[..],
            &p,
            StreamWriteConfig { progress_bytes: 0, ..Default::default() },
            "mixed.bin",
        )
        .unwrap();
        let r = PolerReader::open(&p).unwrap();
        assert_eq!(r.info().total_raw, data.len() as u64);
        assert_eq!(r.info().total_stored, stats.total_stored);
        assert_eq!(r.files().len(), 1);
        assert_eq!(r.files()[0].name, "mixed.bin");

        // полный поток
        let mut out = Vec::new();
        let n = r.stream_out(&mut out).unwrap();
        assert_eq!(n, data.len() as u64);
        assert_eq!(out, data, "lossless: поток байт-в-байт");

        // verify
        let rep = r.verify().unwrap();
        assert!(rep.all_ok, "verify: {:?}", rep.files_bad);
        assert!(rep.stream_ok);
        assert_eq!(rep.files_ok, 1);

        // случайный доступ на странных границах
        for (off, len) in [
            (0u64, 1usize),
            (1, 1),
            (65535, 2),
            (1_500_000, 123_457),
            (data.len() as u64 - 7, 7),
            (3_333_333, 300_003),
        ] {
            let mut buf = Vec::new();
            r.read_range(off, len, &mut buf).unwrap();
            assert_eq!(buf.len(), len, "read_range({off},{len}) длина");
            assert_eq!(buf, &data[off as usize..off as usize + len], "read_range({off},{len}) байты");
        }
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn dedup_index_and_extract() {
        let data = mixed_data(4 * 1024 * 1024);
        let p = tmp("dx.poler");
        let cfg = StreamWriteConfig { progress_bytes: 0, ..Default::default() };
        let stats = write_stream(&data[..], &p, cfg, "mixed.bin").unwrap();
        assert!(stats.dedup_chunks > 0, "повтор должен дедуплицироваться");
        let r = PolerReader::open(&p).unwrap();
        assert_eq!(r.info().logical_chunks, stats.logical_chunks);
        assert_eq!(r.info().physical_chunks, stats.physical_chunks);
        assert_eq!(
            r.info().logical_chunks - r.info().physical_chunks,
            stats.dedup_chunks
        );

        // распаковка + sha256
        let dir = tmp("dx-out");
        let rep = r.extract_all(&dir).unwrap();
        assert_eq!(rep.files_written, 1);
        assert_eq!(rep.files_ok, 1, "извлечённый файл прошёл sha256");
        let extracted = std::fs::read(dir.join("mixed.bin")).unwrap();
        assert_eq!(extracted, data);
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn incremental_writer_same_bytes() {
        let mut data = Vec::new();
        for i in 0..(1_500_000u32) {
            data.push((i as u8).wrapping_mul(31).wrapping_add((i >> 9) as u8));
        }
        let p1 = tmp("i1.poler");
        let p2 = tmp("i2.poler");
        let cfg = StreamWriteConfig { progress_bytes: 0, ..Default::default() };
        write_stream(&data[..], &p1, cfg.clone(), "d.bin").unwrap();
        let mut w = StreamWriter::open(&p2, cfg).unwrap();
        for chunk in data.chunks(97 * 1024 + 13) {
            w.push_bytes(chunk).unwrap();
        }
        w.finish("d.bin").unwrap();
        assert_eq!(std::fs::read(&p1).unwrap(), std::fs::read(&p2).unwrap());
        let _ = std::fs::remove_file(&p1);
        let _ = std::fs::remove_file(&p2);
    }

    #[test]
    fn empty_stream_container() {
        let p = tmp("empty.poler");
        let cfg = StreamWriteConfig { progress_bytes: 0, ..Default::default() };
        write_stream(&[][..], &p, cfg, "empty.bin").unwrap();
        let r = PolerReader::open(&p).unwrap();
        assert_eq!(r.info().total_raw, 0);
        assert_eq!(r.info().logical_chunks, 0);
        let mut out = Vec::new();
        assert_eq!(r.stream_out(&mut out).unwrap(), 0);
        let rep = r.verify().unwrap();
        assert!(rep.all_ok, "пустой поток верифицируется");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn corrupt_trailer_detected() {
        let data = mixed_data(600_000);
        let p = tmp("bad.poler");
        let cfg = StreamWriteConfig { progress_bytes: 0, ..Default::default() };
        write_stream(&data[..], &p, cfg, "x.bin").unwrap();
        let mut bytes = std::fs::read(&p).unwrap();
        let t = bytes.len() - TRAILER_SIZE; // первый байт magic POLEREND
        bytes[t] ^= 0xFF;
        std::fs::write(&p, &bytes).unwrap();
        assert!(PolerReader::open(&p).is_err(), "битый трейлер обязан вскрываться");
        let _ = std::fs::remove_file(&p);
    }
}
