//! Скан архивов без распаковки (v0.28.1, Native Retrieval).
//!
//! Суверенный слой чтения контейнеров: записи zip / tar / tar.gz /
//! tar.zst / gz / zst читаются **прямо из архива в память** — ни один
//! байт не распаковывается на диск. Это продолжение философии движка
//! (mmap-нул-копи чтение, O(1) память на файл): контейнер трактуется
//! как виртуальная файловая система, а запись — как виртуальный файл
//! с адресом `архив::запись`.
//!
//! v0.39.0: сюда же встал суверенный архиватор `.poler`
//! (директива DIRECTIVE_STREAMING_INGESTION_PIPELINE):
//! [`dedup`] — FastCDC + BLAKE3, [`stream_writer`] — потоковая запись
//! сети/файлов в сжатые чанки без сырой выгрузки, [`reader`] —
//! zero-copy mmap-чтение с O(log n) доступом к любому байту.
//!
//! ## Почему без распаковки
//!
//! 1. **Суверенность диска** — распаковка чужого архива означает запись
//!    неизвестного содержимого в ФС (zip-slip, бомбы, краденые inode).
//!    Чтение в bounded-буфер памяти не создаёт файловых артефактов.
//! 2. **Скорость агента** — распаковка 300-файлового экспорта NotebookLM
//!    ради одного grep — минута ввода-вывода; прямой стрим записей —
//!    секунды, и только нужные записи декомпрессируются.
//! 3. **Память не течёт** — каждая запись ограничена [`ReadLimits`]
//!    (лимит несжатого размера, защита от zip-бомб: 42.zip разворачивается
//!    в буфер ≤ лимита и запись отбрасывается с ошибкой, а не в 4 ГБ файл).
//!
//! ## Пароли
//!
//! Архивы zip бывают зашифрованы (ZipCrypto — традиционный PKWARE,
//! AES-256 — WinZip AES). Пароль передаётся:
//! 1. флагом CLI `--archive-password <PASS>` (человек или ИИ-агент
//!    вводит прямо в командной строке);
//! 2. переменной окружения `POLER_ARCHIVE_KEY` (не попадает в историю
//!    shell — как `POLER_VAULT_KEY` у Vault .pvt);
//! 3. интерактивным промптом на stdin, когда терминал — TTY (резолвится
//!    на уровне CLI, см. `main.rs`).
//!
//! Листинг записей ([`open_info`]) пароля НЕ требует: центральный
//! каталог zip читается raw, без дешифрации — агент сначала осматривает
//! контейнер (`--archive-list`), потом решает, чем вскрывать.
//!
//! ## Форматы и границы
//!
//! | Вид | Расширения | Метод | Пароль |
//! |---|---|---|---|
//! | [`ArchiveKind::Zip`] | zip, jar, war, epub, odt | stored / deflate / zstd | ZipCrypto, AES-256 |
//! | [`ArchiveKind::Tar`] | tar | ustar/pax/gnu | — |
//! | [`ArchiveKind::TarGz`] | tar.gz, tgz | tar + gzip | — |
//! | [`ArchiveKind::TarZst`] | tar.zst, tzst | tar + zstd | — |
//! | [`ArchiveKind::GzSingle`] | gz | gzip (мульти-член: ротация логов) | — |
//! | [`ArchiveKind::ZstSingle`] | zst | zstd-стрим | — |
//! | [`ArchiveKind::Poler`] | poler, t5z | CDC-чанки zstd fast/deep + дедуп | — |
//!
//! bzip2/xz/deflate64 не поддерживаются сознательно: C-зависимости
//! (bzip2, lzma) и/или экзотика — суверенный минимум зависимостей.
//! tar.gz/tar.zst читаются одним последовательным проходом стрима
//! (gzip не допускает seek к произвольной записи) — для полного скана
//! это и так единственный проход.
//!
//! ## Интеграция
//!
//! * `--grep --archives` — записи сканируются слоем 0 (grep) с
//!   виртуальными путями `архив::запись` (см. `retrieval::grep`);
//! * `--chunk "архив::запись"` — RAG-чанки конкретной записи (слой B);
//! * `--archive-list` — листинг контейнера для агента;
//! * `--stream-download/--stream-file → .poler` — потоковая запись
//!   гигабайтных потоков без сырой выгрузки (v0.39.0);
//! * `--poler-list/--poler-verify/--poler-extract` — инспекция
//!   `.poler`-контейнеров.

pub mod dedup;
pub mod patcher;
pub mod reader;
pub mod stream_writer;

pub use reader::{ExtractReport, PolerFile, PolerInfo, PolerReader, VerifyReport};
pub use stream_writer::{
    fmt_bytes, peak_rss_kb, write_stream, CompressTier, StreamWriteConfig, StreamWriteStats,
    StreamWriter, SyntheticStream,
};

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

/// Лимит несжатой записи по умолчанию: 64 МиБ (как `max_file_bytes`
/// резонансного движка — единая рамка «ни один буфер не больше»).
pub const DEFAULT_MAX_ENTRY_BYTES: u64 = 64 * 1024 * 1024;

/// Разделитель виртуального пути «архив::запись».
pub const VIRTUAL_SEP: &str = "::";

// ---------------------------------------------------------------------------
// Вид архива
// ---------------------------------------------------------------------------

/// Вид контейнера — определяет ридер и способ доступа к записям.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveKind {
    /// zip-семейство: zip/jar/war/epub/odt — seek-доступ к произвольной
    /// записи через центральный каталог.
    Zip,
    /// Несжатый tar — записи идут потоком, но header.size() известен
    /// до чтения.
    Tar,
    /// tar + gzip (потоковый, последовательный доступ).
    TarGz,
    /// tar + zstd (потоковый, последовательный доступ).
    TarZst,
    /// Одиночный gzip-файл (одна псевдо-запись; мульти-члены склеиваются
    /// — ротация логов `access.log.1.gz access.log.2.gz` в одном файле).
    GzSingle,
    /// Одиночный zstd-файл (одна псевдо-запись).
    ZstSingle,
    /// Родной контейнер `.poler`/`.t5z`: mmap + файловая таблица из
    /// трейлера, O(log n) доступ к любому чанку, CDC-дедуп,
    /// in-place CoW-патчинг (см. [`reader`], [`patcher`]).
    Poler,
}

impl ArchiveKind {
    /// Короткое имя для отчётов/JSON.
    pub fn as_str(&self) -> &'static str {
        match self {
            ArchiveKind::Zip => "zip",
            ArchiveKind::Tar => "tar",
            ArchiveKind::TarGz => "tar.gz",
            ArchiveKind::TarZst => "tar.zst",
            ArchiveKind::GzSingle => "gz",
            ArchiveKind::ZstSingle => "zst",
            ArchiveKind::Poler => "poler",
        }
    }
}

/// Определение вида архива по расширению. Составные расширения
/// (.tar.gz, .tar.zst) проверяются раньше простых (.gz, .zst):
/// `archive.tar.gz` — это TarGz, а не GzSingle.
pub fn kind_of(path: &Path) -> Option<ArchiveKind> {
    let name = path.file_name()?.to_string_lossy().to_lowercase();
    // Родной контейнер — раньше остальных: `.poler` и `.t5z` не
    // пересекаются с составными расширениями tar-семейства.
    if name.ends_with(".poler") || name.ends_with(".t5z") {
        return Some(ArchiveKind::Poler);
    }
    if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        return Some(ArchiveKind::TarGz);
    }
    if name.ends_with(".tar.zst") || name.ends_with(".tzst") {
        return Some(ArchiveKind::TarZst);
    }
    if name.ends_with(".tar") {
        return Some(ArchiveKind::Tar);
    }
    if name.ends_with(".gz") {
        return Some(ArchiveKind::GzSingle);
    }
    if name.ends_with(".zst") {
        return Some(ArchiveKind::ZstSingle);
    }
    // zip-семейство: контейнеры приложений — те же zip-каталоги.
    for ext in [".zip", ".jar", ".war", ".epub", ".odt"] {
        if name.ends_with(ext) {
            return Some(ArchiveKind::Zip);
        }
    }
    None
}

/// Является ли путь архивом, который движок умеет читать напрямую.
pub fn is_archive(path: &Path) -> bool {
    kind_of(path).is_some()
}

// ---------------------------------------------------------------------------
// Метаданные записей
// ---------------------------------------------------------------------------

/// Метаданные одной записи контейнера (без чтения содержимого).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryMeta {
    /// Имя записи внутри архива (для gz/zst — псевдо-имя файла).
    pub name: String,
    /// Несжатый размер, байт (для gz — 0: неизвестен до декодирования).
    pub size: u64,
    /// Сжатый размер, байт (tar-потоки: 0 — размер не хранится в записи).
    pub compressed: u64,
    /// Каталог (имя кончается «/»).
    pub is_dir: bool,
    /// Запись зашифрована паролем (ZipCrypto/AES).
    pub encrypted: bool,
}

/// Листинг контейнера: вид + все записи.
#[derive(Debug, Clone)]
pub struct ArchiveInfo {
    /// Путь к архиву на диске.
    pub path: PathBuf,
    /// Вид контейнера.
    pub kind: ArchiveKind,
    /// Записи в порядке следования в контейнере.
    pub entries: Vec<EntryMeta>,
}

impl ArchiveInfo {
    /// Есть ли хоть одна зашифрованная запись.
    pub fn encrypted(&self) -> bool {
        self.entries.iter().any(|e| e.encrypted)
    }
}

/// Листинг контейнера: только заголовки записей, без декомпрессии
/// и без пароля. Для zip читается центральный каталог raw-доступом;
/// для tar-потоков — проход по заголовкам (File seek позволяет
/// перепрыгивать данные записей без чтения).
pub fn open_info(path: &Path) -> Result<ArchiveInfo, String> {
    let kind = kind_of(path)
        .ok_or_else(|| format!("{}: не архив (zip/tar/tar.gz/tar.zst/gz/zst)", path.display()))?;
    let entries = match kind {
        ArchiveKind::Zip => zip_info(path)?,
        ArchiveKind::Poler => poler_info(path)?,
        ArchiveKind::Tar | ArchiveKind::TarGz | ArchiveKind::TarZst => tar_info(path, kind)?,
        ArchiveKind::GzSingle | ArchiveKind::ZstSingle => {
            let compressed = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
            // Псевдо-имя: файл без последнего расширения
            // (notes.txt.gz → notes.txt).
            let stem = path
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            vec![EntryMeta {
                name: stem,
                size: 0,
                compressed,
                is_dir: false,
                encrypted: false,
            }]
        }
    };
    Ok(ArchiveInfo {
        path: path.to_path_buf(),
        kind,
        entries,
    })
}

/// Центральный каталог zip: raw-ручки записей дают имя/размеры/флаг
/// шифрования без пароля и без декомпрессии.
fn zip_info(path: &Path) -> Result<Vec<EntryMeta>, String> {
    let file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut ar = zip::ZipArchive::new(file)
        .map_err(|e| format!("{}: некорректный zip: {e}", path.display()))?;
    let mut out = Vec::with_capacity(ar.len() as usize);
    for i in 0..ar.len() {
        let zf = ar
            .by_index_raw(i as usize)
            .map_err(|e| format!("{}: запись {i}: {e}", path.display()))?;
        out.push(EntryMeta {
            name: zf.name().to_string(),
            size: zf.size(),
            compressed: zf.compressed_size(),
            is_dir: zf.is_dir(),
            encrypted: zf.encrypted(),
        });
    }
    Ok(out)
}

/// Заголовки tar-потока. Для несжатого tar файл seek-able: данные записей
/// перепрыгиваются; для tar.gz/tar.zst поток читается последовательно
/// (декомпрессия неизбежна — свойство формата, RAM остаётся bounded).
fn tar_info(path: &Path, kind: ArchiveKind) -> Result<Vec<EntryMeta>, String> {
    let file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let reader: Box<dyn Read> = match kind {
        ArchiveKind::TarGz => Box::new(flate2::read::MultiGzDecoder::new(file)),
        ArchiveKind::TarZst => {
            let dec = zstd::Decoder::new(file)
                .map_err(|e| format!("{}: zstd-стрим: {e}", path.display()))?;
            Box::new(dec)
        }
        _ => Box::new(file),
    };
    let mut ar = tar::Archive::new(reader);
    let entries = ar
        .entries()
        .map_err(|e| format!("{}: tar-записи: {e}", path.display()))?;
    let mut out = Vec::new();
    for e in entries {
        let e = e.map_err(|e| format!("{}: tar-запись: {e}", path.display()))?;
        let header = e.header();
        let size = header.size().unwrap_or(0);
        let is_dir = header.entry_type().is_dir();
        let name = e
            .path()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        out.push(EntryMeta {
            name,
            size,
            compressed: 0,
            is_dir,
            encrypted: false,
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Чтение записей
// ---------------------------------------------------------------------------

/// Ограничения чтения: защита от zip-бомб и гигантских записей.
#[derive(Debug, Clone, Copy)]
pub struct ReadLimits {
    /// Максимум несжатого размера записи. Запись больше лимита не
    /// читается вовсе (ошибка «пропущена»), RAM ≤ лимит + 1 байт
    /// детектора переполнения.
    pub max_entry_bytes: u64,
}

impl Default for ReadLimits {
    fn default() -> Self {
        Self {
            max_entry_bytes: DEFAULT_MAX_ENTRY_BYTES,
        }
    }
}

/// Нормализация имени записи: обратные слэши Windows-zip → прямые,
/// пустые сегменты и «.» срезаются (ведущие/внутренние «./», «//»).
/// Сравнение имён всегда по нормализованной форме — `dir\file.md`,
/// `./dir/file.md` и `dir//file.md` одна и та же запись.
/// Сегменты «..» сохраняются: на диск запись никогда не извлекается,
/// traversal-имена безвредны (и видимы в листинге как есть).
pub fn norm_name(name: &str) -> String {
    let n = name.replace('\\', "/");
    n.split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .collect::<Vec<_>>()
        .join("/")
}

/// Виртуальный путь записи: `архив::запись`.
pub fn virtual_name(archive: &Path, entry: &str) -> String {
    format!("{}{}{}", archive.display(), VIRTUAL_SEP, entry)
}

/// Файловая таблица родного `.poler`: O(1) открытие (mmap + трейлер),
/// метаданные без декомпрессии чанков. `size` — несжатая длина записи
/// (`raw_len`); сжатие в `.poler` посчитано на уровне чанков CDC,
/// поэтому `compressed = 0` (в листинге «-»).
fn poler_info(path: &Path) -> Result<Vec<EntryMeta>, String> {
    let r = reader::PolerReader::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(r
        .files()
        .iter()
        .map(|f| EntryMeta {
            name: f.name.clone(),
            size: f.raw_len,
            compressed: 0,
            is_dir: false,
            encrypted: false,
        })
        .collect())
}

/// Чтение записи `.poler` как байтов: поиск по файловой таблице,
/// затем декомпрессия только покрывающих чанков (≤ 1 МиБ скретч),
/// шаг 1 МиБ — как в `PolerReader::verify` (RAM-дисциплина).
fn poler_read_entry(
    path: &Path,
    entry: &str,
    limits: &ReadLimits,
) -> Result<Vec<u8>, String> {
    let r = reader::PolerReader::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let norm = norm_name(entry);
    let f = r
        .find_file(&norm)
        .or_else(|| {
            r.files()
                .iter()
                .find(|f| norm_name(&f.name) == norm)
        })
        .ok_or_else(|| format!("{}::{}: запись не найдена", path.display(), norm))?;
    if f.raw_len > limits.max_entry_bytes {
        return Err(format!(
            "{}::{}: несжатый размер {} байт > лимита {} байт — запись пропущена \
             (--archive-max-entry-mb)",
            path.display(),
            f.name,
            f.raw_len,
            limits.max_entry_bytes
        ));
    }
    let mut out = Vec::with_capacity(f.raw_len.min(8 * 1024 * 1024) as usize);
    let mut step_buf = Vec::new();
    let mut off = f.raw_off;
    let end = f.raw_off + f.raw_len;
    while off < end {
        let step = ((end - off) as usize).min(1024 * 1024);
        r.read_range(off, step, &mut step_buf)
            .map_err(|e| format!("{}::{}: {e}", path.display(), f.name))?;
        out.extend_from_slice(&step_buf);
        off += step as u64;
    }
    Ok(out)
}

/// Разбор виртуального пути `архив::запись` → (путь к архиву, имя записи).
/// Возвращает None, если разделителя нет или одна из сторон пуста.
pub fn split_virtual(spec: &str) -> Option<(PathBuf, String)> {
    let (archive, entry) = spec.split_once(VIRTUAL_SEP)?;
    if archive.is_empty() || entry.trim_start_matches('/').is_empty() {
        return None;
    }
    Some((PathBuf::from(archive), norm_name(entry)))
}

/// Чтение потока с лимитом: читается не более `max+1` байт, переполнение
/// детектируется и превращается в ошибку пропуска записи.
fn read_bounded<R: Read>(reader: R, max: u64, what: &str) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    reader
        .take(max.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| format!("{what}: {e}"))?;
    if buf.len() as u64 > max {
        return Err(format!(
            "{what}: несжатый размер {} байт > лимита {max} — запись пропущена \
             (--archive-max-entry-mb)",
            buf.len()
        ));
    }
    Ok(buf)
}

/// Чтение одной записи как байтов (random access). Для zip — прямой
/// seek к записи; для tar-потоков — проход до нужной записи.
/// Псевдо-запись gz/zst читается при `entry` = "" либо совпадающем стеме.
pub fn read_entry(
    path: &Path,
    entry: &str,
    password: Option<&str>,
    limits: &ReadLimits,
) -> Result<Vec<u8>, String> {
    let kind = kind_of(path)
        .ok_or_else(|| format!("{}: не архив (zip/tar/tar.gz/tar.zst/gz/zst/poler)", path.display()))?;
    match kind {
        ArchiveKind::Zip => zip_read_entry(path, entry, password, limits),
        ArchiveKind::Poler => poler_read_entry(path, entry, limits),
        ArchiveKind::Tar | ArchiveKind::TarGz | ArchiveKind::TarZst => {
            let mut found: Option<Vec<u8>> = None;
            let mut hit_err: Option<String> = None;
            for_each_entry(path, password, limits, |meta, res| {
                if norm_name(&meta.name) == norm_name(entry) {
                    match res {
                        Ok(b) => found = Some(b),
                        Err(e) => hit_err = Some(e),
                    }
                }
            })?;
            if let Some(b) = found {
                Ok(b)
            } else if let Some(e) = hit_err {
                Err(e)
            } else {
                Err(format!(
                    "{}::{}: запись не найдена",
                    path.display(),
                    norm_name(entry)
                ))
            }
        }
        ArchiveKind::GzSingle | ArchiveKind::ZstSingle => {
            let want = norm_name(
                &path
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default(),
            );
            let asked = norm_name(entry);
            if !asked.is_empty() && asked != want {
                return Err(format!(
                    "{}: одиночный gzip/zst-файл, запись {asked:?} не существует \
                     (доступна псевдо-запись {want:?})",
                    path.display()
                ));
            }
            let file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
            let what = format!("{}::{}", path.display(), want);
            match kind {
                ArchiveKind::GzSingle => {
                    read_bounded(flate2::read::MultiGzDecoder::new(file), limits.max_entry_bytes, &what)
                }
                ArchiveKind::ZstSingle => {
                    let dec = zstd::Decoder::new(file)
                        .map_err(|e| format!("{what}: zstd-стрим: {e}"))?;
                    read_bounded(dec, limits.max_entry_bytes, &what)
                }
                _ => unreachable!(),
            }
        }
    }
}

/// Чтение записи как текста (невалидный UTF-8 конвертируется lossy —
/// та же семантика, что у `with_text` движка).
pub fn read_entry_text(
    path: &Path,
    entry: &str,
    password: Option<&str>,
    limits: &ReadLimits,
) -> Result<String, String> {
    let bytes = read_entry(path, entry, password, limits)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Однопроходное чтение всех записей контейнера: `f(метаданные, байты)`.
/// Каталоги пропускаются. tar-потоки читаются ровно один раз (в отличие
/// от посильного [`read_entry`], который проходит поток до записи);
/// zip читается seek-циклом по индексам.
///
/// Ошибки отдельной записи (пароль, лимит, повреждение) доставляются
/// в `f` как `Err` и НЕ прерывают обход остальных записей.
pub fn for_each_entry(
    path: &Path,
    password: Option<&str>,
    limits: &ReadLimits,
    mut f: impl FnMut(&EntryMeta, Result<Vec<u8>, String>),
) -> Result<(), String> {
    let kind = kind_of(path)
        .ok_or_else(|| format!("{}: не архив", path.display()))?;
    match kind {
        ArchiveKind::Poler => {
            let metas = poler_info(path)?;
            // Детерминизм вывода — по имени, как у zip-ветки.
            let mut metas = metas;
            metas.sort_by(|a, b| norm_name(&a.name).cmp(&norm_name(&b.name)));
            for meta in &metas {
                if meta.is_dir {
                    continue;
                }
                let bytes = poler_read_entry(path, &meta.name, limits);
                f(meta, bytes);
            }
            Ok(())
        }
        ArchiveKind::Zip => {
            let file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
            let mut ar = zip::ZipArchive::new(file)
                .map_err(|e| format!("{}: некорректный zip: {e}", path.display()))?;
            let mut metas = zip_info(path)?;
            // Детерминизм вывода: записи сортируются по имени
            // (порядок центрального каталога — случайность упаковщика).
            metas.sort_by(|a, b| norm_name(&a.name).cmp(&norm_name(&b.name)));
            for meta in &metas {
                if meta.is_dir {
                    continue;
                }
                let bytes = zip_read_by_name(&mut ar, path, &meta.name, password, limits);
                f(meta, bytes);
            }
            Ok(())
        }
        ArchiveKind::Tar | ArchiveKind::TarGz | ArchiveKind::TarZst => {
            let file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
            let reader: Box<dyn Read> = match kind {
                ArchiveKind::TarGz => Box::new(flate2::read::MultiGzDecoder::new(file)),
                ArchiveKind::TarZst => {
                    let dec = zstd::Decoder::new(file)
                        .map_err(|e| format!("{}: zstd-стрим: {e}", path.display()))?;
                    Box::new(dec)
                }
                _ => Box::new(file),
            };
            let mut ar = tar::Archive::new(reader);
            let entries = ar
                .entries()
                .map_err(|e| format!("{}: tar-записи: {e}", path.display()))?;
            for e in entries {
                let mut e = match e {
                    Ok(e) => e,
                    Err(err) => {
                        let meta = EntryMeta {
                            name: String::new(),
                            size: 0,
                            compressed: 0,
                            is_dir: false,
                            encrypted: false,
                        };
                        f(&meta, Err(format!("{}: tar-запись: {err}", path.display())));
                        continue;
                    }
                };
                let header = e.header();
                let meta = EntryMeta {
                    name: e
                        .path()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_default(),
                    size: header.size().unwrap_or(0),
                    compressed: 0,
                    is_dir: header.entry_type().is_dir(),
                    encrypted: false,
                };
                if meta.is_dir {
                    continue;
                }
                let what = format!("{}::{}", path.display(), norm_name(&meta.name));
                let bytes = if meta.size > limits.max_entry_bytes {
                    Err(format!(
                        "{what}: несжатый размер {} байт > лимита {} — запись пропущена",
                        meta.size, limits.max_entry_bytes
                    ))
                } else {
                    read_bounded(&mut e, limits.max_entry_bytes, &what)
                };
                f(&meta, bytes);
            }
            Ok(())
        }
        ArchiveKind::GzSingle | ArchiveKind::ZstSingle => {
            let file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
            let stem = path
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            let compressed = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
            let meta = EntryMeta {
                name: stem,
                size: 0,
                compressed,
                is_dir: false,
                encrypted: false,
            };
            let what = format!("{}::{}", path.display(), norm_name(&meta.name));
            let bytes = match kind {
                ArchiveKind::GzSingle => read_bounded(
                    flate2::read::MultiGzDecoder::new(file),
                    limits.max_entry_bytes,
                    &what,
                ),
                ArchiveKind::ZstSingle => {
                    let dec = zstd::Decoder::new(file)
                        .map_err(|e| format!("{what}: zstd-стрим: {e}"))?;
                    read_bounded(dec, limits.max_entry_bytes, &what)
                }
                _ => unreachable!(),
            };
            f(&meta, bytes);
            Ok(())
        }
    }
}

/// Random-access чтение записи zip по имени.
fn zip_read_entry(
    path: &Path,
    entry: &str,
    password: Option<&str>,
    limits: &ReadLimits,
) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut ar = zip::ZipArchive::new(file)
        .map_err(|e| format!("{}: некорректный zip: {e}", path.display()))?;
    zip_read_by_name(&mut ar, path, entry, password, limits)
}

/// Чтение записи открытого zip-архива по имени (нормализованное
/// сравнение). Шифрованные записи требуют пароль: ZipCrypto и AES
/// дешифруются крейтом zip прозрачно.
fn zip_read_by_name(
    ar: &mut zip::ZipArchive<File>,
    archive_path: &Path,
    entry: &str,
    password: Option<&str>,
    limits: &ReadLimits,
) -> Result<Vec<u8>, String> {
    let want = norm_name(entry);
    // Индекс искомой записи + флаг шифрования — raw, без пароля.
    let mut target: Option<usize> = None;
    let mut encrypted = false;
    for i in 0..ar.len() {
        let zf = ar
            .by_index_raw(i as usize)
            .map_err(|e| format!("{}: запись {i}: {e}", archive_path.display()))?;
        if norm_name(zf.name()) == want {
            target = Some(i as usize);
            encrypted = zf.encrypted();
            break;
        }
    }
    let idx = target.ok_or_else(|| {
        format!(
            "{}::{}: запись не найдена",
            archive_path.display(),
            norm_name(entry)
        )
    })?;
    let what = format!("{}::{}", archive_path.display(), want);
    if encrypted {
        let pw = password.ok_or_else(|| {
            format!(
                "{what}: запись зашифрована — передайте --archive-password \
                 или POLER_ARCHIVE_KEY"
            )
        })?;
        let mut zf = ar.by_index_decrypt(idx, pw.as_bytes()).map_err(|e| {
            if matches!(e, zip::result::ZipError::InvalidPassword) {
                format!("{what}: неверный пароль")
            } else {
                format!("{what}: {e}")
            }
        })?;
        return read_bounded(&mut zf, limits.max_entry_bytes, &what);
    }
    let mut zf = ar
        .by_index(idx)
        .map_err(|e| format!("{what}: {e}"))?;
    read_bounded(&mut zf, limits.max_entry_bytes, &what)
}

// ---------------------------------------------------------------------------
// Тесты: фикстуры собираются в tempfile на лету (zip/tar/tar.gz/tar.zst/
// gz/zst); зашифрованный ZipCrypto-фикстур — включён в репозиторий
// (src/archive/fixtures/), пароль в README рядом.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    const SECRET_MD: &str = "# Субквантовая кинетика\n\nЛа Виолетта: эфирная гипотеза.\n";
    const CODE_RS: &str = "fn main() {\n    println!(\"poler\");\n}\n";

    fn dir() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn write_zip(path: &Path) {
        let f = File::create(path).unwrap();
        let mut zw = zip::ZipWriter::new(f);
        let opts =
            zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        zw.start_file("notes/secret.md", opts).unwrap();
        zw.write_all(SECRET_MD.as_bytes()).unwrap();
        zw.start_file("code/main.rs", opts).unwrap();
        zw.write_all(CODE_RS.as_bytes()).unwrap();
        zw.add_directory("empty_dir/", opts).unwrap();
        zw.finish().unwrap();
    }

    fn write_tar(path: &Path) {
        let f = File::create(path).unwrap();
        let mut b = tar::Builder::new(f);
        let mut h = tar::Header::new_gnu();
        h.set_size(SECRET_MD.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, "notes/secret.md", SECRET_MD.as_bytes()).unwrap();
        let mut h = tar::Header::new_gnu();
        h.set_size(CODE_RS.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, "code/main.rs", CODE_RS.as_bytes()).unwrap();
        b.finish().unwrap();
    }

    fn write_tar_gz(path: &Path) {
        let f = File::create(path).unwrap();
        let enc = flate2::write::GzEncoder::new(f, flate2::Compression::default());
        let mut b = tar::Builder::new(enc);
        let mut h = tar::Header::new_gnu();
        h.set_size(SECRET_MD.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, "notes/secret.md", SECRET_MD.as_bytes()).unwrap();
        b.finish().unwrap();
    }

    fn write_tar_zst(path: &Path) {
        let f = File::create(path).unwrap();
        let enc = zstd::Encoder::new(f, 3).unwrap();
        let mut b = tar::Builder::new(enc);
        let mut h = tar::Header::new_gnu();
        h.set_size(SECRET_MD.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, "notes/secret.md", SECRET_MD.as_bytes()).unwrap();
        let enc = b.into_inner().unwrap();
        enc.finish().unwrap();
    }

    fn write_gz(path: &Path) {
        let f = File::create(path).unwrap();
        let mut enc = flate2::write::GzEncoder::new(f, flate2::Compression::default());
        enc.write_all(SECRET_MD.as_bytes()).unwrap();
        enc.finish().unwrap();
    }

    fn write_zst(path: &Path) {
        let f = File::create(path).unwrap();
        let mut enc = zstd::Encoder::new(f, 3).unwrap();
        enc.write_all(SECRET_MD.as_bytes()).unwrap();
        enc.finish().unwrap();
    }

    #[test]
    fn kind_detection() {
        let k = |s: &str| kind_of(Path::new(s));
        assert_eq!(k("a.zip"), Some(ArchiveKind::Zip));
        assert_eq!(k("a.JAR"), Some(ArchiveKind::Zip));
        assert_eq!(k("book.epub"), Some(ArchiveKind::Zip));
        assert_eq!(k("a.tar"), Some(ArchiveKind::Tar));
        assert_eq!(k("a.tar.gz"), Some(ArchiveKind::TarGz));
        assert_eq!(k("a.TGZ"), Some(ArchiveKind::TarGz));
        assert_eq!(k("a.tar.zst"), Some(ArchiveKind::TarZst));
        assert_eq!(k("a.tzst"), Some(ArchiveKind::TarZst));
        assert_eq!(k("log.gz"), Some(ArchiveKind::GzSingle));
        assert_eq!(k("blob.zst"), Some(ArchiveKind::ZstSingle));
        assert_eq!(k("readme.md"), None);
        assert_eq!(k("noext"), None);
    }

    #[test]
    fn norm_and_virtual_paths() {
        assert_eq!(norm_name(".\\/dir\\file.md"), "dir/file.md".to_string());
        assert_eq!(norm_name("./a/./b.txt"), "a/b.txt".to_string());
        let (a, e) = split_virtual("корпус.zip::dir/файл.md").unwrap();
        assert_eq!(a, PathBuf::from("корпус.zip"));
        assert_eq!(e, "dir/файл.md");
        assert!(split_virtual("нет-разделителя").is_none());
        assert!(split_virtual("пусто.zip::").is_none());
        assert!(split_virtual("::entry.md").is_none());
        assert_eq!(
            virtual_name(Path::new("a.zip"), "b.md"),
            "a.zip::b.md".to_string()
        );
    }

    /// Мини-tar в памяти → StreamWriter → .poler (как CLI
    /// `tar -cf - | poler-engine --stream-file -`).
    fn write_poler(path: &Path, files: &[(&str, &str)]) {
        use super::stream_writer::{StreamWriteConfig, StreamWriter};
        let mut tarbuf = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tarbuf);
            for (name, data) in files {
                let mut h = tar::Header::new_gnu();
                h.set_size(data.len() as u64);
                h.set_mode(0o644);
                h.set_cksum();
                b.append_data(&mut h, *name, data.as_bytes()).unwrap();
            }
            b.finish().unwrap();
        }
        let cfg = StreamWriteConfig { dedup: false, ..Default::default() };
        let mut w = StreamWriter::open(path, cfg).unwrap();
        w.push_bytes(&tarbuf).unwrap();
        w.finish("stream.tar").unwrap();
    }

    #[test]
    fn poler_native_transparency() {
        let d = dir();
        let p = d.path().join("vault.poler");
        write_poler(&p, &[("notes/secret.md", SECRET_MD), ("src/main.rs", "fn main() {}\n")]);

        // kind_of: расширения родного контейнера
        let k = |n: &str| kind_of(Path::new(n));
        assert_eq!(k("vault.poler"), Some(ArchiveKind::Poler));
        assert_eq!(k("crystal.t5z"), Some(ArchiveKind::Poler));
        assert_eq!(k("a.POLER"), Some(ArchiveKind::Poler));

        // Листинг без декомпрессии
        let info = open_info(&p).unwrap();
        assert_eq!(info.kind, ArchiveKind::Poler);
        assert_eq!(info.kind.as_str(), "poler");
        assert_eq!(info.entries.len(), 2);
        assert!(info.entries.iter().any(|e| e.name == "notes/secret.md" && e.size == SECRET_MD.len() as u64));
        assert!(!info.encrypted());

        // Random-access чтение записи (только покрывающие чанки)
        let text = read_entry_text(&p, "notes/secret.md", None, &ReadLimits::default()).unwrap();
        assert_eq!(text, SECRET_MD);
        // Нормализованное имя
        let text2 = read_entry_text(&p, "./notes\\secret.md", None, &ReadLimits::default()).unwrap();
        assert_eq!(text2, SECRET_MD);
        // Несуществующая запись
        assert!(read_entry(&p, "нет.md", None, &ReadLimits::default()).is_err());

        // Полный обход: все записи доставляются, порядок детерминирован
        let mut seen = Vec::new();
        for_each_entry(&p, None, &ReadLimits::default(), |meta, res| {
            assert!(res.is_ok());
            seen.push(norm_name(&meta.name));
        })
        .unwrap();
        seen.sort();
        assert_eq!(seen, vec!["notes/secret.md".to_string(), "src/main.rs".to_string()]);

        // Лимит: запись больше max_entry_bytes отбрасывается с ошибкой,
        // но не валит обход
        let tiny = ReadLimits { max_entry_bytes: 4, ..Default::default() };
        let mut errs = 0;
        for_each_entry(&p, None, &tiny, |_meta, res| {
            if res.is_err() {
                errs += 1;
            }
        })
        .unwrap();
        assert_eq!(errs, 2);
        assert!(read_entry(&p, "src/main.rs", None, &tiny).is_err());
    }

    #[test]
    fn zip_roundtrip_info_and_read() {
        let d = dir();
        let p = d.path().join("corpus.zip");
        write_zip(&p);
        let info = open_info(&p).unwrap();
        assert_eq!(info.kind, ArchiveKind::Zip);
        // 3 записи: 2 файла + каталог
        assert_eq!(info.entries.len(), 3);
        assert!(info.entries.iter().any(|e| e.name == "notes/secret.md" && !e.encrypted));
        assert!(!info.encrypted());
        let text = read_entry_text(&p, "notes/secret.md", None, &ReadLimits::default()).unwrap();
        assert_eq!(text, SECRET_MD);
        // Нормализованное имя: ./ и обратные слэши — та же запись.
        let text2 = read_entry_text(&p, "./notes\\secret.md", None, &ReadLimits::default()).unwrap();
        assert_eq!(text2, SECRET_MD);
        // Несуществующая запись
        assert!(read_entry(&p, "нет.md", None, &ReadLimits::default()).is_err());
    }

    #[test]
    fn tar_roundtrips() {
        for (name, writer) in [
            ("c.tar", write_tar as fn(&Path)),
            ("c.tar.gz", write_tar_gz),
            ("c.tar.zst", write_tar_zst),
        ] {
            let d = dir();
            let p = d.path().join(name);
            writer(&p);
            let info = open_info(&p).unwrap();
            assert!(
                info.entries.iter().any(|e| e.name == "notes/secret.md"),
                "{name}: запись в листинге"
            );
            let text = read_entry_text(&p, "notes/secret.md", None, &ReadLimits::default())
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(text, SECRET_MD, "{name}");
        }
    }

    #[test]
    fn single_file_gz_zst() {
        let d = dir();
        let gz = d.path().join("notes.txt.gz");
        write_gz(&gz);
        // Псевдо-запись — стем файла
        let text = read_entry_text(&gz, "notes.txt", None, &ReadLimits::default()).unwrap();
        assert_eq!(text, SECRET_MD);
        // Пустое имя — тоже допустимо
        let text2 = read_entry_text(&gz, "", None, &ReadLimits::default()).unwrap();
        assert_eq!(text2, SECRET_MD);
        // Чужое имя — ошибка
        assert!(read_entry(&gz, "other.txt", None, &ReadLimits::default()).is_err());

        let zst = d.path().join("blob.txt.zst");
        write_zst(&zst);
        let text3 = read_entry_text(&zst, "blob.txt", None, &ReadLimits::default()).unwrap();
        assert_eq!(text3, SECRET_MD);
    }

    #[test]
    fn for_each_entry_zip_sorted() {
        let d = dir();
        let p = d.path().join("corpus.zip");
        write_zip(&p);
        let mut names = Vec::new();
        let mut total = 0usize;
        for_each_entry(&p, None, &ReadLimits::default(), |meta, bytes| {
            names.push(meta.name.clone());
            total += bytes.unwrap().len();
        })
        .unwrap();
        // Каталоги пропущены, сортировка по имени
        assert_eq!(names, vec!["code/main.rs", "notes/secret.md"]);
        assert_eq!(total, SECRET_MD.len() + CODE_RS.len());
    }

    #[test]
    fn bomb_guard() {
        let d = dir();
        let p = d.path().join("bomb.zip");
        let f = File::create(&p).unwrap();
        let mut zw = zip::ZipWriter::new(f);
        let opts = zip::write::SimpleFileOptions::default();
        zw.start_file("big.txt", opts).unwrap();
        zw.write_all(&vec![b'A'; 100_000]).unwrap();
        zw.finish().unwrap();
        let tiny = ReadLimits { max_entry_bytes: 4096 };
        let err = read_entry(&p, "big.txt", None, &tiny).unwrap_err();
        assert!(err.contains("лимита"), "ошибка лимита: {err}");
        // Лимит больше записи — читается
        let ok = read_entry(&p, "big.txt", None, &ReadLimits { max_entry_bytes: 200_000 });
        assert!(ok.is_ok());
    }

    /// Зашифрованный ZipCrypto-фикстур из репозитория: пароль
    /// «полер-ключ-2026» (см. fixtures/README.txt).
    #[test]
    fn zipcrypto_password_paths() {
        let d = dir();
        let p = d.path().join("enc.zip");
        std::fs::write(&p, include_bytes!("fixtures/zipcrypto_poler.zip")).unwrap();
        // Листинг без пароля: метаданные + флаг шифрования
        let info = open_info(&p).unwrap();
        assert!(info.encrypted());
        assert!(info.entries.iter().any(|e| e.name == "secret_note.md" && e.encrypted));
        // Без пароля — отказ с подсказкой
        let err = read_entry(&p, "secret_note.md", None, &ReadLimits::default()).unwrap_err();
        assert!(err.contains("--archive-password"), "подсказка пароля: {err}");
        // Неверный пароль
        let err = read_entry(&p, "secret_note.md", Some("wrong"), &ReadLimits::default()).unwrap_err();
        assert!(err.contains("неверный пароль"), "{err}");
        // Верный пароль — читается
        let text = read_entry_text(&p, "secret_note.md", Some("полер-ключ-2026"), &ReadLimits::default())
            .unwrap();
        assert!(text.contains("субквантовая кинетика"), "содержимое: {text}");
    }
}
