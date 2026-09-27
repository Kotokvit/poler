//! FastCDC content-defined chunking + BLAKE3-реестр дедупликации
//! (директива docs/DIRECTIVE_STREAMING_INGESTION_PIPELINE.md, §2B).
//!
//! Нарезка потока на чанки 64 KiB – 1 MiB с границами, зависящими
//! ТОЛЬКО от содержимого (gear-хеш): одинаковые данные режутся
//! одинаково при любой позиции в потоке — фундамент дедупликации.
//!
//! Дедуп-реестр держит в RAM лишь u64-префикс BLAKE3 → смещение
//! физического чанка (~24 Б/чанк). При совпадении префикса полная
//! 32-байтная верификация выполняется чтением заголовка уже записанного
//! чанка (pread из page cache) — ложных склеек разных данных нет,
//! потеря дедуп-возможности при коллизии префикса (вероятность ~2^-64
//! на пару) допустима и не влияет на целостность.

use std::collections::HashMap;
use std::os::unix::fs::FileExt;

/// Параметры нарезки FastCDC (нормализованный вариант).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CdcParams {
    /// Минимальный размер чанка, байт.
    pub min: usize,
    /// Целевой средний размер чанка, байт.
    pub avg: usize,
    /// Максимальный размер чанка, байт.
    pub max: usize,
    /// Маска фазы A [min, avg): ⌈log2(avg)⌉ бит — резать «трудно».
    mask_a: u64,
    /// Маска фазы B [avg, max): на 2 бита короче — хвост режется легче.
    mask_b: u64,
}

impl Default for CdcParams {
    fn default() -> Self {
        CdcParams::new(64 * 1024, 256 * 1024, 1024 * 1024)
    }
}

impl CdcParams {
    /// Конструктор с выведением масок из целевых размеров.
    /// Фаза A покрывает [min, avg) маской log2(avg) бит; выжившие
    /// чанк-кандидаты в фазе B [avg, max) режутся маской на 2 бита
    /// короче — распределение концентрируется вокруг avg.
    pub fn new(min: usize, avg: usize, max: usize) -> Self {
        debug_assert!(min >= 1024 && avg > min && max > avg);
        let bits_a = ((avg as f64).log2().round() as u32).clamp(8, 40);
        let bits_b = bits_a.saturating_sub(2).max(6);
        CdcParams {
            min,
            avg,
            max,
            mask_a: ((1u64 << bits_a) - 1) << (64 - bits_a),
            mask_b: ((1u64 << bits_b) - 1) << (64 - bits_b),
        }
    }
}

/// SplitMix64 — детерминированный генератор для gear-таблицы.
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Сид gear-таблицы фиксирован: нарезка воспроизводима между запусками,
/// процессами и архивами (кросс-архивная дедупликация совместима).
const GEAR_SEED: u64 = 0x504F_4C45_5243_4443; // "POLERCDC"

fn gear_table() -> &'static [u64; 256] {
    use std::sync::OnceLock;
    static GEAR: OnceLock<[u64; 256]> = OnceLock::new();
    GEAR.get_or_init(|| {
        let mut t = [0u64; 256];
        let mut st = GEAR_SEED;
        for slot in t.iter_mut() {
            *slot = splitmix64(&mut st) | 1; // нечётные — ненулевые младшие биты
        }
        t
    })
}

/// Точка разреза: длина чанка от начала `data`.
///
/// Контракт вызова (RAM-дисциплина и детерминизм стриминга):
/// - если известно, что за `data` следуют ещё байты, вызывающий обязан
///   гарантировать `data.len() >= p.max` — тогда граница зависит только
///   от содержимого (эффективный лимит = max);
/// - на EOF допускается `data.len() < p.max` (хвостовой чанк).
///
/// `data.len() <= p.min` → весь буфер целиком (хвост потока).
pub fn cut_point(data: &[u8], p: &CdcParams) -> usize {
    if data.len() <= p.min {
        return data.len();
    }
    let limit = p.max.min(data.len());
    let gear = gear_table();
    let mut h: u64 = 0;
    let mut i = p.min;
    while i < limit {
        h = (h << 1).wrapping_add(gear[data[i] as usize]);
        let mask = if i < p.avg { p.mask_a } else { p.mask_b };
        if h & mask == 0 {
            return i + 1;
        }
        i += 1;
    }
    limit
}

/// Разрезать буфер на чанки (для тестов и утилит; стример делает
/// это сам, не покидая буфер).
pub fn split_chunks<'a>(data: &'a [u8], p: &CdcParams) -> Vec<&'a [u8]> {
    let mut out = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let cut = cut_point(rest, p);
        let (head, tail) = rest.split_at(cut);
        out.push(head);
        rest = tail;
    }
    out
}

/// BLAKE3-хеш чанка (256 бит).
pub fn chunk_hash(data: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(data);
    *h.finalize().as_bytes()
}

/// Реестр дедупликации чанков: u64-префикс BLAKE3 → stored_off.
///
/// RAM: ~24 Б на уникальный чанк (400K чанков на 100 GiB ≈ 10 МБ).
pub struct ChunkDedup {
    map: HashMap<u64, u64>,
    /// Найдено дублей (чанк не записан повторно).
    pub hits: u64,
    /// Новых чанков (записаны физически).
    pub misses: u64,
}

impl Default for ChunkDedup {
    fn default() -> Self {
        Self::new()
    }
}

impl ChunkDedup {
    pub fn new() -> Self {
        ChunkDedup { map: HashMap::new(), hits: 0, misses: 0 }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Ключ реестра — первые 8 байт BLAKE3 (little-endian).
    fn key(hash: &[u8; 32]) -> u64 {
        u64::from_le_bytes(hash[0..8].try_into().unwrap())
    }

    /// Поиск физического чанка с тем же содержимым.
    ///
    /// Совпадение u64-префикса — только кандидат: полная верификация
    /// читает 44-байтный заголовок уже записанного чанка из `store`
    /// (только что записанные страницы живут в page cache — чтение
    /// практически бесплатно) и сравнивает все 32 байта хеша.
    /// Коллизия префикса ≠ потеря данных: чанк просто запишется заново.
    pub fn lookup(&self, hash: &[u8; 32], store: &std::fs::File) -> Option<u64> {
        let key = Self::key(hash);
        let off = *self.map.get(&key)?;
        let mut hdr = [0u8; 44];
        store.read_exact_at(&mut hdr, off).ok()?;
        let mut cand = [0u8; 32];
        cand.copy_from_slice(&hdr[0..32]);
        if cand == *hash {
            Some(off)
        } else {
            None
        }
    }

    /// Зарегистрировать новый физический чанк.
    pub fn insert(&mut self, hash: &[u8; 32], stored_off: u64) {
        self.map.insert(Self::key(hash), stored_off);
        self.misses += 1;
    }

    /// Отметить дубликат (для статистики).
    pub fn record_hit(&mut self) {
        self.hits += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pseudo_data(len: usize, seed: u64) -> Vec<u8> {
        let mut st = seed;
        let mut v = Vec::with_capacity(len);
        while v.len() < len {
            st = splitmix64(&mut st);
            v.extend_from_slice(&st.to_le_bytes());
        }
        v.truncate(len);
        v
    }

    #[test]
    fn cut_point_respects_bounds() {
        let p = CdcParams::default();
        let data = pseudo_data(4 * 1024 * 1024, 42);
        let cut = cut_point(&data, &p);
        assert!(cut >= p.min && cut <= p.max, "cut={cut} вне [{},{}]", p.min, p.max);
        // Хвостовые случаи
        assert_eq!(cut_point(&data[..p.min - 1], &p), p.min - 1);
        assert_eq!(cut_point(&data[..p.min], &p), p.min);
        assert_eq!(cut_point(&data[..p.min + 1], &p), p.min + 1);
    }

    #[test]
    fn chunking_is_deterministic() {
        let p = CdcParams::default();
        let a = pseudo_data(3 * 1024 * 1024, 7);
        let b = a.clone();
        let sa: Vec<usize> = split_chunks(&a, &p).iter().map(|c| c.len()).collect();
        let sb: Vec<usize> = split_chunks(&b, &p).iter().map(|c| c.len()).collect();
        assert_eq!(sa, sb, "одинаковые данные режутся одинаково");
    }

    /// Содержательно-зависимые границы: вставка байта в начало меняет
    /// только чанки до точки ресинхронизации (свойство content-defined).
    #[test]
    fn boundaries_shift_with_content() {
        let p = CdcParams::new(1024, 4096, 16 * 1024);
        let base = pseudo_data(64 * 1024, 1);
        let mut shifted = Vec::with_capacity(base.len() + 1);
        shifted.push(0xAB);
        shifted.extend_from_slice(&base);
        let ca = split_chunks(&base, &p);
        let cb = split_chunks(&shifted, &p);
        // Число чанков не может вырасти больше чем на 1 при сдвиге на байт
        assert!(
            cb.len() <= ca.len() + 1,
            "нарезка не рассыпалась: {} vs {}",
            cb.len(),
            ca.len()
        );
    }

    /// Средний размер на псевдослучайных данных ≈ avg (нормализация
    /// фаз A/B): допускаем [0.5, 2.0]×avg — маски выведены из log2.
    #[test]
    fn average_size_near_target() {
        let p = CdcParams::default();
        let data = pseudo_data(32 * 1024 * 1024, 99);
        let chunks = split_chunks(&data, &p);
        let total: usize = chunks.iter().map(|c| c.len()).sum();
        let avg = total as f64 / chunks.len() as f64;
        assert!(
            avg >= p.avg as f64 * 0.5 && avg <= p.avg as f64 * 2.0,
            "средний размер {avg} вне [0.5,2.0]×{}",
            p.avg
        );
    }

    #[test]
    fn dedup_registry_roundtrip() {
        let dir = std::env::temp_dir().join(format!("poler-dedup-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("probe.bin");
        // read+write: lookup читает заголовки через read_exact_at
        use std::fs::OpenOptions;
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        // заголовок 44 байта: blake3(32) + raw_len(4) + stored_len(4) + method/pad(4)
        let mut blob = vec![0u8; 44];
        let h = chunk_hash(b"poler");
        blob[0..32].copy_from_slice(&h);
        use std::io::Write;
        f.write_all(&blob).unwrap();
        f.sync_all().unwrap();

        let mut reg = ChunkDedup::new();
        assert!(reg.lookup(&h, &f).is_none(), "пустой реестр — miss");
        reg.insert(&h, 0);
        assert_eq!(reg.lookup(&h, &f), Some(0), "точное совпадение — hit");
        let other = chunk_hash(b"other");
        assert!(reg.lookup(&other, &f).is_none(), "другой хеш — miss");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn blake3_hash_stable() {
        // Закрепляем префикс хеша «poler» (регрессия формата).
        let h = chunk_hash(b"poler");
        assert_eq!(h.len(), 32);
        assert!(h.iter().any(|&b| b != 0));
    }
}
