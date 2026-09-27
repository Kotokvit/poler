//! Генератор POSIX-ustar поверх файловой системы.
//!
//! Каталог(и) на лету разворачиваются в поток ustar без временных файлов
//! и без крейта `tar`: писатель `.poler` (TarObserver) сам строит файловую
//! таблицу — та же ветка кода, что у poler-engine для
//! `tar -c dir | poler-engine --stream-file -`.

use std::collections::VecDeque;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

#[derive(Debug)]
struct TarEntry {
    name: String,
    is_dir: bool,
    size: u64,
    mode: u32,
    mtime: u64,
    src: Option<PathBuf>,
}

/// Потоковый ustar-генератор: `Read`, который отдаёт заголовки и содержимое
/// файлов по мере чтения. Память — O(1) к размеру данных.
pub struct FsTarReader {
    entries: VecDeque<TarEntry>,
    stage: Vec<u8>,
    file: Option<fs::File>,
    remaining: u64,
    file_size: u64,
    done: bool,
}

impl FsTarReader {
    /// Собрать поток из списка путей (файлы и/или каталоги, рекурсивно).
    /// Симлинки и специальные файлы пропускаются с предупреждением в stderr.
    pub fn new(paths: &[PathBuf]) -> Result<Self, String> {
        let mut entries = Vec::new();
        for p in paths {
            collect_entries(p, p, &mut entries)?;
        }
        Ok(FsTarReader {
            entries: entries.into(),
            stage: Vec::new(),
            file: None,
            remaining: 0,
            file_size: 0,
            done: false,
        })
    }
}

fn collect_entries(root: &Path, cur: &Path, out: &mut Vec<TarEntry>) -> Result<(), String> {
    let meta = fs::symlink_metadata(cur).map_err(|e| format!("{}: {e}", cur.display()))?;
    let name = to_arc_name(root, cur);
    if meta.is_dir() {
        out.push(TarEntry {
            name: format!("{name}/"),
            is_dir: true,
            size: 0,
            mode: unix_mode(&meta),
            mtime: unix_mtime(&meta),
            src: None,
        });
        let mut children: Vec<PathBuf> = fs::read_dir(cur)
            .map_err(|e| format!("{}: {e}", cur.display()))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .collect();
        children.sort();
        for ch in children {
            collect_entries(root, &ch, out)?;
        }
    } else if meta.is_file() {
        out.push(TarEntry {
            name,
            is_dir: false,
            size: meta.len(),
            mode: unix_mode(&meta),
            mtime: unix_mtime(&meta),
            src: Some(cur.to_path_buf()),
        });
    } else {
        eprintln!("poler: пропуск symlink/special: {}", cur.display());
    }
    Ok(())
}

fn to_arc_name(_root: &Path, cur: &Path) -> String {
    // как GNU tar: имя относительное, ведущие '/' срезаются
    let s = cur.to_string_lossy().replace('\\', "/");
    let s = s.trim_start_matches("./");
    let s = s.trim_start_matches('/');
    s.to_string()
}

#[cfg(unix)]
fn unix_mode(meta: &fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    (meta.mode() & 0o7777) as u32
}

#[cfg(not(unix))]
fn unix_mode(_meta: &fs::Metadata) -> u32 {
    0o644
}

#[cfg(unix)]
fn unix_mtime(meta: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    meta.mtime().max(0) as u64
}

#[cfg(not(unix))]
fn unix_mtime(meta: &fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Read for FsTarReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut filled = 0usize;
        'outer: loop {
            // A) выгрузить stage (заголовок/пад/терминатор)
            if !self.stage.is_empty() {
                filled += drain_stage(&mut self.stage, buf, filled);
                if filled == buf.len() {
                    return Ok(filled);
                }
            }
            // B) данные текущего файла — напрямую в buf, без буферизации
            if let Some(f) = self.file.as_mut() {
                while filled < buf.len() && self.remaining > 0 {
                    let want = (buf.len() - filled).min(self.remaining as usize);
                    let n = f.read(&mut buf[filled..filled + want])?;
                    if n == 0 {
                        return Err(io::Error::other(
                            "файл сократился во время архивации",
                        ));
                    }
                    self.remaining -= n as u64;
                    filled += n;
                }
                if self.remaining == 0 {
                    self.file = None;
                    self.stage = pad_bytes(self.file_size);
                    continue 'outer;
                }
                if filled == buf.len() {
                    return Ok(filled);
                }
            }
            // C) нет ни stage, ни файла → следующий entry или терминатор
            if let Some(e) = self.entries.pop_front() {
                self.stage = ustar_header(&e)?;
                if let Some(src) = &e.src {
                    self.file = Some(fs::File::open(src)?);
                    self.remaining = e.size;
                    self.file_size = e.size;
                } else {
                    self.stage.extend(pad_bytes(0)); // каталог: данных нет
                }
                continue 'outer;
            } else if !self.done {
                self.stage = vec![0u8; 1024]; // два нулевых блока — конец tar
                self.done = true;
                continue 'outer;
            } else {
                return Ok(filled); // поток исчерпан (возможно, EOF: filled == 0)
            }
        }
    }
}

fn drain_stage(stage: &mut Vec<u8>, buf: &mut [u8], filled: usize) -> usize {
    if stage.is_empty() || filled >= buf.len() {
        return 0;
    }
    let n = (buf.len() - filled).min(stage.len());
    buf[filled..filled + n].copy_from_slice(&stage[..n]);
    stage.drain(..n);
    n
}

fn pad_bytes(size: u64) -> Vec<u8> {
    let rem = (size % 512) as usize;
    if rem == 0 {
        Vec::new()
    } else {
        vec![0u8; 512 - rem]
    }
}

fn ustar_header(e: &TarEntry) -> io::Result<Vec<u8>> {
    let mut b = vec![0u8; 512];
    let (name, prefix) = split_ustar_name(&e.name).map_err(io::Error::other)?;
    put_field(&mut b[0..100], name.as_bytes())?;
    put_octal(&mut b[100..108], 7, e.mode as u64);
    put_octal(&mut b[108..116], 7, 0); // uid
    put_octal(&mut b[116..124], 7, 0); // gid
    put_octal(&mut b[124..136], 11, e.size);
    put_octal(&mut b[136..148], 11, e.mtime);
    for x in b[148..156].iter_mut() {
        *x = b' '; // поле контрольной суммы, заполненное пробелами
    }
    b[156] = if e.is_dir { b'5' } else { b'0' };
    b[257..262].copy_from_slice(b"ustar");
    b[262] = 0;
    b[263..265].copy_from_slice(b"00");
    put_field(&mut b[265..297], b"poler")?;
    put_field(&mut b[297..329], b"poler")?;
    put_octal(&mut b[329..337], 7, 0);
    put_octal(&mut b[337..345], 7, 0);
    put_field(&mut b[345..500], prefix.as_bytes())?;
    let sum: u32 = b.iter().map(|&x| x as u32).sum();
    put_octal(&mut b[148..154], 6, sum as u64);
    b[154] = 0;
    b[155] = b' ';
    Ok(b)
}

fn split_ustar_name(name: &str) -> Result<(String, String), String> {
    let n = name.as_bytes();
    if n.len() <= 100 {
        return Ok((name.to_string(), String::new()));
    }
    // POSIX-ustar: prefix[155] + '/' + name[100]
    let cut = n.len() - 100;
    if n.len() > 255 || !n[cut..].iter().all(|&c| c != 0) {
        return Err(format!(
            "имя записи длиннее ustar-поля (255): «{name}» — используйте GNU tar в конвейере"
        ));
    }
    let prefix = String::from_utf8_lossy(&n[..cut]).trim_end_matches('/').to_string();
    let file = String::from_utf8_lossy(&n[cut..]).to_string();
    if prefix.is_empty() || file.is_empty() {
        return Err(format!("не удалось разделить ustar-имя: «{name}»"));
    }
    Ok((file, prefix))
}

fn put_field(dst: &mut [u8], val: &[u8]) -> io::Result<()> {
    if val.len() >= dst.len() {
        return Err(io::Error::other("поле ustar переполнено"));
    }
    dst[..val.len()].copy_from_slice(val);
    dst[val.len()..].fill(0);
    Ok(())
}

fn put_octal(dst: &mut [u8], digits: usize, v: u64) {
    let s = format!("{:0width$o}", v, width = digits);
    let bytes = s.as_bytes();
    let n = bytes.len().min(dst.len() - 1);
    dst[..n].copy_from_slice(&bytes[bytes.len() - n..]);
    dst[dst.len() - 1] = 0;
}
