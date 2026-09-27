//! `poler` — CLI суверенного стримингового архиватора `.poler`.
//!
//! Standalone: крейт `poler-archive` не зависит от poler-engine.
//! Подкоманды в стиле tar/7z: create / list / info / verify / extract /
//! cat / patch / rollback.

use std::env;
use std::fs;
use std::io::{self};
use std::path::{Path, PathBuf};

use poler_archive::{
    patch_archive, rollback_archive, CompressTier, FsTarReader, PatchOp, PatchOptions,
    PolerReader, StreamWriteConfig, StreamWriteStats, write_stream,
};

const USAGE: &str = "\
poler — суверенный стриминговый архиватор .poler
Формат: FastCDC-чанки + BLAKE3-дедуп + zstd(3/15) + файловая таблица, crash-safe.

ИСПОЛЬЗОВАНИЕ:
  poler create ARCHIVE.poler ПУТЬ...      заархивировать файлы/каталоги
  poler create ARCHIVE.poler -            tar из stdin -> .poler (конвейер)
  poler list  ARCHIVE.poler [--json]      листинг записей
  poler info  ARCHIVE.poler               метаданные контейнера
  poler verify ARCHIVE.poler              целостность (SHA-256 потока и записей)
  poler extract ARCHIVE.poler [DIR]       распаковка (защита от zip-slip)
  poler cat ARCHIVE.poler ЗАПИСЬ          вывести запись в stdout
  poler patch ARCHIVE.poler add|replace|delete ИМЯ [ФАЙЛ]
      --ops 'add name=file; replace name=file; delete name'  (список операций)
  poler rollback ARCHIVE.poler            откат к .polerbak

ОПЦИИ create/patch: --tier fast|deep|auto (def: auto)  --no-dedup
                     --avg KiB (цель чанка, def: 256)
Статистика записи выводится JSON в stdout.";

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    match run(args) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("poler: {e}");
            std::process::exit(1);
        }
    }
}

fn run(args: Vec<String>) -> Result<i32, String> {
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
        print!("{USAGE}");
        return Ok(0);
    }
    match args[0].as_str() {
        "c" | "create" | "a" => cmd_create(&args[1..]),
        "l" | "list" | "t" => cmd_list(&args[1..]),
        "i" | "info" => cmd_info(&args[1..]),
        "test" | "verify" => cmd_verify(&args[1..]),
        "x" | "extract" => cmd_extract(&args[1..]),
        "cat" => cmd_cat(&args[1..]),
        "patch" => cmd_patch(&args[1..]),
        "rollback" => cmd_rollback(&args[1..]),
        other => Err(format!("неизвестная команда «{other}». --help — справка")),
    }
}

// ───────────────────────── create ─────────────────────────

fn cmd_create(rest: &[String]) -> Result<i32, String> {
    let mut tier = CompressTier::Auto;
    let mut dedup = true;
    let mut avg_kib: Option<usize> = None;
    let mut positional: Vec<String> = Vec::new();

    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--tier" => {
                i += 1;
                tier = match rest.get(i).map(|s| s.as_str()) {
                    Some("fast") => CompressTier::Fast,
                    Some("deep") => CompressTier::Deep,
                    Some("auto") => CompressTier::Auto,
                    _ => return Err("--tier: fast | deep | auto".into()),
                };
            }
            "--no-dedup" => dedup = false,
            "--avg" => {
                i += 1;
                avg_kib = Some(
                    rest.get(i)
                        .and_then(|s| s.parse().ok())
                        .ok_or("--avg KiB: число")?,
                );
            }
            s if s.starts_with('-') && s != "-" => {
                return Err(format!("неизвестный флаг create: {s}"))
            }
            s => positional.push(s.to_string()),
        }
        i += 1;
    }
    if positional.len() < 2 {
        return Err("create ARCHIVE.poler ПУТЬ... (или «-» для tar из stdin)".into());
    }
    let out = PathBuf::from(&positional[0]);
    let sources: Vec<String> = positional[1..].to_vec();

    let mut cfg = StreamWriteConfig::default();
    cfg.tier = tier;
    cfg.dedup = dedup;
    if let Some(kib) = avg_kib {
        let avg = kib * 1024;
        if !(4..=4096).contains(&kib) {
            return Err("--avg: 4..4096 KiB".into());
        }
        let min = (avg / 4).max(1024);
        let max = (avg * 4).min(4 << 20);
        cfg.cdc = poler_archive::CdcParams::new(min, avg, max);
    }

    let stats: StreamWriteStats = if sources.len() == 1 && sources[0] == "-" {
        // конвейер: tar -c dir | poler create out.poler -
        write_stream(io::stdin(), &out, cfg, "stdin-stream")
            .map_err(|e| format!("stdin: {e}"))?
    } else if sources.len() == 1 && Path::new(&sources[0]).is_file() {
        let src_path = Path::new(&sources[0]);
        let name_lower = src_path
            .file_name()
            .map(|s| s.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        if name_lower.ends_with(".tar.gz") || name_lower.ends_with(".tgz") {
            let f = fs::File::open(src_path)
                .map_err(|e| format!("{}: {e}", src_path.display()))?;
            let gz = flate2::read::MultiGzDecoder::new(f);
            write_stream(gz, &out, cfg, "tar.gz-stream")
                .map_err(|e| format!("{}: {e}", out.display()))?
        } else if name_lower.ends_with(".tar.zst") || name_lower.ends_with(".tzst") {
            let f = fs::File::open(src_path)
                .map_err(|e| format!("{}: {e}", src_path.display()))?;
            let zdec = zstd::Decoder::new(f)
                .map_err(|e| format!("{}: {e}", src_path.display()))?;
            write_stream(zdec, &out, cfg, "tar.zst-stream")
                .map_err(|e| format!("{}: {e}", out.display()))?
        } else if name_lower.ends_with(".tar") {
            let f = fs::File::open(src_path)
                .map_err(|e| format!("{}: {e}", src_path.display()))?;
            write_stream(f, &out, cfg, "tar-stream")
                .map_err(|e| format!("{}: {e}", out.display()))?
        } else if name_lower.ends_with(".gz") {
            let f = fs::File::open(src_path)
                .map_err(|e| format!("{}: {e}", src_path.display()))?;
            let gz = flate2::read::MultiGzDecoder::new(f);
            write_stream(gz, &out, cfg, "gz-stream")
                .map_err(|e| format!("{}: {e}", out.display()))?
        } else if name_lower.ends_with(".zst") {
            let f = fs::File::open(src_path)
                .map_err(|e| format!("{}: {e}", src_path.display()))?;
            let zdec = zstd::Decoder::new(f)
                .map_err(|e| format!("{}: {e}", src_path.display()))?;
            write_stream(zdec, &out, cfg, "zst-stream")
                .map_err(|e| format!("{}: {e}", out.display()))?
        } else {
            let paths: Vec<PathBuf> = sources.iter().map(PathBuf::from).collect();
            let tar = FsTarReader::new(&paths)?;
            write_stream(tar, &out, cfg, "archive")
                .map_err(|e| format!("{}: {e}", out.display()))?
        }
    } else {
        let paths: Vec<PathBuf> = sources.iter().map(PathBuf::from).collect();
        let tar = FsTarReader::new(&paths)?;
        write_stream(tar, &out, cfg, "archive")
            .map_err(|e| format!("{}: {e}", out.display()))?
    };
    println!("{}", serde_json::to_string_pretty(&stats).unwrap());
    if !stats.output.is_empty() {
        eprintln!(
            "poler: {} -> {} ({}, ratio {:.3})",
            poler_archive::fmt_bytes(stats.total_raw),
            stats.output,
            poler_archive::fmt_bytes(stats.total_stored),
            stats.ratio
        );
    }
    Ok(0)
}

// ───────────────────── чтение: list/info/verify/extract/cat ─────────────────────

fn open_reader(path: &str) -> Result<PolerReader, String> {
    PolerReader::open(Path::new(path))
}

fn cmd_list(rest: &[String]) -> Result<i32, String> {
    let json = rest.iter().any(|a| a == "--json");
    let path = rest
        .iter()
        .find(|a| !a.starts_with("--"))
        .ok_or("list ARCHIVE.poler [--json]")?;
    let r = open_reader(path)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&r.list_json()).unwrap());
    } else {
        for f in r.files() {
            println!("{:>12}  {}", f.raw_len, f.name);
        }
        eprintln!(
            "poler: {} записей, {} сырое, {} сохранённое",
            r.files().len(),
            poler_archive::fmt_bytes(r.info().total_raw),
            poler_archive::fmt_bytes(r.info().total_stored)
        );
    }
    Ok(0)
}

fn cmd_info(rest: &[String]) -> Result<i32, String> {
    let path = rest.first().ok_or("info ARCHIVE.poler")?;
    let r = open_reader(path)?;
    println!("{}", serde_json::to_string_pretty(&r.info()).unwrap());
    Ok(0)
}

fn cmd_verify(rest: &[String]) -> Result<i32, String> {
    let path = rest.first().ok_or("verify ARCHIVE.poler")?;
    let r = open_reader(path)?;
    let rep = r.verify()?;
    println!("{}", serde_json::to_string_pretty(&rep).unwrap());
    if rep.all_ok {
        eprintln!(
            "poler: OK — поток SHA-256 сходится, {} записей проверено",
            rep.files_ok
        );
        Ok(0)
    } else {
        eprintln!("poler: ЦЕЛОСТНОСТЬ НАРУШЕНА: {:?}", rep.files_bad);
        Ok(2)
    }
}

fn cmd_extract(rest: &[String]) -> Result<i32, String> {
    let path = rest.first().ok_or("extract ARCHIVE.poler [DIR]")?;
    let dir = rest.get(1).map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(Path::new(path).file_stem().and_then(|s| s.to_str()).unwrap_or("poler-out"))
    });
    let r = open_reader(path)?;
    let rep = r.extract_all(&dir)?;
    println!("{}", serde_json::to_string_pretty(&rep).unwrap());
    if !rep.files_bad.is_empty() || !rep.files_skipped_unsafe.is_empty() {
        eprintln!(
            "poler: извлечено с проблемами: SHA-256 не сошёлся у {:?}, небезопасные пути пропущены: {:?}",
            rep.files_bad, rep.files_skipped_unsafe
        );
        Ok(2)
    } else {
        eprintln!(
            "poler: {} файлов -> {} (все SHA-256 OK)",
            rep.files_written,
            dir.display()
        );
        Ok(0)
    }
}

fn cmd_cat(rest: &[String]) -> Result<i32, String> {
    if rest.len() < 2 {
        return Err("cat ARCHIVE.poler ЗАПИСЬ".into());
    }
    let r = open_reader(&rest[0])?;
    let name = &rest[1];
    let f = r.find_file(name).ok_or_else(|| {
        let mut hint = String::new();
        if let Some(sim) = r
            .files()
            .iter()
            .map(|f| f.name.as_str())
            .min_by_key(|n| edit_distance(n, name))
        {
            hint = format!(" (похоже: «{sim}»? см. poler list)");
        }
        format!("запись «{name}» не найдена{hint}")
    })?;
    let mut out = io::stdout();
    let mut buf = Vec::new();
    let mut off = f.raw_off;
    let end = f.raw_off + f.raw_len;
    while off < end {
        let step = ((end - off) as usize).min(1024 * 1024);
        r.read_range(off, step, &mut buf)?;
        use std::io::Write;
        out.write_all(&buf).map_err(|e| format!("cat: {e}"))?;
        off += step as u64;
    }
    Ok(0)
}

// ───────────────────────── patch / rollback ─────────────────────────

fn cmd_patch(rest: &[String]) -> Result<i32, String> {
    let mut path: Option<String> = None;
    let mut ops: Vec<PatchOp> = Vec::new();
    let mut tier = CompressTier::Auto;

    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--tier" => {
                i += 1;
                tier = match rest.get(i).map(|s| s.as_str()) {
                    Some("fast") => CompressTier::Fast,
                    Some("deep") => CompressTier::Deep,
                    _ => CompressTier::Auto,
                };
            }
            "--ops" => {
                i += 1;
                let list = rest.get(i).ok_or("--ops 'add name=file; delete name'")?;
                for one in list.split(';') {
                    let one = one.trim();
                    if one.is_empty() {
                        continue;
                    }
                    ops.push(parse_op(one)?);
                }
            }
            s if path.is_none() => path = Some(s.to_string()),
            s => return Err(format!("лишний аргумент patch: {s}")),
        }
        i += 1;
    }
    let path = path.ok_or("patch ARCHIVE.poler --ops '...'")?;
    if ops.is_empty() {
        return Err("нет операций: --ops 'add name=file; replace name=file; delete name'".into());
    }
    let opts = PatchOptions {
        cdc: poler_archive::CdcParams::default(),
        tier,
        force_bak: false,
    };
    let rep = patch_archive(Path::new(&path), &ops, &opts)?;
    println!("{}", serde_json::to_string_pretty(&rep).unwrap());
    Ok(0)
}

fn parse_op(one: &str) -> Result<PatchOp, String> {
    let (kind, tail) = one.split_once(' ').ok_or("операция: add|replace|delete ИМЯ[=ФАЙЛ]")?;
    match kind {
        "delete" => Ok(PatchOp::delete(tail.trim())),
        "add" | "replace" => {
            let (name, file) = tail.split_once('=').ok_or("add/replace ИМЯ=ФАЙЛ")?;
            let data = fs::read(file.trim())
                .map_err(|e| format!("{}: {e}", file.trim()))?;
            if kind == "add" {
                Ok(PatchOp::add(name.trim(), data))
            } else {
                Ok(PatchOp::replace(name.trim(), data))
            }
        }
        k => Err(format!("неизвестная операция «{k}»")),
    }
}

fn cmd_rollback(rest: &[String]) -> Result<i32, String> {
    let path = rest.first().ok_or("rollback ARCHIVE.poler")?;
    let rep = rollback_archive(Path::new(path))?;
    println!("{}", serde_json::to_string_pretty(&rep).unwrap());
    Ok(0)
}

fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for i in 1..=a.len() {
        cur[0] = i;
        for j in 1..=b.len() {
            cur[j] = (prev[j] + 1)
                .min(cur[j - 1] + 1)
                .min(prev[j - 1] + if a[i - 1] == b[j - 1] { 0 } else { 1 });
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}
