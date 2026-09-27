//! `poler-box` — CLI нативной коробки «без ОС» поверх `.poler`.
//!
//! Архив + запись = изолированный процесс: userns (через доверенный
//! /usr/bin/unshare), pivot_root на tmpfs, seccomp-белый список, netns
//! (только loopback), pidns (payload = pid 1), губернатор RSS/CPU.
//! Образа ОС нет: rootfs коробки стримится прямо из архива.
//!
//! Stage2-вход (`POLER_BOX_STAGE2=1`) обязан стоять ДО парсинга argv —
//! им же пользуется unshare-хелпер при ре-запуске нас самих.

use std::env;
use std::path::PathBuf;

use poler_box::{run_box, BoxSpec};

const USAGE: &str = "\
poler-box — нативная коробка без ОС поверх .poler-архивов
Изоляция: userns + pivot_root(tmpfs) + seccomp-белый список + netns + pidns.

ИСПОЛЬЗОВАНИЕ:
  poler-box run ARCHIVE.poler ЗАПИСЬ [аргументы payload...]
      --map ПРЕФИКС=КАТАЛОГ   смонтировать записи архива в каталог коробки
      --rss-mb N               лимит RSS дерева (def: 512)
      --cpu-s N                лимит CPU-времени, с (def: 60)
      --tmpfs-mb N             размер tmpfs rootfs (def: 256)
      --no-isolate             debug: без ns/pivot/seccomp (только губернатор)
  poler-box safe-extract ARCHIVE.poler [DIR]
      --max-files N            (def: 100000)
      --max-total-mb N         (def: 8192) — защита от бомб
  poler-box list ARCHIVE.poler --entries   только имена исполняемых записей

Отчёт — JSON в stdout.";

fn main() {
    // stage2: мы перезапущены unshare-хелпером с env-спецификацией
    if env::var_os("POLER_BOX_STAGE2").is_some() {
        let code = poler_box::stage2_main();
        std::process::exit(code);
    }
    let args: Vec<String> = env::args().skip(1).collect();
    match run(args) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("poler-box: {e}");
            std::process::exit(1);
        }
    }
}

fn run(args: Vec<String>) -> Result<i32, String> {
    if args.is_empty() || args[0] == "-h" || args[0] == "--help" {
        print!("{USAGE}");
        return Ok(0);
    }
    match args[0].as_str() {
        "run" => cmd_run(&args[1..]),
        "safe-extract" | "x" => cmd_safe_extract(&args[1..]),
        "list" => cmd_list(&args[1..]),
        other => Err(format!("неизвестная команда «{other}». --help — справка")),
    }
}

fn cmd_run(rest: &[String]) -> Result<i32, String> {
    let mut archive: Option<String> = None;
    let mut entry: Option<String> = None;
    let mut payload_args: Vec<String> = Vec::new();
    let mut maps: Vec<(String, String)> = Vec::new();
    let mut rss_mb: u64 = 512;
    let mut cpu_s: u64 = 60;
    let mut tmpfs_mb: u64 = 256;
    let mut isolate = true;

    let mut i = 0;
    let mut after_entry = false;
    while i < rest.len() {
        let a = rest[i].as_str();
        if after_entry {
            payload_args.push(a.to_string());
        } else {
            match a {
                "--map" => {
                    i += 1;
                    let m = rest.get(i).ok_or("--map ПРЕФИКС=КАТАЛОГ")?;
                    let (p, c) = m.split_once('=').ok_or("--map ПРЕФИКС=КАТАЛОГ")?;
                    maps.push((p.trim().to_string(), c.trim().to_string()));
                }
                "--rss-mb" => {
                    i += 1;
                    rss_mb = rest.get(i).and_then(|s| s.parse().ok()).ok_or("--rss-mb N")?;
                }
                "--cpu-s" => {
                    i += 1;
                    cpu_s = rest.get(i).and_then(|s| s.parse().ok()).ok_or("--cpu-s N")?;
                }
                "--tmpfs-mb" => {
                    i += 1;
                    tmpfs_mb =
                        rest.get(i).and_then(|s| s.parse().ok()).ok_or("--tmpfs-mb N")?;
                }
                "--no-isolate" => isolate = false,
                s if s.starts_with("--") => return Err(format!("неизвестный флаг run: {s}")),
                s if archive.is_none() => archive = Some(s.to_string()),
                s if entry.is_none() => {
                    entry = Some(s.to_string());
                    after_entry = true;
                }
                s => return Err(format!("лишний аргумент run: {s}")),
            }
        }
        i += 1;
    }
    let archive = archive.ok_or("run ARCHIVE.poler ЗАПИСЬ [аргументы...]")?;
    let entry = entry.ok_or("run ARCHIVE.poler ЗАПИСЬ (см. poler-box list ARCHIVE.poler)")?;

    let spec = BoxSpec {
        archive: PathBuf::from(&archive),
        entry,
        args: payload_args,
        maps,
        rss_mb,
        cpu_s,
        tmpfs_mb,
        isolate,
    };
    let report = run_box(&spec)?;
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
    Ok(report.exit_code.unwrap_or(0))
}

fn cmd_safe_extract(rest: &[String]) -> Result<i32, String> {
    let mut path: Option<String> = None;
    let mut dir = String::from("poler-extracted");
    let mut max_files: usize = 100_000;
    let mut max_total: u64 = 8192;

    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--max-files" => {
                i += 1;
                max_files = rest.get(i).and_then(|s| s.parse().ok()).ok_or("--max-files N")?;
            }
            "--max-total-mb" => {
                i += 1;
                max_total =
                    rest.get(i).and_then(|s| s.parse().ok()).ok_or("--max-total-mb N")?;
            }
            s if path.is_none() => path = Some(s.to_string()),
            s => dir = s.to_string(),
        }
        i += 1;
    }
    let path = path.ok_or("safe-extract ARCHIVE.poler [DIR]")?;

    // Бомба-фильтр ДО распаковки: лимиты по количеству и суммарному объёму
    let reader = poler_archive::PolerReader::open(std::path::Path::new(&path))?;
    let files = reader.files();
    if files.len() > max_files {
        return Err(format!(
            "бомба? {} записей > лимита {max_files} (--max-files)",
            files.len()
        ));
    }
    let total: u64 = files.iter().map(|f| f.raw_len).sum();
    if total > max_total * 1024 * 1024 {
        return Err(format!(
            "бомба? суммарно {} > лимита {max_total} МиБ (--max-total-mb)",
            poler_archive::fmt_bytes(total)
        ));
    }
    let rep = reader.extract_all(std::path::Path::new(&dir))?;
    println!("{}", serde_json::to_string_pretty(&rep).unwrap());
    if rep.files_bad.is_empty() && rep.files_skipped_unsafe.is_empty() {
        eprintln!(
            "poler-box: безопасно извлечено {} файлов -> {} (SHA-256 OK)",
            rep.files_written, dir
        );
        Ok(0)
    } else {
        eprintln!(
            "poler-box: проблемы: битые {:?}, небезопасные {:?}",
            rep.files_bad, rep.files_skipped_unsafe
        );
        Ok(2)
    }
}

fn cmd_list(rest: &[String]) -> Result<i32, String> {
    let entries_only = rest.iter().any(|a| a == "--entries");
    let path = rest
        .iter()
        .find(|a| !a.starts_with("--"))
        .ok_or("list ARCHIVE.poler [--entries]")?;
    let reader = poler_archive::PolerReader::open(std::path::Path::new(path))?;
    for f in reader.files() {
        if entries_only {
            println!("{}", f.name);
        } else {
            println!("{:>12}  {}", f.raw_len, f.name);
        }
    }
    Ok(0)
}
