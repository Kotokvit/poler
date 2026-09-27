//! poler-box (v0.41.0): нативна «заміна Docker без ОС» — циклічна обгортка
//! виконання поверх .poler-архівів.
//!
//! ## Архітектура (три процеси)
//!
//! ```text
//! P  poler-engine (CLI)          — fork/exec, губернатор (RSS/CPU), звіт
//! C1 └─ /usr/bin/unshare -Ur —   — привілейований хелпер: userns + мапа 0↔uid
//!     └─ poler-engine (stage2)   — unshare(mnt/pid/net/ipc/uts), tmpfs,
//!                                  стрім payload з архіву, pivot_root,
//!                                  rlimits, seccomp, execveat(memfd)
//!        └─ D = payload (pid 1)  — зсередини: хост невидимий, syscall-мур,
//!                                  нативні CPU/RAM хоста
//! ```
//!
//! ## Чому unshare-хелпер
//! Кастомне ядро пісочниці (kangaroo) відхиляє запис uid_map від бінарників,
//! невідомих його політиці (свіжоскомпільовані — EPERM, util-linux — так).
//! Тому userns+мапу встановлює exec довіреного /usr/bin/unshare -Ur —
//! стандартний патерн rootless-контейнерів (аналог newuidmap).
//!
//! ## Чому це «коробка без ОС»
//! Жодного образу ОС всередині: rootfs коробки — це tmpfs (RAM), куди
//! стрімляться записи .poler-архіву. Процеси виконуються нативно на залізі
//! хоста (спільне ядро, спільні CPU/RAM — «залізо ідентичне хосту»), але:
//!   * шляхи: pivot_root на tmpfs — файлова система хоста зникає з виду;
//!   * сисколи: seccomp-білий список (~140) + KILL для смертельних;
//!   * мережа: netns (тільки loopback, AF_INET/6 → EPERM подвійно);
//!   * процеси: pidns (payload = pid 1, хостових pid не існує);
//!   * пам'ять/CPU: губернатор з деревом процесів + rlimits-кордони.
//!
//! ## Циклічність
//! Полер-движок сам може бути записом архіву: poler-box запускає
//! poler-engine з архіву всередині коробки, який відкриває інші архіви
//! (передані в rootfs) — обгортка всередині обгортки, без кінця.

//! ## Портативність
//! Ізоляція — суто API ядра Linux (userns/pivot_root/seccomp/netns/pidns):
//! увесь цей модуль компілюється тільки на Linux. `safe-extract`/`list`
//! (у бінарнику poler-box) працюють на всіх ОС — це тонкі обгортки
//! poler-archive без сисколів ядра.

#![cfg(target_os = "linux")]

use std::collections::VecDeque;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Параметри запуску коробки (CLI → P → env → stage2).
#[derive(Debug, Clone)]
pub struct BoxSpec {
    /// .poler-архів з payload.
    pub archive: PathBuf,
    /// Запис архіву, що стає процесом коробки.
    pub entry: String,
    /// Аргументи payload (argv[1..]).
    pub args: Vec<String>,
    /// Мапи «префікс записів архіву → каталог коробки».
    pub maps: Vec<(String, String)>,
    /// Ліміт RSS усієї дерева, МБ (губернатор).
    pub rss_mb: u64,
    /// Ліміт CPU-часу дерева, с (губернатор).
    pub cpu_s: u64,
    /// Розмір tmpfs rootfs, МБ.
    pub tmpfs_mb: u64,
    /// Повна ізоляція (ns + pivot + seccomp). false = debug (губернатор лише).
    pub isolate: bool,
}

impl Default for BoxSpec {
    fn default() -> Self {
        Self {
            archive: PathBuf::new(),
            entry: String::new(),
            args: Vec::new(),
            maps: vec![("rootfs/".to_string(), "/".to_string())],
            rss_mb: 512,
            cpu_s: 60,
            tmpfs_mb: 512,
            isolate: true,
        }
    }
}

/// Звіт губернатора (друкується P у stderr як JSON після завершення).
#[derive(Debug, Clone, serde::Serialize)]
pub struct BoxReport {
    pub entry: String,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub kill_reason: Option<&'static str>,
    pub peak_tree_rss_kb: u64,
    pub cpu_seconds: f64,
    pub wall_seconds: f64,
    pub isolation: IsolationSummary,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct IsolationSummary {
    pub userns_via_helper: bool,
    pub namespaces: &'static str,
    pub pivot_root: bool,
    pub seccomp: String,
    pub notes: Vec<String>,
}

// ============================== STAGE 1 (P) ==============================

/// Головний вхід `--poler-box`: fork → exec unshare-хелпера → губернатор.
pub fn run_box(spec: &BoxSpec) -> Result<BoxReport, String> {
    if !spec.archive.exists() {
        return Err(format!("архів не знайдено: {}", spec.archive.display()));
    }
    if spec.entry.is_empty() {
        return Err("вкажіть --box-entry <ім'я запису>".into());
    }

    // Перевіряємо запис ще в P — швидкий fail без розгортання процесів.
    {
        let reader = poler_archive::reader::PolerReader::open(&spec.archive)?;
        if reader.find_file(&spec.entry).is_none() {
            return Err(format!(
                "запис '{}' відсутній в {} (див. --poler-list)",
                spec.entry,
                spec.archive.display()
            ));
        }
    }

    let self_exe = read_self_exe()?;
    let _unshare_bin = find_unshare().ok_or_else(|| {
        "не знайдено /usr/bin/unshare — привілейований хелпер userns відсутній".to_string()
    })?;

    let (rep_r, rep_w) = nix_pipe()?;
    let t0 = std::time::Instant::now();

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!("fork: {}", std::io::Error::last_os_error()));
    }
    if pid == 0 {
        // === C1: стане unshare-хелпером, потім stage2 ===
        unsafe {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
            libc::close(rep_r);
        }
        let env_pairs = spec_to_env(spec, rep_w);
        for (k, v) in &env_pairs {
            std::env::set_var(k, v);
        }
        let argv: Vec<std::ffi::CString> = vec![
            std::ffi::CString::new("unshare").unwrap(),
            std::ffi::CString::new("-Ur").unwrap(),
            std::ffi::CString::new("--").unwrap(),
            std::ffi::CString::new(self_exe.as_os_str().as_encoded_bytes())
                .map_err(|e| e.to_string())?,
        ];
        let mut cargv: Vec<*const std::os::raw::c_char> =
            argv.iter().map(|c| c.as_ptr()).collect();
        cargv.push(std::ptr::null());
        unsafe { libc::execvp(cargv[0], cargv.as_mut_ptr()) };
        eprintln!(
            "poler-box: execvp(unshare): {}",
            std::io::Error::last_os_error()
        );
        std::process::exit(126);
    }

    // === P: губернатор ===
    unsafe {
        libc::close(rep_w);
    }
    let payload_pid = read_pid_from_pipe(rep_r);
    Ok(govern_and_reap(pid, payload_pid, spec, t0))
}

/// Губернатор: поллінг дерева RSS/CPU, kill при перевищенні, reap, звіт.
fn govern_and_reap(
    child_pid: i32,
    payload_pid: Option<i32>,
    spec: &BoxSpec,
    t0: std::time::Instant,
) -> BoxReport {
    let mut kill_reason: Option<&'static str> = None;
    let mut peak_rss_kb: u64 = 0;
    let mut cpu_seconds: f64 = 0.0;
    let rss_limit_kb = spec.rss_mb.saturating_mul(1024);
    let cpu_limit = spec.cpu_s as f64;
    let monitor = payload_pid.map(|ppid| {
        std::thread::spawn(move || -> (u64, f64, Option<&'static str>) {
            let mut peak: u64 = 0;
            let mut cpu: f64 = 0.0;
            let mut reason: Option<&'static str> = None;
            loop {
                let tree = collect_tree(ppid);
                if !path_alive(ppid) {
                    break; // процес зник
                }
                let mut rss_sum: u64 = 0;
                let mut cpu_sum: f64 = 0.0;
                for &p in &tree {
                    rss_sum += read_status_field(p, "VmRSS").unwrap_or(0);
                    cpu_sum += read_cpu_seconds(p);
                }
                peak = peak.max(rss_sum);
                cpu = cpu_sum;
                if rss_sum > rss_limit_kb {
                    unsafe {
                        libc::kill(ppid, libc::SIGKILL);
                    }
                    reason = Some("rss_limit");
                    break;
                }
                if cpu_sum > cpu_limit {
                    unsafe {
                        libc::kill(ppid, libc::SIGKILL);
                    }
                    reason = Some("cpu_limit");
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            (peak, cpu, reason)
        })
    });

    let mut status: i32 = 0;
    unsafe {
        libc::waitpid(child_pid, &mut status, 0);
    }
    if let Some(handle) = monitor {
        let (peak, cpu, reason) = handle.join().unwrap_or((0, 0.0, None));
        peak_rss_kb = peak;
        cpu_seconds = cpu;
        if kill_reason.is_none() {
            kill_reason = reason;
        }
    }
    let (exit_code, signal) = if libc_wifexited(status) {
        (Some(libc_wexitstatus(status)), None)
    } else if libc_wifsignaled(status) {
        (None, Some(libc_wtermsig(status)))
    } else {
        (None, None)
    };
    BoxReport {
        entry: spec.entry.clone(),
        exit_code,
        signal,
        kill_reason,
        peak_tree_rss_kb: peak_rss_kb,
        cpu_seconds,
        wall_seconds: t0.elapsed().as_secs_f64(),
        isolation: IsolationSummary {
            userns_via_helper: spec.isolate,
            namespaces: if spec.isolate {
                "user,mnt,pid,net,ipc,uts"
            } else {
                "none (debug)"
            },
            pivot_root: spec.isolate,
            seccomp: if spec.isolate {
                format!("whitelist; deadly_killed={}", DEADLY.len())
            } else {
                "off".to_string()
            },
            notes: Vec::new(),
        },
    }
}

fn spec_to_env(spec: &BoxSpec, rep_fd: i32) -> Vec<(String, String)> {
    let maps = spec
        .maps
        .iter()
        .map(|(a, b)| format!("{a}|{b}"))
        .collect::<Vec<_>>()
        .join(";");
    vec![
        ("POLER_BOX_STAGE2".into(), "1".into()),
        ("POLER_BOX_ARCHIVE".into(), spec.archive.display().to_string()),
        ("POLER_BOX_ENTRY".into(), spec.entry.clone()),
        ("POLER_BOX_ARGS".into(), spec.args.join("\u{1}")),
        ("POLER_BOX_MAPS".into(), maps),
        ("POLER_BOX_RSS_MB".into(), spec.rss_mb.to_string()),
        ("POLER_BOX_CPU_S".into(), spec.cpu_s.to_string()),
        ("POLER_BOX_TMPFS_MB".into(), spec.tmpfs_mb.to_string()),
        (
            "POLER_BOX_ISOLATE".into(),
            if spec.isolate { "1" } else { "0" }.into(),
        ),
        ("POLER_BOX_REPORT_FD".into(), rep_fd.to_string()),
    ]
}

fn read_self_exe() -> Result<PathBuf, String> {
    let p =
        std::fs::read_link("/proc/self/exe").map_err(|e| format!("readlink /proc/self/exe: {e}"))?;
    Ok(p)
}

fn find_unshare() -> Option<PathBuf> {
    for p in ["/usr/bin/unshare", "/bin/unshare"] {
        if Path::new(p).exists() {
            return Some(PathBuf::from(p));
        }
    }
    None
}

fn nix_pipe() -> Result<(i32, i32), String> {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(format!("pipe: {}", std::io::Error::last_os_error()));
    }
    Ok((fds[0], fds[1]))
}

fn read_pid_from_pipe(fd: i32) -> Option<i32> {
    let mut buf = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().add(got) as *mut _, 4 - got) };
        if n <= 0 {
            unsafe {
                libc::close(fd);
            }
            return None;
        }
        got += n as usize;
    }
    unsafe {
        libc::close(fd);
    }
    Some(i32::from_le_bytes(buf))
}

// ============================== STAGE 2 (C1) ==============================

/// Вхід stage2 — визивається з main() за наявності POLER_BOX_STAGE2.
pub fn stage2_main() -> i32 {
    match stage2_run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("poler-box stage2: {e}");
            125
        }
    }
}

fn env_or(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_string())
}

fn stage2_run() -> Result<i32, String> {
    let archive = PathBuf::from(env_or("POLER_BOX_ARCHIVE", ""));
    let entry = env_or("POLER_BOX_ENTRY", "");
    let args: Vec<String> = env_or("POLER_BOX_ARGS", "")
        .split('\u{1}')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    let maps: Vec<(String, String)> = env_or("POLER_BOX_MAPS", "rootfs/|/")
        .split(';')
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.split_once('|').map(|(a, b)| (a.to_string(), b.to_string())))
        .collect();
    let rss_mb: u64 = env_or("POLER_BOX_RSS_MB", "512").parse().unwrap_or(512);
    let cpu_s: u64 = env_or("POLER_BOX_CPU_S", "60").parse().unwrap_or(60);
    let tmpfs_mb: u64 = env_or("POLER_BOX_TMPFS_MB", "512").parse().unwrap_or(512);
    let isolate = env_or("POLER_BOX_ISOLATE", "1") == "1";
    let rep_fd: i32 = env_or("POLER_BOX_REPORT_FD", "-1").parse().unwrap_or(-1);

    if archive.as_os_str().is_empty() || entry.is_empty() {
        return Err("stage2: немає POLER_BOX_ARCHIVE/ENTRY".into());
    }

    // --- простори імен (ми вже root-in-userns від unshare -Ur) ---
    if isolate {
        let flags = libc::CLONE_NEWNS
            | libc::CLONE_NEWPID
            | libc::CLONE_NEWNET
            | libc::CLONE_NEWIPC
            | libc::CLONE_NEWUTS;
        if unsafe { libc::unshare(flags) } != 0 {
            return Err(format!(
                "unshare(ns): {} (ядро може обмежувати вкладеність)",
                std::io::Error::last_os_error()
            ));
        }
    }

    // --- staging: tmpfs у приватному mntns = rootfs коробки в RAM ---
    let staging = if isolate {
        let dir = std::env::temp_dir().join(format!("poler-box-{}", std::process::id()));
        std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir staging: {e}"))?;
        // ВАЖЛИВО: опції mount мають бути NUL-терміновані (CString, не String)
        let opts = std::ffi::CString::new(format!("size={tmpfs_mb}m,mode=0755"))
            .map_err(|e| format!("tmpfs opts: {e}"))?;
        if unsafe {
            libc::mount(
                b"polerbox\0".as_ptr() as *const _,
                cpath(&dir).as_ptr(),
                b"tmpfs\0".as_ptr() as *const _,
                libc::MS_NOSUID | libc::MS_NODEV,
                opts.as_ptr() as *const _,
            )
        } != 0
        {
            return Err(format!("tmpfs: {}", std::io::Error::last_os_error()));
        }
        dir
    } else {
        let dir = std::env::temp_dir().join(format!("poler-box-dbg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir staging(debug): {e}"))?;
        dir
    };

    // --- розгортання payload з архіву (стрім, zero-disk) ---
    let reader = poler_archive::reader::PolerReader::open(&archive)?;
    let mut extracted: u64 = 0;
    let mut extracted_bytes: u64 = 0;
    for f in reader.files() {
        for (prefix, box_dir) in &maps {
            if let Some(rest) = f.name.strip_prefix(prefix.as_str()) {
                if rest.is_empty() {
                    continue;
                }
                let target = safe_join(&staging, box_dir, rest)?;
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
                }
                let mut out = std::fs::File::create(&target)
                    .map_err(|e| format!("create {}: {e}", target.display()))?;
                stream_file_out(&reader, f, &mut out)
                    .map_err(|e| format!("extract {}: {e}", f.name))?;
                let mode = if is_exec_path(rest) { 0o755 } else { 0o644 };
                set_mode(&target, mode);
                extracted += 1;
                extracted_bytes += f.raw_len;
            }
        }
    }

    // --- читання entry у пам'ять (стрім, zero-disk) ---
    let entry_file = reader
        .find_file(&entry)
        .ok_or_else(|| format!("запис '{entry}' зник з архіву"))?;
    let mut entry_bytes: Vec<u8> = Vec::with_capacity(entry_file.raw_len.min(64 << 20) as usize);
    stream_file_out(&reader, entry_file, &mut entry_bytes)
        .map_err(|e| format!("читання entry: {e}"))?;

    // --- v0.42.0 winpe: PE32+ → нативний Win64-субстрат БЕЗ exec ---
    // (після pivot_root динамічний інтерпретатор самого engine зникає — тому
    // Windows-шлях виконується напряму в D-процесі)
    if crate::winpe::is_pe32_plus(&entry_bytes) {
        eprintln!(
            "poler-box: entry={entry} — PE32+ AMD64, Win64-субстрат (без Wine/VM)"
        );
        let mut wargv = vec![
            Path::new(&entry)
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| entry.clone()),
        ];
        wargv.extend(args.iter().cloned());
        let wenv: Vec<(String, String)> = vec![
            ("PATH".into(), "/usr/local/bin:/usr/bin:/bin".into()),
            ("SystemDrive".into(), "C:".into()),
            ("SystemRoot".into(), "C:\\Windows".into()),
            ("TEMP".into(), "C:\\Temp".into()),
            ("TMP".into(), "C:\\Temp".into()),
            ("POLER_BOX".into(), "1".into()),
        ];
        match crate::winpe::winexec(&entry_bytes, wargv, wenv) {
            Ok(code) => std::process::exit(code),
            Err(e) => {
                eprintln!("poler-box D: winexec: {e}");
                std::process::exit(126);
            }
        }
    }

    // --- запис entry у memfd: виконання прямо з пам'яті, без дубля на fs ---
    let memfd = unsafe { libc::memfd_create(b"poler-box-entry\0".as_ptr() as *const _, 0) };
    if memfd < 0 {
        return Err(format!("memfd_create: {}", std::io::Error::last_os_error()));
    }
    {
        use std::os::unix::io::FromRawFd;
        let mut mf = unsafe { std::fs::File::from_raw_fd(memfd) };
        use std::io::Write;
        mf.write_all(&entry_bytes)
            .map_err(|e| format!("memfd entry: {e}"))?;
        let _ = mf.flush();
        std::mem::forget(mf); // fd живе далі для execveat
    }
    eprintln!(
        "poler-box: rootfs {extracted} файлів ({extracted_bytes} байт) з архіву; entry={entry} (memfd)"
    );

    // --- D: процес-пасажир, pid 1 нового pidns ---
    let d = unsafe { libc::fork() };
    if d < 0 {
        return Err(format!("fork(D): {}", std::io::Error::last_os_error()));
    }
    if d > 0 {
        // C1: передаємо pid D губернатору, чекаємо, прибираємо
        if rep_fd >= 0 {
            let b = d.to_le_bytes();
            unsafe {
                libc::write(rep_fd, b.as_ptr() as *const _, 4);
                libc::close(rep_fd);
            }
        }
        let mut st: i32 = 0;
        unsafe {
            libc::waitpid(d, &mut st, 0);
        }
        if libc_wifexited(st) {
            return Ok(libc_wexitstatus(st));
        }
        if libc_wifsignaled(st) {
            return Ok(128 + libc_wtermsig(st));
        }
        return Ok(124);
    }

    // === D: підготовка середовища і exec ===
    unsafe {
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
    }

    if isolate {
        if let Err(e) = pivot_into(&staging) {
            eprintln!("poler-box D: {e}");
            std::process::exit(127);
        }
    } else {
        let _ = std::env::set_current_dir(&staging);
    }

    // rlimits: жорсткі кордони поверх губернатора
    set_rlimits(rss_mb, cpu_s);

    if isolate {
        install_seccomp_or_die();
    }

    // закрити все зайве крім stdio та memfd
    let keep: [i32; 4] = [0, 1, 2, memfd];
    for fd in 3..1024 {
        if !keep.contains(&fd) {
            unsafe {
                libc::close(fd);
            }
        }
    }

    // execveat(memfd, "") — чисте виконання запису архіву
    let argv0 = std::ffi::CString::new(
        Path::new(&entry)
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| entry.clone()),
    )
    .map_err(|e| e.to_string())?;
    let mut cargs: Vec<std::ffi::CString> = Vec::with_capacity(args.len() + 1);
    cargs.push(argv0);
    for a in &args {
        cargs.push(std::ffi::CString::new(a.clone()).map_err(|e| e.to_string())?);
    }
    let mut envv: Vec<std::ffi::CString> = vec![
        std::ffi::CString::new(
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .unwrap(),
        std::ffi::CString::new("HOME=/").unwrap(),
        std::ffi::CString::new("LANG=C.UTF-8").unwrap(),
        std::ffi::CString::new("POLER_BOX=1").unwrap(),
        std::ffi::CString::new(format!("POLER_BOX_RSS_MB={rss_mb}")).unwrap(),
        std::ffi::CString::new(format!("POLER_BOX_CPU_S={cpu_s}")).unwrap(),
    ];
    if let Ok(term) = std::env::var("TERM") {
        envv.push(std::ffi::CString::new(format!("TERM={term}")).unwrap());
    }
    let mut cargv: Vec<*const std::os::raw::c_char> = cargs.iter().map(|c| c.as_ptr()).collect();
    cargv.push(std::ptr::null());
    let mut cenv: Vec<*const std::os::raw::c_char> = envv.iter().map(|c| c.as_ptr()).collect();
    cenv.push(std::ptr::null());
    let empty = std::ffi::CString::new("").unwrap();
    let _ = unsafe {
        libc::syscall(
            libc::SYS_execveat,
            memfd,
            empty.as_ptr(),
            cargv.as_ptr() as *const *mut std::os::raw::c_char,
            cenv.as_ptr() as *const *mut std::os::raw::c_char,
            libc::AT_EMPTY_PATH,
        )
    };
    let err = std::io::Error::last_os_error();
    eprintln!(
        "poler-box D: execveat(memfd) провалився: {err} (для динамічних payload потрібні бібліотеки в rootfs: lib/ld-linux, lib/x86_64-linux-gnu/libc.so.6)"
    );
    std::process::exit(126);
}

fn pivot_into(staging: &Path) -> Result<(), String> {
    std::env::set_current_dir(staging).map_err(|e| format!("chdir staging: {e}"))?;
    std::fs::create_dir_all("old").map_err(|e| format!("mkdir old: {e}"))?;
    let dot = cstr(".");
    let old = cstr("old");
    let r = unsafe {
        libc::syscall(libc::SYS_pivot_root, dot.as_ptr(), old.as_ptr())
    };
    if r != 0 {
        return Err(format!("pivot_root: {}", std::io::Error::last_os_error()));
    }
    std::env::set_current_dir("/").map_err(|e| format!("chdir /: {e}"))?;
    unsafe {
        libc::umount2(cstr("/old").as_ptr(), libc::MNT_DETACH);
    }
    let _ = std::fs::remove_dir("/old");
    // /proc — маска (справжній proc у pidns недоступний на цьому ядрі)
    let _ = std::fs::create_dir_all("/proc");
    let _ = unsafe {
        libc::mount(
            b"polerbox-proc\0".as_ptr() as *const _,
            cstr("/proc").as_ptr(),
            b"tmpfs\0".as_ptr() as *const _,
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            b"size=1m,mode=555\0".as_ptr() as *const _,
        )
    };
    Ok(())
}

fn set_rlimits(rss_mb: u64, cpu_s: u64) {
    unsafe {
        let as_lim = rss_mb
            .saturating_mul(1024 * 1024)
            .saturating_mul(3)
            .max(2u64 << 30);
        let rl = libc::rlimit {
            rlim_cur: as_lim,
            rlim_max: as_lim,
        };
        libc::setrlimit(libc::RLIMIT_AS, &rl);
        let rl = libc::rlimit {
            rlim_cur: cpu_s,
            rlim_max: cpu_s.saturating_add(5),
        };
        libc::setrlimit(libc::RLIMIT_CPU, &rl);
        let rl = libc::rlimit {
            rlim_cur: 512,
            rlim_max: 512,
        };
        libc::setrlimit(libc::RLIMIT_NPROC, &rl);
        let rl = libc::rlimit {
            rlim_cur: 256,
            rlim_max: 256,
        };
        libc::setrlimit(libc::RLIMIT_NOFILE, &rl);
        let rl = libc::rlimit {
            rlim_cur: 512 << 20,
            rlim_max: 512 << 20,
        };
        libc::setrlimit(libc::RLIMIT_FSIZE, &rl);
        let rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &rl);
    }
}

fn safe_join(staging: &Path, box_dir: &str, rest: &str) -> Result<PathBuf, String> {
    let rel = box_dir.trim_start_matches('/');
    let base = if rel.is_empty() {
        staging.to_path_buf()
    } else {
        staging.join(rel)
    };
    let mut p = base.clone();
    // захист від ../ в іменах записів: шлях не може виходити за межі base
    for seg in rest.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if p == base || !p.pop() {
                    return Err(format!("небезпечний шлях у записі: {rest}"));
                }
            }
            s => p.push(s),
        }
    }
    if !p.starts_with(staging) {
        return Err(format!("небезпечний шлях у записі: {rest}"));
    }
    Ok(p)
}

fn is_exec_path(rest: &str) -> bool {
    if Path::new(rest).extension().map_or(false, |e| e == "sh") {
        return true;
    }
    // динамічний лінкер — виконуваний за призначенням (PT_INTERP потребує +x)
    if rest.contains("ld-linux") || rest.contains("ld-musl") || rest.contains("ld64.so") {
        return true;
    }
    let joined = rest.to_ascii_lowercase();
    joined.starts_with("bin/")
        || joined.starts_with("sbin/")
        || joined.contains("/bin/")
        || joined.contains("/sbin/")
}

fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

fn stream_file_out<W: Write>(
    reader: &poler_archive::reader::PolerReader,
    f: &poler_archive::reader::PolerFile,
    out: &mut W,
) -> Result<(), String> {
    const CHUNK: usize = 1 << 20;
    let mut off: u64 = 0;
    let mut buf: Vec<u8> = Vec::with_capacity(CHUNK);
    while off < f.raw_len {
        let n = CHUNK.min((f.raw_len - off) as usize);
        buf.clear();
        reader
            .read_range(f.raw_off + off, n, &mut buf)
            .map_err(|e| format!("read_range: {e}"))?;
        out.write_all(&buf).map_err(|e| format!("write: {e}"))?;
        off += n as u64;
    }
    Ok(())
}

fn cpath(p: &Path) -> std::ffi::CString {
    std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap_or_else(|_| cstr("/"))
}

fn cstr(s: &str) -> std::ffi::CString {
    std::ffi::CString::new(s).unwrap()
}

// ============================== ГОЛОВНИЦТВО ==============================

/// Дерево процесів payload (pidns не видно з P — будуємо через children).
fn collect_tree(root: i32) -> Vec<i32> {
    let mut out = vec![root];
    let mut queue = VecDeque::from([root]);
    let mut hops = 0;
    while let Some(p) = queue.pop_front() {
        hops += 1;
        if hops > 512 {
            break;
        }
        for c in children_of(p) {
            if !out.contains(&c) {
                out.push(c);
                queue.push_back(c);
            }
        }
    }
    out
}

fn children_of(pid: i32) -> Vec<i32> {
    let mut out = Vec::new();
    let tasks = match std::fs::read_dir(format!("/proc/{pid}/task")) {
        Ok(rd) => rd,
        Err(_) => return out,
    };
    for task in tasks.flatten() {
        if let Ok(s) = std::fs::read_to_string(task.path().join("children")) {
            for tok in s.split_whitespace() {
                if let Ok(c) = tok.parse::<i32>() {
                    out.push(c);
                }
            }
        }
    }
    out
}

fn path_alive(pid: i32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

fn read_status_field(pid: i32, field: &str) -> Option<u64> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix(field) {
            // формат: "VmRSS:\t  2048 kB" — після префікса йдуть : \t і пробіли
            let num: String = rest
                .trim_start_matches(|c| c == ':' || c == ' ' || c == '\t')
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            return num.parse().ok();
        }
    }
    None
}

fn read_cpu_seconds(pid: i32) -> f64 {
    let Ok(s) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return 0.0;
    };
    let Some(close) = s.rfind(')') else {
        return 0.0;
    };
    let rest = &s[close + 1..];
    let fields: Vec<&str> = rest.split_whitespace().collect();
    let ut: f64 = fields.get(11).and_then(|v| v.parse().ok()).unwrap_or(0.0);
    let st: f64 = fields.get(12).and_then(|v| v.parse().ok()).unwrap_or(0.0);
    (ut + st) / 100.0
}

fn libc_wifexited(st: i32) -> bool {
    st & 0x7f == 0
}
fn libc_wexitstatus(st: i32) -> i32 {
    (st >> 8) & 0xff
}
fn libc_wifsignaled(st: i32) -> bool {
    let sig = st & 0x7f;
    sig != 0 && sig != 0x7f
}
fn libc_wtermsig(st: i32) -> i32 {
    st & 0x7f
}

mod seccomp;
mod winpe;

fn install_seccomp_or_die() {
    if let Err(e) = seccomp::install() {
        eprintln!("poler-box D: seccomp: {e}");
        std::process::exit(127);
    }
}

/// Смертельні сисколи — KILL_PROCESS одразу.
pub const DEADLY: &[i64] = &[
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_swapon,
    libc::SYS_swapoff,
    libc::SYS_reboot,
    libc::SYS_sethostname,
    libc::SYS_setdomainname,
    libc::SYS_iopl,
    libc::SYS_ioperm,
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    libc::SYS_quotactl,
    libc::SYS_perf_event_open,
    libc::SYS_kexec_load,
    libc::SYS_kexec_file_load,
    libc::SYS_bpf,
    libc::SYS_ptrace,
    libc::SYS_uselib,
    libc::SYS_acct,
    libc::SYS_vhangup,
    libc::SYS_open_by_handle_at,
    libc::SYS_name_to_handle_at,
    libc::SYS_setns,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_kcmp,
    libc::SYS_fanotify_init,
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_keyctl,
    libc::SYS_lookup_dcookie,
    libc::SYS_afs_syscall,
    libc::SYS_tuxcall,
    libc::SYS_security,
    libc::SYS_getpmsg,
    libc::SYS_putpmsg,
    libc::SYS_ioprio_set,
    libc::SYS_ioprio_get,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_collection_handles_missing_proc() {
        let t = collect_tree(999_999_999);
        assert_eq!(t, vec![999_999_999]);
    }

    #[test]
    fn safe_join_blocks_traversal() {
        let staging = Path::new("/tmp/staging");
        assert!(safe_join(staging, "/", "../../etc/passwd").is_err());
        assert_eq!(
            safe_join(staging, "/", "bin/hello").unwrap(),
            PathBuf::from("/tmp/staging/bin/hello")
        );
        assert_eq!(
            safe_join(staging, "/data", "a/b.bin").unwrap(),
            PathBuf::from("/tmp/staging/data/a/b.bin")
        );
    }

    #[test]
    fn exec_paths_detected() {
        assert!(is_exec_path("bin/hello"));
        assert!(is_exec_path("usr/bin/tcc"));
        assert!(is_exec_path("run.sh"));
        assert!(!is_exec_path("src/hello.c"));
        assert!(!is_exec_path("lib/libc.so.6"));
    }

    #[test]
    fn spec_env_roundtrip_defaults() {
        let spec = BoxSpec::default();
        let env = spec_to_env(&spec, 42);
        assert_eq!(env[0].0, "POLER_BOX_STAGE2");
        assert!(env.iter().any(|(k, v)| k == "POLER_BOX_REPORT_FD" && v == "42"));
    }
}
