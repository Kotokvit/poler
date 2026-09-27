//! `poler-fuse` — CLI: смонтировать `.poler` как каталог.
//!
//!   poler-fuse ARCHIVE.poler /точка/монтирования [--foreground]
//!
//! Смонтированный каталог живёт, пока жив процесс. Автоматическое
//! размонтирование: fusermount -u /точка (или Ctrl+C в foreground).

use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        eprintln!(
            "poler-fuse — смонтировать .poler как каталог (только чтение)\n\
             \n  poler-fuse ARCHIVE.poler ТОЧКА [--foreground] [--allow-other]\n\
             \nРазмонтирование: fusermount -u ТОЧКА"
        );
        std::process::exit(0);
    }
    let foreground = args.iter().any(|a| a == "--foreground");
    let allow_other = args.iter().any(|a| a == "--allow-other");
    let positional: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
    if positional.len() != 2 {
        eprintln!("poler-fuse: нужны ARCHIVE.poler и ТОЧКА монтирования");
        std::process::exit(1);
    }
    let archive = PathBuf::from(positional[0]);
    let mountpoint = PathBuf::from(positional[1]);

    let fs = match poler_fuse::PolerFs::open(&archive) {
        Ok(fs) => fs,
        Err(e) => {
            eprintln!("poler-fuse: {e}");
            std::process::exit(1);
        }
    };
    eprintln!(
        "poler-fuse: {} -> {} (Ctrl+C / fusermount -u для размонтирования)",
        archive.display(),
        mountpoint.display()
    );
    let mut options = vec![fuser::MountOption::RO, fuser::MountOption::FSName("poler".into())];
    if allow_other {
        options.push(fuser::MountOption::AllowOther);
    }
    if !foreground {
        options.push(fuser::MountOption::AutoUnmount);
    }
    if let Err(e) = fuser::mount2(fs, &mountpoint, &options) {
        eprintln!("poler-fuse: mount: {e} (нужен libfuse и /dev/fuse?)");
        std::process::exit(1);
    }
}
