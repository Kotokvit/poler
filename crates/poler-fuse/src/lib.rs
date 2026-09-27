//! poler-fuse: `.poler`-архив как каталог (FUSE, только чтение).
//!
//! После `poler-fuse ARCHIVE.poler /mnt/point` архив виден ПАПКОЙ во всех
//! файловых менеджерах Linux (Dolphin/Nautilus/Nemo/Thunar/PCManFM/Caja,
//! mc/ranger/yazi) и во всех программах: копирование, grep, просмотр —
//! без распаковки на диск. Чтение — mmap-ридер с O(log n) доступом.
//!
//! Требует libfuse (пакет fuse3/libfuse3-dev) и /dev/fuse — поэтому крейт
//! НЕ входит в default-members workspace: `cargo build -p poler-fuse`.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::Path;
use std::time::{Duration, SystemTime};

use fuser::{
    FileAttr, Filesystem, KernelConfig, ReplyAttr, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyOpen, Request,
};
use poler_archive::PolerReader;

const TTL: Duration = Duration::from_secs(1);
const ROOT_INO: u64 = 1;

/// Собрать виртуальное дерево путей из плоской таблицы файлов архива.
pub struct PolerFs {
    reader: PolerReader,
    /// inode -> (имя, родитель, файловая запись или каталог)
    nodes: BTreeMap<u64, FsNode>,
    next_ino: u64,
}

struct FsNode {
    name: String,
    parent: u64,
    /// None = каталог, Some(idx) = индекс в reader.files()
    file: Option<usize>,
}

impl FsNode {
    fn is_dir(&self) -> bool {
        self.file.is_none()
    }
}

impl PolerFs {
    pub fn open(archive: &Path) -> Result<PolerFs, String> {
        let reader = PolerReader::open(archive)?;
        let mut fs = PolerFs {
            reader,
            nodes: BTreeMap::new(),
            next_ino: ROOT_INO + 1,
        };
        fs.nodes.insert(
            ROOT_INO,
            FsNode {
                name: String::new(),
                parent: ROOT_INO,
                file: None,
            },
        );
        for (idx, f) in fs.reader.files().iter().enumerate() {
            let mut path_parts: Vec<&str> =
                f.name.split('/').filter(|s| !s.is_empty()).collect();
            if path_parts.is_empty() {
                continue;
            }
            let file_name = path_parts.pop().unwrap().to_string();
            // промежуточные каталоги
            let mut parent = ROOT_INO;
            let mut walked = String::new();
            for dir in path_parts {
                walked.push_str(dir);
                parent = fs.ensure_dir(parent, dir);
                walked.push('/');
            }
            let ino = fs.alloc_ino();
            fs.nodes.insert(
                ino,
                FsNode {
                    name: file_name,
                    parent,
                    file: Some(idx),
                },
            );
        }
        Ok(fs)
    }

    fn alloc_ino(&mut self) -> u64 {
        let ino = self.next_ino;
        self.next_ino += 1;
        ino
    }

    fn ensure_dir(&mut self, parent: u64, name: &str) -> u64 {
        if let Some((ino, _)) = self
            .nodes
            .iter()
            .find(|(_, n)| n.parent == parent && n.name == name && n.is_dir())
        {
            return *ino;
        }
        let ino = self.alloc_ino();
        self.nodes.insert(
            ino,
            FsNode {
                name: name.to_string(),
                parent,
                file: None,
            },
        );
        ino
    }

    fn attr(&self, ino: u64) -> FileAttr {
        let now = SystemTime::now();
        let node = self.nodes.get(&ino);
        let (kind, size, name_len) = match node {
            None => (fuser::FileType::RegularFile, 0, 0),
            Some(n) if n.is_dir() => {
                let children = self
                    .nodes
                    .values()
                    .filter(|c| c.parent == ino)
                    .count() as u64;
                (fuser::FileType::Directory, 4096.max(children * 32), 0)
            }
            Some(n) => {
                let size = n
                    .file
                    .map(|i| self.reader.files()[i].raw_len)
                    .unwrap_or(0);
                (fuser::FileType::RegularFile, size, 0)
            }
        };
        let _ = name_len;
        FileAttr {
            ino,
            size,
            blocks: (size + 511) / 512,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind,
            perm: if kind == fuser::FileType::Directory {
                0o555
            } else {
                0o444
            },
            nlink: 1,
            uid: fuser::getuid().unwrap_or(0),
            gid: fuser::getgid().unwrap_or(0),
            rdev: 0,
            blksize: 512,
            flags: 0,
        }
    }
}

impl Filesystem for PolerFs {
    fn init(&mut self, _req: &Request<'_>, _config: &mut KernelConfig) -> Result<(), i32> {
        Ok(())
    }

    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let name = name.to_string_lossy();
        if let Some((ino, _)) = self
            .nodes
            .iter()
            .find(|(_, n)| n.parent == parent && n.name == name)
        {
            let attr = self.attr(*ino);
            reply.entry(&TTL, &attr, 0);
        } else {
            reply.error(libc::ENOENT);
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        if self.nodes.contains_key(&ino) {
            reply.attr(&TTL, &self.attr(ino));
        } else {
            reply.error(libc::ENOENT);
        }
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        if flags & libc::O_ACCMODE != libc::O_RDONLY {
            reply.error(libc::EROFS); // архив — только чтение
        } else if self.nodes.contains_key(&ino) {
            reply.opened(0, 0);
        } else {
            reply.error(libc::ENOENT);
        }
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyData,
    ) {
        let Some(node) = self.nodes.get(&ino) else {
            reply.error(libc::ENOENT);
            return;
        };
        let Some(idx) = node.file else {
            reply.error(libc::EISDIR);
            return;
        };
        let f = &self.reader.files()[idx];
        let offset = offset.max(0) as u64;
        if offset >= f.raw_len {
            reply.data(&[]);
            return;
        }
        let want = (size as u64).min(f.raw_len - offset) as usize;
        let mut buf = Vec::with_capacity(want);
        match self.reader.read_range(f.raw_off + offset, want, &mut buf) {
            Ok(()) => reply.data(&buf),
            Err(e) => {
                eprintln!("poler-fuse: read {ino}: {e}");
                reply.error(libc::EIO);
            }
        }
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        if !self.nodes.contains_key(&ino) {
            reply.error(libc::ENOENT);
            return;
        }
        let mut children: Vec<(u64, &str, fuser::FileType)> = self
            .nodes
            .iter()
            .filter(|(_, n)| n.parent == ino)
            .map(|(child_ino, n)| {
                (
                    *child_ino,
                    n.name.as_str(),
                    if n.is_dir() {
                        fuser::FileType::Directory
                    } else {
                        fuser::FileType::RegularFile
                    },
                )
            })
            .collect();
        children.sort();
        children.insert(
            0,
            (
                ino,
                ".",
                fuser::FileType::Directory,
            ),
        );
        children.insert(
            1,
            (
                self.nodes[&ino].parent,
                "..",
                fuser::FileType::Directory,
            ),
        );
        for (i, (child_ino, name, kind)) in children.iter().enumerate().skip(offset.max(0) as usize)
        {
            if reply.add(*child_ino, i as i64 + 1, *kind, name) {
                break; // буфер переполнен — продолжение со следующего offset
            }
        }
        reply.ok();
    }

    fn destroy(&mut self) {}
}
