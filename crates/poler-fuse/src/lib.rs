//! poler-fuse — FUSE-монтирование .poler-архивов как доступных на чтение папок.
//!
//! Архитектура:
//!   - дерево каталогов восстанавливается из файловой таблицы при монтировании;
//!   - чтение файлов идёт через `PolerReader::read_range` напрямую из mmap/zstd;
//!   - inode 1 = корень; каталоги получают синтетические inode;
//!   - только чтение (EROFS на любые попытки записи).

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::Path;
use std::time::{Duration, SystemTime};

use fuser::{
    FileAttr, Filesystem, KernelConfig, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry,
    ReplyOpen, Request,
};
use poler_archive::PolerReader;

const TTL: Duration = Duration::from_secs(1);
const ROOT_INO: u64 = 1;

#[derive(Debug, Clone)]
struct FsNode {
    name: String,
    parent: u64,
    /// Индекс в `PolerReader::files()`, если это регулярный файл
    file: Option<usize>,
}

impl FsNode {
    fn is_dir(&self) -> bool {
        self.file.is_none()
    }
}

pub struct PolerFs {
    reader: PolerReader,
    nodes: BTreeMap<u64, FsNode>,
    next_ino: u64,
}

impl PolerFs {
    pub fn open(path: &Path) -> Result<Self, String> {
        let reader = PolerReader::open(path)?;
        let mut fs = Self {
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

        let file_names: Vec<(usize, String)> = fs
            .reader
            .files()
            .iter()
            .enumerate()
            .map(|(idx, f)| (idx, f.name.clone()))
            .collect();

        for (idx, name) in file_names {
            let mut path_parts: Vec<&str> =
                name.split('/').filter(|s| !s.is_empty()).collect();
            if path_parts.is_empty() {
                continue;
            }
            let file_name = path_parts.pop().unwrap().to_string();
            let mut parent = ROOT_INO;
            for dir in path_parts {
                parent = fs.ensure_dir(parent, dir);
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
        let node = &self.nodes[&ino];
        let (size, kind) = match node.file {
            Some(idx) => (
                self.reader.files()[idx].raw_len,
                fuser::FileType::RegularFile,
            ),
            None => (0, fuser::FileType::Directory),
        };
        let now = SystemTime::now();
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
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
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
        let mut children: Vec<(u64, String, fuser::FileType)> = self
            .nodes
            .iter()
            .filter(|(_, n)| n.parent == ino)
            .map(|(child_ino, n)| {
                (
                    *child_ino,
                    n.name.clone(),
                    if n.is_dir() {
                        fuser::FileType::Directory
                    } else {
                        fuser::FileType::RegularFile
                    },
                )
            })
            .collect();
        children.sort_by(|a, b| a.1.cmp(&b.1));
        children.insert(
            0,
            (
                ino,
                ".".to_string(),
                fuser::FileType::Directory,
            ),
        );
        children.insert(
            1,
            (
                self.nodes[&ino].parent,
                "..".to_string(),
                fuser::FileType::Directory,
            ),
        );

        let entries: Vec<(u64, fuser::FileType, String)> = children
            .into_iter()
            .map(|(child_ino, name, kind)| (child_ino, kind, name))
            .collect();

        for (i, (child_ino, kind, name)) in entries.iter().enumerate().skip(offset as usize) {
            if reply.add(*child_ino, (i + 1) as i64, *kind, name) {
                break;
            }
        }
        reply.ok();
    }
}
