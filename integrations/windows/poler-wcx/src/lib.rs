//! poler-wcx — плагин Total Commander (WCX 1.6) для формата `.poler`.
//!
//! Даёт Total Commander'у открывать `.poler` по Enter как архив: листинг
//! записей (ReadHeader) + извлечение (ProcessFile). Запаковка (PackFiles)
//! тоже поддержана — через вызов системного `poler create`.
//!
//! Сборка (Windows-хост или cross):
//!   rustup target add x86_64-pc-windows-gnu
//!   cargo build --release --target x86_64-pc-windows-gnu
//!   cp target/x86_64-pc-windows-gnu/release/poler_wcx.dll POLER.wcx
//!   Total Commander -> Configuration -> Options -> Packer -> Plugin FS:
//!     добавить POLER.wcx, расширение: poler;t5z
//!
//! Полагается на poler.exe в PATH (PackFiles); чтение/распаковка работают
//! и без него — через собственную статическую линковку poler-archive.

#![allow(non_snake_case, non_camel_case_types, clippy::missing_safety_doc)]

use std::ffi::{c_char, c_int, c_uchar, CStr};
use std::path::PathBuf;

use poler_archive::PolerReader;

// ─────────── WCX-типы (wcxhead.h Total Commander) ───────────

#[repr(C)]
pub struct tHeaderData {
    pub ArcName: [c_char; 260],
    pub FileName: [c_char; 260],
    pub Flags: c_int,
    pub PackSize: c_int,
    pub UnpSize: c_int,
    pub HostOS: c_int,
    pub FileCRC: c_int,
    pub FileTime: c_int,
    pub UnpVer: c_int,
    pub Method: c_int,
    pub FileAttr: c_int,
    pub CmtBuf: *mut c_char,
    pub CmtBufSize: c_int,
    pub CmtState: c_int,
    pub Compress: c_int,
}

#[repr(C)]
pub struct PackDefaultParam {
    pub size: c_int,
    pub PluginInterfaceVersionLow: c_int,
    pub PluginInterfaceVersionHi: c_int,
    pub DefaultIniName: [c_char; 260],
}

const PK_CAPS_NEW: c_int = 1; // allows multiple pack steps

// ─────────── мост poler-archive ↔ WCX ───────────

struct OpenArchive {
    reader: PolerReader,
    arc_path: String,
    /// следующий индекс для ReadHeader
    next: usize,
    /// индекс записи, которую попросит ProcessFile (после ReadHeader)
    pending: usize,
}

static mut OPENED: Option<OpenArchive> = None;

fn cstr_into(dst: &mut [c_char], s: &str) {
    let bytes = s.as_bytes();
    let n = bytes.len().min(dst.len() - 1);
    for i in 0..n {
        dst[i] = bytes[i] as c_char;
    }
    dst[n] = 0;
}

unsafe fn reader_mut() -> Option<&'static mut OpenArchive> {
    OPENED.as_mut()
}

// ─────────── экспорты WCX ───────────

/// Открыть архив для просмотра. Возвращаемое значение — произвольный
/// хэндл (используем 1); ошибка — E_BAD_ARCHIVE.
#[no_mangle]
pub unsafe extern "system" fn OpenArchive(
    ArcName: *mut c_char,
    _OpenMode: c_int,
) -> isize {
    let name = CStr::from_ptr(ArcName).to_string_lossy().into_owned();
    match PolerReader::open(&PathBuf::from(&name)) {
        Ok(reader) => {
            OPENED = Some(OpenArchive {
                reader,
                arc_path: name,
                next: 0,
                pending: 0,
            });
            1
        }
        Err(_) => 0xFFFF_FFFF - 1, // E_BAD_ARCHIVE
    }
}

/// Прочитать следующую запись архива в HeaderData.
/// Возврат: 0=OK, 1=конец.
#[no_mangle]
pub unsafe extern "system" fn ReadHeader(
    _hArcData: isize,
    HeaderData: *mut tHeaderData,
) -> c_int {
    let Some(oa) = reader_mut() else { return 0xFFFF_FFFF - 2 };
    let hd = &mut *HeaderData;
    if oa.next >= oa.reader.files().len() {
        return 1; // конец архива
    }
    let f = &oa.reader.files()[oa.next];
    oa.pending = oa.next;
    oa.next += 1;
    cstr_into(&mut hd.ArcName, &oa.arc_path);
    cstr_into(&mut hd.FileName, &f.name);
    hd.Flags = 0;
    hd.UnpSize = f.raw_len.min(i32::MAX as u64) as c_int;
    hd.PackSize = (hd.UnpSize as u64 / 2).min(i32::MAX as u64) as c_int;
    hd.HostOS = 6; // Windows
    hd.FileTime = 0;
    hd.UnpVer = 20;
    hd.Method = 0;
    hd.FileAttr = 0x20; // FILE_ATTRIBUTE_ARCHIVE
    if !hd.CmtBuf.is_null() && hd.CmtBufSize > 0 {
        *hd.CmtBuf = 0;
        hd.CmtState = 0;
    }
    0
}

/// Извлечь последнюю прочитенную запись в DestName.
#[no_mangle]
pub unsafe extern "system" fn ProcessFile(
    _hArcData: isize,
    Operation: c_int,
    _DestPath: *mut c_char,
    DestName: *mut c_char,
) -> c_int {
    if Operation != 0 {
        return 0xFFFF_FFFF - 4; // неподдержанная операция (копирование в память)
    }
    let Some(oa) = reader_mut() else { return 0xFFFF_FFFF - 2 };
    let f = match oa.reader.files().get(oa.pending) {
        Some(f) => f,
        None => return 0xFFFF_FFFF - 3,
    };
    let dest = CStr::from_ptr(DestName).to_string_lossy().into_owned();
    let mut out = match std::fs::File::create(&dest) {
        Ok(o) => std::io::BufWriter::new(o),
        Err(_) => return 0xFFFF_FFFF - 6, // E_ECREATE
    };
    let mut buf = Vec::new();
    let mut off = f.raw_off;
    let end = f.raw_off + f.raw_len;
    use std::io::Write;
    while off < end {
        let step = ((end - off) as usize).min(1024 * 1024);
        if oa.reader.read_range(off, step, &mut buf).is_err() {
            return 0xFFFF_FFFF - 9; // E_EREAD
        }
        if out.write_all(&buf).is_err() {
            return 0xFFFF_FFFF - 5; // E_EWRITE
        }
        off += step as u64;
    }
    0
}

#[no_mangle]
pub unsafe extern "system" fn CloseArchive(_hArcData: isize) -> c_int {
    OPENED = None;
    0
}

#[no_mangle]
pub unsafe extern "system" fn GetPackerCaps() -> c_int {
    PK_CAPS_NEW
}

/// Запаковка: делегируем системному `poler create` — единая реализация
/// формата, никаких дублирований.
#[no_mangle]
pub unsafe extern "system" fn PackFiles(
    PackedFile: *mut c_char,
    _SubPath: *mut c_char,
    _SrcPath: *mut c_char,
    AddList: *mut *mut c_char,
    _Flags: c_int,
) -> c_int {
    use std::process::Command;
    let out = CStr::from_ptr(PackedFile).to_string_lossy().into_owned();
    let mut files: Vec<String> = Vec::new();
    let mut p = AddList;
    while !(*p).is_null() {
        let s = CStr::from_ptr(*p).to_string_lossy().into_owned();
        if !s.is_empty() {
            files.push(s);
        }
        p = p.add(1);
    }
    if files.is_empty() {
        return 0xFFFF_FFFF - 10; // E_NO_FILES
    }
    let mut cmd = Command::new("poler");
    cmd.arg("create").arg(&out).args(&files);
    match cmd.status() {
        Ok(st) if st.success() => 0,
        _ => 0xFFFF_FFFF - 11, // E_EABORTED
    }
}

#[no_mangle]
pub unsafe extern "system" fn SetChangeVolProc(_proc: *mut c_uchar) {}

#[no_mangle]
pub unsafe extern "system" fn SetProcessDataProc(_proc: *mut c_uchar) {}

/// Конфигурационный диалог не нужен.
#[no_mangle]
pub unsafe extern "system" fn ConfigureDlg(
    _Parent: isize,
    _dllinst: isize,
) -> bool {
    true
}

// путь relative Cargo.toml — фиксируем одинаково с lib.rs
#[allow(dead_code)]
fn _unused_type(param: PackDefaultParam) -> PackDefaultParam {
    param
}
