//! Round-trip тесты `.poler`: запись → чтение → верификация → распаковка.
//! Плюс байтовая совместимость формата с poler-engine v0.61.0.

use std::fs;
use std::io::Cursor;
use std::path::PathBuf;

use poler_archive::{
    write_stream, CompressTier, FsTarReader, PolerReader, StreamWriteConfig, MAGIC_END,
    MAGIC_START,
};

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("poler-test-{}-{}", tag, std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

// ─── 1. Одиночный поток (не tar): весь поток = одна запись ───

#[test]
fn single_stream_roundtrip() {
    let dir = tmpdir("single");
    let out = dir.join("s.poler");
    let payload: Vec<u8> = "суверенный архиватор poler — "
        .repeat(5000)
        .into_bytes();
    let cfg = StreamWriteConfig {
        tier: CompressTier::Auto,
        ..Default::default()
    };
    let stats = write_stream(Cursor::new(payload.clone()), &out, cfg, "stream-hint").unwrap();
    assert!(stats.total_stored < payload.len() as u64, "сжатие должно работать");

    let r = PolerReader::open(&out).unwrap();
    assert!(!r.info().tar_mode);
    assert_eq!(r.files().len(), 1, "одна запись в нетар-режиме");
    let rep = r.verify().unwrap();
    assert!(rep.all_ok, "verify: поток и запись целы");

    let ex = dir.join("ex");
    let report = r.extract_all(&ex).unwrap();
    assert_eq!(report.files_ok, 1);
    let back = fs::read(ex.join(r.files()[0].name.as_str())).unwrap();
    assert_eq!(back, payload, "содержимое бит-в-бит");
    let _ = fs::remove_dir_all(&dir);
}

// ─── 2. FS → ustar → .poler: файловая таблица, вложенность, пустой каталог ───

#[test]
fn fs_roundtrip() {
    let dir = tmpdir("fs");
    let src = dir.join("data");
    fs::create_dir_all(src.join("nested/deep")).unwrap();
    fs::create_dir_all(src.join("empty")).unwrap();
    fs::write(src.join("a.txt"), b"hello poler").unwrap();
    fs::write(src.join("nested/b.bin"), vec![7u8; 300_000]).unwrap();
    fs::write(src.join("nested/deep/c.txt"), b"deep").unwrap();

    // канонический вызов: относительный путь из cwd (как `tar -c data`)
    std::env::set_current_dir(&dir).unwrap();

    let out = dir.join("fs.poler");
    let tar = FsTarReader::new(&[PathBuf::from("data")]).unwrap();
    let cfg = StreamWriteConfig::default();
    let stats = write_stream(tar, &out, cfg, "fs").unwrap();
    assert!(stats.tar_mode, "tar-режим должен быть распознан");
    assert_eq!(stats.files, 3, "3 файла в таблице");

    let r = PolerReader::open(&out).unwrap();
    let names: Vec<&str> = r.files().iter().map(|f| f.name.as_str()).collect();
    for expect in [
        "data/a.txt",
        "data/nested/b.bin",
        "data/nested/deep/c.txt",
    ] {
        assert!(names.contains(&expect), "нет {expect} в {names:?}");
    }
    let rep = r.verify().unwrap();
    assert!(rep.all_ok);

    let ex = dir.join("ex");
    let report = r.extract_all(&ex).unwrap();
    assert_eq!(report.files_written, 3);
    assert_eq!(report.files_ok, 3);
    assert!(report.files_bad.is_empty());
    assert_eq!(
        fs::read(ex.join("data/nested/b.bin")).unwrap(),
        vec![7u8; 300_000]
    );
    assert!(ex.join("data/nested").is_dir(), "структура восстановлена");
    // Пустые каталоги НЕ сохраняются форматом v0.61.0 (таблица = только файлы;
    // движок ведёт себя так же) — поведение сохранено для байт-совместимости.
    let _ = fs::remove_dir_all(&dir);
}

// ─── 3. Дедуп: повторные данные не должны раздувать архив ───

#[test]
fn dedup_shrinks_repeats() {
    let dir = tmpdir("dedup");
    let block: Vec<u8> = (0..256 * 1024u32).map(|i| (i % 251) as u8).collect();
    let mut payload = Vec::new();
    for _ in 0..8 {
        payload.extend_from_slice(&block); // 8 одинаковых блоков
    }
    let out = dir.join("d.poler");
    let cfg = StreamWriteConfig::default(); // dedup: true
    let stats = write_stream(Cursor::new(payload), &out, cfg, "dedup").unwrap();
    assert!(
        stats.physical_chunks < stats.logical_chunks,
        "физических чанков меньше логических: {} vs {}",
        stats.physical_chunks,
        stats.logical_chunks
    );
    assert!(stats.dedup_chunks > 0, "дедуп сработал");
    let r = PolerReader::open(&out).unwrap();
    assert!(r.verify().unwrap().all_ok, "после дедупа целостность держится");
    let _ = fs::remove_dir_all(&dir);
}

// ─── 4. Формат байт-в-байт как у poler-engine v0.61.0 ───

#[test]
fn magic_bytes_match_engine() {
    let dir = tmpdir("magic");
    let out = dir.join("m.poler");
    write_stream(
        Cursor::new(b"format check".to_vec()),
        &out,
        StreamWriteConfig::default(),
        "magic",
    )
    .unwrap();
    let bytes = fs::read(&out).unwrap();
    assert_eq!(&bytes[..8], &MAGIC_START[..], "заголовок POLERARC");
    let n = bytes.len();
    assert_eq!(&bytes[n - 104..n - 96], &MAGIC_END[..], "трейлер POLEREND");
    let _ = fs::remove_dir_all(&dir);
}

// ─── 5. CoW-патчинг: add + replace + rollback ───

#[test]
fn patch_and_rollback() {
    use poler_archive::{patch_archive, rollback_archive, PatchOp, PatchOptions};
    let dir = tmpdir("patch");
    let out = dir.join("p.poler");
    write_stream(
        Cursor::new(b"base payload for patching".to_vec()),
        &out,
        StreamWriteConfig::default(),
        "patch-base",
    )
    .unwrap();

    let ops = vec![
        PatchOp::add("config/new.txt", b"added by patch".to_vec()),
        PatchOp::replace("patch-base", b"REPLACED".to_vec()),
    ];
    let rep = patch_archive(&out, &ops, &PatchOptions::default()).unwrap();
    assert!(rep.ops_applied >= 1, "патч применён: {rep:?}");

    let r = PolerReader::open(&out).unwrap();
    assert!(r.verify().unwrap().all_ok, "после патча целостность держится");
    assert!(r.find_file("config/new.txt").is_some(), "новая запись видна");
    // Windows: rollback делает set_len — на файле с активным mmap-ридером
    // это os error 1224 (user-mapped section); ридер закрываем ДО мутации
    drop(r);

    let _rrep = rollback_archive(&out).unwrap();
    let r2 = PolerReader::open(&out).unwrap();
    assert!(r2.verify().unwrap().all_ok);
    assert!(r2.find_file("config/new.txt").is_none(), "после отката патча нет");
    let _ = fs::remove_dir_all(&dir);
}

// ─── 6. Умышленная порча: verify обязан поймать ───

#[test]
fn verify_catches_corruption() {
    let dir = tmpdir("corrupt");
    let out = dir.join("c.poler");
    write_stream(
        Cursor::new((0..128 * 1024u32).map(|i| (i.wrapping_mul(2654435761) % 251) as u8).collect::<Vec<u8>>()),
        &out,
        StreamWriteConfig::default(),
        "corrupt-me",
    )
    .unwrap();
    let mut bytes = fs::read(&out).unwrap();
    // испортить SHA-256 последней записи в файловой таблице (32 байта перед
    // трейлером) — распаковка успешна, но контрольная сумма не сойдётся
    let n = bytes.len();
    for b in &mut bytes[n - 136..n - 104] {
        *b ^= 0xFF;
    }
    fs::write(&out, bytes).unwrap();
    let r = PolerReader::open(&out).unwrap();
    let rep = r.verify().unwrap();
    assert!(!rep.all_ok, "порча обязана быть поймана");
    let _ = fs::remove_dir_all(&dir);
}

// ─── 7. CLI-транскодинг контейнеров на лету: .tar.gz / .tar.zst / .tar ───
//
// Реальный бинарник `poler` (CARGO_BIN_EXE): gzip/zstd-декодеры разворачивают
// поток прямо в конвейер FastCDC — без временных файлов. Проверяем, что
// TarObserver строит файловую таблицу из внутреннего tar, а не пакует
// контейнер как монолитный блоб.

#[test]
fn cli_transcode_containers() {
    use std::io::{Read, Write};
    use std::process::Command;

    let dir = tmpdir("transcode");
    let src = dir.join("data");
    fs::create_dir_all(src.join("nested")).unwrap();
    fs::write(src.join("a.txt"), b"transcode me").unwrap();
    fs::write(src.join("nested/b.bin"), vec![42u8; 700_000]).unwrap();

    // tar-поток через публичный генератор: абсолютный путь даёт те же
    // имена записей `data/...`, что и относительный — cwd не трогаем
    // (параллельные тесты не должны соревноваться за set_current_dir).
    let mut tar = FsTarReader::new(&[src.clone()]).unwrap();
    let mut tar_bytes = Vec::new();
    tar.read_to_end(&mut tar_bytes).unwrap();

    // .tar.gz — flate2 rust_backend, тот же стек, что в cmd_create
    let tgz = dir.join("data.tar.gz");
    {
        let mut enc = flate2::write::GzEncoder::new(
            fs::File::create(&tgz).unwrap(),
            flate2::Compression::default(),
        );
        enc.write_all(&tar_bytes).unwrap();
        enc.finish().unwrap();
    }
    // .tar.zst — zstd, та же версия крейта, что в cmd_create
    let tzst = dir.join("data.tar.zst");
    {
        let mut enc = zstd::stream::Encoder::new(fs::File::create(&tzst).unwrap(), 3).unwrap();
        enc.write_all(&tar_bytes).unwrap();
        enc.finish().unwrap();
    }
    // .tar — без декодера (прямой поток)
    let plain = dir.join("data.tar");
    fs::write(&plain, &tar_bytes).unwrap();

    let bin = env!("CARGO_BIN_EXE_poler");

    // --version: стандартный вызов установщиков/скриптов
    let ver = Command::new(bin).arg("--version").output().unwrap();
    assert!(ver.status.success(), "--version упал");
    assert!(
        String::from_utf8_lossy(&ver.stdout).starts_with("poler 0."),
        "--version: {}",
        String::from_utf8_lossy(&ver.stdout)
    );

    for (container, tag) in [(&tgz, "targz"), (&tzst, "tarzst"), (&plain, "tar")] {
        let out = dir.join(format!("from_{tag}.poler"));
        let st = Command::new(bin)
            .arg("create")
            .arg(out.as_os_str())
            .arg(container.as_os_str())
            .output()
            .unwrap();
        assert!(
            st.status.success(),
            "{tag}: create упал: {}",
            String::from_utf8_lossy(&st.stderr)
        );
        // контейнер распакован в поток: размер ≈ tar-байты, а не запакованный блоб
        let r = PolerReader::open(&out).unwrap();
        assert!(r.info().tar_mode, "{tag}: tar-режим распознан");
        assert_eq!(r.files().len(), 2, "{tag}: файловая таблица построена");
        assert!(r.find_file("data/a.txt").is_some(), "{tag}: a.txt в таблице");
        assert!(
            r.find_file("data/nested/b.bin").is_some(),
            "{tag}: b.bin в таблице"
        );
        assert!(r.verify().unwrap().all_ok, "{tag}: verify после транскодинга");
        // транскодинг ≈ прямая упаковка того же tar-потока (±3%)
        let direct = dir.join(format!("direct_{tag}.poler"));
        write_stream(
            fs::File::open(&plain).unwrap(),
            &direct,
            StreamWriteConfig::default(),
            "direct",
        )
        .unwrap();
        let (a, b) = (fs::metadata(&out).unwrap().len(), fs::metadata(&direct).unwrap().len());
        assert!(
            (a as i64 - b as i64).unsigned_abs() < b / 33,
            "{tag}: размер {a} отличается от прямой упаковки {b} более чем на 3%"
        );
        let _ = fs::remove_file(&direct);
        // содержимое бит-в-бит
        let ex = dir.join(format!("ex_{tag}"));
        let rep = r.extract_all(&ex).unwrap();
        assert_eq!(rep.files_ok, 2, "{tag}: распаковка сошлась по SHA-256");
        assert_eq!(
            fs::read(ex.join("data/nested/b.bin")).unwrap(),
            vec![42u8; 700_000],
            "{tag}: содержимое бит-в-бит"
        );
        let _ = fs::remove_dir_all(&ex);
    }
    let _ = fs::remove_dir_all(&dir);
}
