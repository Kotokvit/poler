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
