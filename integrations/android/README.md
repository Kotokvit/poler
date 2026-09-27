# POLER на Android

## Почему это работает

Крейт `poler-archive` — чистый Rust + zstd (C, собирается NDK-clang'ом).
Никаких системных зависимостей: Android NDK собирает его как JNI-библиотеку.

MiXplorer / ZArchiver / Solid Explorer — проприетарные проводники, вшивающие
свои копии libarchive. Подключить `.poler` в них нельзя, но любой собственный
просмотрщик (или форк с открытым кодом) получает формат одной зависимостью.

## Сборка JNI-библиотеки

```bash
cargo install cargo-ndk
rustup target add aarch64-linux-android armv7-linux-androideabi

cd crates/poler-archive
cargo ndk -t arm64-v8a -t armeabi-v7a -o src/main/jniLibs build --release
```

## JNI-мост (Kotlin)

```kotlin
object Poler {
    init { System.loadLibrary("poler_jni") }

    // список записей: массив "name size" (см. PolerReader::files)
    external fun list(archivePath: String): Array<String>
    // извлечь запись в файл
    external fun extract(archivePath: String, entry: String, destPath: String): Boolean
    // верификация целого архива
    external fun verify(archivePath: String): Boolean
}
```

Пример обёртки (`poler-jni`): `list` маппится на `PolerReader::open` +
`files()`, `extract` — на `read_range` в `FileOutputStream` (буфер 1 МиБ,
как в CLI `cat`), `verify` — на `PolerReader::verify().all_ok`.

## Ограничения

- mmap-ридер использует unix-API — на Android работает;
- `peak_rss_kb` читает `/proc/self/status` — на Android возвращает 0
  (безвредно, только статистика);
- POLER BOX (unshare/seccomp) — Linux-only, на Android не собирается
  (ядро без user-namespace в per-user конфигурации).
