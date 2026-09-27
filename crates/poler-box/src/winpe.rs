//! Облегчённый слой winpe для standalone poler-box.
//!
//! В poler-engine полный Win64-субстрат (`src/winpe/`, 5.7K строк: PE-
//! загрузчик, CRT, SEH, API-таблица) исполняет PE32+ прямо внутри коробки
//! без Wine/VM. В standalone-крейте по умолчанию включается только
//! детектирование PE32+ (чтобы коробка честно отказывала на Windows-payload
//! вместо попытки исполнить его как ELF); полный субстрат — фича `winpe`
//! в дорожной карте.

/// Детект PE32+ AMD64 (MZ + PE\0\0 + Machine == 0x8664).
pub fn is_pe32_plus(bytes: &[u8]) -> bool {
    if bytes.len() < 0x40 || &bytes[..2] != b"MZ" {
        return false;
    }
    let pe_off =
        u32::from_le_bytes([bytes[0x3c], bytes[0x3d], bytes[0x3e], bytes[0x3f]]) as usize;
    if pe_off + 6 > bytes.len() || &bytes[pe_off..pe_off + 4] != b"PE\0\0" {
        return false;
    }
    // COFF Machine: 0x8664 = AMD64; 0x14c = i386 (не 64-битный PE)
    let machine = u16::from_le_bytes([bytes[pe_off + 4], bytes[pe_off + 5]]);
    machine == 0x8664
}

/// Исполнение PE32+ внутри коробки (в движке — полный Win64-субстрат).
///
/// В standalone-сборке отключено: собирайте poler-engine с winpe или
/// дождитесь feature `winpe` этого крейта.
pub fn winexec(
    _entry: &[u8],
    _argv: Vec<String>,
    _env: Vec<(String, String)>,
) -> Result<i32, String> {
    Err(
        "winpe: исполнение Windows PE не входит в standalone poler-box \
         (используйте poler-engine или feature `winpe` из дорожной карты)"
            .to_string(),
    )
}
