# poler-shell.ps1 — мост «Проводник Windows -> poler.exe».
# Вызывается из контекстного меню (см. POLER-Explorer.reg).
# %POLER_HOME% (или текущий каталог) должен содержать poler.exe.
param(
    [Parameter(Mandatory=$true)][string]$Action,
    [Parameter(Mandatory=$true)][string]$Archive
)

$poler = Join-Path $env:POLER_HOME "poler.exe"
if (-not (Test-Path $poler)) { $poler = "poler.exe" }   # fallback: PATH

function Show($title, $text) {
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show($text, $title) | Out-Null
}

switch ($Action) {
    "extract-here" {
        $dir = Split-Path -Parent $Archive
        $out = & $poler extract $Archive $dir 2>&1
        if ($LASTEXITCODE -eq 0) { Show "POLER" "Извлечено в: $dir" }
        else { Show "POLER — ошибка" ($out | Out-String) }
    }
    "extract-to" {
        $fbd = New-Object System.Windows.Forms.FolderBrowserDialog
        if ($fbd.ShowDialog() -eq "OK") {
            $out = & $poler extract $Archive $fbd.SelectedPath 2>&1
            if ($LASTEXITCODE -eq 0) { Show "POLER" "Извлечено в: $($fbd.SelectedPath)" }
            else { Show "POLER — ошибка" ($out | Out-String) }
        }
    }
    "verify" {
        $out = & $poler verify $Archive 2>&1
        if ($LASTEXITCODE -eq 0) { Show "POLER — целостность OK" ($out | Out-String) }
        else { Show "POLER — НАРУШЕНИЕ ЦЕЛОСТНОСТИ" ($out | Out-String) }
    }
    "list" {
        $out = & $poler list $Archive 2>&1
        Show "POLER — содержимое $($Archive)" ($out | Out-String)
    }
    default { Show "POLER" "Неизвестное действие: $Action" }
}
