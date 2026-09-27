#!/usr/bin/env bash
# install.sh — интеграция POLER в файловые менеджеры Linux.
#
# Устанавливает: CLI (~/.local/bin) · MIME-тип + иконку · ServiceMenus KDE
# (Dolphin/Krusader) · скрипты Nautilus · действия Nemo · действия Thunar ·
# poler-gui · poler-fuse (если есть libfuse) · пункт «Сжать в .poler».
#
# Работает с: Dolphin, Nautilus, Nemo, Thunar, PCManFM(-Qt), Caja, mc, ranger,
# yazi (последние три — через CLI; FUSE-маунт работает везде).
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
BIN_DIR="$HOME/.local/bin"
DETECT=""

say() { printf '\033[1;32m▸\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m▸\033[0m %s\n' "$*"; }

# ── 0. окружение ──
command -v cargo >/dev/null 2>&1 || { warn "cargo не найден — беру готовые бинарники, если есть"; }
[ -x "$REPO/target/release/poler" ] && REL=release || REL=debug

# ── 1. бинарники ──
say "CLI poler / poler-box -> $BIN_DIR (сборка: $REL)"
mkdir -p "$BIN_DIR"
if [ -x "$REPO/target/$REL/poler" ]; then
    install -m 0755 "$REPO/target/$REL/poler" "$BIN_DIR/poler"
    install -m 0755 "$REPO/target/$REL/poler-box" "$BIN_DIR/poler-box"
else
    say "собираю release…"
    (cd "$REPO" && cargo build --release)
    install -m 0755 "$REPO/target/release/poler" "$BIN_DIR/poler"
    install -m 0755 "$REPO/target/release/poler-box" "$BIN_DIR/poler-box"
fi

# poler-fuse — отдельная сборка (нужен libfuse)
if pkg-config --exists fuse 2>/dev/null && [ -e /dev/fuse ]; then
    say "libfuse найден — собираю poler-fuse (маунт .poler как папки)"
    (cd "$REPO" && cargo build --release -p poler-fuse) \
        && install -m 0755 "$REPO/target/release/poler-fuse" "$BIN_DIR/poler-fuse" \
        || warn "poler-fuse не собрался — действие «открыть как папку» недоступно"
else
    warn "libfuse//dev/fuse нет — poler-fuse пропущен (sudo apt install libfuse3-dev)"
fi

# ── 2. GUI-обёртка ──
say "poler-gui -> $BIN_DIR"
install -m 0755 "$REPO/gui/poler-gui" "$BIN_DIR/poler-gui"
command -v yad >/dev/null || warn "поставь yad для лучших диалогов: sudo apt install yad (fallback: zenity)"

# ── 3. MIME-тип + иконка ──
say "MIME application/x-poler (*.poler, *.t5z)"
mkdir -p "$HOME/.local/share/mime/packages"
cp "$HERE/poler-mime.xml" "$HOME/.local/share/mime/packages/"
mkdir -p "$HOME/.local/share/icons/hicolor/scalable/mimetypes"
cat > "$HOME/.local/share/icons/hicolor/scalable/mimetypes/application-x-poler.svg" << 'SVG'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <rect x="8" y="14" width="48" height="40" rx="5" fill="#1d3557"/>
  <rect x="8" y="6" width="48" height="12" rx="5" fill="#457b9d"/>
  <path d="M20 30h24M20 38h24M20 46h14" stroke="#a8dadc" stroke-width="3" stroke-linecap="round"/>
  <circle cx="47" cy="46" r="7" fill="#2a9d8f"/>
  <path d="M44 46l2.5 2.5L51 43" stroke="#fff" stroke-width="2.2" fill="none" stroke-linecap="round"/>
</svg>
SVG
update-mime-database "$HOME/.local/share/mime" 2>/dev/null || true
update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true

# ── 4. KDE ServiceMenus (Dolphin, Konqueror, Krusader) ──
if command -v dolphin >/dev/null 2>&1 || ls /usr/bin | grep -qiE '^(dolphin|krusader)$' >/dev/null 2>&1; then
    DETECT="${DETECT} Dolphin(ServiceMenus)"
    say "KDE ServiceMenus"
    for d in "$HOME/.local/share/kio/services/ServiceMenus" "$HOME/.local/share/kservices5/ServiceMenus"; do
        mkdir -p "$d"
        cp "$HERE/poler-servicemenu.desktop" "$d/"
        cp "$HERE/poler-compress-servicemenu.desktop" "$d/"
    done
fi

# ── 5. Nautilus (GNOME) ──
if command -v nautilus >/dev/null 2>&1; then
    DETECT="${DETECT} Nautilus(scripts)"
    say "Nautilus: скрипты контекстного меню"
    NS="$HOME/.local/share/nautilus/scripts"
    mkdir -p "$NS/POLER"
    ln -sf "$BIN_DIR/poler-gui" "$NS/POLER/Извлечь сюда" 2>/dev/null || true
    for act in extract-to verify list compress box-extract; do
        ln -sf "$BIN_DIR/poler-gui" "$NS/POLER/$act" 2>/dev/null || true
    done
    # nautilus передаёт выделение как аргументы скрипту — обёртка:
    cat > "$NS/POLER/Извлечь сюда" << 'EOF'
#!/usr/bin/env bash
exec poler-gui extract-here "$@"
EOF
    cat > "$NS/POLER/Проверить целостность" << 'EOF'
#!/usr/bin/env bash
exec poler-gui verify "$@"
EOF
    cat > "$NS/POLER/Сжать в .poler" << 'EOF'
#!/usr/bin/env bash
exec poler-gui compress "$@"
EOF
    chmod +x "$NS/POLER"/*
fi

# ── 6. Nemo (Cinnamon/Mint) ──
if command -v nemo >/dev/null 2>&1; then
    DETECT="${DETECT} Nemo(actions)"
    say "Nemo actions"
    NA="$HOME/.local/share/nemo/actions"
    mkdir -p "$NA"
    cat > "$NA/poler-extract.nemo_action" << 'EOF'
[Nemo Action]
Name=POLER: извлечь сюда
Comment=Распаковать .poler-архив в текущий каталог
Exec=poler-gui extract-here %F
Icon-Name=package-x-generic
Selection=S
Extensions=poler;t5z;
EOF
    cat > "$NA/poler-verify.nemo_action" << 'EOF'
[Nemo Action]
Name=POLER: проверить целостность
Comment=SHA-256 всего потока и каждой записи
Exec=poler-gui verify %F
Icon-Name=checkbox
Selection=S
Extensions=poler;t5z;
EOF
    cat > "$NA/poler-compress.nemo_action" << 'EOF'
[Nemo Action]
Name=POLER: сжать в .poler
Exec=poler-gui compress %F
Icon-Name=package-x-generic
Selection=Any
Extensions=any;
EOF
fi

# ── 7. Thunar (XFCE) ──
if command -v thunar >/dev/null 2>&1; then
    DETECT="${DETECT} Thunar(custom actions)"
    say "Thunar: пользовательские действия (uca.xml)"
    TU="$HOME/.config/Thunar/uca.xml"
    mkdir -p "$(dirname "$TU")"
    if [ ! -f "$TU" ]; then
        printf '<?xml version="1.0" encoding="UTF-8"?>\n<actions>\n</actions>\n' > "$TU"
    fi
    python3 - "$TU" << 'PYEOF'
import sys, xml.etree.ElementTree as ET
path = sys.argv[1]
tree = ET.parse(path); root = tree.getroot()
def have(name):
    return any(a.findtext('Name','') == name for a in root.findall('action'))
def add(name, cmd, patterns, desc):
    if have(name): return
    a = ET.SubElement(root, 'action')
    ET.SubElement(a,'icon').text='package-x-generic'
    ET.SubElement(a,'name').text=name
    ET.SubElement(a,'command').text=cmd
    ET.SubElement(a,'description').text=desc
    ET.SubElement(a,'patterns').text=patterns
    ET.SubElement(a,'directories').text='0' if patterns!='*' else '1'
add('POLER: извлечь сюда', 'poler-gui extract-here %f', '*.poler;*.t5z', 'Распаковать архив POLER')
add('POLER: проверить', 'poler-gui verify %f', '*.poler;*.t5z', 'Целостность SHA-256')
add('POLER: сжать в .poler', 'poler-gui compress %F', '*', 'Создать .poler-архив из выделенного')
ET.indent(tree, space='  ')
tree.write(path, encoding='UTF-8', xml_declaration=True)
print('uca.xml обновлён')
PYEOF
fi

# ── 8. .desktop для запуска GUI вручную ──
mkdir -p "$HOME/.local/share/applications"
cat > "$HOME/.local/share/applications/poler-gui.desktop" << 'EOF'
[Desktop Entry]
Type=Application
Name=POLER Archiver
GenericName=Архиватор .poler
Comment=Суверенный стриминговый архиватор: FastCDC + дедуп + zstd
Exec=poler-gui
Terminal=false
Icon=package-x-generic
Categories=Utility;Archiving;
EOF

say "готово. Обнаруженные оболочки:${DETECT:-<никаких из известных — CLI установлен>}"
say "перезапусти проводник (или сеанс), чтобы подхватить MIME/меню"
echo
echo "  Быстрая проверка:  poler list АРХИВ.poler   |   poler-gui verify АРХИВ.poler"
echo "  FUSE-режим:        poler-fuse АРХИВ.poler /точка/монтирования"
echo "  Безопасное вскрытие чужого архива:  poler-box safe-extract АРХИВ.poler"
