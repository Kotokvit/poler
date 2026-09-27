#!/usr/bin/env bash
# install-macos.sh — интеграция POLER в Finder (macOS).
#
# 1) бинарники -> ~/bin (или /usr/local/bin при правах)
# 2) Quick Action «POLER: извлечь» через Automator — интерактивные шаги
#    печатаются в конце (скриптовая регистрация services macOS запрещает
#    Apple с 13.x для не-подписанных приложений)
# 3) ассоциация .poler -> poler-gui через duti (если установлен)
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
BIN_DIR="$HOME/bin"

say() { printf '\033[1;32m▸\033[0m %s\n' "$*"; }

if [ -x "$REPO/target/release/poler" ]; then
    mkdir -p "$BIN_DIR"
    install -m 0755 "$REPO/target/release/poler" "$BIN_DIR/poler"
    install -m 0755 "$REPO/target/release/poler-box" "$BIN_DIR/poler-box"
    install -m 0755 "$REPO/gui/poler-gui" "$BIN_DIR/poler-gui"
    say "установлено в $BIN_DIR"
else
    say "сначала: cargo build --release (в корне репо)"
    exit 1
fi

# PATH-подсказка
case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) say "добавь в ~/.zshrc: export PATH=\"\$HOME/bin:\$PATH\"" ;;
esac

# ассоциация расширения через duti (опционально)
if command -v duti >/dev/null 2>&1 && command -v osascript >/dev/null 2>&1; then
    say "duty-ассоциация .poler (опционально)"
    echo "  duti -s poler.archive .poler all   # после создания приложения-обёртки"
else
    say "duti не найден: brew install duti — для ассоциации расширения"
fi

say "Quick Action (Finder → правый клик → Quick Actions):"
cat << 'EOF'
  1. Automator -> New -> Quick Action
  2. «Workflow receives» = «files or folders» in «Finder»
  3. Добавь действие «Run Shell Script»:
       /bin/bash -c 'for f in "$@"; do case "$f" in *.poler) "$HOME/bin/poler" extract "$f" "$(dirname "$f")";; esac; done' "$@"
     (Shell: /bin/bash, «Pass input: as arguments»)
  4. Сохрани как «POLER — извлечь сюда»
  Быстрая проверка: ~/bin/poler list АРХИВ.poler
EOF
