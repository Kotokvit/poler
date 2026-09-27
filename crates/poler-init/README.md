# poler-init

**Суверенный Linux PID 1 Init-процесс нового поколения**

`poler-init` полностью устраняет командные оболочки и скриптовые цепочки 90-х годов (`SysVinit`, `rc.local`, медленные shell-генераторы `systemd`, `bash` в роли загрузочного клея). 

Он предоставляет ультрабыструю, нативную загрузку прямо в **`poler-sh`** / **`poler-engine`** с соблюдением закона памяти $O(1) \le 48\text{ МБ}$.

---

## Архитектурные свойства

1. **Мгновенный холодный старт:** инициализация VFS (`/proc`, `/sys`, `/dev`, `/dev/pts`, `/dev/shm`, `/run`, `/tmp`, `/sys/fs/cgroup`), tty-консоли, hostname и loopback-интерфейса выполняется за **< 1 мс** (в тестах QEMU на ядре CachyOS 7.2.5 — **0.535 мс**).
2. **Нулевой GNU/Shell оверхед:** отсутствие промежуточных `/bin/sh`-скриптов при старте системы.
3. **Суверенный супервизор:** мониторинг жизненного цикла оболочки `poler-sh`, автоматический сбор zombie-процессов через `waitpid` цикл, изоляция сбоев без паники ядра (Kernel Panic).
4. **Безопасная перезагрузка / выключение:** нативная обработка сигналов и системных вызовов `libc::reboot`.

---

## Тестирование в QEMU

Сборка минимального суверенного initramfs и запуск поверх нативного ядра Linux CachyOS:

```bash
# 1. Сборка бинарника
cargo build -p poler-init --release

# 2. Запуск в QEMU
qemu-system-x86_64 \
  -enable-kvm -cpu host -m 512M \
  -kernel /usr/lib/modules/$(uname -r)/vmlinuz \
  -initrd /tmp/poler_initramfs.cpio.gz \
  -append "console=ttyS0 init=/init loglevel=3 panic=1" \
  -nographic
```

---

## Лицензия

MIT / Apache-2.0
