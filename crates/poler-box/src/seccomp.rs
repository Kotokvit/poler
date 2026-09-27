//! Seccomp-фільтр poler-box: білий список сисколів для нативних payload
//! (статичний glibc, динамічні ELF з rootfs-бібліотеками, Rust-бінарники,
//! tcc -run). Все поза списком — ERRNO(EPERM), смертельне — KILL_PROCESS.
//!
//! Формат seccomp_data (x86_64 LE): nr@0, arch@4, ip@8, args[6]@16..64.
//! На little-endian молодше слово args[0] лежить за зміщенням 16.
//!
//! Розмітка програми (усі офсети відомі до емісії):
//! ```text
//! [0]  LD arch
//! [1]  JEQ x86_64: так → [2], ні → [ERRNO]      (остання інструкція)
//! [2]  LD nr
//!      DEADLY:  JEQ d: так → RET KILL (наступна), ні → далі     (пари)
//!      SOCKET:  JEQ SYS_socket: так → далі, ні → пропустити блок
//!              LD args[0]
//!              { JEQ blocked_af: так → RET ERRNO, ні → далі }×N
//!              RET ALLOW
//!              LD nr                    (перезавантаження)
//!      ALLOW:   JEQ a: так → RET ALLOW (наступна), ні → далі    (пари)
//! [E]  RET ERRNO                                (дефолт)
//! ```

/// Білий список сисколів (x86_64), достатній для:
/// * статичних/динамічних glibc-програм (TLS, malloc, stdio, futex);
/// * Rust-бінарників (std::process, std::thread, std::fs, unix-сокети);
/// * tcc (компіляція + tcc -run через memfd);
/// * poler-engine як payload (mmap-архіви, rayon-пул).
const ALLOW: &[i64] = &[
    // файли
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_readv,
    libc::SYS_writev,
    libc::SYS_pread64,
    libc::SYS_pwritev,
    libc::SYS_preadv,
    libc::SYS_open,
    libc::SYS_openat,
    libc::SYS_close,
    libc::SYS_stat,
    libc::SYS_fstat,
    libc::SYS_lstat,
    libc::SYS_newfstatat,
    libc::SYS_statx,
    libc::SYS_lseek,
    libc::SYS_getdents,
    libc::SYS_getdents64,
    libc::SYS_fcntl,
    libc::SYS_flock,
    libc::SYS_fsync,
    libc::SYS_fdatasync,
    libc::SYS_truncate,
    libc::SYS_ftruncate,
    libc::SYS_access,
    libc::SYS_faccessat,
    libc::SYS_faccessat2,
    libc::SYS_link,
    libc::SYS_linkat,
    libc::SYS_unlink,
    libc::SYS_unlinkat,
    libc::SYS_rename,
    libc::SYS_renameat,
    libc::SYS_renameat2,
    libc::SYS_symlink,
    libc::SYS_symlinkat,
    libc::SYS_readlink,
    libc::SYS_readlinkat,
    libc::SYS_mkdir,
    libc::SYS_mkdirat,
    libc::SYS_rmdir,
    libc::SYS_creat,
    libc::SYS_chmod,
    libc::SYS_fchmod,
    libc::SYS_fchmodat,
    libc::SYS_chown,
    libc::SYS_fchown,
    libc::SYS_lchown,
    libc::SYS_fchownat,
    libc::SYS_utimensat,
    libc::SYS_umask,
    libc::SYS_getcwd,
    libc::SYS_chdir,
    libc::SYS_fchdir,
    libc::SYS_sendfile,
    libc::SYS_copy_file_range,
    libc::SYS_readahead,
    libc::SYS_memfd_create,
    libc::SYS_execveat,
    // пам'ять
    libc::SYS_mmap,
    libc::SYS_munmap,
    libc::SYS_mprotect,
    libc::SYS_mremap,
    libc::SYS_madvise,
    libc::SYS_msync,
    libc::SYS_mincore,
    libc::SYS_brk,
    libc::SYS_mlock,
    libc::SYS_munlock,
    libc::SYS_membarrier,
    // сигнали
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_rt_sigpending,
    libc::SYS_rt_sigtimedwait,
    libc::SYS_rt_sigsuspend,
    libc::SYS_sigaltstack,
    libc::SYS_kill,
    libc::SYS_tkill,
    libc::SYS_tgkill,
    libc::SYS_signalfd4,
    // процеси
    libc::SYS_clone,
    libc::SYS_clone3,
    libc::SYS_fork,
    libc::SYS_vfork,
    libc::SYS_execve,
    libc::SYS_exit,
    libc::SYS_exit_group,
    libc::SYS_wait4,
    libc::SYS_waitid,
    libc::SYS_getpid,
    libc::SYS_getppid,
    libc::SYS_gettid,
    libc::SYS_set_tid_address,
    libc::SYS_set_robust_list,
    libc::SYS_get_robust_list,
    libc::SYS_rseq,
    libc::SYS_prctl,
    libc::SYS_arch_prctl,
    libc::SYS_prlimit64,
    libc::SYS_getrlimit,
    libc::SYS_setrlimit,
    libc::SYS_capget,
    libc::SYS_capset,
    libc::SYS_uname,
    libc::SYS_personality,
    libc::SYS_getuid,
    libc::SYS_getgid,
    libc::SYS_geteuid,
    libc::SYS_getegid,
    libc::SYS_getgroups,
    libc::SYS_setgroups,
    libc::SYS_setuid,
    libc::SYS_setgid,
    libc::SYS_setresuid,
    libc::SYS_setresgid,
    libc::SYS_setreuid,
    libc::SYS_setregid,
    libc::SYS_setfsuid,
    libc::SYS_setfsgid,
    libc::SYS_getcpu,
    libc::SYS_sched_yield,
    libc::SYS_sched_getaffinity,
    libc::SYS_sched_setaffinity,
    libc::SYS_sched_getparam,
    libc::SYS_sched_setscheduler,
    libc::SYS_getpriority,
    libc::SYS_setpriority,
    libc::SYS_restart_syscall,
    // час
    libc::SYS_clock_gettime,
    libc::SYS_clock_getres,
    libc::SYS_clock_nanosleep,
    libc::SYS_nanosleep,
    libc::SYS_gettimeofday,
    libc::SYS_time,
    libc::SYS_times,
    libc::SYS_timerfd_create,
    libc::SYS_timerfd_settime,
    libc::SYS_timerfd_gettime,
    libc::SYS_getrandom,
    libc::SYS_sysinfo,
    // події/пайпи
    libc::SYS_pipe,
    libc::SYS_pipe2,
    libc::SYS_dup,
    libc::SYS_dup2,
    libc::SYS_dup3,
    libc::SYS_poll,
    libc::SYS_ppoll,
    libc::SYS_select,
    libc::SYS_pselect6,
    libc::SYS_epoll_create1,
    libc::SYS_epoll_ctl,
    libc::SYS_epoll_wait,
    libc::SYS_epoll_pwait,
    libc::SYS_eventfd2,
    libc::SYS_ioctl,
    libc::SYS_futex,
    // локальні сокети (AF_UNIX дозволено; AF_INET/6/NETLINK/PACKET → EPERM)
    libc::SYS_socket,
    libc::SYS_socketpair,
    libc::SYS_shutdown,
    libc::SYS_bind,
    libc::SYS_listen,
    libc::SYS_accept,
    libc::SYS_accept4,
    libc::SYS_connect,
    libc::SYS_sendto,
    libc::SYS_recvfrom,
    libc::SYS_sendmsg,
    libc::SYS_recvmsg,
    libc::SYS_recvmmsg,
    libc::SYS_sendmmsg,
    libc::SYS_getsockname,
    libc::SYS_getpeername,
    libc::SYS_setsockopt,
    libc::SYS_getsockopt,
];

/// Родини адрес, заборонені на socket() (мережевий вихід із коробки).
const BLOCKED_AF: &[u32] = &[
    2,  // AF_INET
    10, // AF_INET6
    16, // AF_NETLINK
    17, // AF_PACKET
];

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt: 0, jf: 0, k }
}

fn jeq(k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
        jt,
        jf,
        k,
    }
}

const LD: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
const RET: u16 = (libc::BPF_RET | libc::BPF_K) as u16;

/// Збірка фільтра: чиста арифметика офсетів, без другого проходу.
pub fn build_filter() -> Vec<libc::sock_filter> {
    let ret_kill = libc::SECCOMP_RET_KILL_PROCESS as u32;
    let ret_errno = (libc::SECCOMP_RET_ERRNO as u32) | (libc::EPERM as u32);
    let ret_allow = libc::SECCOMP_RET_ALLOW as u32;

    let deadly = super::DEADLY;
    // довжини блоків
    let socket_block = 1 /*LD af*/ + 2 * BLOCKED_AF.len() + 1 /*RET allow*/ + 1 /*LD nr*/;
    let total = 2 /*LD arch + JEQ arch*/
        + 1 /*LD nr*/
        + 2 * deadly.len()
        + 1 /*JEQ socket*/
        + socket_block
        + 2 * ALLOW.len()
        + 1; /*RET errno (дефолт)*/
    let errno_idx = total - 1;
    // арх-перевірка: промах → дефолт-ERRNO; офсет від [2] до [errno_idx]
    let arch_jf = (errno_idx - 2) as u8;

    let mut f: Vec<libc::sock_filter> = Vec::with_capacity(total);

    f.push(stmt(LD, 4)); // arch
    // AUDIT_ARCH_X86_64 (0xC000003E) — канонічне значення linux/audit.h;
    // у libc-crate цієї версії константа відсутня.
    f.push(jeq(0xC000_003E, 0, arch_jf));
    f.push(stmt(LD, 0)); // nr

    for &d in deadly {
        f.push(jeq(d as u32, 0, 1)); // збіг → наступна (RET KILL); промах → пропустити RET
        f.push(stmt(RET, ret_kill));
    }

    // socket → перевірка родини
    f.push(jeq(libc::SYS_socket as u32, 0, socket_block as u8));
    f.push(stmt(LD, 16)); // args[0]
    for &af in BLOCKED_AF {
        f.push(jeq(af, 0, 1));
        f.push(stmt(RET, ret_errno));
    }
    f.push(stmt(RET, ret_allow)); // дозволена родина (AF_UNIX тощо)
    f.push(stmt(LD, 0)); // перезавантажити nr

    for &a in ALLOW {
        f.push(jeq(a as u32, 0, 1));
        f.push(stmt(RET, ret_allow));
    }

    f.push(stmt(RET, ret_errno)); // дефолт

    debug_assert_eq!(f.len(), total);
    f
}

/// Установка фільтра в поточний процес (перед exec payload).
/// Після встановлення зняти неможливо — фільтр успадковується дітьми.
pub fn install() -> Result<(), String> {
    let mut filter = build_filter();
    if filter.len() > 4096 {
        return Err(format!("filter too large: {}", filter.len()));
    }
    let mut prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    let r0 = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if r0 != 0 {
        return Err(format!(
            "PR_SET_NO_NEW_PRIVS: {}",
            std::io::Error::last_os_error()
        ));
    }
    let r1 = unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &mut prog) };
    if r1 != 0 {
        return Err(format!(
            "PR_SET_SECCOMP: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_wellformed_and_covers_essentials() {
        let f = build_filter();
        assert!(f.len() > 100 && f.len() < 4096, "len={}", f.len());

        assert_eq!(f[0].code, LD);
        assert_eq!(f[0].k, 4);

        let ret_allow = libc::SECCOMP_RET_ALLOW as u32;
        let ret_errno = (libc::SECCOMP_RET_ERRNO as u32) | (libc::EPERM as u32);
        let ret_kill = libc::SECCOMP_RET_KILL_PROCESS as u32;

        assert!(f.iter().any(|i| i.code == RET && i.k == ret_allow));
        assert!(f.iter().any(|i| i.code == RET && i.k == ret_errno));
        assert!(f.iter().any(|i| i.code == RET && i.k == ret_kill));

        for must in [
            libc::SYS_read as u32,
            libc::SYS_write as u32,
            libc::SYS_mmap as u32,
            libc::SYS_execve as u32,
            libc::SYS_exit_group as u32,
            libc::SYS_futex as u32,
        ] {
            let jeq = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
            assert!(
                f.iter().any(|i| i.code == jeq && i.k == must),
                "білий список без syscall {must}"
            );
        }

        // стрибки в межах програми
        let jeq_code = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
        for (idx, i) in f.iter().enumerate() {
            if i.code == jeq_code {
                assert!(idx + 1 + i.jt as usize <= f.len(), "jt за межами при {idx}");
                assert!(idx + 1 + i.jf as usize <= f.len(), "jf за межами при {idx}");
            }
        }

        // семантика: за білим списком слідує RET ALLOW
        for (idx, i) in f.iter().enumerate() {
            if i.code == jeq_code && i.jt == 0 && i.jf == 1 {
                assert_eq!(f[idx + 1].code, RET, "пара JEQ/RET порушена при {idx}");
            }
        }
    }

    #[test]
    fn whitelist_has_no_deadly_overlap() {
        for &d in super::super::DEADLY {
            assert!(!ALLOW.contains(&d), "deadly syscall у білому списку: {d}");
        }
    }

    #[test]
    fn socket_family_gate_present() {
        let f = build_filter();
        let jeq_code = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
        assert!(f.iter().any(|i| i.code == jeq_code && i.k == libc::SYS_socket as u32));
        // LD args[0]
        assert!(f.iter().any(|i| i.code == LD && i.k == 16));
        for &af in BLOCKED_AF {
            assert!(f.iter().any(|i| i.code == jeq_code && i.k == af));
        }
    }
}
