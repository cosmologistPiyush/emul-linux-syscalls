/* $NetBSD: linux_syscalls.c,v 1.38 2010/07/07 01:31:51 chs Exp $ */

/*
 * System call names.
 *
 * DO NOT EDIT-- this file is automatically generated.
 * created from	NetBSD: syscalls.master,v 1.35 2010/07/07 01:30:33 chs Exp
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: linux_syscalls.c,v 1.38 2010/07/07 01:31:51 chs Exp $");

#if defined(_KERNEL_OPT)
#if defined(_KERNEL_OPT)
#include "opt_sysv.h"
#include "opt_compat_43.h"
#include "opt_compat_netbsd.h"
#endif
#include <sys/param.h>
#include <sys/poll.h>
#include <sys/systm.h>
#include <sys/signal.h>
#include <sys/mount.h>
#include <sys/syscallargs.h>
#include <sys/time.h>
#include <compat/sys/time.h>
#include <compat/linux/common/linux_types.h>
#include <compat/linux/common/linux_mmap.h>
#include <compat/linux/common/linux_ipc.h>
#include <compat/linux/common/linux_msg.h>
#include <compat/linux/common/linux_sem.h>
#include <compat/linux/common/linux_shm.h>
#include <compat/linux/common/linux_signal.h>
#include <compat/linux/common/linux_siginfo.h>
#include <compat/linux/common/linux_machdep.h>
#include <compat/linux/linux_syscallargs.h>
#endif /* _KERNEL_OPT */

const char *const linux_syscallnames[] = {
	/*   0 */	"read",
	/*   1 */	"write",
	/*   2 */	"open",
	/*   3 */	"close",
	/*   4 */	"stat64",
	/*   5 */	"fstat64",
	/*   6 */	"lstat64",
	/*   7 */	"poll",
	/*   8 */	"lseek",
	/*   9 */	"mmap",
	/*  10 */	"mprotect",
	/*  11 */	"munmap",
	/*  12 */	"brk",
	/*  13 */	"rt_sigaction",
	/*  14 */	"rt_sigprocmask",
	/*  15 */	"rt_sigreturn",
	/*  16 */	"ioctl",
	/*  17 */	"pread",
	/*  18 */	"pwrite",
	/*  19 */	"readv",
	/*  20 */	"writev",
	/*  21 */	"access",
	/*  22 */	"pipe",
	/*  23 */	"select",
	/*  24 */	"sched_yield",
	/*  25 */	"mremap",
	/*  26 */	"__msync13",
	/*  27 */	"mincore",
	/*  28 */	"madvise",
#ifdef SYSVSHM
	/*  29 */	"shmget",
	/*  30 */	"shmat",
	/*  31 */	"shmctl",
#else
	/*  29 */	"#29 (unimplemented shmget)",
	/*  30 */	"#30 (unimplemented shmat)",
	/*  31 */	"#31 (unimplemented shmctl)",
#endif
	/*  32 */	"dup",
	/*  33 */	"dup2",
	/*  34 */	"pause",
	/*  35 */	"nanosleep",
	/*  36 */	"getitimer",
	/*  37 */	"alarm",
	/*  38 */	"setitimer",
	/*  39 */	"getpid",
	/*  40 */	"#40 (unimplemented sendfile)",
	/*  41 */	"socket",
	/*  42 */	"connect",
	/*  43 */	"oaccept",
	/*  44 */	"sendto",
	/*  45 */	"recvfrom",
	/*  46 */	"sendmsg",
	/*  47 */	"recvmsg",
	/*  48 */	"shutdown",
	/*  49 */	"bind",
	/*  50 */	"listen",
	/*  51 */	"getsockname",
	/*  52 */	"getpeername",
	/*  53 */	"socketpair",
	/*  54 */	"setsockopt",
	/*  55 */	"getsockopt",
	/*  56 */	"clone",
	/*  57 */	"fork",
	/*  58 */	"__vfork14",
	/*  59 */	"execve",
	/*  60 */	"exit",
	/*  61 */	"wait4",
	/*  62 */	"kill",
	/*  63 */	"uname",
#ifdef SYSVSEM
	/*  64 */	"semget",
	/*  65 */	"semop",
	/*  66 */	"semctl",
#else
	/*  64 */	"#64 (unimplemented semget)",
	/*  65 */	"#65 (unimplemented semop)",
	/*  66 */	"#66 (unimplemented semctl)",
#endif
#ifdef SYSVSHM
	/*  67 */	"shmdt",
#else
	/*  67 */	"#67 (unimplemented shmdt)",
#endif
#ifdef SYSVMSG
	/*  68 */	"msgget",
	/*  69 */	"msgsnd",
	/*  70 */	"msgrcv",
	/*  71 */	"msgctl",
#else
	/*  68 */	"#68 (unimplemented msgget)",
	/*  69 */	"#69 (unimplemented msgsnd)",
	/*  70 */	"#70 (unimplemented msgrcv)",
	/*  71 */	"#71 (unimplemented msgctl)",
#endif
	/*  72 */	"fcntl",
	/*  73 */	"flock",
	/*  74 */	"fsync",
	/*  75 */	"fdatasync",
	/*  76 */	"truncate64",
	/*  77 */	"ftruncate64",
	/*  78 */	"getdents",
	/*  79 */	"__getcwd",
	/*  80 */	"chdir",
	/*  81 */	"fchdir",
	/*  82 */	"__posix_rename",
	/*  83 */	"mkdir",
	/*  84 */	"rmdir",
	/*  85 */	"creat",
	/*  86 */	"link",
	/*  87 */	"unlink",
	/*  88 */	"symlink",
	/*  89 */	"readlink",
	/*  90 */	"chmod",
	/*  91 */	"fchmod",
	/*  92 */	"__posix_chown",
	/*  93 */	"__posix_fchown",
	/*  94 */	"__posix_lchown",
	/*  95 */	"umask",
	/*  96 */	"gettimeofday",
	/*  97 */	"getrlimit",
	/*  98 */	"getrusage",
	/*  99 */	"sysinfo",
	/* 100 */	"times",
	/* 101 */	"ptrace",
	/* 102 */	"getuid",
	/* 103 */	"#103 (unimplemented syslog)",
	/* 104 */	"getgid",
	/* 105 */	"setuid",
	/* 106 */	"setgid",
	/* 107 */	"geteuid",
	/* 108 */	"getegid",
	/* 109 */	"setpgid",
	/* 110 */	"getppid",
	/* 111 */	"getpgrp",
	/* 112 */	"setsid",
	/* 113 */	"setreuid",
	/* 114 */	"setregid",
	/* 115 */	"getgroups",
	/* 116 */	"setgroups",
	/* 117 */	"setresuid",
	/* 118 */	"getresuid",
	/* 119 */	"setresgid",
	/* 120 */	"getresgid",
	/* 121 */	"getpgid",
	/* 122 */	"setfsuid",
	/* 123 */	"setfsgid",
	/* 124 */	"getsid",
	/* 125 */	"#125 (unimplemented capget)",
	/* 126 */	"#126 (unimplemented capset)",
	/* 127 */	"rt_sigpending",
	/* 128 */	"#128 (unimplemented rt_sigtimedwait)",
	/* 129 */	"rt_queueinfo",
	/* 130 */	"rt_sigsuspend",
	/* 131 */	"sigaltstack",
	/* 132 */	"utime",
	/* 133 */	"mknod",
#ifdef EXEC_AOUT
	/* 134 */	"uselib",
#else
	/* 134 */	"#134 (unimplemented sys_uselib)",
#endif
	/* 135 */	"personality",
	/* 136 */	"#136 (unimplemented ustat)",
	/* 137 */	"statfs",
	/* 138 */	"fstatfs",
	/* 139 */	"#139 (unimplemented sysfs)",
	/* 140 */	"getpriority",
	/* 141 */	"setpriority",
	/* 142 */	"sched_setparam",
	/* 143 */	"sched_getparam",
	/* 144 */	"sched_setscheduler",
	/* 145 */	"sched_getscheduler",
	/* 146 */	"sched_get_priority_max",
	/* 147 */	"sched_get_priority_min",
	/* 148 */	"#148 (unimplemented sys_sched_rr_get_interval)",
	/* 149 */	"mlock",
	/* 150 */	"munlock",
	/* 151 */	"mlockall",
	/* 152 */	"munlockall",
	/* 153 */	"#153 (unimplemented vhangup)",
	/* 154 */	"modify_ldt",
	/* 155 */	"#155 (unimplemented pivot_root)",
	/* 156 */	"__sysctl",
	/* 157 */	"#157 (unimplemented prctl)",
	/* 158 */	"arch_prctl",
	/* 159 */	"#159 (unimplemented adjtimex)",
	/* 160 */	"setrlimit",
	/* 161 */	"chroot",
	/* 162 */	"sync",
	/* 163 */	"acct",
	/* 164 */	"settimeofday",
	/* 165 */	"#165 (unimplemented mount)",
	/* 166 */	"#166 (unimplemented umount2)",
	/* 167 */	"swapon",
	/* 168 */	"swapoff",
	/* 169 */	"reboot",
	/* 170 */	"sethostname",
	/* 171 */	"setdomainname",
	/* 172 */	"iopl",
	/* 173 */	"ioperm",
	/* 174 */	"#174 (unimplemented create_module)",
	/* 175 */	"#175 (unimplemented init_module)",
	/* 176 */	"#176 (unimplemented delete_module)",
	/* 177 */	"#177 (unimplemented get_kernel_syms)",
	/* 178 */	"#178 (unimplemented query_module)",
	/* 179 */	"#179 (unimplemented quotactl)",
	/* 180 */	"#180 (unimplemented nfsservctl)",
	/* 181 */	"#181 (unimplemented getpmsg)",
	/* 182 */	"#182 (unimplemented putpmsg)",
	/* 183 */	"#183 (unimplemented afs_syscall)",
	/* 184 */	"#184 (unimplemented tuxcall)",
	/* 185 */	"#185 (unimplemented security)",
	/* 186 */	"gettid",
	/* 187 */	"#187 (unimplemented readahead)",
	/* 188 */	"setxattr",
	/* 189 */	"lsetxattr",
	/* 190 */	"fsetxattr",
	/* 191 */	"getxattr",
	/* 192 */	"lgetxattr",
	/* 193 */	"fgetxattr",
	/* 194 */	"listxattr",
	/* 195 */	"llistxattr",
	/* 196 */	"flistxattr",
	/* 197 */	"removexattr",
	/* 198 */	"lremovexattr",
	/* 199 */	"fremovexattr",
	/* 200 */	"tkill",
	/* 201 */	"time",
	/* 202 */	"futex",
	/* 203 */	"sched_setaffinity",
	/* 204 */	"sched_getaffinity",
	/* 205 */	"#205 (unimplemented set_thread_area)",
	/* 206 */	"#206 (unimplemented io_setup)",
	/* 207 */	"#207 (unimplemented io_destroy)",
	/* 208 */	"#208 (unimplemented io_getevents)",
	/* 209 */	"#209 (unimplemented io_submit)",
	/* 210 */	"#210 (unimplemented io_cancel)",
	/* 211 */	"#211 (unimplemented get_thread_area)",
	/* 212 */	"#212 (unimplemented lookup_dcookie)",
	/* 213 */	"#213 (unimplemented epoll_create)",
	/* 214 */	"#214 (unimplemented epoll_ctl_old)",
	/* 215 */	"#215 (unimplemented epoll_wait_old)",
	/* 216 */	"#216 (unimplemented remap_file_pages)",
	/* 217 */	"getdents64",
	/* 218 */	"set_tid_address",
	/* 219 */	"#219 (unimplemented restart_syscall)",
	/* 220 */	"#220 (unimplemented semtimedop)",
	/* 221 */	"#221 (unimplemented fadvise64)",
	/* 222 */	"#222 (unimplemented timer_create)",
	/* 223 */	"#223 (unimplemented timer_settime)",
	/* 224 */	"#224 (unimplemented timer_gettime)",
	/* 225 */	"#225 (unimplemented timer_getoverrun)",
	/* 226 */	"#226 (unimplemented timer_delete)",
	/* 227 */	"clock_settime",
	/* 228 */	"clock_gettime",
	/* 229 */	"clock_getres",
	/* 230 */	"clock_nanosleep",
	/* 231 */	"exit_group",
	/* 232 */	"#232 (unimplemented epoll_wait)",
	/* 233 */	"#233 (unimplemented epoll_ctl)",
	/* 234 */	"tgkill",
	/* 235 */	"#235 (unimplemented utimes)",
	/* 236 */	"#236 (unimplemented vserver)",
	/* 237 */	"#237 (unimplemented mbind)",
	/* 238 */	"#238 (unimplemented set_mempolicy)",
	/* 239 */	"#239 (unimplemented get_mempolicy)",
	/* 240 */	"#240 (unimplemented mq_open)",
	/* 241 */	"#241 (unimplemented mq_unlink)",
	/* 242 */	"#242 (unimplemented mq_timedsend)",
	/* 243 */	"#243 (unimplemented mq_timedreceive)",
	/* 244 */	"#244 (unimplemented mq_notify)",
	/* 245 */	"#245 (unimplemented mq_getsetattr)",
	/* 246 */	"#246 (unimplemented kexec_load)",
	/* 247 */	"#247 (unimplemented waitid)",
	/* 248 */	"#248 (unimplemented add_key)",
	/* 249 */	"#249 (unimplemented request_key)",
	/* 250 */	"#250 (unimplemented keyctl)",
	/* 251 */	"#251 (unimplemented ioprio_set)",
	/* 252 */	"#252 (unimplemented ioprio_get)",
	/* 253 */	"#253 (unimplemented inotify_init)",
	/* 254 */	"#254 (unimplemented inotify_add_watch)",
	/* 255 */	"#255 (unimplemented inotify_rm_watch)",
	/* 256 */	"#256 (unimplemented migrate_pages)",
	/* 257 */	"#257 (unimplemented openat)",
	/* 258 */	"#258 (unimplemented mkdirat)",
	/* 259 */	"#259 (unimplemented mknodat)",
	/* 260 */	"#260 (unimplemented fchownat)",
	/* 261 */	"#261 (unimplemented futimesat)",
	/* 262 */	"#262 (unimplemented newfstatat)",
	/* 263 */	"#263 (unimplemented unlinkat)",
	/* 264 */	"#264 (unimplemented renameat)",
	/* 265 */	"#265 (unimplemented linkat)",
	/* 266 */	"#266 (unimplemented symlinkat)",
	/* 267 */	"#267 (unimplemented readlinkat)",
	/* 268 */	"#268 (unimplemented fchmodat)",
	/* 269 */	"#269 (unimplemented faccessat)",
	/* 270 */	"#270 (unimplemented pselect6)",
	/* 271 */	"#271 (unimplemented ppoll)",
	/* 272 */	"#272 (unimplemented unshare)",
	/* 273 */	"set_robust_list",
	/* 274 */	"get_robust_list",
	/* 275 */	"#275 (unimplemented splice)",
	/* 276 */	"#276 (unimplemented tee)",
	/* 277 */	"#277 (unimplemented sync_file_range)",
	/* 278 */	"#278 (unimplemented vmsplice)",
	/* 279 */	"#279 (unimplemented move_pages)",
	/* 280 */	"#280 (unimplemented utimensat)",
	/* 281 */	"#281 (unimplemented epoll_pwait)",
	/* 282 */	"#282 (unimplemented signalfd)",
	/* 283 */	"#283 (unimplemented timerfd_create)",
	/* 284 */	"#284 (unimplemented eventfd)",
	/* 285 */	"#285 (unimplemented fallocate)",
	/* 286 */	"#286 (unimplemented timerfd_settime)",
	/* 287 */	"#287 (unimplemented timerfd_gettime)",
	/* 288 */	"#288 (unimplemented accept4)",
	/* 289 */	"#289 (unimplemented signalfd4)",
	/* 290 */	"#290 (unimplemented eventfd2)",
	/* 291 */	"#291 (unimplemented epoll_create1)",
	/* 292 */	"#292 (unimplemented dup3)",
	/* 293 */	"#293 (unimplemented pipe2)",
	/* 294 */	"#294 (unimplemented inotify_init1)",
	/* 295 */	"#295 (unimplemented preadv)",
	/* 296 */	"#296 (unimplemented pwritev)",
	/* 297 */	"#297 (unimplemented rt_tgsigqueueinfo)",
	/* 298 */	"#298 (unimplemented perf_counter_open)",
	/* 299 */	"#299 (unimplemented recvmmsg)",
	/* 300 */	"nosys",
};
