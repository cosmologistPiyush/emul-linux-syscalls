/* $NetBSD: netbsd32_syscalls.c,v 1.60 2006/09/01 21:19:45 matt Exp $ */

/*
 * System call names.
 *
 * DO NOT EDIT-- this file is automatically generated.
 * created from	NetBSD: syscalls.master,v 1.53 2006/09/01 20:58:18 matt Exp
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: netbsd32_syscalls.c,v 1.60 2006/09/01 21:19:45 matt Exp $");

#if defined(_KERNEL_OPT)
#if defined(_KERNEL_OPT)
#include "opt_ktrace.h"
#include "opt_nfsserver.h"
#include "opt_compat_netbsd.h"
#include "opt_ntp.h"
#include "opt_sysv.h"
#include "opt_compat_43.h"
#include "opt_posix.h"
#include "fs_lfs.h"
#include "fs_nfs.h"
#endif
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/signal.h>
#include <sys/mount.h>
#include <sys/sa.h>
#include <sys/syscallargs.h>
#include <compat/netbsd32/netbsd32.h>
#include <compat/netbsd32/netbsd32_syscallargs.h>
#endif /* _KERNEL_OPT */

const char *const netbsd32_syscallnames[] = {
	"syscall",			/* 0 = syscall */
	"netbsd32_exit",			/* 1 = netbsd32_exit */
	"fork",			/* 2 = fork */
	"netbsd32_read",			/* 3 = netbsd32_read */
	"netbsd32_write",			/* 4 = netbsd32_write */
	"netbsd32_open",			/* 5 = netbsd32_open */
	"netbsd32_close",			/* 6 = netbsd32_close */
	"netbsd32_wait4",			/* 7 = netbsd32_wait4 */
	"compat_43_netbsd32_ocreat",	/* 8 = compat_43 netbsd32_ocreat */
	"netbsd32_link",			/* 9 = netbsd32_link */
	"netbsd32_unlink",			/* 10 = netbsd32_unlink */
	"#11 (obsolete execv)",		/* 11 = obsolete execv */
	"netbsd32_chdir",			/* 12 = netbsd32_chdir */
	"netbsd32_fchdir",			/* 13 = netbsd32_fchdir */
	"netbsd32_mknod",			/* 14 = netbsd32_mknod */
	"netbsd32_chmod",			/* 15 = netbsd32_chmod */
	"netbsd32_chown",			/* 16 = netbsd32_chown */
	"netbsd32_break",			/* 17 = netbsd32_break */
	"compat_20_netbsd32_getfsstat",	/* 18 = compat_20 netbsd32_getfsstat */
	"compat_43_netbsd32_olseek",	/* 19 = compat_43 netbsd32_olseek */
	"getpid",			/* 20 = getpid */
	"netbsd32_mount",			/* 21 = netbsd32_mount */
	"netbsd32_unmount",			/* 22 = netbsd32_unmount */
	"netbsd32_setuid",			/* 23 = netbsd32_setuid */
	"getuid",			/* 24 = getuid */
	"geteuid",			/* 25 = geteuid */
	"netbsd32_ptrace",			/* 26 = netbsd32_ptrace */
	"netbsd32_recvmsg",			/* 27 = netbsd32_recvmsg */
	"netbsd32_sendmsg",			/* 28 = netbsd32_sendmsg */
	"netbsd32_recvfrom",			/* 29 = netbsd32_recvfrom */
	"netbsd32_accept",			/* 30 = netbsd32_accept */
	"netbsd32_getpeername",			/* 31 = netbsd32_getpeername */
	"netbsd32_getsockname",			/* 32 = netbsd32_getsockname */
	"netbsd32_access",			/* 33 = netbsd32_access */
	"netbsd32_chflags",			/* 34 = netbsd32_chflags */
	"netbsd32_fchflags",			/* 35 = netbsd32_fchflags */
	"sync",			/* 36 = sync */
	"netbsd32_kill",			/* 37 = netbsd32_kill */
	"compat_43_netbsd32_stat43",	/* 38 = compat_43 netbsd32_stat43 */
	"getppid",			/* 39 = getppid */
	"compat_43_netbsd32_lstat43",	/* 40 = compat_43 netbsd32_lstat43 */
	"netbsd32_dup",			/* 41 = netbsd32_dup */
	"pipe",			/* 42 = pipe */
	"getegid",			/* 43 = getegid */
	"netbsd32_profil",			/* 44 = netbsd32_profil */
#if defined(KTRACE) || !defined(_KERNEL)
	"netbsd32_ktrace",			/* 45 = netbsd32_ktrace */
#else
	"#45 (excluded netbsd32_ktrace)",		/* 45 = excluded netbsd32_ktrace */
#endif
	"netbsd32_sigaction",			/* 46 = netbsd32_sigaction */
	"getgid",			/* 47 = getgid */
	"compat_13_sigprocmask13",	/* 48 = compat_13 sigprocmask13 */
	"netbsd32___getlogin",			/* 49 = netbsd32___getlogin */
	"netbsd32_setlogin",			/* 50 = netbsd32_setlogin */
	"netbsd32_acct",			/* 51 = netbsd32_acct */
	"compat_13_sigpending13",	/* 52 = compat_13 sigpending13 */
	"compat_13_netbsd32_sigaltstack13",	/* 53 = compat_13 netbsd32_sigaltstack13 */
	"netbsd32_ioctl",			/* 54 = netbsd32_ioctl */
	"compat_12_netbsd32_reboot",	/* 55 = compat_12 netbsd32_reboot */
	"netbsd32_revoke",			/* 56 = netbsd32_revoke */
	"netbsd32_symlink",			/* 57 = netbsd32_symlink */
	"netbsd32_readlink",			/* 58 = netbsd32_readlink */
	"netbsd32_execve",			/* 59 = netbsd32_execve */
	"netbsd32_umask",			/* 60 = netbsd32_umask */
	"netbsd32_chroot",			/* 61 = netbsd32_chroot */
	"compat_43_netbsd32_fstat43",	/* 62 = compat_43 netbsd32_fstat43 */
	"compat_43_netbsd32_ogetkerninfo",	/* 63 = compat_43 netbsd32_ogetkerninfo */
	"compat_43_ogetpagesize",	/* 64 = compat_43 ogetpagesize */
	"compat_12_netbsd32_msync",	/* 65 = compat_12 netbsd32_msync */
	"vfork",			/* 66 = vfork */
	"#67 (obsolete vread)",		/* 67 = obsolete vread */
	"#68 (obsolete vwrite)",		/* 68 = obsolete vwrite */
	"netbsd32_sbrk",			/* 69 = netbsd32_sbrk */
	"netbsd32_sstk",			/* 70 = netbsd32_sstk */
	"compat_43_netbsd32_ommap",	/* 71 = compat_43 netbsd32_ommap */
	"vadvise",			/* 72 = vadvise */
	"netbsd32_munmap",			/* 73 = netbsd32_munmap */
	"netbsd32_mprotect",			/* 74 = netbsd32_mprotect */
	"netbsd32_madvise",			/* 75 = netbsd32_madvise */
	"#76 (obsolete vhangup)",		/* 76 = obsolete vhangup */
	"#77 (obsolete vlimit)",		/* 77 = obsolete vlimit */
	"netbsd32_mincore",			/* 78 = netbsd32_mincore */
	"netbsd32_getgroups",			/* 79 = netbsd32_getgroups */
	"netbsd32_setgroups",			/* 80 = netbsd32_setgroups */
	"getpgrp",			/* 81 = getpgrp */
	"netbsd32_setpgid",			/* 82 = netbsd32_setpgid */
	"netbsd32_setitimer",			/* 83 = netbsd32_setitimer */
	"compat_43_owait",	/* 84 = compat_43 owait */
	"compat_12_netbsd32_oswapon",	/* 85 = compat_12 netbsd32_oswapon */
	"netbsd32_getitimer",			/* 86 = netbsd32_getitimer */
	"compat_43_netbsd32_ogethostname",	/* 87 = compat_43 netbsd32_ogethostname */
	"compat_43_netbsd32_osethostname",	/* 88 = compat_43 netbsd32_osethostname */
	"compat_43_ogetdtablesize",	/* 89 = compat_43 ogetdtablesize */
	"netbsd32_dup2",			/* 90 = netbsd32_dup2 */
	"#91 (unimplemented getdopt)",		/* 91 = unimplemented getdopt */
	"netbsd32_fcntl",			/* 92 = netbsd32_fcntl */
	"netbsd32_select",			/* 93 = netbsd32_select */
	"#94 (unimplemented setdopt)",		/* 94 = unimplemented setdopt */
	"netbsd32_fsync",			/* 95 = netbsd32_fsync */
	"netbsd32_setpriority",			/* 96 = netbsd32_setpriority */
	"compat_30_netbsd32_socket",	/* 97 = compat_30 netbsd32_socket */
	"netbsd32_connect",			/* 98 = netbsd32_connect */
	"compat_43_netbsd32_oaccept",	/* 99 = compat_43 netbsd32_oaccept */
	"netbsd32_getpriority",			/* 100 = netbsd32_getpriority */
	"compat_43_netbsd32_osend",	/* 101 = compat_43 netbsd32_osend */
	"compat_43_netbsd32_orecv",	/* 102 = compat_43 netbsd32_orecv */
	"compat_13_sigreturn13",	/* 103 = compat_13 sigreturn13 */
	"netbsd32_bind",			/* 104 = netbsd32_bind */
	"netbsd32_setsockopt",			/* 105 = netbsd32_setsockopt */
	"netbsd32_listen",			/* 106 = netbsd32_listen */
	"#107 (obsolete vtimes)",		/* 107 = obsolete vtimes */
	"compat_43_netbsd32_osigvec",	/* 108 = compat_43 netbsd32_osigvec */
#if defined(COMPAT_43) || defined(COMPAT_SUNOS)
	"compat_43_netbsd32_sigblock",	/* 109 = compat_43 netbsd32_sigblock */
	"compat_43_netbsd32_sigsetmask",	/* 110 = compat_43 netbsd32_sigsetmask */
#else
	"#109 (obsolete sigblock)",		/* 109 = obsolete sigblock */
	"#110 (obsolete sigsetmask)",		/* 110 = obsolete sigsetmask */
#endif
	"compat_13_sigsuspend13",	/* 111 = compat_13 sigsuspend13 */
	"compat_43_netbsd32_osigstack",	/* 112 = compat_43 netbsd32_osigstack */
	"compat_43_netbsd32_orecvmsg",	/* 113 = compat_43 netbsd32_orecvmsg */
	"compat_43_netbsd32_osendmsg",	/* 114 = compat_43 netbsd32_osendmsg */
	"#115 (obsolete vtrace)",		/* 115 = obsolete vtrace */
	"netbsd32_gettimeofday",			/* 116 = netbsd32_gettimeofday */
	"netbsd32_getrusage",			/* 117 = netbsd32_getrusage */
	"netbsd32_getsockopt",			/* 118 = netbsd32_getsockopt */
	"#119 (obsolete resuba)",		/* 119 = obsolete resuba */
	"netbsd32_readv",			/* 120 = netbsd32_readv */
	"netbsd32_writev",			/* 121 = netbsd32_writev */
	"netbsd32_settimeofday",			/* 122 = netbsd32_settimeofday */
	"netbsd32_fchown",			/* 123 = netbsd32_fchown */
	"netbsd32_fchmod",			/* 124 = netbsd32_fchmod */
	"compat_43_netbsd32_orecvfrom",	/* 125 = compat_43 netbsd32_orecvfrom */
	"netbsd32_setreuid",			/* 126 = netbsd32_setreuid */
	"netbsd32_setregid",			/* 127 = netbsd32_setregid */
	"netbsd32_rename",			/* 128 = netbsd32_rename */
	"compat_43_netbsd32_otruncate",	/* 129 = compat_43 netbsd32_otruncate */
	"compat_43_netbsd32_oftruncate",	/* 130 = compat_43 netbsd32_oftruncate */
	"netbsd32_flock",			/* 131 = netbsd32_flock */
	"netbsd32_mkfifo",			/* 132 = netbsd32_mkfifo */
	"netbsd32_sendto",			/* 133 = netbsd32_sendto */
	"netbsd32_shutdown",			/* 134 = netbsd32_shutdown */
	"netbsd32_socketpair",			/* 135 = netbsd32_socketpair */
	"netbsd32_mkdir",			/* 136 = netbsd32_mkdir */
	"netbsd32_rmdir",			/* 137 = netbsd32_rmdir */
	"netbsd32_utimes",			/* 138 = netbsd32_utimes */
	"#139 (obsolete 4.2 sigreturn)",		/* 139 = obsolete 4.2 sigreturn */
	"netbsd32_adjtime",			/* 140 = netbsd32_adjtime */
	"compat_43_netbsd32_ogetpeername",	/* 141 = compat_43 netbsd32_ogetpeername */
	"compat_43_ogethostid",	/* 142 = compat_43 ogethostid */
#if defined(COMPAT_43) || defined(COMPAT_SUNOS)
	"compat_43_netbsd32_sethostid",	/* 143 = compat_43 netbsd32_sethostid */
#else
	"#143 (obsolete sethostid)",		/* 143 = obsolete sethostid */
#endif
	"compat_43_netbsd32_ogetrlimit",	/* 144 = compat_43 netbsd32_ogetrlimit */
	"compat_43_netbsd32_osetrlimit",	/* 145 = compat_43 netbsd32_osetrlimit */
#if defined(COMPAT_43) || defined(COMPAT_SUNOS)
	"compat_43_netbsd32_killpg",	/* 146 = compat_43 netbsd32_killpg */
#else
	"#146 (obsolete killpg)",		/* 146 = obsolete killpg */
#endif
	"setsid",			/* 147 = setsid */
	"netbsd32_quotactl",			/* 148 = netbsd32_quotactl */
	"compat_43_oquota",	/* 149 = compat_43 oquota */
	"compat_43_netbsd32_ogetsockname",	/* 150 = compat_43 netbsd32_ogetsockname */
	"#151 (unimplemented)",		/* 151 = unimplemented */
	"#152 (unimplemented)",		/* 152 = unimplemented */
	"#153 (unimplemented)",		/* 153 = unimplemented */
	"#154 (unimplemented)",		/* 154 = unimplemented */
#if defined(NFS) || defined(NFSSERVER) || !defined(_KERNEL)
	"netbsd32_nfssvc",			/* 155 = netbsd32_nfssvc */
#else
	"#155 (excluded netbsd32_nfssvc)",		/* 155 = excluded netbsd32_nfssvc */
#endif
	"compat_43_netbsd32_ogetdirentries",	/* 156 = compat_43 netbsd32_ogetdirentries */
	"compat_20_netbsd32_statfs",	/* 157 = compat_20 netbsd32_statfs */
	"compat_20_netbsd32_fstatfs",	/* 158 = compat_20 netbsd32_fstatfs */
	"#159 (unimplemented)",		/* 159 = unimplemented */
	"#160 (unimplemented)",		/* 160 = unimplemented */
	"compat_30_netbsd32_getfh",	/* 161 = compat_30 netbsd32_getfh */
	"compat_09_netbsd32_ogetdomainname",	/* 162 = compat_09 netbsd32_ogetdomainname */
	"compat_09_netbsd32_osetdomainname",	/* 163 = compat_09 netbsd32_osetdomainname */
	"compat_09_netbsd32_uname",	/* 164 = compat_09 netbsd32_uname */
	"netbsd32_sysarch",			/* 165 = netbsd32_sysarch */
	"#166 (unimplemented)",		/* 166 = unimplemented */
	"#167 (unimplemented)",		/* 167 = unimplemented */
	"#168 (unimplemented)",		/* 168 = unimplemented */
#if defined(SYSVSEM) || !defined(_KERNEL)
	"compat_10_osemsys",	/* 169 = compat_10 osemsys */
#else
	"#169 (excluded netbsd32_sys_semsys)",		/* 169 = excluded netbsd32_sys_semsys */
#endif
#if defined(SYSVMSG) || !defined(_KERNEL)
	"compat_10_omsgsys",	/* 170 = compat_10 omsgsys */
#else
	"#170 (excluded netbsd32_sys_msgsys)",		/* 170 = excluded netbsd32_sys_msgsys */
#endif
#if defined(SYSVSHM) || !defined(_KERNEL)
	"compat_10_oshmsys",	/* 171 = compat_10 oshmsys */
#else
	"#171 (excluded netbsd32_sys_shmsys)",		/* 171 = excluded netbsd32_sys_shmsys */
#endif
	"#172 (unimplemented)",		/* 172 = unimplemented */
	"netbsd32_pread",			/* 173 = netbsd32_pread */
	"netbsd32_pwrite",			/* 174 = netbsd32_pwrite */
	"compat_30_netbsd32_ntp_gettime",	/* 175 = compat_30 netbsd32_ntp_gettime */
	"netbsd32_ntp_adjtime",			/* 176 = netbsd32_ntp_adjtime */
	"#177 (unimplemented)",		/* 177 = unimplemented */
	"#178 (unimplemented)",		/* 178 = unimplemented */
	"#179 (unimplemented)",		/* 179 = unimplemented */
	"#180 (unimplemented)",		/* 180 = unimplemented */
	"netbsd32_setgid",			/* 181 = netbsd32_setgid */
	"netbsd32_setegid",			/* 182 = netbsd32_setegid */
	"netbsd32_seteuid",			/* 183 = netbsd32_seteuid */
#if defined(LFS) || !defined(_KERNEL)
	"lfs_bmapv",			/* 184 = lfs_bmapv */
	"lfs_markv",			/* 185 = lfs_markv */
	"lfs_segclean",			/* 186 = lfs_segclean */
	"lfs_segwait",			/* 187 = lfs_segwait */
#else
	"#184 (excluded netbsd32_sys_lfs_bmapv)",		/* 184 = excluded netbsd32_sys_lfs_bmapv */
	"#185 (excluded netbsd32_sys_lfs_markv)",		/* 185 = excluded netbsd32_sys_lfs_markv */
	"#186 (excluded netbsd32_sys_lfs_segclean)",		/* 186 = excluded netbsd32_sys_lfs_segclean */
	"#187 (excluded netbsd32_sys_lfs_segwait)",		/* 187 = excluded netbsd32_sys_lfs_segwait */
#endif
	"compat_12_netbsd32_stat12",	/* 188 = compat_12 netbsd32_stat12 */
	"compat_12_netbsd32_fstat12",	/* 189 = compat_12 netbsd32_fstat12 */
	"compat_12_netbsd32_lstat12",	/* 190 = compat_12 netbsd32_lstat12 */
	"netbsd32_pathconf",			/* 191 = netbsd32_pathconf */
	"netbsd32_fpathconf",			/* 192 = netbsd32_fpathconf */
	"#193 (unimplemented)",		/* 193 = unimplemented */
	"netbsd32_getrlimit",			/* 194 = netbsd32_getrlimit */
	"netbsd32_setrlimit",			/* 195 = netbsd32_setrlimit */
	"compat_12_netbsd32_getdirentries",	/* 196 = compat_12 netbsd32_getdirentries */
	"netbsd32_mmap",			/* 197 = netbsd32_mmap */
	"__syscall",			/* 198 = __syscall */
	"netbsd32_lseek",			/* 199 = netbsd32_lseek */
	"netbsd32_truncate",			/* 200 = netbsd32_truncate */
	"netbsd32_ftruncate",			/* 201 = netbsd32_ftruncate */
	"netbsd32___sysctl",			/* 202 = netbsd32___sysctl */
	"netbsd32_mlock",			/* 203 = netbsd32_mlock */
	"netbsd32_munlock",			/* 204 = netbsd32_munlock */
	"netbsd32_undelete",			/* 205 = netbsd32_undelete */
	"netbsd32_futimes",			/* 206 = netbsd32_futimes */
	"netbsd32_getpgid",			/* 207 = netbsd32_getpgid */
	"netbsd32_reboot",			/* 208 = netbsd32_reboot */
	"netbsd32_poll",			/* 209 = netbsd32_poll */
#if defined(LKM) || !defined(_KERNEL)
	"lkmnosys",			/* 210 = lkmnosys */
	"lkmnosys",			/* 211 = lkmnosys */
	"lkmnosys",			/* 212 = lkmnosys */
	"lkmnosys",			/* 213 = lkmnosys */
	"lkmnosys",			/* 214 = lkmnosys */
	"lkmnosys",			/* 215 = lkmnosys */
	"lkmnosys",			/* 216 = lkmnosys */
	"lkmnosys",			/* 217 = lkmnosys */
	"lkmnosys",			/* 218 = lkmnosys */
	"lkmnosys",			/* 219 = lkmnosys */
#else	/* !LKM || !_KERNEL */
	"#210 (excluded lkmnosys)",		/* 210 = excluded lkmnosys */
	"#211 (excluded lkmnosys)",		/* 211 = excluded lkmnosys */
	"#212 (excluded lkmnosys)",		/* 212 = excluded lkmnosys */
	"#213 (excluded lkmnosys)",		/* 213 = excluded lkmnosys */
	"#214 (excluded lkmnosys)",		/* 214 = excluded lkmnosys */
	"#215 (excluded lkmnosys)",		/* 215 = excluded lkmnosys */
	"#216 (excluded lkmnosys)",		/* 216 = excluded lkmnosys */
	"#217 (excluded lkmnosys)",		/* 217 = excluded lkmnosys */
	"#218 (excluded lkmnosys)",		/* 218 = excluded lkmnosys */
	"#219 (excluded lkmnosys)",		/* 219 = excluded lkmnosys */
#endif	/* !LKM || !_KERNEL */
#if defined(SYSVSEM) || !defined(_KERNEL)
	"compat_14_netbsd32___semctl",	/* 220 = compat_14 netbsd32___semctl */
	"netbsd32_semget",			/* 221 = netbsd32_semget */
	"netbsd32_semop",			/* 222 = netbsd32_semop */
	"netbsd32_semconfig",			/* 223 = netbsd32_semconfig */
#else
	"#220 (excluded compat_14_netbsd32_semctl)",		/* 220 = excluded compat_14_netbsd32_semctl */
	"#221 (excluded netbsd32_semget)",		/* 221 = excluded netbsd32_semget */
	"#222 (excluded netbsd32_semop)",		/* 222 = excluded netbsd32_semop */
	"#223 (excluded netbsd32_semconfig)",		/* 223 = excluded netbsd32_semconfig */
#endif
#if defined(SYSVMSG) || !defined(_KERNEL)
	"compat_14_netbsd32_msgctl",	/* 224 = compat_14 netbsd32_msgctl */
	"netbsd32_msgget",			/* 225 = netbsd32_msgget */
	"netbsd32_msgsnd",			/* 226 = netbsd32_msgsnd */
	"netbsd32_msgrcv",			/* 227 = netbsd32_msgrcv */
#else
	"#224 (excluded compat_14_netbsd32_msgctl)",		/* 224 = excluded compat_14_netbsd32_msgctl */
	"#225 (excluded netbsd32_msgget)",		/* 225 = excluded netbsd32_msgget */
	"#226 (excluded netbsd32_msgsnd)",		/* 226 = excluded netbsd32_msgsnd */
	"#227 (excluded netbsd32_msgrcv)",		/* 227 = excluded netbsd32_msgrcv */
#endif
#if defined(SYSVSHM) || !defined(_KERNEL)
	"netbsd32_shmat",			/* 228 = netbsd32_shmat */
	"compat_14_netbsd32_shmctl",	/* 229 = compat_14 netbsd32_shmctl */
	"netbsd32_shmdt",			/* 230 = netbsd32_shmdt */
	"netbsd32_shmget",			/* 231 = netbsd32_shmget */
#else
	"#228 (excluded netbsd32_shmat)",		/* 228 = excluded netbsd32_shmat */
	"#229 (excluded compat_14_netbsd32_shmctl)",		/* 229 = excluded compat_14_netbsd32_shmctl */
	"#230 (excluded netbsd32_shmdt)",		/* 230 = excluded netbsd32_shmdt */
	"#231 (excluded netbsd32_shmget)",		/* 231 = excluded netbsd32_shmget */
#endif
	"netbsd32_clock_gettime",			/* 232 = netbsd32_clock_gettime */
	"netbsd32_clock_settime",			/* 233 = netbsd32_clock_settime */
	"netbsd32_clock_getres",			/* 234 = netbsd32_clock_getres */
	"netbsd32_timer_create",			/* 235 = netbsd32_timer_create */
	"netbsd32_timer_delete",			/* 236 = netbsd32_timer_delete */
	"netbsd32_timer_settime",			/* 237 = netbsd32_timer_settime */
	"netbsd32_timer_gettime",			/* 238 = netbsd32_timer_gettime */
	"netbsd32_timer_getoverrun",			/* 239 = netbsd32_timer_getoverrun */
	"netbsd32_nanosleep",			/* 240 = netbsd32_nanosleep */
	"netbsd32_fdatasync",			/* 241 = netbsd32_fdatasync */
	"netbsd32_mlockall",			/* 242 = netbsd32_mlockall */
	"munlockall",			/* 243 = munlockall */
	"netbsd32___sigtimedwait",			/* 244 = netbsd32___sigtimedwait */
	"#245 (unimplemented)",		/* 245 = unimplemented */
	"#246 (unimplemented)",		/* 246 = unimplemented */
#if defined(P1003_1B_SEMAPHORE) || (!defined(_KERNEL) && defined(_LIBC))
	"netbsd32__ksem_init",			/* 247 = netbsd32__ksem_init */
	"netbsd32__ksem_open",			/* 248 = netbsd32__ksem_open */
	"netbsd32__ksem_unlink",			/* 249 = netbsd32__ksem_unlink */
	"netbsd32__ksem_close",			/* 250 = netbsd32__ksem_close */
	"netbsd32__ksem_post",			/* 251 = netbsd32__ksem_post */
	"netbsd32__ksem_wait",			/* 252 = netbsd32__ksem_wait */
	"netbsd32__ksem_trywait",			/* 253 = netbsd32__ksem_trywait */
	"netbsd32__ksem_getvalue",			/* 254 = netbsd32__ksem_getvalue */
	"netbsd32__ksem_destroy",			/* 255 = netbsd32__ksem_destroy */
	"#256 (unimplemented sys__ksem_timedwait)",		/* 256 = unimplemented sys__ksem_timedwait */
#else
	"#247 (excluded sys__ksem_init)",		/* 247 = excluded sys__ksem_init */
	"#248 (excluded sys__ksem_open)",		/* 248 = excluded sys__ksem_open */
	"#249 (excluded sys__ksem_unlink)",		/* 249 = excluded sys__ksem_unlink */
	"#250 (excluded sys__ksem_close)",		/* 250 = excluded sys__ksem_close */
	"#251 (excluded sys__ksem_post)",		/* 251 = excluded sys__ksem_post */
	"#252 (excluded sys__ksem_wait)",		/* 252 = excluded sys__ksem_wait */
	"#253 (excluded sys__ksem_trywait)",		/* 253 = excluded sys__ksem_trywait */
	"#254 (excluded sys__ksem_getvalue)",		/* 254 = excluded sys__ksem_getvalue */
	"#255 (excluded sys__ksem_destroy)",		/* 255 = excluded sys__ksem_destroy */
	"#256 (unimplemented sys__ksem_timedwait)",		/* 256 = unimplemented sys__ksem_timedwait */
#endif
	"#257 (unimplemented)",		/* 257 = unimplemented */
	"#258 (unimplemented)",		/* 258 = unimplemented */
	"#259 (unimplemented)",		/* 259 = unimplemented */
	"#260 (unimplemented)",		/* 260 = unimplemented */
	"#261 (unimplemented)",		/* 261 = unimplemented */
	"#262 (unimplemented)",		/* 262 = unimplemented */
	"#263 (unimplemented)",		/* 263 = unimplemented */
	"#264 (unimplemented)",		/* 264 = unimplemented */
	"#265 (unimplemented)",		/* 265 = unimplemented */
	"#266 (unimplemented)",		/* 266 = unimplemented */
	"#267 (unimplemented)",		/* 267 = unimplemented */
	"#268 (unimplemented)",		/* 268 = unimplemented */
	"#269 (unimplemented)",		/* 269 = unimplemented */
	"netbsd32___posix_rename",			/* 270 = netbsd32___posix_rename */
	"netbsd32_swapctl",			/* 271 = netbsd32_swapctl */
	"netbsd32_getdents",			/* 272 = netbsd32_getdents */
	"netbsd32_minherit",			/* 273 = netbsd32_minherit */
	"netbsd32_lchmod",			/* 274 = netbsd32_lchmod */
	"netbsd32_lchown",			/* 275 = netbsd32_lchown */
	"netbsd32_lutimes",			/* 276 = netbsd32_lutimes */
	"netbsd32___msync13",			/* 277 = netbsd32___msync13 */
	"netbsd32___stat13",			/* 278 = netbsd32___stat13 */
	"netbsd32___fstat13",			/* 279 = netbsd32___fstat13 */
	"netbsd32___lstat13",			/* 280 = netbsd32___lstat13 */
	"netbsd32___sigaltstack14",			/* 281 = netbsd32___sigaltstack14 */
	"__vfork14",			/* 282 = __vfork14 */
	"netbsd32___posix_chown",			/* 283 = netbsd32___posix_chown */
	"netbsd32___posix_fchown",			/* 284 = netbsd32___posix_fchown */
	"netbsd32___posix_lchown",			/* 285 = netbsd32___posix_lchown */
	"netbsd32_getsid",			/* 286 = netbsd32_getsid */
	"netbsd32___clone",			/* 287 = netbsd32___clone */
#if defined(KTRACE) || !defined(_KERNEL)
	"netbsd32_fktrace",			/* 288 = netbsd32_fktrace */
#else
	"#288 (excluded netbsd32_fktrace)",		/* 288 = excluded netbsd32_fktrace */
#endif
	"netbsd32_preadv",			/* 289 = netbsd32_preadv */
	"netbsd32_pwritev",			/* 290 = netbsd32_pwritev */
	"netbsd32___sigaction14",			/* 291 = netbsd32___sigaction14 */
	"netbsd32___sigpending14",			/* 292 = netbsd32___sigpending14 */
	"netbsd32___sigprocmask14",			/* 293 = netbsd32___sigprocmask14 */
	"netbsd32___sigsuspend14",			/* 294 = netbsd32___sigsuspend14 */
	"compat_16_netbsd32___sigreturn14",	/* 295 = compat_16 netbsd32___sigreturn14 */
	"netbsd32___getcwd",			/* 296 = netbsd32___getcwd */
	"netbsd32_fchroot",			/* 297 = netbsd32_fchroot */
	"compat_30_netbsd32_fhopen",	/* 298 = compat_30 netbsd32_fhopen */
	"compat_30_netbsd32_fhstat",	/* 299 = compat_30 netbsd32_fhstat */
	"compat_20_netbsd32_fhstatfs",	/* 300 = compat_20 netbsd32_fhstatfs */
#if defined(SYSVSEM) || !defined(_KERNEL)
	"netbsd32___semctl14",			/* 301 = netbsd32___semctl14 */
#else
	"#301 (excluded __semctl14)",		/* 301 = excluded __semctl14 */
#endif
#if defined(SYSVMSG) || !defined(_KERNEL)
	"netbsd32___msgctl13",			/* 302 = netbsd32___msgctl13 */
#else
	"#302 (excluded __msgctl13)",		/* 302 = excluded __msgctl13 */
#endif
#if defined(SYSVSHM) || !defined(_KERNEL)
	"netbsd32___shmctl13",			/* 303 = netbsd32___shmctl13 */
#else
	"#303 (excluded __shmctl13)",		/* 303 = excluded __shmctl13 */
#endif
	"netbsd32_lchflags",			/* 304 = netbsd32_lchflags */
	"issetugid",			/* 305 = issetugid */
	"netbsd32_utrace",			/* 306 = netbsd32_utrace */
	"netbsd32_getcontext",			/* 307 = netbsd32_getcontext */
	"netbsd32_setcontext",			/* 308 = netbsd32_setcontext */
	"netbsd32__lwp_create",			/* 309 = netbsd32__lwp_create */
	"_lwp_exit",			/* 310 = _lwp_exit */
	"_lwp_self",			/* 311 = _lwp_self */
	"netbsd32__lwp_wait",			/* 312 = netbsd32__lwp_wait */
	"netbsd32__lwp_suspend",			/* 313 = netbsd32__lwp_suspend */
	"netbsd32__lwp_continue",			/* 314 = netbsd32__lwp_continue */
	"netbsd32__lwp_wakeup",			/* 315 = netbsd32__lwp_wakeup */
	"_lwp_getprivate",			/* 316 = _lwp_getprivate */
	"netbsd32__lwp_setprivate",			/* 317 = netbsd32__lwp_setprivate */
	"#318 (unimplemented)",		/* 318 = unimplemented */
	"#319 (unimplemented)",		/* 319 = unimplemented */
	"#320 (unimplemented)",		/* 320 = unimplemented */
	"#321 (unimplemented)",		/* 321 = unimplemented */
	"#322 (unimplemented)",		/* 322 = unimplemented */
	"#323 (unimplemented)",		/* 323 = unimplemented */
	"#324 (unimplemented)",		/* 324 = unimplemented */
	"#325 (unimplemented)",		/* 325 = unimplemented */
	"#326 (unimplemented)",		/* 326 = unimplemented */
	"#327 (unimplemented)",		/* 327 = unimplemented */
	"#328 (unimplemented)",		/* 328 = unimplemented */
	"#329 (unimplemented)",		/* 329 = unimplemented */
	"netbsd32_sa_register",			/* 330 = netbsd32_sa_register */
	"netbsd32_sa_stacks",			/* 331 = netbsd32_sa_stacks */
	"sa_enable",			/* 332 = sa_enable */
	"netbsd32_sa_setconcurrency",			/* 333 = netbsd32_sa_setconcurrency */
	"sa_yield",			/* 334 = sa_yield */
	"netbsd32_sa_preempt",			/* 335 = netbsd32_sa_preempt */
	"#336 (obsolete sys_sa_unblockyield)",		/* 336 = obsolete sys_sa_unblockyield */
	"#337 (unimplemented)",		/* 337 = unimplemented */
	"#338 (unimplemented)",		/* 338 = unimplemented */
	"#339 (unimplemented)",		/* 339 = unimplemented */
	"netbsd32___sigaction_sigtramp",			/* 340 = netbsd32___sigaction_sigtramp */
	"#341 (unimplemented)",		/* 341 = unimplemented */
	"#342 (unimplemented)",		/* 342 = unimplemented */
	"netbsd32_rasctl",			/* 343 = netbsd32_rasctl */
	"kqueue",			/* 344 = kqueue */
	"netbsd32_kevent",			/* 345 = netbsd32_kevent */
	"#346 (unimplemented)",		/* 346 = unimplemented */
	"#347 (unimplemented)",		/* 347 = unimplemented */
	"#348 (unimplemented)",		/* 348 = unimplemented */
	"#349 (unimplemented)",		/* 349 = unimplemented */
	"#350 (unimplemented)",		/* 350 = unimplemented */
	"#351 (unimplemented)",		/* 351 = unimplemented */
	"#352 (unimplemented)",		/* 352 = unimplemented */
	"#353 (unimplemented)",		/* 353 = unimplemented */
	"netbsd32_fsync_range",			/* 354 = netbsd32_fsync_range */
	"netbsd32_uuidgen",			/* 355 = netbsd32_uuidgen */
	"netbsd32_getvfsstat",			/* 356 = netbsd32_getvfsstat */
	"netbsd32_statvfs1",			/* 357 = netbsd32_statvfs1 */
	"netbsd32_fstatvfs1",			/* 358 = netbsd32_fstatvfs1 */
	"compat_30_netbsd32_fhstatvfs1",	/* 359 = compat_30 netbsd32_fhstatvfs1 */
	"netbsd32_extattrctl",			/* 360 = netbsd32_extattrctl */
	"netbsd32_extattr_set_file",			/* 361 = netbsd32_extattr_set_file */
	"netbsd32_extattr_get_file",			/* 362 = netbsd32_extattr_get_file */
	"netbsd32_extattr_delete_file",			/* 363 = netbsd32_extattr_delete_file */
	"netbsd32_extattr_set_fd",			/* 364 = netbsd32_extattr_set_fd */
	"netbsd32_extattr_get_fd",			/* 365 = netbsd32_extattr_get_fd */
	"netbsd32_extattr_delete_fd",			/* 366 = netbsd32_extattr_delete_fd */
	"netbsd32_extattr_set_link",			/* 367 = netbsd32_extattr_set_link */
	"netbsd32_extattr_get_link",			/* 368 = netbsd32_extattr_get_link */
	"netbsd32_extattr_delete_link",			/* 369 = netbsd32_extattr_delete_link */
	"netbsd32_extattr_list_fd",			/* 370 = netbsd32_extattr_list_fd */
	"netbsd32_extattr_list_file",			/* 371 = netbsd32_extattr_list_file */
	"netbsd32_extattr_list_link",			/* 372 = netbsd32_extattr_list_link */
	"netbsd32_pselect",			/* 373 = netbsd32_pselect */
	"netbsd32_pollts",			/* 374 = netbsd32_pollts */
	"netbsd32_setxattr",			/* 375 = netbsd32_setxattr */
	"netbsd32_lsetxattr",			/* 376 = netbsd32_lsetxattr */
	"netbsd32_fsetxattr",			/* 377 = netbsd32_fsetxattr */
	"netbsd32_getxattr",			/* 378 = netbsd32_getxattr */
	"netbsd32_lgetxattr",			/* 379 = netbsd32_lgetxattr */
	"netbsd32_fgetxattr",			/* 380 = netbsd32_fgetxattr */
	"netbsd32_listxattr",			/* 381 = netbsd32_listxattr */
	"netbsd32_llistxattr",			/* 382 = netbsd32_llistxattr */
	"netbsd32_flistxattr",			/* 383 = netbsd32_flistxattr */
	"netbsd32_removexattr",			/* 384 = netbsd32_removexattr */
	"netbsd32_lremovexattr",			/* 385 = netbsd32_lremovexattr */
	"netbsd32_fremovexattr",			/* 386 = netbsd32_fremovexattr */
	"__stat30",			/* 387 = __stat30 */
	"__fstat30",			/* 388 = __fstat30 */
	"__lstat30",			/* 389 = __lstat30 */
	"__getdents30",			/* 390 = __getdents30 */
	"posix_fadvise",			/* 391 = posix_fadvise */
	"compat_30___fhstat30",	/* 392 = compat_30 __fhstat30 */
	"netbsd32_ntp_gettime",			/* 393 = netbsd32_ntp_gettime */
	"__socket30",			/* 394 = __socket30 */
	"netbsd32___getfh30",			/* 395 = netbsd32___getfh30 */
	"netbsd32___fhopen40",			/* 396 = netbsd32___fhopen40 */
	"netbsd32___fhstatvfs140",			/* 397 = netbsd32___fhstatvfs140 */
	"netbsd32___fhstat40",			/* 398 = netbsd32___fhstat40 */
};
