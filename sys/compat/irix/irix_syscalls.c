/* $NetBSD: irix_syscalls.c,v 1.14 2001/12/25 16:40:48 manu Exp $ */

/*
 * System call names.
 *
 * DO NOT EDIT-- this file is automatically generated.
 * created from	NetBSD: syscalls.master,v 1.12 2001/12/23 20:57:30 manu Exp 
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: irix_syscalls.c,v 1.14 2001/12/25 16:40:48 manu Exp $");

#if defined(_KERNEL_OPT)
#if defined(_KERNEL_OPT)
#include "opt_ntp.h"
#include "opt_sysv.h"
#endif
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/signal.h>
#include <sys/mount.h>
#include <sys/poll.h>
#include <sys/ioctl_compat.h>
#include <sys/syscallargs.h>
#include <compat/svr4/svr4_types.h>
#include <compat/irix/irix_types.h>
#include <compat/irix/irix_syscallargs.h>
#endif /* _KERNEL_OPT */

const char *const irix_syscallnames[] = {
	"syscall",			/* 0 = syscall */
	"exit",			/* 1 = exit */
	"fork",			/* 2 = fork */
	"read",			/* 3 = read */
	"write",			/* 4 = write */
	"open",			/* 5 = open */
	"close",			/* 6 = close */
	"#7 (obsolete wait)",		/* 7 = obsolete wait */
	"creat",			/* 8 = creat */
	"link",			/* 9 = link */
	"unlink",			/* 10 = unlink */
	"execv",			/* 11 = execv */
	"chdir",			/* 12 = chdir */
	"time",			/* 13 = time */
	"#14 (obsolete mknod)",		/* 14 = obsolete mknod */
	"chmod",			/* 15 = chmod */
	"chown",			/* 16 = chown */
	"break",			/* 17 = break */
	"#18 (obsolete stat)",		/* 18 = obsolete stat */
	"lseek",			/* 19 = lseek */
	"getpid",			/* 20 = getpid */
	"#21 (unimplemented old_mount)",		/* 21 = unimplemented old_mount */
	"#22 (unimplemented System V umount)",		/* 22 = unimplemented System V umount */
	"setuid",			/* 23 = setuid */
	"getuid_with_euid",			/* 24 = getuid_with_euid */
	"#25 (unimplemented stime)",		/* 25 = unimplemented stime */
	"#26 (unimplemented ptrace)",		/* 26 = unimplemented ptrace */
	"#27 (obsolete alarm)",		/* 27 = obsolete alarm */
	"fstat",			/* 28 = fstat */
	"pause",			/* 29 = pause */
	"utime",			/* 30 = utime */
	"#31 (unimplemented was stty)",		/* 31 = unimplemented was stty */
	"#32 (unimplemented was gtty)",		/* 32 = unimplemented was gtty */
	"access",			/* 33 = access */
	"nice",			/* 34 = nice */
	"#35 (unimplemented statfs)",		/* 35 = unimplemented statfs */
	"sync",			/* 36 = sync */
	"kill",			/* 37 = kill */
	"#38 (unimplemented fstatfs)",		/* 38 = unimplemented fstatfs */
	"pgrpsys",			/* 39 = pgrpsys */
	"syssgi",			/* 40 = syssgi */
	"dup",			/* 41 = dup */
	"pipe",			/* 42 = pipe */
	"times",			/* 43 = times */
	"#44 (unimplemented profil)",		/* 44 = unimplemented profil */
	"#45 (unimplemented plock)",		/* 45 = unimplemented plock */
	"setgid",			/* 46 = setgid */
	"getgid_with_egid",			/* 47 = getgid_with_egid */
	"#48 (obsolete ssig)",		/* 48 = obsolete ssig */
#ifdef SYSVMSG
	"msgsys",			/* 49 = msgsys */
#else
	"#49 (unimplemented msgsys)",		/* 49 = unimplemented msgsys */
#endif
	"#50 (unimplemented sysmips)",		/* 50 = unimplemented sysmips */
	"#51 (unimplemented acct)",		/* 51 = unimplemented acct */
#ifdef SYSVSHM
	"shmsys",			/* 52 = shmsys */
#else
	"#52 (unimplemented shmsys)",		/* 52 = unimplemented shmsys */
#endif
#ifdef SYSVSEM
	"semsys",			/* 53 = semsys */
#else
	"#53 (unimplemented semsys)",		/* 53 = unimplemented semsys */
#endif
	"ioctl",			/* 54 = ioctl */
	"#55 (unimplemented uadmin)",		/* 55 = unimplemented uadmin */
	"sysmp",			/* 56 = sysmp */
	"utssys",			/* 57 = utssys */
	"#58 (unimplemented)",		/* 58 = unimplemented */
	"execve",			/* 59 = execve */
	"umask",			/* 60 = umask */
	"chroot",			/* 61 = chroot */
	"fcntl",			/* 62 = fcntl */
	"ulimit",			/* 63 = ulimit */
	"#64 (unimplemented reserved for unix/pc)",		/* 64 = unimplemented reserved for unix/pc */
	"#65 (unimplemented reserved for unix/pc)",		/* 65 = unimplemented reserved for unix/pc */
	"#66 (unimplemented reserved for unix/pc)",		/* 66 = unimplemented reserved for unix/pc */
	"#67 (unimplemented reserved for unix/pc)",		/* 67 = unimplemented reserved for unix/pc */
	"#68 (unimplemented reserved for unix/pc)",		/* 68 = unimplemented reserved for unix/pc */
	"#69 (unimplemented reserved for unix/pc)",		/* 69 = unimplemented reserved for unix/pc */
	"#70 (obsolete advfs)",		/* 70 = obsolete advfs */
	"#71 (obsolete unadvfs)",		/* 71 = obsolete unadvfs */
	"#72 (obsolete rmount)",		/* 72 = obsolete rmount */
	"#73 (obsolete rumount)",		/* 73 = obsolete rumount */
	"#74 (obsolete rfstart)",		/* 74 = obsolete rfstart */
	"#75 (obsolete sigret)",		/* 75 = obsolete sigret */
	"#76 (obsolete rdebug)",		/* 76 = obsolete rdebug */
	"#77 (obsolete rfstop)",		/* 77 = obsolete rfstop */
	"lseek64",			/* 78 = lseek64 */
	"rmdir",			/* 79 = rmdir */
	"mkdir",			/* 80 = mkdir */
	"getdents",			/* 81 = getdents */
	"sginap",			/* 82 = sginap */
	"#83 (unimplemented sgikopt)",		/* 83 = unimplemented sgikopt */
	"#84 (unimplemented sysfs)",		/* 84 = unimplemented sysfs */
	"getmsg",			/* 85 = getmsg */
	"putmsg",			/* 86 = putmsg */
	"poll",			/* 87 = poll */
	"sigreturn",			/* 88 = sigreturn */
	"#89 (unimplemented accept)",		/* 89 = unimplemented accept */
	"#90 (unimplemented bind)",		/* 90 = unimplemented bind */
	"#91 (unimplemented connect)",		/* 91 = unimplemented connect */
	"#92 (unimplemented sys_gethostid)",		/* 92 = unimplemented sys_gethostid */
	"#93 (unimplemented getpeername)",		/* 93 = unimplemented getpeername */
	"#94 (unimplemented getsockname)",		/* 94 = unimplemented getsockname */
	"#95 (unimplemented getsockopt)",		/* 95 = unimplemented getsockopt */
	"#96 (unimplemented listen)",		/* 96 = unimplemented listen */
	"#97 (unimplemented recv)",		/* 97 = unimplemented recv */
	"#98 (unimplemented recvfrom)",		/* 98 = unimplemented recvfrom */
	"#99 (unimplemented recvmsg)",		/* 99 = unimplemented recvmsg */
	"#100 (unimplemented select)",		/* 100 = unimplemented select */
	"#101 (unimplemented send)",		/* 101 = unimplemented send */
	"#102 (unimplemented sendmsg)",		/* 102 = unimplemented sendmsg */
	"#103 (unimplemented sendto)",		/* 103 = unimplemented sendto */
	"#104 (unimplemented sys_sethostid)",		/* 104 = unimplemented sys_sethostid */
	"#105 (unimplemented setsockopt)",		/* 105 = unimplemented setsockopt */
	"#106 (unimplemented shutdown)",		/* 106 = unimplemented shutdown */
	"#107 (unimplemented socket)",		/* 107 = unimplemented socket */
	"#108 (unimplemented sys_gethostname)",		/* 108 = unimplemented sys_gethostname */
	"#109 (unimplemented sethostname)",		/* 109 = unimplemented sethostname */
	"#110 (unimplemented sys_getdomainname)",		/* 110 = unimplemented sys_getdomainname */
	"#111 (unimplemented setdomainname)",		/* 111 = unimplemented setdomainname */
	"#112 (unimplemented truncate)",		/* 112 = unimplemented truncate */
	"#113 (unimplemented ftruncate)",		/* 113 = unimplemented ftruncate */
	"#114 (unimplemented rename)",		/* 114 = unimplemented rename */
	"#115 (unimplemented symlink)",		/* 115 = unimplemented symlink */
	"#116 (unimplemented readlink)",		/* 116 = unimplemented readlink */
	"#117 (unimplemented lstat)",		/* 117 = unimplemented lstat */
	"#118 (unimplemented)",		/* 118 = unimplemented */
	"#119 (unimplemented nfs_svc)",		/* 119 = unimplemented nfs_svc */
	"#120 (unimplemented nfs_getfh)",		/* 120 = unimplemented nfs_getfh */
	"#121 (unimplemented async_daemon)",		/* 121 = unimplemented async_daemon */
	"#122 (unimplemented exportfs)",		/* 122 = unimplemented exportfs */
	"#123 (unimplemented setregid)",		/* 123 = unimplemented setregid */
	"#124 (unimplemented setreuid)",		/* 124 = unimplemented setreuid */
	"#125 (unimplemented getitimer)",		/* 125 = unimplemented getitimer */
	"#126 (unimplemented setitimer)",		/* 126 = unimplemented setitimer */
	"#127 (unimplemented adjtime)",		/* 127 = unimplemented adjtime */
	"#128 (unimplemented gettimeofday)",		/* 128 = unimplemented gettimeofday */
	"#129 (unimplemented sproc)",		/* 129 = unimplemented sproc */
	"prctl",			/* 130 = prctl */
	"#131 (unimplemented procblk)",		/* 131 = unimplemented procblk */
	"#132 (unimplemented sprocsp)",		/* 132 = unimplemented sprocsp */
	"#133 (unimplemented sgigsc)",		/* 133 = unimplemented sgigsc */
	"mmap",			/* 134 = mmap */
	"#135 (unimplemented munmap)",		/* 135 = unimplemented munmap */
	"#136 (unimplemented mprotect)",		/* 136 = unimplemented mprotect */
	"#137 (unimplemented msync)",		/* 137 = unimplemented msync */
	"#138 (unimplemented madvise)",		/* 138 = unimplemented madvise */
	"#139 (unimplemented pagelock)",		/* 139 = unimplemented pagelock */
	"#140 (unimplemented getpagesize)",		/* 140 = unimplemented getpagesize */
	"#141 (unimplemented quotactl)",		/* 141 = unimplemented quotactl */
	"#142 (unimplemented)",		/* 142 = unimplemented */
	"#143 (unimplemented getpgrp)",		/* 143 = unimplemented getpgrp */
	"#144 (unimplemented setpgrp)",		/* 144 = unimplemented setpgrp */
	"#145 (unimplemented vhangup)",		/* 145 = unimplemented vhangup */
	"#146 (unimplemented fsync)",		/* 146 = unimplemented fsync */
	"#147 (unimplemented fchdir)",		/* 147 = unimplemented fchdir */
	"#148 (unimplemented getrlimit)",		/* 148 = unimplemented getrlimit */
	"#149 (unimplemented setrlimit)",		/* 149 = unimplemented setrlimit */
	"#150 (unimplemented cacheflush)",		/* 150 = unimplemented cacheflush */
	"#151 (unimplemented cachectl)",		/* 151 = unimplemented cachectl */
	"#152 (unimplemented fchown)",		/* 152 = unimplemented fchown */
	"#153 (unimplemented fchmod)",		/* 153 = unimplemented fchmod */
	"#154 (unimplemented wait3)",		/* 154 = unimplemented wait3 */
	"#155 (unimplemented socketpair)",		/* 155 = unimplemented socketpair */
	"#156 (unimplemented systeminfo)",		/* 156 = unimplemented systeminfo */
	"#157 (unimplemented uname)",		/* 157 = unimplemented uname */
	"xstat",			/* 158 = xstat */
	"lxstat",			/* 159 = lxstat */
	"fxstat",			/* 160 = fxstat */
	"#161 (unimplemented xmknod)",		/* 161 = unimplemented xmknod */
	"sigaction",			/* 162 = sigaction */
	"sigpending",			/* 163 = sigpending */
	"sigprocmask",			/* 164 = sigprocmask */
	"sigsuspend",			/* 165 = sigsuspend */
	"#166 (unimplemented sigpoll_sys)",		/* 166 = unimplemented sigpoll_sys */
	"#167 (unimplemented swapctl)",		/* 167 = unimplemented swapctl */
	"#168 (unimplemented getcontext)",		/* 168 = unimplemented getcontext */
	"#169 (unimplemented setcontext)",		/* 169 = unimplemented setcontext */
	"#170 (unimplemented waitsys)",		/* 170 = unimplemented waitsys */
	"#171 (unimplemented sigstack)",		/* 171 = unimplemented sigstack */
	"#172 (unimplemented sigaltstack)",		/* 172 = unimplemented sigaltstack */
	"#173 (unimplemented sigsendset)",		/* 173 = unimplemented sigsendset */
	"#174 (unimplemented statvfs)",		/* 174 = unimplemented statvfs */
	"#175 (unimplemented fstatvfs)",		/* 175 = unimplemented fstatvfs */
	"#176 (unimplemented getpmsg)",		/* 176 = unimplemented getpmsg */
	"#177 (unimplemented putpmsg)",		/* 177 = unimplemented putpmsg */
	"#178 (unimplemented lchown)",		/* 178 = unimplemented lchown */
	"#179 (unimplemented priocntl)",		/* 179 = unimplemented priocntl */
	"#180 (unimplemented sigqueue)",		/* 180 = unimplemented sigqueue */
	"#181 (unimplemented readv)",		/* 181 = unimplemented readv */
	"#182 (unimplemented writev)",		/* 182 = unimplemented writev */
	"#183 (unimplemented truncate64)",		/* 183 = unimplemented truncate64 */
	"#184 (unimplemented ftruncate64)",		/* 184 = unimplemented ftruncate64 */
	"#185 (unimplemented mmap64)",		/* 185 = unimplemented mmap64 */
	"#186 (unimplemented dmi)",		/* 186 = unimplemented dmi */
	"#187 (unimplemented pread)",		/* 187 = unimplemented pread */
	"#188 (unimplemented pwrite)",		/* 188 = unimplemented pwrite */
	"#189 (unimplemented fdatasync)",		/* 189 = unimplemented fdatasync */
	"#190 (unimplemented sgifastpath)",		/* 190 = unimplemented sgifastpath */
	"#191 (unimplemented attr_get)",		/* 191 = unimplemented attr_get */
	"#192 (unimplemented attr_getf)",		/* 192 = unimplemented attr_getf */
	"#193 (unimplemented attr_set)",		/* 193 = unimplemented attr_set */
	"#194 (unimplemented attr_setf)",		/* 194 = unimplemented attr_setf */
	"#195 (unimplemented attr_remove)",		/* 195 = unimplemented attr_remove */
	"#196 (unimplemented attr_removef)",		/* 196 = unimplemented attr_removef */
	"#197 (unimplemented attr_list)",		/* 197 = unimplemented attr_list */
	"#198 (unimplemented attr_listf)",		/* 198 = unimplemented attr_listf */
	"#199 (unimplemented attr_multi)",		/* 199 = unimplemented attr_multi */
	"#200 (unimplemented attr_multif)",		/* 200 = unimplemented attr_multif */
	"#201 (unimplemented statvfs64)",		/* 201 = unimplemented statvfs64 */
	"#202 (unimplemented fstatvfs64)",		/* 202 = unimplemented fstatvfs64 */
	"getmountid",			/* 203 = getmountid */
	"#204 (unimplemented nsproc)",		/* 204 = unimplemented nsproc */
	"#205 (unimplemented getdents64)",		/* 205 = unimplemented getdents64 */
	"#206 (unimplemented afs_syscall)",		/* 206 = unimplemented afs_syscall */
	"ngetdents",			/* 207 = ngetdents */
	"#208 (unimplemented ngetdents64)",		/* 208 = unimplemented ngetdents64 */
	"#209 (unimplemented sgi_sesmgr)",		/* 209 = unimplemented sgi_sesmgr */
	"#210 (unimplemented pidsprocsp)",		/* 210 = unimplemented pidsprocsp */
	"#211 (unimplemented rexec)",		/* 211 = unimplemented rexec */
	"#212 (unimplemented timer_create)",		/* 212 = unimplemented timer_create */
	"#213 (unimplemented timer_delete)",		/* 213 = unimplemented timer_delete */
	"#214 (unimplemented timer_settime)",		/* 214 = unimplemented timer_settime */
	"#215 (unimplemented timer_gettime)",		/* 215 = unimplemented timer_gettime */
	"#216 (unimplemented timer_setoverrun)",		/* 216 = unimplemented timer_setoverrun */
	"#217 (unimplemented sched_rr_get_interval)",		/* 217 = unimplemented sched_rr_get_interval */
	"#218 (unimplemented sched_yield)",		/* 218 = unimplemented sched_yield */
	"#219 (unimplemented sched_getscheduler)",		/* 219 = unimplemented sched_getscheduler */
	"#220 (unimplemented sched_setscheduler)",		/* 220 = unimplemented sched_setscheduler */
	"#221 (unimplemented sched_getparam)",		/* 221 = unimplemented sched_getparam */
	"#222 (unimplemented sched_setparam)",		/* 222 = unimplemented sched_setparam */
	"#223 (unimplemented usync_cntl)",		/* 223 = unimplemented usync_cntl */
	"#224 (unimplemented psema_cntl)",		/* 224 = unimplemented psema_cntl */
	"#225 (unimplemented restartreturn)",		/* 225 = unimplemented restartreturn */
	"#226 (unimplemented sysget)",		/* 226 = unimplemented sysget */
	"#227 (unimplemented xpg4_recvmsg)",		/* 227 = unimplemented xpg4_recvmsg */
	"#228 (unimplemented umfscall)",		/* 228 = unimplemented umfscall */
	"#229 (unimplemented nsproctid)",		/* 229 = unimplemented nsproctid */
	"#230 (unimplemented rexec_complete)",		/* 230 = unimplemented rexec_complete */
	"#231 (unimplemented xpg4_sigaltstack)",		/* 231 = unimplemented xpg4_sigaltstack */
	"#232 (unimplemented xpg4_sigaltstack)",		/* 232 = unimplemented xpg4_sigaltstack */
	"#233 (unimplemented xpg4_setregid)",		/* 233 = unimplemented xpg4_setregid */
	"#234 (unimplemented linkfollow)",		/* 234 = unimplemented linkfollow */
	"#235 (unimplemented utimets)",		/* 235 = unimplemented utimets */
};
