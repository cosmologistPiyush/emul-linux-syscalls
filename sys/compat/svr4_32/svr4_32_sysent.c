/* $NetBSD: svr4_32_sysent.c,v 1.1 2001/02/06 16:37:59 eeh Exp $ */

/*
 * System call switch table.
 *
 * DO NOT EDIT-- this file is automatically generated.
 * created from	NetBSD: syscalls.master,v 1.48 2000/12/09 05:27:30 mycroft Exp 
 */

#if defined(_KERNEL) && !defined(_LKM)
#include "opt_ntp.h"
#include "opt_sysv.h"
#endif
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/signal.h>
#include <sys/mount.h>
#include <sys/poll.h>
#include <sys/syscallargs.h>
#include <compat/svr4_32/svr4_32_types.h>
#include <compat/netbsd32/netbsd32_syscallargs.h>
#include <compat/svr4_32/svr4_32_time.h>
#include <compat/svr4_32/svr4_32_signal.h>
#include <compat/svr4_32/svr4_32_ucontext.h>
#include <compat/svr4_32/svr4_32_lwp.h>
#include <compat/svr4_32/svr4_32_syscallargs.h>
#include <compat/svr4_32/svr4_32_statvfs.h>
#include <compat/svr4_32/svr4_32_resource.h>
#include <compat/svr4_32/svr4_32_acl.h>

#define	s(type)	sizeof(type)

struct sysent svr4_32_sysent[] = {
	{ 0, 0,
	    sys_nosys },			/* 0 = syscall */
	{ 1, s(struct sys_exit_args),
	    sys_exit },				/* 1 = exit */
	{ 0, 0,
	    sys_fork },				/* 2 = fork */
	{ 3, s(struct netbsd32_read_args),
	    netbsd32_read },			/* 3 = netbsd32_read */
	{ 3, s(struct netbsd32_write_args),
	    netbsd32_write },			/* 4 = netbsd32_write */
	{ 3, s(struct svr4_32_sys_open_args),
	    svr4_32_sys_open },			/* 5 = open */
	{ 1, s(struct sys_close_args),
	    sys_close },			/* 6 = close */
	{ 1, s(struct svr4_32_sys_wait_args),
	    svr4_32_sys_wait },			/* 7 = wait */
	{ 2, s(struct svr4_32_sys_creat_args),
	    svr4_32_sys_creat },		/* 8 = creat */
	{ 2, s(struct netbsd32_link_args),
	    netbsd32_link },			/* 9 = netbsd32_link */
	{ 1, s(struct netbsd32_unlink_args),
	    netbsd32_unlink },			/* 10 = netbsd32_unlink */
	{ 2, s(struct svr4_32_sys_execv_args),
	    svr4_32_sys_execv },		/* 11 = execv */
	{ 1, s(struct netbsd32_chdir_args),
	    netbsd32_chdir },			/* 12 = netbsd32_chdir */
	{ 1, s(struct svr4_32_sys_time_args),
	    svr4_32_sys_time },			/* 13 = time */
	{ 3, s(struct svr4_32_sys_mknod_args),
	    svr4_32_sys_mknod },		/* 14 = mknod */
	{ 2, s(struct netbsd32_chmod_args),
	    netbsd32_chmod },			/* 15 = netbsd32_chmod */
	{ 3, s(struct netbsd32___posix_chown_args),
	    netbsd32___posix_chown },		/* 16 = chown */
	{ 1, s(struct svr4_32_sys_break_args),
	    svr4_32_sys_break },		/* 17 = break */
	{ 2, s(struct svr4_32_sys_stat_args),
	    svr4_32_sys_stat },			/* 18 = stat */
	{ 3, s(struct compat_43_sys_lseek_args),
	    compat_43_sys_lseek },		/* 19 = lseek */
	{ 0, 0,
	    sys_getpid },			/* 20 = getpid */
	{ 0, 0,
	    sys_nosys },			/* 21 = unimplemented old_mount */
	{ 0, 0,
	    sys_nosys },			/* 22 = unimplemented System V umount */
	{ 1, s(struct sys_setuid_args),
	    sys_setuid },			/* 23 = setuid */
	{ 0, 0,
	    sys_getuid },			/* 24 = getuid */
	{ 0, 0,
	    sys_nosys },			/* 25 = unimplemented stime */
	{ 0, 0,
	    sys_nosys },			/* 26 = unimplemented ptrace */
	{ 1, s(struct svr4_32_sys_alarm_args),
	    svr4_32_sys_alarm },		/* 27 = alarm */
	{ 2, s(struct svr4_32_sys_fstat_args),
	    svr4_32_sys_fstat },		/* 28 = fstat */
	{ 0, 0,
	    svr4_32_sys_pause },		/* 29 = pause */
	{ 2, s(struct svr4_32_sys_utime_args),
	    svr4_32_sys_utime },		/* 30 = utime */
	{ 0, 0,
	    sys_nosys },			/* 31 = unimplemented was stty */
	{ 0, 0,
	    sys_nosys },			/* 32 = unimplemented was gtty */
	{ 2, s(struct svr4_32_sys_access_args),
	    svr4_32_sys_access },		/* 33 = access */
	{ 1, s(struct svr4_32_sys_nice_args),
	    svr4_32_sys_nice },			/* 34 = nice */
	{ 0, 0,
	    sys_nosys },			/* 35 = unimplemented statfs */
	{ 0, 0,
	    sys_sync },				/* 36 = sync */
	{ 2, s(struct svr4_32_sys_kill_args),
	    svr4_32_sys_kill },			/* 37 = kill */
	{ 0, 0,
	    sys_nosys },			/* 38 = unimplemented fstatfs */
	{ 3, s(struct svr4_32_sys_pgrpsys_args),
	    svr4_32_sys_pgrpsys },		/* 39 = pgrpsys */
	{ 0, 0,
	    sys_nosys },			/* 40 = unimplemented xenix */
	{ 1, s(struct sys_dup_args),
	    sys_dup },				/* 41 = dup */
	{ 0, 0,
	    sys_pipe },				/* 42 = pipe */
	{ 1, s(struct svr4_32_sys_times_args),
	    svr4_32_sys_times },		/* 43 = times */
	{ 0, 0,
	    sys_nosys },			/* 44 = unimplemented profil */
	{ 0, 0,
	    sys_nosys },			/* 45 = unimplemented plock */
	{ 1, s(struct sys_setgid_args),
	    sys_setgid },			/* 46 = setgid */
	{ 0, 0,
	    sys_getgid },			/* 47 = getgid */
	{ 2, s(struct svr4_32_sys_signal_args),
	    svr4_32_sys_signal },		/* 48 = signal */
#ifdef SYSVMSG
	{ 5, s(struct svr4_32_sys_msgsys_args),
	    svr4_32_sys_msgsys },		/* 49 = msgsys */
#else
	{ 0, 0,
	    sys_nosys },			/* 49 = unimplemented msgsys */
#endif
	{ 2, s(struct svr4_32_sys_sysarch_args),
	    svr4_32_sys_sysarch },		/* 50 = sysarch */
	{ 0, 0,
	    sys_nosys },			/* 51 = unimplemented acct */
#ifdef SYSVSHM
	{ 4, s(struct svr4_32_sys_shmsys_args),
	    svr4_32_sys_shmsys },		/* 52 = shmsys */
#else
	{ 0, 0,
	    sys_nosys },			/* 52 = unimplemented shmsys */
#endif
#ifdef SYSVSEM
	{ 5, s(struct svr4_32_sys_semsys_args),
	    svr4_32_sys_semsys },		/* 53 = semsys */
#else
	{ 0, 0,
	    sys_nosys },			/* 53 = unimplemented semsys */
#endif
	{ 3, s(struct svr4_32_sys_ioctl_args),
	    svr4_32_sys_ioctl },		/* 54 = ioctl */
	{ 0, 0,
	    sys_nosys },			/* 55 = unimplemented uadmin */
	{ 0, 0,
	    sys_nosys },			/* 56 = unimplemented exch */
	{ 4, s(struct svr4_32_sys_utssys_args),
	    svr4_32_sys_utssys },		/* 57 = utssys */
	{ 1, s(struct sys_fsync_args),
	    sys_fsync },			/* 58 = fsync */
	{ 3, s(struct netbsd32_execve_args),
	    netbsd32_execve },			/* 59 = netbsd32_execve */
	{ 1, s(struct sys_umask_args),
	    sys_umask },			/* 60 = umask */
	{ 1, s(struct netbsd32_chroot_args),
	    netbsd32_chroot },			/* 61 = netbsd32_chroot */
	{ 3, s(struct svr4_32_sys_fcntl_args),
	    svr4_32_sys_fcntl },		/* 62 = fcntl */
	{ 2, s(struct svr4_32_sys_ulimit_args),
	    svr4_32_sys_ulimit },		/* 63 = ulimit */
	{ 0, 0,
	    sys_nosys },			/* 64 = unimplemented reserved for unix/pc */
	{ 0, 0,
	    sys_nosys },			/* 65 = unimplemented reserved for unix/pc */
	{ 0, 0,
	    sys_nosys },			/* 66 = unimplemented reserved for unix/pc */
	{ 0, 0,
	    sys_nosys },			/* 67 = unimplemented reserved for unix/pc */
	{ 0, 0,
	    sys_nosys },			/* 68 = unimplemented reserved for unix/pc */
	{ 0, 0,
	    sys_nosys },			/* 69 = unimplemented reserved for unix/pc */
	{ 0, 0,
	    sys_nosys },			/* 70 = obsolete advfs */
	{ 0, 0,
	    sys_nosys },			/* 71 = obsolete unadvfs */
	{ 0, 0,
	    sys_nosys },			/* 72 = obsolete rmount */
	{ 0, 0,
	    sys_nosys },			/* 73 = obsolete rumount */
	{ 0, 0,
	    sys_nosys },			/* 74 = obsolete rfstart */
	{ 0, 0,
	    sys_nosys },			/* 75 = obsolete sigret */
	{ 0, 0,
	    sys_nosys },			/* 76 = obsolete rdebug */
	{ 0, 0,
	    sys_nosys },			/* 77 = obsolete rfstop */
	{ 0, 0,
	    sys_nosys },			/* 78 = unimplemented rfsys */
	{ 1, s(struct netbsd32_rmdir_args),
	    netbsd32_rmdir },			/* 79 = netbsd32_rmdir */
	{ 2, s(struct netbsd32_mkdir_args),
	    netbsd32_mkdir },			/* 80 = netbsd32_mkdir */
	{ 3, s(struct svr4_32_sys_getdents_args),
	    svr4_32_sys_getdents },		/* 81 = getdents */
	{ 0, 0,
	    sys_nosys },			/* 82 = obsolete libattach */
	{ 0, 0,
	    sys_nosys },			/* 83 = obsolete libdetach */
	{ 0, 0,
	    sys_nosys },			/* 84 = unimplemented sysfs */
	{ 4, s(struct svr4_32_sys_getmsg_args),
	    svr4_32_sys_getmsg },		/* 85 = getmsg */
	{ 4, s(struct svr4_32_sys_putmsg_args),
	    svr4_32_sys_putmsg },		/* 86 = putmsg */
	{ 3, s(struct netbsd32_poll_args),
	    netbsd32_poll },			/* 87 = netbsd32_poll */
	{ 2, s(struct svr4_32_sys_lstat_args),
	    svr4_32_sys_lstat },		/* 88 = lstat */
	{ 2, s(struct netbsd32_symlink_args),
	    netbsd32_symlink },			/* 89 = netbsd32_symlink */
	{ 3, s(struct netbsd32_readlink_args),
	    netbsd32_readlink },		/* 90 = netbsd32_readlink */
	{ 2, s(struct netbsd32_getgroups_args),
	    netbsd32_getgroups },		/* 91 = netbsd32_getgroups */
	{ 2, s(struct netbsd32_setgroups_args),
	    netbsd32_setgroups },		/* 92 = netbsd32_setgroups */
	{ 2, s(struct sys_fchmod_args),
	    sys_fchmod },			/* 93 = fchmod */
	{ 3, s(struct sys___posix_fchown_args),
	    sys___posix_fchown },		/* 94 = fchown */
	{ 3, s(struct svr4_32_sys_sigprocmask_args),
	    svr4_32_sys_sigprocmask },		/* 95 = sigprocmask */
	{ 1, s(struct svr4_32_sys_sigsuspend_args),
	    svr4_32_sys_sigsuspend },		/* 96 = sigsuspend */
	{ 2, s(struct svr4_32_sys_sigaltstack_args),
	    svr4_32_sys_sigaltstack },		/* 97 = sigaltstack */
	{ 3, s(struct svr4_32_sys_sigaction_args),
	    svr4_32_sys_sigaction },		/* 98 = sigaction */
	{ 2, s(struct svr4_32_sys_sigpending_args),
	    svr4_32_sys_sigpending },		/* 99 = sigpending */
	{ 2, s(struct svr4_32_sys_context_args),
	    svr4_32_sys_context },		/* 100 = context */
	{ 0, 0,
	    sys_nosys },			/* 101 = unimplemented evsys */
	{ 0, 0,
	    sys_nosys },			/* 102 = unimplemented evtrapret */
	{ 2, s(struct svr4_32_sys_statvfs_args),
	    svr4_32_sys_statvfs },		/* 103 = statvfs */
	{ 2, s(struct svr4_32_sys_fstatvfs_args),
	    svr4_32_sys_fstatvfs },		/* 104 = fstatvfs */
	{ 0, 0,
	    sys_nosys },			/* 105 = unimplemented */
	{ 0, 0,
	    sys_nosys },			/* 106 = unimplemented nfssvc */
	{ 4, s(struct svr4_32_sys_waitsys_args),
	    svr4_32_sys_waitsys },		/* 107 = waitsys */
	{ 0, 0,
	    sys_nosys },			/* 108 = unimplemented sigsendsys */
	{ 5, s(struct svr4_32_sys_hrtsys_args),
	    svr4_32_sys_hrtsys },		/* 109 = hrtsys */
	{ 0, 0,
	    sys_nosys },			/* 110 = unimplemented acancel */
	{ 0, 0,
	    sys_nosys },			/* 111 = unimplemented async */
	{ 0, 0,
	    sys_nosys },			/* 112 = unimplemented priocntlsys */
	{ 2, s(struct svr4_32_sys_pathconf_args),
	    svr4_32_sys_pathconf },		/* 113 = pathconf */
	{ 0, 0,
	    sys_nosys },			/* 114 = unimplemented mincore */
	{ 6, s(struct svr4_32_sys_mmap_args),
	    svr4_32_sys_mmap },			/* 115 = mmap */
	{ 3, s(struct netbsd32_mprotect_args),
	    netbsd32_mprotect },		/* 116 = netbsd32_mprotect */
	{ 2, s(struct netbsd32_munmap_args),
	    netbsd32_munmap },			/* 117 = netbsd32_munmap */
	{ 2, s(struct svr4_32_sys_fpathconf_args),
	    svr4_32_sys_fpathconf },		/* 118 = fpathconf */
	{ 0, 0,
	    sys_vfork },			/* 119 = vfork */
	{ 1, s(struct sys_fchdir_args),
	    sys_fchdir },			/* 120 = fchdir */
	{ 3, s(struct netbsd32_readv_args),
	    netbsd32_readv },			/* 121 = netbsd32_readv */
	{ 3, s(struct netbsd32_writev_args),
	    netbsd32_writev },			/* 122 = netbsd32_writev */
	{ 3, s(struct svr4_32_sys_xstat_args),
	    svr4_32_sys_xstat },		/* 123 = xstat */
	{ 3, s(struct svr4_32_sys_lxstat_args),
	    svr4_32_sys_lxstat },		/* 124 = lxstat */
	{ 3, s(struct svr4_32_sys_fxstat_args),
	    svr4_32_sys_fxstat },		/* 125 = fxstat */
	{ 4, s(struct svr4_32_sys_xmknod_args),
	    svr4_32_sys_xmknod },		/* 126 = xmknod */
	{ 0, 0,
	    sys_nosys },			/* 127 = unimplemented clocal */
	{ 2, s(struct svr4_32_sys_setrlimit_args),
	    svr4_32_sys_setrlimit },		/* 128 = setrlimit */
	{ 2, s(struct svr4_32_sys_getrlimit_args),
	    svr4_32_sys_getrlimit },		/* 129 = getrlimit */
	{ 3, s(struct netbsd32_lchown_args),
	    netbsd32_lchown },			/* 130 = lchown */
	{ 6, s(struct svr4_32_sys_memcntl_args),
	    svr4_32_sys_memcntl },		/* 131 = memcntl */
	{ 0, 0,
	    sys_nosys },			/* 132 = unimplemented getpmsg */
	{ 0, 0,
	    sys_nosys },			/* 133 = unimplemented putpmsg */
	{ 2, s(struct netbsd32___posix_rename_args),
	    netbsd32___posix_rename },		/* 134 = rename */
	{ 2, s(struct svr4_32_sys_uname_args),
	    svr4_32_sys_uname },		/* 135 = uname */
	{ 1, s(struct sys_setegid_args),
	    sys_setegid },			/* 136 = setegid */
	{ 1, s(struct svr4_32_sys_sysconfig_args),
	    svr4_32_sys_sysconfig },		/* 137 = sysconfig */
	{ 2, s(struct netbsd32_adjtime_args),
	    netbsd32_adjtime },			/* 138 = netbsd32_adjtime */
	{ 3, s(struct svr4_32_sys_systeminfo_args),
	    svr4_32_sys_systeminfo },		/* 139 = systeminfo */
	{ 0, 0,
	    sys_nosys },			/* 140 = unimplemented */
	{ 1, s(struct sys_seteuid_args),
	    sys_seteuid },			/* 141 = seteuid */
	{ 0, 0,
	    sys_nosys },			/* 142 = unimplemented vtrace */
	{ 0, 0,
	    sys_fork },				/* 143 = fork1 */
	{ 0, 0,
	    sys_nosys },			/* 144 = unimplemented sigtimedwait */
	{ 1, s(struct svr4_32_sys__lwp_info_args),
	    svr4_32_sys__lwp_info },		/* 145 = _lwp_info */
	{ 0, 0,
	    sys_nosys },			/* 146 = unimplemented yield */
	{ 0, 0,
	    sys_nosys },			/* 147 = unimplemented lwp_sema_wait */
	{ 0, 0,
	    sys_nosys },			/* 148 = unimplemented lwp_sema_post */
	{ 0, 0,
	    sys_nosys },			/* 149 = unimplemented lwp_sema_trywait */
	{ 0, 0,
	    sys_nosys },			/* 150 = unimplemented */
	{ 0, 0,
	    sys_nosys },			/* 151 = unimplemented */
	{ 0, 0,
	    sys_nosys },			/* 152 = unimplemented modctl */
	{ 1, s(struct sys_fchroot_args),
	    sys_fchroot },			/* 153 = fchroot */
	{ 2, s(struct svr4_32_sys_utimes_args),
	    svr4_32_sys_utimes },		/* 154 = utimes */
	{ 0, 0,
	    svr4_32_sys_vhangup },		/* 155 = vhangup */
	{ 1, s(struct svr4_32_sys_gettimeofday_args),
	    svr4_32_sys_gettimeofday },		/* 156 = gettimeofday */
	{ 2, s(struct netbsd32_getitimer_args),
	    netbsd32_getitimer },		/* 157 = netbsd32_getitimer */
	{ 3, s(struct netbsd32_setitimer_args),
	    netbsd32_setitimer },		/* 158 = netbsd32_setitimer */
	{ 3, s(struct svr4_32_sys__lwp_create_args),
	    svr4_32_sys__lwp_create },		/* 159 = _lwp_create */
	{ 0, 0,
	    svr4_32_sys__lwp_exit },		/* 160 = _lwp_exit */
	{ 1, s(struct svr4_32_sys__lwp_suspend_args),
	    svr4_32_sys__lwp_suspend },		/* 161 = _lwp_suspend */
	{ 1, s(struct svr4_32_sys__lwp_continue_args),
	    svr4_32_sys__lwp_continue },	/* 162 = _lwp_continue */
	{ 2, s(struct svr4_32_sys__lwp_kill_args),
	    svr4_32_sys__lwp_kill },		/* 163 = _lwp_kill */
	{ 0, 0,
	    svr4_sys__lwp_self },		/* 164 = _lwp_self */
	{ 0, 0,
	    svr4_32_sys__lwp_getprivate },	/* 165 = _lwp_getprivate */
	{ 1, s(struct svr4_32_sys__lwp_setprivate_args),
	    svr4_32_sys__lwp_setprivate },	/* 166 = _lwp_setprivate */
	{ 2, s(struct svr4_32_sys__lwp_wait_args),
	    svr4_32_sys__lwp_wait },		/* 167 = _lwp_wait */
	{ 0, 0,
	    sys_nosys },			/* 168 = unimplemented lwp_mutex_unlock */
	{ 0, 0,
	    sys_nosys },			/* 169 = unimplemented lwp_mutex_lock */
	{ 0, 0,
	    sys_nosys },			/* 170 = unimplemented lwp_cond_wait */
	{ 0, 0,
	    sys_nosys },			/* 171 = unimplemented lwp_cond_signal */
	{ 0, 0,
	    sys_nosys },			/* 172 = unimplemented lwp_cond_broadcast */
	{ 4, s(struct svr4_32_sys_pread_args),
	    svr4_32_sys_pread },		/* 173 = pread */
	{ 4, s(struct svr4_32_sys_pwrite_args),
	    svr4_32_sys_pwrite },		/* 174 = pwrite */
	{ 4, s(struct svr4_32_sys_llseek_args),
	    svr4_32_sys_llseek },		/* 175 = llseek */
	{ 0, 0,
	    sys_nosys },			/* 176 = unimplemented inst_sync */
	{ 0, 0,
	    sys_nosys },			/* 177 = unimplemented */
	{ 0, 0,
	    sys_nosys },			/* 178 = unimplemented kaio */
	{ 0, 0,
	    sys_nosys },			/* 179 = unimplemented */
	{ 0, 0,
	    sys_nosys },			/* 180 = unimplemented */
	{ 0, 0,
	    sys_nosys },			/* 181 = unimplemented */
	{ 0, 0,
	    sys_nosys },			/* 182 = unimplemented */
	{ 0, 0,
	    sys_nosys },			/* 183 = unimplemented */
	{ 0, 0,
	    sys_nosys },			/* 184 = unimplemented tsolsys */
	{ 4, s(struct svr4_32_sys_acl_args),
	    svr4_32_sys_acl },			/* 185 = acl */
	{ 6, s(struct svr4_32_sys_auditsys_args),
	    svr4_32_sys_auditsys },		/* 186 = auditsys */
	{ 0, 0,
	    sys_nosys },			/* 187 = unimplemented processor_bind */
	{ 0, 0,
	    sys_nosys },			/* 188 = unimplemented processor_info */
	{ 0, 0,
	    sys_nosys },			/* 189 = unimplemented p_online */
	{ 0, 0,
	    sys_nosys },			/* 190 = unimplemented sigqueue */
	{ 0, 0,
	    sys_nosys },			/* 191 = unimplemented clock_gettime */
	{ 0, 0,
	    sys_nosys },			/* 192 = unimplemented clock_settime */
	{ 0, 0,
	    sys_nosys },			/* 193 = unimplemented clock_getres */
	{ 0, 0,
	    sys_nosys },			/* 194 = unimplemented timer_create */
	{ 0, 0,
	    sys_nosys },			/* 195 = unimplemented timer_delete */
	{ 0, 0,
	    sys_nosys },			/* 196 = unimplemented timer_settime */
	{ 0, 0,
	    sys_nosys },			/* 197 = unimplemented timer_gettime */
	{ 0, 0,
	    sys_nosys },			/* 198 = unimplemented timer_getoverrun */
	{ 2, s(struct netbsd32_nanosleep_args),
	    netbsd32_nanosleep },		/* 199 = netbsd32_nanosleep */
	{ 4, s(struct svr4_32_sys_facl_args),
	    svr4_32_sys_facl },			/* 200 = facl */
	{ 0, 0,
	    sys_nosys },			/* 201 = unimplemented door */
	{ 2, s(struct sys_setreuid_args),
	    sys_setreuid },			/* 202 = setreuid */
	{ 2, s(struct sys_setregid_args),
	    sys_setregid },			/* 203 = setregid */
	{ 0, 0,
	    sys_nosys },			/* 204 = unimplemented install_utrap */
	{ 0, 0,
	    sys_nosys },			/* 205 = unimplemented signotify */
	{ 0, 0,
	    sys_nosys },			/* 206 = unimplemented schedctl */
	{ 0, 0,
	    sys_nosys },			/* 207 = unimplemented pset */
	{ 0, 0,
	    sys_nosys },			/* 208 = unimplemented */
	{ 3, s(struct svr4_32_sys_resolvepath_args),
	    svr4_32_sys_resolvepath },		/* 209 = resolvepath */
	{ 0, 0,
	    sys_nosys },			/* 210 = unimplemented signotifywait */
	{ 0, 0,
	    sys_nosys },			/* 211 = unimplemented lwp_sigredirect */
	{ 0, 0,
	    sys_nosys },			/* 212 = unimplemented lwp_alarm */
	{ 3, s(struct svr4_32_sys_getdents64_args),
	    svr4_32_sys_getdents64 },		/* 213 = getdents64 */
	{ 6, s(struct svr4_32_sys_mmap64_args),
	    svr4_32_sys_mmap64 },		/* 214 = mmap64 */
	{ 2, s(struct svr4_32_sys_stat64_args),
	    svr4_32_sys_stat64 },		/* 215 = stat64 */
	{ 2, s(struct svr4_32_sys_lstat64_args),
	    svr4_32_sys_lstat64 },		/* 216 = lstat64 */
	{ 2, s(struct svr4_32_sys_fstat64_args),
	    svr4_32_sys_fstat64 },		/* 217 = fstat64 */
	{ 2, s(struct svr4_32_sys_statvfs64_args),
	    svr4_32_sys_statvfs64 },		/* 218 = statvfs64 */
	{ 2, s(struct svr4_32_sys_fstatvfs64_args),
	    svr4_32_sys_fstatvfs64 },		/* 219 = fstatvfs64 */
	{ 2, s(struct svr4_32_sys_setrlimit64_args),
	    svr4_32_sys_setrlimit64 },		/* 220 = setrlimit64 */
	{ 2, s(struct svr4_32_sys_getrlimit64_args),
	    svr4_32_sys_getrlimit64 },		/* 221 = getrlimit64 */
	{ 4, s(struct svr4_32_sys_pread64_args),
	    svr4_32_sys_pread64 },		/* 222 = pread64 */
	{ 4, s(struct svr4_32_sys_pwrite64_args),
	    svr4_32_sys_pwrite64 },		/* 223 = pwrite64 */
	{ 2, s(struct svr4_32_sys_creat64_args),
	    svr4_32_sys_creat64 },		/* 224 = creat64 */
	{ 3, s(struct svr4_32_sys_open64_args),
	    svr4_32_sys_open64 },		/* 225 = open64 */
	{ 0, 0,
	    sys_nosys },			/* 226 = unimplemented rpcsys */
	{ 0, 0,
	    sys_nosys },			/* 227 = unimplemented */
	{ 0, 0,
	    sys_nosys },			/* 228 = unimplemented */
	{ 0, 0,
	    sys_nosys },			/* 229 = unimplemented */
	{ 3, s(struct svr4_32_sys_socket_args),
	    svr4_32_sys_socket },		/* 230 = socket */
	{ 4, s(struct netbsd32_socketpair_args),
	    netbsd32_socketpair },		/* 231 = netbsd32_socketpair */
	{ 3, s(struct netbsd32_bind_args),
	    netbsd32_bind },			/* 232 = netbsd32_bind */
	{ 2, s(struct sys_listen_args),
	    sys_listen },			/* 233 = listen */
	{ 3, s(struct compat_43_sys_accept_args),
	    compat_43_sys_accept },		/* 234 = accept */
	{ 3, s(struct netbsd32_connect_args),
	    netbsd32_connect },			/* 235 = netbsd32_connect */
	{ 2, s(struct sys_shutdown_args),
	    sys_shutdown },			/* 236 = shutdown */
	{ 4, s(struct compat_43_sys_recv_args),
	    compat_43_sys_recv },		/* 237 = recv */
	{ 6, s(struct compat_43_sys_recvfrom_args),
	    compat_43_sys_recvfrom },		/* 238 = recvfrom */
	{ 3, s(struct compat_43_sys_recvmsg_args),
	    compat_43_sys_recvmsg },		/* 239 = recvmsg */
	{ 4, s(struct compat_43_sys_send_args),
	    compat_43_sys_send },		/* 240 = send */
	{ 3, s(struct compat_43_sys_sendmsg_args),
	    compat_43_sys_sendmsg },		/* 241 = sendmsg */
	{ 6, s(struct netbsd32_sendto_args),
	    netbsd32_sendto },			/* 242 = netbsd32_sendto */
	{ 3, s(struct compat_43_sys_getpeername_args),
	    compat_43_sys_getpeername },	/* 243 = getpeername */
	{ 3, s(struct compat_43_sys_getsockname_args),
	    compat_43_sys_getsockname },	/* 244 = getsockname */
	{ 5, s(struct netbsd32_getsockopt_args),
	    netbsd32_getsockopt },		/* 245 = netbsd32_getsockopt */
	{ 5, s(struct netbsd32_setsockopt_args),
	    netbsd32_setsockopt },		/* 246 = netbsd32_setsockopt */
	{ 0, 0,
	    sys_nosys },			/* 247 = unimplemented sockconfig */
	{ 1, s(struct netbsd32_ntp_gettime_args),
	    netbsd32_ntp_gettime },		/* 248 = netbsd32_ntp_gettime */
#if defined(NTP) || !defined(_KERNEL)
	{ 1, s(struct netbsd32_ntp_adjtime_args),
	    netbsd32_ntp_adjtime },		/* 249 = netbsd32_ntp_adjtime */
#else
	{ 0, 0,
	    sys_nosys },			/* 249 = excluded ntp_adjtime */
#endif
	{ 0, 0,
	    sys_nosys },			/* 250 = filler */
	{ 0, 0,
	    sys_nosys },			/* 251 = filler */
	{ 0, 0,
	    sys_nosys },			/* 252 = filler */
	{ 0, 0,
	    sys_nosys },			/* 253 = filler */
	{ 0, 0,
	    sys_nosys },			/* 254 = filler */
	{ 0, 0,
	    sys_nosys },			/* 255 = filler */
};

