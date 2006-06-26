/* $NetBSD: ultrix_syscallargs.h,v 1.45 2006/06/26 21:30:50 mrg Exp $ */

/*
 * System call argument lists.
 *
 * DO NOT EDIT-- this file is automatically generated.
 * created from	NetBSD: syscalls.master,v 1.41 2006/06/26 21:23:58 mrg Exp
 */

#ifndef _ULTRIX_SYS_SYSCALLARGS_H_
#define	_ULTRIX_SYS_SYSCALLARGS_H_

#ifdef	syscallarg
#undef	syscallarg
#endif

#define	syscallarg(x)							\
	union {								\
		register_t pad;						\
		struct { x datum; } le;					\
		struct { /* LINTED zero array dimension */		\
			int8_t pad[  /* CONSTCOND */			\
				(sizeof (register_t) < sizeof (x))	\
				? 0					\
				: sizeof (register_t) - sizeof (x)];	\
			x datum;					\
		} be;							\
	}

struct ultrix_sys_open_args {
	syscallarg(const char *) path;
	syscallarg(int) flags;
	syscallarg(int) mode;
};

struct ultrix_sys_creat_args {
	syscallarg(const char *) path;
	syscallarg(int) mode;
};

struct ultrix_sys_execv_args {
	syscallarg(const char *) path;
	syscallarg(char **) argp;
};

struct ultrix_sys_mknod_args {
	syscallarg(const char *) path;
	syscallarg(int) mode;
	syscallarg(int) dev;
};

struct ultrix_sys_mount_args {
	syscallarg(char *) special;
	syscallarg(char *) dir;
	syscallarg(int) rdonly;
	syscallarg(int) type;
	syscallarg(caddr_t) data;
};

struct ultrix_sys_access_args {
	syscallarg(const char *) path;
	syscallarg(int) flags;
};

struct ultrix_sys_stat_args {
	syscallarg(const char *) path;
	syscallarg(struct stat43 *) ub;
};

struct ultrix_sys_lstat_args {
	syscallarg(const char *) path;
	syscallarg(struct stat43 *) ub;
};

struct ultrix_sys_ioctl_args {
	syscallarg(int) fd;
	syscallarg(u_long) com;
	syscallarg(caddr_t) data;
};

struct ultrix_sys_execve_args {
	syscallarg(const char *) path;
	syscallarg(char **) argp;
	syscallarg(char **) envp;
};

struct ultrix_sys_mmap_args {
	syscallarg(caddr_t) addr;
	syscallarg(size_t) len;
	syscallarg(int) prot;
	syscallarg(u_int) flags;
	syscallarg(int) fd;
	syscallarg(long) pos;
};

struct ultrix_sys_setpgrp_args {
	syscallarg(int) pid;
	syscallarg(int) pgid;
};

struct ultrix_sys_wait3_args {
	syscallarg(int *) status;
	syscallarg(int) options;
	syscallarg(struct rusage *) rusage;
};

struct ultrix_sys_fcntl_args {
	syscallarg(int) fd;
	syscallarg(int) cmd;
	syscallarg(void *) arg;
};

struct ultrix_sys_select_args {
	syscallarg(u_int) nd;
	syscallarg(fd_set *) in;
	syscallarg(fd_set *) ou;
	syscallarg(fd_set *) ex;
	syscallarg(struct timeval *) tv;
};

struct ultrix_sys_sigreturn_args {
	syscallarg(struct sigcontext *) sigcntxp;
};

struct ultrix_sys_setsockopt_args {
	syscallarg(int) s;
	syscallarg(int) level;
	syscallarg(int) name;
	syscallarg(caddr_t) val;
	syscallarg(int) valsize;
};

struct ultrix_sys_sigvec_args {
	syscallarg(int) signum;
	syscallarg(struct sigvec *) nsv;
	syscallarg(struct sigvec *) osv;
};

struct ultrix_sys_sigsuspend_args {
	syscallarg(int) mask;
};

struct ultrix_sys_sigcleanup_args {
	syscallarg(struct sigcontext *) sigcntxp;
};
#ifdef __mips

struct ultrix_sys_cacheflush_args {
	syscallarg(char *) addr;
	syscallarg(int) nbytes;
	syscallarg(int) whichcache;
};

struct ultrix_sys_cachectl_args {
	syscallarg(char *) addr;
	syscallarg(int) nbytes;
	syscallarg(int) cacheop;
};
#else	/* !mips */
#endif	/* !mips */
#ifdef NFSSERVER

struct ultrix_sys_nfssvc_args {
	syscallarg(int) fd;
};
#else
#endif

struct ultrix_sys_statfs_args {
	syscallarg(const char *) path;
	syscallarg(struct ultrix_statfs *) buf;
};

struct ultrix_sys_fstatfs_args {
	syscallarg(int) fd;
	syscallarg(struct ultrix_statfs *) buf;
};
#ifdef NFS
#else
#endif

struct ultrix_sys_quotactl_args {
	syscallarg(int) cmd;
	syscallarg(char *) special;
	syscallarg(int) uid;
	syscallarg(caddr_t) addr;
};

struct ultrix_sys_exportfs_args {
	syscallarg(char *) path;
	syscallarg(char *) ex;
};

struct ultrix_sys_uname_args {
	syscallarg(struct ultrix_utsname *) name;
};

struct ultrix_sys_shmsys_args {
	syscallarg(u_int) shmop;
	syscallarg(u_int) a2;
	syscallarg(u_int) a3;
	syscallarg(u_int) a4;
};

struct ultrix_sys_ustat_args {
	syscallarg(int) dev;
	syscallarg(struct ultrix_ustat *) buf;
};

struct ultrix_sys_getmnt_args {
	syscallarg(int *) start;
	syscallarg(struct ultrix_fs_data *) buf;
	syscallarg(int) bufsize;
	syscallarg(int) mode;
	syscallarg(char *) path;
};

struct ultrix_sys_sigpending_args {
	syscallarg(int *) mask;
};

struct ultrix_sys_waitpid_args {
	syscallarg(int) pid;
	syscallarg(int *) status;
	syscallarg(int) options;
};

struct ultrix_sys_getsysinfo_args {
	syscallarg(unsigned) op;
	syscallarg(char *) buffer;
	syscallarg(unsigned) nbytes;
	syscallarg(int *) start;
	syscallarg(char *) arg;
};

struct ultrix_sys_setsysinfo_args {
	syscallarg(unsigned) op;
	syscallarg(char *) buffer;
	syscallarg(unsigned) nbytes;
	syscallarg(unsigned) arg;
	syscallarg(unsigned) flag;
};

/*
 * System call prototypes.
 */

int	sys_nosys(struct lwp *, void *, register_t *);

int	sys_exit(struct lwp *, void *, register_t *);

int	sys_fork(struct lwp *, void *, register_t *);

int	sys_read(struct lwp *, void *, register_t *);

int	sys_write(struct lwp *, void *, register_t *);

int	ultrix_sys_open(struct lwp *, void *, register_t *);

int	sys_close(struct lwp *, void *, register_t *);

int	compat_43_sys_wait(struct lwp *, void *, register_t *);

int	ultrix_sys_creat(struct lwp *, void *, register_t *);

int	sys_link(struct lwp *, void *, register_t *);

int	sys_unlink(struct lwp *, void *, register_t *);

int	ultrix_sys_execv(struct lwp *, void *, register_t *);

int	sys_chdir(struct lwp *, void *, register_t *);

int	ultrix_sys_mknod(struct lwp *, void *, register_t *);

int	sys_chmod(struct lwp *, void *, register_t *);

int	sys___posix_chown(struct lwp *, void *, register_t *);

int	sys_obreak(struct lwp *, void *, register_t *);

int	compat_43_sys_lseek(struct lwp *, void *, register_t *);

int	sys_getpid(struct lwp *, void *, register_t *);

int	ultrix_sys_mount(struct lwp *, void *, register_t *);

int	sys_setuid(struct lwp *, void *, register_t *);

int	sys_getuid(struct lwp *, void *, register_t *);

int	ultrix_sys_access(struct lwp *, void *, register_t *);

int	sys_sync(struct lwp *, void *, register_t *);

int	sys_kill(struct lwp *, void *, register_t *);

int	ultrix_sys_stat(struct lwp *, void *, register_t *);

int	ultrix_sys_lstat(struct lwp *, void *, register_t *);

int	sys_dup(struct lwp *, void *, register_t *);

int	sys_pipe(struct lwp *, void *, register_t *);

int	sys_profil(struct lwp *, void *, register_t *);

int	sys_getgid(struct lwp *, void *, register_t *);

int	sys_acct(struct lwp *, void *, register_t *);

int	ultrix_sys_ioctl(struct lwp *, void *, register_t *);

int	sys_reboot(struct lwp *, void *, register_t *);

int	sys_symlink(struct lwp *, void *, register_t *);

int	sys_readlink(struct lwp *, void *, register_t *);

int	ultrix_sys_execve(struct lwp *, void *, register_t *);

int	sys_umask(struct lwp *, void *, register_t *);

int	sys_chroot(struct lwp *, void *, register_t *);

int	compat_43_sys_fstat(struct lwp *, void *, register_t *);

int	compat_43_sys_getpagesize(struct lwp *, void *, register_t *);

int	sys_vfork(struct lwp *, void *, register_t *);

int	sys_sbrk(struct lwp *, void *, register_t *);

int	sys_sstk(struct lwp *, void *, register_t *);

int	ultrix_sys_mmap(struct lwp *, void *, register_t *);

int	sys_ovadvise(struct lwp *, void *, register_t *);

int	sys_munmap(struct lwp *, void *, register_t *);

int	sys_mprotect(struct lwp *, void *, register_t *);

int	sys_madvise(struct lwp *, void *, register_t *);

int	ultrix_sys_vhangup(struct lwp *, void *, register_t *);

int	sys_mincore(struct lwp *, void *, register_t *);

int	sys_getgroups(struct lwp *, void *, register_t *);

int	sys_setgroups(struct lwp *, void *, register_t *);

int	sys_getpgrp(struct lwp *, void *, register_t *);

int	ultrix_sys_setpgrp(struct lwp *, void *, register_t *);

int	sys_setitimer(struct lwp *, void *, register_t *);

int	ultrix_sys_wait3(struct lwp *, void *, register_t *);

int	compat_12_sys_swapon(struct lwp *, void *, register_t *);

int	sys_getitimer(struct lwp *, void *, register_t *);

int	compat_43_sys_gethostname(struct lwp *, void *, register_t *);

int	compat_43_sys_sethostname(struct lwp *, void *, register_t *);

int	compat_43_sys_getdtablesize(struct lwp *, void *, register_t *);

int	sys_dup2(struct lwp *, void *, register_t *);

int	ultrix_sys_fcntl(struct lwp *, void *, register_t *);

int	ultrix_sys_select(struct lwp *, void *, register_t *);

int	sys_fsync(struct lwp *, void *, register_t *);

int	sys_setpriority(struct lwp *, void *, register_t *);

int	compat_30_sys_socket(struct lwp *, void *, register_t *);

int	sys_connect(struct lwp *, void *, register_t *);

int	compat_43_sys_accept(struct lwp *, void *, register_t *);

int	sys_getpriority(struct lwp *, void *, register_t *);

int	compat_43_sys_send(struct lwp *, void *, register_t *);

int	compat_43_sys_recv(struct lwp *, void *, register_t *);

int	ultrix_sys_sigreturn(struct lwp *, void *, register_t *);

int	sys_bind(struct lwp *, void *, register_t *);

int	ultrix_sys_setsockopt(struct lwp *, void *, register_t *);

int	sys_listen(struct lwp *, void *, register_t *);

int	ultrix_sys_sigvec(struct lwp *, void *, register_t *);

int	compat_43_sys_sigblock(struct lwp *, void *, register_t *);

int	compat_43_sys_sigsetmask(struct lwp *, void *, register_t *);

int	ultrix_sys_sigsuspend(struct lwp *, void *, register_t *);

int	compat_43_sys_sigstack(struct lwp *, void *, register_t *);

int	compat_43_sys_recvmsg(struct lwp *, void *, register_t *);

int	compat_43_sys_sendmsg(struct lwp *, void *, register_t *);

int	sys_gettimeofday(struct lwp *, void *, register_t *);

int	sys_getrusage(struct lwp *, void *, register_t *);

int	sys_getsockopt(struct lwp *, void *, register_t *);

int	sys_readv(struct lwp *, void *, register_t *);

int	sys_writev(struct lwp *, void *, register_t *);

int	sys_settimeofday(struct lwp *, void *, register_t *);

int	sys___posix_fchown(struct lwp *, void *, register_t *);

int	sys_fchmod(struct lwp *, void *, register_t *);

int	compat_43_sys_recvfrom(struct lwp *, void *, register_t *);

int	sys_setreuid(struct lwp *, void *, register_t *);

int	sys_setregid(struct lwp *, void *, register_t *);

int	sys_rename(struct lwp *, void *, register_t *);

int	compat_43_sys_truncate(struct lwp *, void *, register_t *);

int	compat_43_sys_ftruncate(struct lwp *, void *, register_t *);

int	sys_flock(struct lwp *, void *, register_t *);

int	sys_sendto(struct lwp *, void *, register_t *);

int	sys_shutdown(struct lwp *, void *, register_t *);

int	sys_socketpair(struct lwp *, void *, register_t *);

int	sys_mkdir(struct lwp *, void *, register_t *);

int	sys_rmdir(struct lwp *, void *, register_t *);

int	sys_utimes(struct lwp *, void *, register_t *);

int	ultrix_sys_sigcleanup(struct lwp *, void *, register_t *);

int	sys_adjtime(struct lwp *, void *, register_t *);

int	compat_43_sys_getpeername(struct lwp *, void *, register_t *);

int	compat_43_sys_gethostid(struct lwp *, void *, register_t *);

int	compat_43_sys_getrlimit(struct lwp *, void *, register_t *);

int	compat_43_sys_setrlimit(struct lwp *, void *, register_t *);

int	compat_43_sys_killpg(struct lwp *, void *, register_t *);

int	compat_43_sys_getsockname(struct lwp *, void *, register_t *);

#ifdef __mips
int	ultrix_sys_cacheflush(struct lwp *, void *, register_t *);

int	ultrix_sys_cachectl(struct lwp *, void *, register_t *);

#else	/* !mips */
#endif	/* !mips */
#ifdef NFSSERVER
int	ultrix_sys_nfssvc(struct lwp *, void *, register_t *);

#else
#endif
int	compat_43_sys_getdirentries(struct lwp *, void *, register_t *);

int	ultrix_sys_statfs(struct lwp *, void *, register_t *);

int	ultrix_sys_fstatfs(struct lwp *, void *, register_t *);

#ifdef NFS
int	async_daemon(struct lwp *, void *, register_t *);

int	sys_getfh(struct lwp *, void *, register_t *);

#else
#endif
int	compat_09_sys_getdomainname(struct lwp *, void *, register_t *);

int	compat_09_sys_setdomainname(struct lwp *, void *, register_t *);

int	ultrix_sys_quotactl(struct lwp *, void *, register_t *);

int	ultrix_sys_exportfs(struct lwp *, void *, register_t *);

int	ultrix_sys_uname(struct lwp *, void *, register_t *);

int	ultrix_sys_shmsys(struct lwp *, void *, register_t *);

int	ultrix_sys_ustat(struct lwp *, void *, register_t *);

int	ultrix_sys_getmnt(struct lwp *, void *, register_t *);

int	ultrix_sys_sigpending(struct lwp *, void *, register_t *);

int	sys_setsid(struct lwp *, void *, register_t *);

int	ultrix_sys_waitpid(struct lwp *, void *, register_t *);

int	ultrix_sys_getsysinfo(struct lwp *, void *, register_t *);

int	ultrix_sys_setsysinfo(struct lwp *, void *, register_t *);

#endif /* _ULTRIX_SYS_SYSCALLARGS_H_ */
