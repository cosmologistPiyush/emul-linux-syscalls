/*
 * System call numbers.
 *
 * DO NOT EDIT-- this file is automatically generated.
 * created from	NetBSD: syscalls.master,v 1.23 1994/11/25 23:59:31 deraadt Exp 
 */

#define	SUNOS_SYS_syscall	0
#define	SUNOS_SYS_exit	1
#define	SUNOS_SYS_fork	2
#define	SUNOS_SYS_read	3
#define	SUNOS_SYS_write	4
#define	SUNOS_SYS_sunos_open	5
#define	SUNOS_SYS_close	6
#define	SUNOS_SYS_sunos_wait4	7
#define	SUNOS_SYS_sunos_creat	8
#define	SUNOS_SYS_link	9
#define	SUNOS_SYS_unlink	10
#define	SUNOS_SYS_sunos_execv	11
#define	SUNOS_SYS_chdir	12
				/* 13 is obsolete time */
#define	SUNOS_SYS_sunos_mknod	14
#define	SUNOS_SYS_chmod	15
#define	SUNOS_SYS_chown	16
#define	SUNOS_SYS_break	17
				/* 18 is obsolete stat */
#define	SUNOS_SYS_compat_43_lseek	19
#define	SUNOS_SYS_getpid	20
				/* 21 is obsolete sunos_old_mount */
#define	SUNOS_SYS_setuid	23
#define	SUNOS_SYS_getuid	24
#define	SUNOS_SYS_sunos_ptrace	26
#define	SUNOS_SYS_access	33
#define	SUNOS_SYS_sync	36
#define	SUNOS_SYS_kill	37
#define	SUNOS_SYS_compat_43_stat	38
#define	SUNOS_SYS_compat_43_lstat	40
#define	SUNOS_SYS_dup	41
#define	SUNOS_SYS_pipe	42
#define	SUNOS_SYS_profil	44
#define	SUNOS_SYS_setgid	46
#define	SUNOS_SYS_getgid	47
#define	SUNOS_SYS_acct	51
#define	SUNOS_SYS_sunos_mctl	53
#define	SUNOS_SYS_sunos_ioctl	54
#define	SUNOS_SYS_reboot	55
				/* 56 is obsolete sunos_owait3 */
#define	SUNOS_SYS_symlink	57
#define	SUNOS_SYS_readlink	58
#define	SUNOS_SYS_execve	59
#define	SUNOS_SYS_umask	60
#define	SUNOS_SYS_chroot	61
#define	SUNOS_SYS_compat_43_fstat	62
#define	SUNOS_SYS_compat_43_getpagesize	64
#define	SUNOS_SYS_sunos_omsync	65
#define	SUNOS_SYS_vfork	66
				/* 67 is obsolete vread */
				/* 68 is obsolete vwrite */
#define	SUNOS_SYS_sbrk	69
#define	SUNOS_SYS_sstk	70
#define	SUNOS_SYS_sunos_mmap	71
#define	SUNOS_SYS_vadvise	72
#define	SUNOS_SYS_munmap	73
#define	SUNOS_SYS_mprotect	74
#define	SUNOS_SYS_madvise	75
#define	SUNOS_SYS_sunos_vhangup	76
#define	SUNOS_SYS_mincore	78
#define	SUNOS_SYS_getgroups	79
#define	SUNOS_SYS_setgroups	80
#define	SUNOS_SYS_getpgrp	81
#define	SUNOS_SYS_sunos_setpgid	82
#define	SUNOS_SYS_setitimer	83
#define	SUNOS_SYS_swapon	85
#define	SUNOS_SYS_getitimer	86
#define	SUNOS_SYS_compat_43_gethostname	87
#define	SUNOS_SYS_compat_43_sethostname	88
#define	SUNOS_SYS_compat_43_getdtablesize	89
#define	SUNOS_SYS_dup2	90
#define	SUNOS_SYS_fcntl	92
#define	SUNOS_SYS_select	93
#define	SUNOS_SYS_fsync	95
#define	SUNOS_SYS_setpriority	96
#define	SUNOS_SYS_socket	97
#define	SUNOS_SYS_connect	98
#define	SUNOS_SYS_compat_43_accept	99
#define	SUNOS_SYS_getpriority	100
#define	SUNOS_SYS_compat_43_send	101
#define	SUNOS_SYS_compat_43_recv	102
#define	SUNOS_SYS_bind	104
#define	SUNOS_SYS_sunos_setsockopt	105
#define	SUNOS_SYS_listen	106
#define	SUNOS_SYS_compat_43_sigvec	108
#define	SUNOS_SYS_compat_43_sigblock	109
#define	SUNOS_SYS_compat_43_sigsetmask	110
#define	SUNOS_SYS_sigsuspend	111
#define	SUNOS_SYS_compat_43_sigstack	112
#define	SUNOS_SYS_compat_43_recvmsg	113
#define	SUNOS_SYS_compat_43_sendmsg	114
				/* 115 is obsolete vtrace */
#define	SUNOS_SYS_gettimeofday	116
#define	SUNOS_SYS_getrusage	117
#define	SUNOS_SYS_getsockopt	118
#define	SUNOS_SYS_readv	120
#define	SUNOS_SYS_writev	121
#define	SUNOS_SYS_settimeofday	122
#define	SUNOS_SYS_fchown	123
#define	SUNOS_SYS_fchmod	124
#define	SUNOS_SYS_compat_43_recvfrom	125
#define	SUNOS_SYS_compat_43_setreuid	126
#define	SUNOS_SYS_compat_43_setregid	127
#define	SUNOS_SYS_rename	128
#define	SUNOS_SYS_compat_43_truncate	129
#define	SUNOS_SYS_compat_43_ftruncate	130
#define	SUNOS_SYS_flock	131
#define	SUNOS_SYS_sendto	133
#define	SUNOS_SYS_shutdown	134
#define	SUNOS_SYS_socketpair	135
#define	SUNOS_SYS_mkdir	136
#define	SUNOS_SYS_rmdir	137
#define	SUNOS_SYS_utimes	138
#define	SUNOS_SYS_sigreturn	139
#define	SUNOS_SYS_adjtime	140
#define	SUNOS_SYS_compat_43_getpeername	141
#define	SUNOS_SYS_compat_43_gethostid	142
#define	SUNOS_SYS_sunos_getrlimit	144
#define	SUNOS_SYS_sunos_setrlimit	145
#define	SUNOS_SYS_compat_43_killpg	146
#define	SUNOS_SYS_compat_43_getsockname	150
#define	SUNOS_SYS_sunos_poll	153
#define	SUNOS_SYS_sunos_nfssvc	155
#define	SUNOS_SYS_getdirentries	156
#define	SUNOS_SYS_sunos_statfs	157
#define	SUNOS_SYS_sunos_fstatfs	158
#define	SUNOS_SYS_sunos_unmount	159
#define	SUNOS_SYS_async_daemon	160
#define	SUNOS_SYS_getfh	161
#define	SUNOS_SYS_compat_09_getdomainname	162
#define	SUNOS_SYS_compat_09_setdomainname	163
#define	SUNOS_SYS_sunos_quotactl	165
#define	SUNOS_SYS_sunos_exportfs	166
#define	SUNOS_SYS_sunos_mount	167
#define	SUNOS_SYS_sunos_ustat	168
#define	SUNOS_SYS_semsys	169
#define	SUNOS_SYS_msgsys	170
#define	SUNOS_SYS_shmsys	171
#define	SUNOS_SYS_sunos_auditsys	172
#define	SUNOS_SYS_sunos_getdents	174
#define	SUNOS_SYS_setsid	175
#define	SUNOS_SYS_fchdir	176
#define	SUNOS_SYS_sunos_fchroot	177
#define	SUNOS_SYS_sunos_sigpending	183
#define	SUNOS_SYS_setpgid	185
#define	SUNOS_SYS_pathconf	186
#define	SUNOS_SYS_fpathconf	187
#define	SUNOS_SYS_sunos_sysconf	188
#define	SUNOS_SYS_sunos_uname	189
