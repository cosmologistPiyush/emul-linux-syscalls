/*
 * Copyright (c) 1997 Erez Zadok
 * Copyright (c) 1990 Jan-Simon Pendry
 * Copyright (c) 1990 Imperial College of Science, Technology & Medicine
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Jan-Simon Pendry at Imperial College, London.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      %W% (Berkeley) %G%
 *
 * $Id: am_defs.h,v 1.3 1997/09/22 22:11:05 christos Exp $
 *
 */

/*
 * Definitions that are not specific to the am-utils package, but
 * are rather generic, and can be used elsewhere.
 */

#ifndef _AM_DEFS_H
#define _AM_DEFS_H

/*
 * Actions to take if ANSI C.
 */
#if STDC_HEADERS
# include <string.h>
/* for function prototypes */
# define P(x) x
# define P_void void
#else /* not STDC_HEADERS */
/* empty function prototypes */
# define P(x) ()
# define P_void
# ifndef HAVE_STRCHR
#  define strchr index
#  define strrchr rindex
# endif /* not HAVE_STRCHR */
char *strchr(), *strrchr(), *strdup();
#endif /* not STDC_HEADERS */

/*
 * How to handle signals of any type
 */
#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif /* HAVE_SYS_WAIT_H */
#ifndef WEXITSTATUS
# define WEXITSTATUS(stat_val) ((unsigned)(stat_val) >> 8)
#endif /* not WEXITSTATUS */
#ifndef WIFEXITED
# define WIFEXITED(stat_val) (((stat_val) & 255) == 0)
#endif /* not WIFEXITED */

/*
 * Actions to take regarding <time.h> and <sys/time.h>.
 */
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else /* not TIME_WITH_SYS_TIME */
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else /* not HAVE_SYS_TIME_H */
#  include <time.h>
# endif /* not HAVE_SYS_TIME_H */
#endif /* not TIME_WITH_SYS_TIME */

/*
 * Actions to take if <machine/endian.h> exists.
 */
#ifdef HAVE_MACHINE_ENDIAN_H
# include <machine/endian.h>
#endif /* HAVE_MACHINE_ENDIAN_H */

/*
 * Big-endian or little-endian?
 */
#ifdef WORDS_BIGENDIAN
# define ARCH_ENDIAN "big"
#else /* not WORDS_BIGENDIAN */
# define ARCH_ENDIAN "little"
#endif /* not WORDS_BIGENDIAN */

/*
 * Actions to take if HAVE_SYS_TYPES_H is defined.
 */
#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif /* HAVE_SYS_TYPES_H */

/*
 * Actions to take if HAVE_UNISTD_H is defined.
 */
#if HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */

/* after <unistd.h>, check if this is a POSIX.1 system */
#ifdef _POSIX_VERSION
/* Code for POSIX.1 systems. */
#endif /* _POSIX_VERSION */

/*
 * Variable length argument lists.
 * Use one of the two.
 */
#ifdef HAVE_STDARG_H
# include <stdarg.h>
#else /* not HAVE_STDARG_H */
# ifdef HAVE_VARARGS_H
#  include <varargs.h>
# endif /* HAVE_VARARGS_H */
#endif /* not HAVE_STDARG_H */

/*
 * Pick the right header file and macros for directory processing functions.
 */
#if HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else /* not HAVE_DIRENT_H */
# define dirent direct
# define NAMLEN(dirent) (dirent)->d_namlen
# if HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif /* HAVE_SYS_NDIR_H */
# if HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif /* HAVE_SYS_DIR_H */
# if HAVE_NDIR_H
#  include <ndir.h>
# endif /* HAVE_NDIR_H */
#endif /* not HAVE_DIRENT_H */

/*
 * Actions to take if HAVE_FCNTL_H is defined.
 */
#if HAVE_FCNTL_H
# include <fcntl.h>
#endif /* HAVE_FCNTL_H */

/*
 * Actions to take if HAVE_MEMORY_H is defined.
 */
#if HAVE_MEMORY_H
# include <memory.h>
#endif /* HAVE_MEMORY_H */

/*
 * Actions to take if HAVE_SYS_FILE_H is defined.
 */
#if HAVE_SYS_FILE_H
# include <sys/file.h>
#endif /* HAVE_SYS_FILE_H */

/*
 * Actions to take if HAVE_SYS_IOCTL_H is defined.
 */
#if HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#endif /* HAVE_SYS_IOCTL_H */

/*
 * Actions to take if HAVE_SYSLOG_H or HAVE_SYS_SYSLOG_H is defined.
 */
#ifdef HAVE_SYSLOG_H
# include <syslog.h>
#else /* not HAVE_SYSLOG_H */
# if HAVE_SYS_SYSLOG_H
#  include <sys/syslog.h>
# endif /* HAVE_SYS_SYSLOG_H */
#endif /* HAVE_SYSLOG_H */

/*
 * Actions to take if <sys/param.h> exists.
 */
#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif /* HAVE_SYS_PARAM_H */

/*
 * Actions to take if <sys/socket.h> exists.
 */
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif /* HAVE_SYS_SOCKET_H */

/*
 * Actions to take if <rpc/rpc.h> exists.
 */
#ifdef HAVE_RPC_RPC_H
/*
 * Turn on PORTMAP, so that additional header files would get included
 * and the important definition for UDPMSGSIZE is included too.
 */
# ifndef PORTMAP
#  define PORTMAP
# endif /* not PORTMAP */
# include <rpc/rpc.h>
# ifndef XDRPROC_T_TYPE
typedef bool_t (*xdrproc_t) __P ((XDR *, __ptr_t, ...));
# endif /* not XDRPROC_T_TYPE */
#endif /* HAVE_RPC_RPC_H */

/*
 * Actions to take if <rpc/types.h> exists.
 */
#ifdef HAVE_RPC_TYPES_H
# include <rpc/types.h>
#endif /* HAVE_RPC_TYPES_H */

/*
 * Actions to take if <rpc/xdr.h> exists.
 */
#ifdef HAVE_RPC_XDR_H
# include <rpc/xdr.h>
#endif /* HAVE_RPC_XDR_H */

/*
 * Actions to take if <malloc.h> exists.
 */
#ifdef HAVE_MALLOC_H
# include <malloc.h>
#endif /* HAVE_MALLOC_H */

/*
 * Actions to take if <mntent.h> exists.
 */
#ifdef HAVE_MNTENT_H
/* some systems need <stdio.h> before <mntent.h> is included */
# ifdef HAVE_STDIO_H
#  include <stdio.h>
# endif /* HAVE_STDIO_H */
# include <mntent.h>
#endif /* HAVE_MNTENT_H */

/*
 * Actions to take if <sys/errno.h> exists.
 */
#ifdef HAVE_SYS_ERRNO_H
# include <sys/errno.h>
extern int errno;
#endif /* HAVE_SYS_ERRNO_H */

/*
 * Actions to take if <sys/fsid.h> exists.
 */
#ifdef HAVE_SYS_FSID_H
# include <sys/fsid.h>
#endif /* HAVE_SYS_FSID_H */

/*
 * Actions to take if <sys/utsname.h> exists.
 */
#ifdef HAVE_SYS_UTSNAME_H
# include <sys/utsname.h>
#endif /* HAVE_SYS_UTSNAME_H */

/*
 * Actions to take if <sys/mntent.h> exists.
 */
#ifdef HAVE_SYS_MNTENT_H
# include <sys/mntent.h>
#endif /* HAVE_SYS_MNTENT_H */

/*
 * Actions to take if <ndbm.h> exists.
 * Should be included before <rpcsvc/yp_prot.h> because on some systems
 * like Linux, it also defines "struct datum".
 */
#ifdef HAVE_NDBM_H
# include <ndbm.h>
# ifndef DATUM
/* ensure that struct datum is not included again from <rpcsvc/yp_prot.h> */
#  define DATUM
# endif /* not DATUM */
#endif /* HAVE_NDBM_H */

/*
 * Actions to take if <net/errno.h> exists.
 */
#ifdef HAVE_NET_ERRNO_H
# include <net/errno.h>
#endif /* HAVE_NET_ERRNO_H */

/*
 * Actions to take if <net/if.h> exists.
 */
#ifdef HAVE_NET_ROUTE_H
# include <net/route.h>
#endif /* HAVE_NET_ROUTE_H */

/*
 * Actions to take if <net/if.h> exists.
 */
#ifdef HAVE_SYS_MBUF_H
# include <sys/mbuf.h>
/*
 * OSF4 (DU-4.0) defines m_next and m_data also in <sys/mount> so I must
 # undefine them here to avoid conflicts.
 */
# ifdef m_next
#  undef m_next
# endif /* m_next */
# ifdef m_data
#  undef m_data
# endif /* m_data */
/*
 * AIX 3 defines MFREE and m_flags also in <sys/mount>.
 */
# ifdef m_flags
#  undef m_flags
# endif /* m_flags */
# ifdef MFREE
#  undef MFREE
# endif /* MFREE */
#endif /* HAVE_SYS_MBUF_H */

/*
 * Actions to take if <net/if.h> exists.
 */
#ifdef HAVE_NET_IF_H
# include <net/if.h>
#endif /* HAVE_NET_IF_H */

/*
 * Actions to take if <netdb.h> exists.
 */
#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif /* HAVE_NETDB_H */

/*
 * Actions to take if <netdir.h> exists.
 */
#ifdef HAVE_NETDIR_H
# include <netdir.h>
#endif /* HAVE_NETDIR_H */

/*
 * Actions to take if <net/if_var.h> exists.
 */
#ifdef HAVE_NET_IF_VAR_H
# include <net/if_var.h>
#endif /* HAVE_NET_IF_VAR_H */

/*
 * Actions to take if <netinet/if_ether.h> exists.
 */
#ifdef HAVE_NETINET_IF_ETHER_H
# include <netinet/if_ether.h>
#endif /* HAVE_NETINET_IF_ETHER_H */

/*
 * Actions to take if <netinet/in.h> exists.
 */
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif /* HAVE_NETINET_IN_H */

/*
 * Actions to take if <rpcsvc/yp_prot.h> exists.
 */
#ifdef HAVE_RPCSVC_YP_PROT_H
# include <rpcsvc/yp_prot.h>
#endif /* HAVE_RPCSVC_YP_PROT_H */

/*
 * Actions to take if <rpcsvc/ypclnt.h> exists.
 */
#ifdef HAVE_RPCSVC_YPCLNT_H
# include <rpcsvc/ypclnt.h>
#endif /* HAVE_RPCSVC_YPCLNT_H */

/*
 * Actions to take if <sys/ucred.h> exists.
 */
#ifdef HAVE_SYS_UCRED_H
# include <sys/ucred.h>
#endif /* HAVE_SYS_UCRED_H */


/*
 * Actions to take if <sys/mount.h> exists.
 */
#ifdef HAVE_SYS_MOUNT_H
/*
 * Some operating systems must define these variables to get
 * NFS and other definitions included.
 */
# ifndef NFSCLIENT
#  define NFSCLIENT
# endif /* not NFSCLIENT */
# ifndef NFS
#  define NFS
# endif /* not NFS */
# ifndef PCFS
#  define PCFS
# endif /* not PCFS */
# ifndef LOFS
#  define LOFS
# endif /* not LOFS */
# ifndef RFS
#  define RFS
# endif /* not RFS */
# ifndef MSDOSFS
#  define MSDOSFS
# endif /* not MSDOSFS */
# ifndef MFS
#  define MFS
# endif /* not MFS */
# ifndef CD9660
#  define CD9660
# endif /* not CD9660 */
# ifndef NFS
#  define NFS
# endif /* not NFS */
# include <sys/mount.h>
#endif /* HAVE_SYS_MOUNT_H */

#ifdef HAVE_SYS_VMOUNT_H
# include <sys/vmount.h>
#endif /* HAVE_SYS_VMOUNT_H */

/*
 * Actions to take if <linux/fs.h> exists.
 */
#ifdef HAVE_LINUX_FS_H
# include <linux/fs.h>
#endif /* HAVE_LINUX_FS_H */

/*
 * Actions to take if <linux/auto_fs.h> exists.
 */
#ifdef HAVE_LINUX_AUTO_FS_H
# include <linux/auto_fs.h>
#endif /* HAVE_LINUX_AUTO_FS_H */

/*
 * Actions to take if <sys/fs/autofs.h> exists.
 */
#ifdef HAVE_SYS_FS_AUTOFS_H
# include <sys/fs/autofs.h>
#endif /* HAVE_SYS_FS_AUTOFS_H */

/*
 * Actions to take if <sys/fs/autofs_prot.h> exists.
 */
#ifdef HAVE_SYS_FS_AUTOFS_PROT_H
# include <sys/fs/autofs_prot.h>
#endif /* HAVE_SYS_FS_AUTOFS_PROT_H */

/*
 * NFS PROTOCOL HEADER FILES:
 */

/*
 * Actions to take if <nfs/export.h> exists.
 */
#ifdef HAVE_NFS_EXPORT_H
# include <nfs/export.h>
#endif /* HAVE_NFS_EXPORT_H */

/****************************************************************************
 ** IMPORTANT!!!							   **
 ** We always include am-util's amu_nfs_prot.h.				   **
 ** That is actually defined in "conf/nfs_prot/nfs_prot_${host_os_name}.h" **
 ****************************************************************************/
#include <amu_nfs_prot.h>

/*
 * DO NOT INCLUDE THESE FILES:
 * They conflicts with other NFS headers and are generally not needed.
 */
#ifdef DO_NOT_INCLUDE
# ifdef HAVE_NFS_NFS_CLNT_H
#  include <nfs/nfs_clnt.h>
# endif /* HAVE_NFS_NFS_CLNT_H */
# ifdef HAVE_LINUX_NFS_H
#  include <linux/nfs.h>
# endif /* HAVE_LINUX_NFS_H */
#endif /* DO NOT INCLUDE */

/*
 * Actions to take if one of the nfs headers exists.
 */
#ifdef HAVE_NFS_NFS_GFS_H
# include <nfs/nfs_gfs.h>
#endif /* HAVE_NFS_NFS_GFS_H */
#ifdef HAVE_NFS_MOUNT_H
# include <nfs/mount.h>
#endif /* HAVE_NFS_MOUNT_H */
#ifdef HAVE_NFS_NFS_MOUNT_H_off
# include <nfs/nfs_mount.h>
#endif /* HAVE_NFS_NFS_MOUNT_H */
#ifdef HAVE_NFS_PATHCONF_H
# include <nfs/pathconf.h>
#endif /* HAVE_NFS_PATHCONF_H */
#ifdef HAVE_SYS_FS_NFS_MOUNT_H
# include <sys/fs/nfs/mount.h>
#endif /* HAVE_SYS_FS_NFS_MOUNT_H */
#ifdef HAVE_SYS_FS_NFS_NFS_CLNT_H
# include <sys/fs/nfs/nfs_clnt.h>
#endif /* HAVE_SYS_FS_NFS_NFS_CLNT_H */
#ifdef HAVE_SYS_FS_NFS_CLNT_H
# include <sys/fs/nfs_clnt.h>
#endif /* HAVE_SYS_FS_NFS_CLNT_H */
#ifdef HAVE_LINUX_NFS_MOUNT_H
# include <linux/nfs_mount.h>
#endif /* HAVE_LINUX_NFS_MOUNT_H */

/*
 * Actions to take if <pwd.h> exists.
 */
#ifdef HAVE_PWD_H
# include <pwd.h>
#endif /* HAVE_PWD_H */

/*
 * Actions to take if <hesiod.h> exists.
 */
#ifdef HAVE_HESIOD_H
# include <hesiod.h>
#endif /* HAVE_HESIOD_H */

/*
 * Actions to take if <lber.h> exists.
 * This header file is required before <ldap.h> can be included.
 */
#ifdef HAVE_LBER_H
# include <lber.h>
#endif /* HAVE_LBER_H */

/*
 * Actions to take if <ldap.h> exists.
 */
#ifdef HAVE_LDAP_H
# include <ldap.h>
#endif /* HAVE_LDAP_H */

/*
 * Actions to take if <arpa/nameser.h> exists.
 * Should be included before <resolv.h>.
 */
#ifdef HAVE_ARPA_NAMESER_H
# ifdef NOERROR
#  undef NOERROR
# endif /* NOERROR */
# include <arpa/nameser.h>
#endif /* HAVE_ARPA_NAMESER_H */

/*
 * Actions to take if <arpa/inet.h> exists.
 */
#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif /* HAVE_ARPA_INET_H */

/*
 * Actions to take if <resolv.h> exists.
 */
#ifdef HAVE_RESOLV_H
# include <resolv.h>
#endif /* HAVE_RESOLV_H */

/*
 * Actions to take if <sys/uio.h> exists.
 */
#ifdef HAVE_SYS_UIO_H
# include <sys/uio.h>
#endif /* HAVE_SYS_UIO_H */

/*
 * Actions to take if <sys/fs/cachefs_fs.h> exists.
 */
#ifdef HAVE_SYS_FS_CACHEFS_FS_H
# include <sys/fs/cachefs_fs.h>
#endif /* HAVE_SYS_FS_CACHEFS_FS_H */

/*
 * Actions to take if <sys/fs/pc_fs.h> exists.
 */
#ifdef HAVE_SYS_FS_PC_FS_H
# include <sys/fs/pc_fs.h>
#endif /* HAVE_SYS_FS_PC_FS_H */

/*
 * Actions to take if <sys/fs/tmp.h> exists.
 */
#ifdef HAVE_SYS_FS_TMP_H
# include <sys/fs/tmp.h>
#endif /* HAVE_SYS_FS_TMP_H */

/*
 * Actions to take if <sys/fs/ufs_mount.h> exists.
 */
#ifdef HAVE_SYS_FS_UFS_MOUNT_H
# include <sys/fs/ufs_mount.h>
#endif /* HAVE_SYS_FS_UFS_MOUNT_H */

/*
 * Actions to take if <sys/fs/efs_clnt.h> exists.
 */
#ifdef HAVE_SYS_FS_EFS_CLNT_H
# include <sys/fs/efs_clnt.h>
#endif /* HAVE_SYS_FS_EFS_CLNT_H */

/*
 * Actions to take if <assert.h> exists.
 */
#ifdef HAVE_ASSERT_H
# include <assert.h>
#endif /* HAVE_ASSERT_H */

/*
 * Actions to take if <cfs.h> exists.
 */
#ifdef HAVE_CFS_H
# include <cfs.h>
#endif /* HAVE_CFS_H */

/*
 * Actions to take if <cluster.h> exists.
 */
#ifdef HAVE_CLUSTER_H
# include <cluster.h>
#endif /* HAVE_CLUSTER_H */

/*
 * Actions to take if <ctype.h> exists.
 */
#ifdef HAVE_CTYPE_H
# include <ctype.h>
#endif /* HAVE_CTYPE_H */

/*
 * Actions to take if <errno.h> exists.
 */
#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif /* HAVE_ERRNO_H */

/*
 * Actions to take if <grp.h> exists.
 */
#ifdef HAVE_GRP_H
# include <grp.h>
#endif /* HAVE_GRP_H */

/*
 * Actions to take if <hsfs/hsfs.h> exists.
 */
#ifdef HAVE_HSFS_HSFS_H
# include <hsfs/hsfs.h>
#endif /* HAVE_HSFS_HSFS_H */

/*
 * Actions to take if <mount.h> exists.
 */
#ifdef HAVE_MOUNT_H
# include <mount.h>
#endif /* HAVE_MOUNT_H */

/*
 * Actions to take if <nsswitch.h> exists.
 */
#ifdef HAVE_NSSWITCH_H
# include <nsswitch.h>
#endif /* HAVE_NSSWITCH_H */

/*
 * Actions to take if <rpc/auth_des.h> exists.
 */
#ifdef HAVE_RPC_AUTH_DES_H
# include <rpc/auth_des.h>
#endif /* HAVE_RPC_AUTH_DES_H */

/*
 * Actions to take if <rpc/pmap_clnt.h> exists.
 */
#ifdef HAVE_RPC_PMAP_CLNT_H
# include <rpc/pmap_clnt.h>
#endif /* HAVE_RPC_PMAP_CLNT_H */

/*
 * Actions to take if <rpc/pmap_prot.h> exists.
 */
#ifdef HAVE_RPC_PMAP_PROT_H
# include <rpc/pmap_prot.h>
#endif /* HAVE_RPC_PMAP_PROT_H */


/*
 * Actions to take if <rpcsvc/mount.h> exists.
 * AIX does not protect against this file doubly included,
 * so I have to do my own protection here.
 */
#ifdef HAVE_RPCSVC_MOUNT_H
# ifndef _RPCSVC_MOUNT_H
#  include <rpcsvc/mount.h>
# endif /* not _RPCSVC_MOUNT_H */
#endif /* HAVE_RPCSVC_MOUNT_H */

/*
 * Actions to take if <rpcsvc/nis.h> exists.
 */
#ifdef HAVE_RPCSVC_NIS_H
# include <rpcsvc/nis.h>
#endif /* HAVE_RPCSVC_NIS_H */

/*
 * Actions to take if <setjmp.h> exists.
 */
#ifdef HAVE_SETJMP_H
# include <setjmp.h>
#endif /* HAVE_SETJMP_H */

/*
 * Actions to take if <signal.h> exists.
 */
#ifdef HAVE_SIGNAL_H
# include <signal.h>
#endif /* HAVE_SIGNAL_H */

/*
 * Actions to take if <string.h> exists.
 */
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */

/*
 * Actions to take if <strings.h> exists.
 */
#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */

/*
 * Actions to take if <sys/config.h> exists.
 */
#ifdef HAVE_SYS_CONFIG_H
# include <sys/config.h>
#endif /* HAVE_SYS_CONFIG_H */

/*
 * Actions to take if <sys/dg_mount.h> exists.
 */
#ifdef HAVE_SYS_DG_MOUNT_H
# include <sys/dg_mount.h>
#endif /* HAVE_SYS_DG_MOUNT_H */

/*
 * Actions to take if <sys/fs_types.h> exists.
 */
#ifdef HAVE_SYS_FS_TYPES_H
# include <sys/fs_types.h>
#endif /* HAVE_SYS_FS_TYPES_H */

/*
 * Actions to take if <sys/fstyp.h> exists.
 */
#ifdef HAVE_SYS_FSTYP_H
# include <sys/fstyp.h>
#endif /* HAVE_SYS_FSTYP_H */

/*
 * Actions to take if <sys/lock.h> exists.
 */
#ifdef HAVE_SYS_LOCK_H
# include <sys/lock.h>
#endif /* HAVE_SYS_LOCK_H */

/*
 * Actions to take if <sys/machine.h> exists.
 */
#ifdef HAVE_SYS_MACHINE_H
# include <sys/machine.h>
#endif /* HAVE_SYS_MACHINE_H */

/*
 * Actions to take if <sys/mntctl.h> exists.
 */
#ifdef HAVE_SYS_MNTCTL_H
# include <sys/mntctl.h>
#endif /* HAVE_SYS_MNTCTL_H */

/*
 * Actions to take if <sys/mnttab.h> exists.
 */
#ifdef HAVE_SYS_MNTTAB_H
# include <sys/mnttab.h>
#endif /* HAVE_SYS_MNTTAB_H */

/*
 * Actions to take if <mnttab.h> exists.
 * Do not include it if MNTTAB is already defined because it probably
 * came from <sys/mnttab.h> and we do not want conflicting definitions.
 */
#if defined(HAVE_MNTTAB_H) && !defined(MNTTAB)
# include <mnttab.h>
#endif /* defined(HAVE_MNTTAB_H) && !defined(MNTTAB) */

/*
 * Actions to take if <netconfig.h> exists.
 */
#ifdef HAVE_NETCONFIG_H
# include <netconfig.h>
/* Some systems (Solaris 2.5.1) don't declare this external */
extern char *nc_sperror(void);
#endif /* HAVE_NETCONFIG_H */

/*
 * Actions to take if <sys/netconfig.h> exists.
 */
#ifdef HAVE_SYS_NETCONFIG_H
# include <sys/netconfig.h>
#endif /* HAVE_SYS_NETCONFIG_H */

/*
 * Actions to take if <sys/pathconf.h> exists.
 */
#ifdef HAVE_SYS_PATHCONF_H
# include <sys/pathconf.h>
#endif /* HAVE_SYS_PATHCONF_H */

/*
 * Actions to take if <sys/resource.h> exists.
 */
#ifdef HAVE_SYS_RESOURCE_H
# include <sys/resource.h>
#endif /* HAVE_SYS_RESOURCE_H */

/*
 * Actions to take if <sys/sema.h> exists.
 */
#ifdef HAVE_SYS_SEMA_H
# include <sys/sema.h>
#endif /* HAVE_SYS_SEMA_H */

/*
 * Actions to take if <sys/signal.h> exists.
 */
#ifdef HAVE_SYS_SIGNAL_H
# include <sys/signal.h>
#endif /* HAVE_SYS_SIGNAL_H */

/*
 * Actions to take if <sys/sockio.h> exists.
 */
#ifdef HAVE_SYS_SOCKIO_H
# include <sys/sockio.h>
#endif /* HAVE_SYS_SOCKIO_H */

/*
 * Actions to take if <sys/syscall.h> exists.
 */
#ifdef HAVE_SYS_SYSCALL_H
# include <sys/syscall.h>
#endif /* HAVE_SYS_SYSCALL_H */

/*
 * Actions to take if <sys/syslimits.h> exists.
 */
#ifdef HAVE_SYS_SYSLIMITS_H
# include <sys/syslimits.h>
#endif /* HAVE_SYS_SYSLIMITS_H */

/*
 * Actions to take if <tiuser.h> exists.
 */
#ifdef HAVE_TIUSER_H
/*
 * Some systems like AIX have multiple definitions for T_NULL and othersd
 * that are defined first in <arpa/nameser.h>.
 */
# ifdef HAVE_ARPA_NAMESER_H
#  ifdef T_NULL
#   undef T_NULL
#  endif /* T_NULL */
#  ifdef T_UNSPEC
#   undef T_UNSPEC
#  endif /* T_UNSPEC */
#  ifdef T_IDLE
#   undef T_IDLE
#  endif /* T_IDLE */
# endif /* HAVE_ARPA_NAMESER_H */
# include <tiuser.h>
#endif /* HAVE_TIUSER_H */

/*
 * Actions to take if <sys/tiuser.h> exists.
 */
#ifdef HAVE_SYS_TIUSER_H
# include <sys/tiuser.h>
#endif /* HAVE_SYS_TIUSER_H */

/*
 * Actions to take if <sys/statfs.h> exists.
 */
#ifdef HAVE_SYS_STATFS_H
# include <sys/statfs.h>
#endif /* HAVE_SYS_STATFS_H */

/*
 * Actions to take if <sys/vfs.h> exists.
 */
#ifdef HAVE_SYS_VFS_H
# include <sys/vfs.h>
#endif /* HAVE_SYS_VFS_H */

/*
 * Actions to take if <sys/vmount.h> exists.
 */
#ifdef HAVE_SYS_VMOUNT_H
# include <sys/vmount.h>
#endif /* HAVE_SYS_VMOUNT_H */

/*
 * Actions to take if <ufs/ufs_mount.h> exists.
 */
#ifdef HAVE_UFS_UFS_MOUNT_H
# include <ufs/ufs_mount.h>
#endif /* HAVE_UFS_UFS_MOUNT_H */

/*
 * Are S_ISDIR, S_ISREG, et al broken?  If not, include <sys/stat.h>.
 * Turned off the not using sys/stat.h based on if the macros are
 * "broken", because they incorrectly get reported as broken on
 * ncr2.
 */
#ifndef STAT_MACROS_BROKEN_notused
# ifdef HAVE_SYS_STAT_H
#  include <sys/stat.h>
# endif /* HAVE_SYS_STAT_H */
#endif /* not STAT_MACROS_BROKEN_notused */

/*
 * Actions to take if <stdio.h> exists.
 */
#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif /* HAVE_STDIO_H */

/*
 * Actions to take if <stdlib.h> exists.
 */
#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */

/*
 * Actions to take if <regex.h> exists.
 */
#ifdef HAVE_REGEX_H
# include <regex.h>
#endif /* HAVE_REGEX_H */


/****************************************************************************/
/*
 * Specific macros we're looking for.
 */
#ifndef HAVE_MEMSET
# ifdef HAVE_BZERO
#  define	memset(ptr, val, len)	bzero((ptr), (len))
# else /* not HAVE_BZERO */
#  error Cannot find either memset or bzero!
# endif /* not HAVE_BZERO */
#endif /* not HAVE_MEMSET */

#ifndef HAVE_MEMMOVE
# ifdef HAVE_BCOPY
#  define	memmove(to, from, len)	bcopy((from), (to), (len))
# else /* not HAVE_BCOPY */
#  error Cannot find either memmove or bcopy!
# endif /* not HAVE_BCOPY */
#endif /* not HAVE_MEMMOVE */

/*
 * memcmp() is more problematic:
 * Systems that don't have it, but have bcmp(), will use bcmp() instead.
 * Those that have it, but it is bad (SunOS 4 doesn't handle
 * 8 bit comparisons correctly), will get to use am_memcmp().
 * Otherwise if you have memcmp() and it is good, use it.
 */
#ifdef HAVE_MEMCMP
# ifdef HAVE_BAD_MEMCMP
#  define	memcmp		am_memcmp
extern int am_memcmp(const voidp s1, const voidp s2, size_t len);
# endif /* HAVE_BAD_MEMCMP */
#else /* not HAVE_MEMCMP */
# ifdef HAVE_BCMP
#  define	memcmp(a, b, len)	bcmp((a), (b), (len))
# endif /* HAVE_BCMP */
#endif /* not HAVE_MEMCMP */

#ifndef HAVE_SETEUID
# ifdef HAVE_SETRESUID
#  define	seteuid(x)		setresuid(-1,(x),-1)
# else /* not HAVE_SETRESUID */
#  error Cannot find either seteuid or setresuid!
# endif /* not HAVE_SETRESUID */
#endif /* not HAVE_SETEUID */

/*
 * Define type of mntent_t.
 * Defaults to struct mntent, else struct mnttab.  If neither is found, and
 * the operating system does keep not mount tables in the kernel, then flag
 * it as an error.  If neither is found and the OS keeps mount tables in the
 * kernel, then define our own version of mntent; it will be needed for amd
 * to keep its own internal version of the mount tables.
 */
#ifdef HAVE_STRUCT_MNTENT
typedef struct mntent mntent_t;
#else /* not HAVE_STRUCT_MNTENT */
# ifdef HAVE_STRUCT_MNTTAB
typedef struct mnttab mntent_t;
# else /* not HAVE_STRUCT_MNTTAB */
#  ifdef MOUNT_TABLE_ON_FILE
#   error Could not find definition for struct mntent or struct mnttab!
#  else /* not MOUNT_TABLE_ON_FILE */
typedef struct _am_mntent {
  char	*mnt_fsname;		/* name of mounted file system */
  char	*mnt_dir;		/* file system path prefix */
  char	*mnt_type;		/* MNTTYPE_* */
  char	*mnt_opts;		/* MNTOPT* */
  int	mnt_freq;		/* dump frequency, in days */
  int	mnt_passno;		/* pass number on parallel fsck */
} mntent_t;
#  endif /* not MOUNT_TABLE_ON_FILE */
# endif /* not HAVE_STRUCT_MNTTAB */
#endif /* not HAVE_STRUCT_MNTENT */


/*
 * Complete external definitions missing from some systems.
 */

#ifndef HAVE_EXTERN_SYS_ERRLIST
extern const char * const sys_errlist[];
#endif /* not HAVE_EXTERN_SYS_ERRLIST */

#ifndef HAVE_EXTERN_OPTARG
extern char *optarg;
extern int optind;
#endif /* not HAVE_EXTERN_OPTARG */

#if defined(HAVE_CLNT_SPERRNO) && !defined(HAVE_EXTERN_CLNT_SPERRNO)
extern char *clnt_sperrno(const enum clnt_stat num);
#endif /* defined(HAVE_CLNT_SPERRNO) && !defined(HAVE_EXTERN_CLNT_SPERRNO) */

#if defined(HAVE_GET_MYADDRESS) && !defined(HAVE_EXTERN_GET_MYADDRESS)
extern void get_myaddress(struct sockaddr_in *addr);
#endif /* defined(HAVE_GET_MYADDRESS) && !defined(HAVE_EXTERN_GET_MYADDRESS) */

#if defined(HAVE_GETDOMAINNAME) && !defined(HAVE_EXTERN_GETDOMAINNAME)
# if defined(HAVE_MAP_NIS) || defined(HAVE_MAP_NISPLUS)
extern int getdomainname(char *name, int namelen);
# endif /* defined(HAVE_MAP_NIS) || defined(HAVE_MAP_NISPLUS) */
#endif /* defined(HAVE_GETDOMAINNAME) && !defined(HAVE_EXTERN_GETDOMAINNAME) */

#if defined(HAVE_GETDTABLESIZE) && !defined(HAVE_EXTERN_GETDTABLESIZE)
extern int getdtablesize(void);
#endif /* defined(HAVE_GETDTABLESIZE) && !defined(HAVE_EXTERN_GETDTABLESIZE) */

#if defined(HAVE_GETHOSTNAME) && !defined(HAVE_EXTERN_GETHOSTNAME)
extern int gethostname(char *name, int namelen);
#endif /* defined(HAVE_GETHOSTNAME) && !defined(HAVE_EXTERN_GETHOSTNAME) */

#if defined(HAVE_GETPAGESIZE) && !defined(HAVE_EXTERN_GETPAGESIZE)
extern int getpagesize(void);
#endif /* defined(HAVE_GETPAGESIZE) && !defined(HAVE_EXTERN_GETPAGESIZE) */

#ifndef HAVE_EXTERN_INNETGR
extern int innetgr(char *, char *, char *, char *);
#endif /* not HAVE_EXTERN_INNETGR */

#ifndef HAVE_EXTERN_SBRK
extern caddr_t sbrk(int incr);
#endif /* not HAVE_EXTERN_SBRK */

#if defined(HAVE_STRDUP) && !defined(HAVE_EXTERN_STRDUP)
extern char *strdup(const char *s);
#endif /* defined(HAVE_STRDUP) && !defined(HAVE_EXTERN_STRDUP) */

#if defined(HAVE_USLEEP) && !defined(HAVE_EXTERN_USLEEP)
extern int usleep(u_int useconds);
#endif /* defined(HAVE_USLEEP) && !defined(HAVE_EXTERN_USLEEP) */

#if defined(HAVE_UALARM) && !defined(HAVE_EXTERN_UALARM)
extern u_int ualarm(u_int usecs, u_int interval);
#endif /* defined(HAVE_UALARM) && !defined(HAVE_EXTERN_UALARM) */

#if defined(HAVE_WAIT3) && !defined(HAVE_EXTERN_WAIT3)
extern int wait3(int *statusp, int options, struct rusage *rusage);
#endif /* defined(HAVE_WAIT3) && !defined(HAVE_EXTERN_WAIT3) */

#ifndef HAVE_EXTERN_XDR_OPAQUE_AUTH
extern bool_t xdr_opaque_auth(XDR *, struct opaque_auth *);
#endif /* not HAVE_EXTERN_XDR_OPAQUE_AUTH */

#ifndef HAVE_EXTERN_GETLOGIN
extern char *getlogin(void);
#endif /* not HAVE_EXTERN_GETLOGIN */

/****************************************************************************/
/*
 * amd-specific header files.
 */
#ifdef THIS_HEADER_FILE_IS_INCLUDED_ABOVE
# include <amu_nfs_prot.h>
#endif /* THIS_HEADER_FILE_IS_INCLUDED_ABOVE */
#include <am_utils.h>
#include <amq_defs.h>
#include <aux_conf.h>
/* compatibilty with old amd, while autoconfistating it */
#include <am_compat.h>


/****************************************************************************/
/*
 * External defintions that depend on other macros available (or not)
 * and those are probably declared in any of the above headers.
 */

#ifndef HAVE_CLNT_SPERRNO
extern char *clnt_sperrno(enum clnt_stat stat);
#endif /* not HAVE_CLNT_SPERRNO */

#ifndef HAVE_HASMNTOPT
extern char *hasmntopt(mntent_t *mnt, char *opt);
#endif /* not HAVE_HASMNTOPT */

#ifndef HAVE_STRDUP
extern char *strdup(const char *s);
#endif /* not HAVE_STRDUP */

#ifndef HAVE_UALARM
extern u_int ualarm(u_int usecs, u_int interval);
#endif /* not HAVE_UALARM */

#ifndef HAVE_XDR_EXPORTS
bool_t xdr_exports(XDR *xdrs, exports *objp);
#endif /* not HAVE_XDR_EXPORTS */

#ifndef HAVE_XDR_FHSTATUS
extern bool_t xdr_fhstatus(XDR *xdrs, fhstatus *objp);
#endif /* not HAVE_XDR_FHSTATUS */

#ifndef HAVE_XDR_FTYPE
extern bool_t xdr_ftype(XDR *xdrs, nfsftype *objp);
#endif /* not HAVE_XDR_FTYPE */

#ifndef HAVE_XDR_NFSSTAT
extern bool_t xdr_nfsstat(XDR *xdrs, nfsstat *objp);
#endif /* not HAVE_XDR_NFSSTAT */

#ifndef HAVE_XDR_POINTER
extern bool_t xdr_pointer(register XDR *xdrs, char **objpp, u_int obj_size, XDRPROC_T_TYPE xdr_obj);
#endif /* not HAVE_XDR_POINTER */


#endif /* not _AM_DEFS_H */
