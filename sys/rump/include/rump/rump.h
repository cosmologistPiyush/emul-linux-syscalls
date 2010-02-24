/*	$NetBSD: rump.h,v 1.37 2010/02/24 14:56:04 pooka Exp $	*/

/*
 * Copyright (c) 2007 Antti Kantee.  All Rights Reserved.
 *
 * Development of this software was supported by Google Summer of Code.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _RUMP_RUMP_H_
#define _RUMP_RUMP_H_

/*
 * NOTE: do not #include anything from <sys> here.  Otherwise this
 * has no chance of working on non-NetBSD platforms.
 */

struct mount;
struct vnode;
struct vattr;
struct componentname;
struct vfsops;
struct fid;
struct statvfs;
struct stat;

/* yetch */
#if !defined(_RUMPKERNEL) && !defined(__NetBSD__)
struct kauth_cred;
typedef struct kauth_cred *kauth_cred_t;
#endif
#if defined(__NetBSD__)
#include <prop/proplib.h>
#else
#ifndef HAVE_PROP_DICTIONARY_T
#define HAVE_PROP_DICTIONARY_T
struct prop_dictionary;
typedef struct prop_dictionary *prop_dictionary_t;
#endif
#endif /* __NetBSD__ */

struct lwp;
struct modinfo;

#include <rump/rumpvnode_if.h>
#include <rump/rumpdefs.h>

/* rumpkern */
enum rump_uiorw { RUMPUIO_READ, RUMPUIO_WRITE };
typedef int (*rump_sysproxy_t)(int, void *, uint8_t *, size_t, register_t *);

/* rumpvfs */
#define RUMPCN_FREECRED  0x02
#define RUMPCN_FORCEFREE 0x04
#define RUMP_ETFS_SIZE_ENDOFF ((uint64_t)-1)
enum rump_etfs_type { RUMP_ETFS_REG, RUMP_ETFS_BLK, RUMP_ETFS_CHR };

/*
 * Something like rump capabilities would be nicer, but let's
 * do this for a start.
 */
#define RUMP_VERSION	01
#define rump_init()	rump__init(RUMP_VERSION)

/* um, what's the point ?-) */
#ifdef _BEGIN_DECLS
_BEGIN_DECLS
#endif

int	rump_boot_gethowto(void);
void	rump_boot_sethowto(int);

void	rump_schedule(void);
void	rump_unschedule(void);

int	rump__init(int);

#ifndef _RUMPKERNEL
#include <rump/rumpkern_if_pub.h>
#include <rump/rumpvfs_if_pub.h>
#include <rump/rumpnet_if_pub.h>
#endif

#ifdef _END_DECLS
_END_DECLS
#endif

/*
 * Begin rump syscall conditionals.  Yes, something a little better
 * is required here.
 */
#ifdef RUMP_SYS_NETWORKING
#define socket(a,b,c) rump_sys_socket(a,b,c)
#define accept(a,b,c) rump_sys_accept(a,b,c)
#define bind(a,b,c) rump_sys_bind(a,b,c)
#define connect(a,b,c) rump_sys_connect(a,b,c)
#define getpeername(a,b,c) rump_sys_getpeername(a,b,c)
#define getsockname(a,b,c) rump_sys_getsockname(a,b,c)
#define listen(a,b) rump_sys_listen(a,b)
#define recvfrom(a,b,c,d,e,f) rump_sys_recvfrom(a,b,c,d,e,f)
#define recvmsg(a,b,c) rump_sys_recvmsg(a,b,c)
#define sendto(a,b,c,d,e,f) rump_sys_sendto(a,b,c,d,e,f)
#define sendmsg(a,b,c) rump_sys_sendmsg(a,b,c)
#define getsockopt(a,b,c,d,e) rump_sys_getsockopt(a,b,c,d,e)
#define setsockopt(a,b,c,d,e) rump_sys_setsockopt(a,b,c,d,e)
#define shutdown(a,b) rump_sys_shutdown(a,b)
#endif /* RUMP_SYS_NETWORKING */

#ifdef RUMP_SYS_IOCTL
#define ioctl(...) rump_sys_ioctl(__VA_ARGS__)
#endif /* RUMP_SYS_IOCTL */

#ifdef RUMP_SYS_CLOSE
#define close(a) rump_sys_close(a)
#endif /* RUMP_SYS_CLOSE */

#ifdef RUMP_SYS_OPEN
#define open(...) rump_sys_open(__VA_ARGS__)
#endif /* RUMP_SYS_OPEN */

#ifdef RUMP_SYS_READWRITE
#define read(a,b,c) rump_sys_read(a,b,c)
#define readv(a,b,c) rump_sys_readv(a,b,c)
#define pread(a,b,c,d) rump_sys_pread(a,b,c,d)
#define preadv(a,b,c,d) rump_sys_preadv(a,b,c,d)
#define write(a,b,c) rump_sys_write(a,b,c)
#define writev(a,b,c) rump_sys_writev(a,b,c)
#define pwrite(a,b,c,d) rump_sys_pwrite(a,b,c,d)
#define pwritev(a,b,c,d) rump_sys_pwritev(a,b,c,d)
#endif /* RUMP_SYS_READWRITE */

#ifdef RUMP_SYS_FILEOPS
#define mkdir(a,b) rump_sys_mkdir(a,b)
#define rmdir(a) rump_sys_rmdir(a)
#define link(a,b) rump_sys_link(a,b)
#define symlink(a,b) rump_sys_symlink(a,b)
#define unlink(a) rump_sys_unlink(a)
#define readlink(a,b,c) rump_sys_readlink(a,b,c)
#endif /* RUMP_SYS_FILEOPS */

#endif /* _RUMP_RUMP_H_ */
