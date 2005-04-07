/*	$NetBSD: statfs.c,v 1.3 2005/04/07 16:24:18 christos Exp $	*/

/*-
 * Copyright (c) 2004 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Christos Zoulas.
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
 *        This product includes software developed by the NetBSD
 *        Foundation, Inc. and its contributors.
 * 4. Neither the name of The NetBSD Foundation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#define __LIBC12_SOURCE__

#include "namespace.h"
#include <sys/types.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <string.h>
#include <stdlib.h>

__warn_references(statfs,
    "warning: reference to obsolete statfs(); use statvfs()")

__warn_references(fstatfs,
    "warning: reference to obsolete fstatfs(); use fstatvfs()")

__warn_references(fhstatfs,
    "warning: reference to obsolete fhstatfs(); use fhstatvfs()")

__warn_references(getfsstat,
    "warning: reference to obsolete getfsstat(); use getvfsstat()")

int _getfsstat(struct statfs12 *, long, int);

/*
 * Convert from a new statvfs to an old statfs structure.
 */

static void vfs2fs(struct statfs12 *, const struct statvfs *);

#define MOUNTNO_NONE	0
#define MOUNTNO_UFS	1		/* UNIX "Fast" Filesystem */
#define MOUNTNO_NFS	2		/* Network Filesystem */
#define MOUNTNO_MFS	3		/* Memory Filesystem */
#define MOUNTNO_MSDOS	4		/* MSDOS Filesystem */
#define MOUNTNO_CD9660	5		/* iso9660 cdrom */
#define MOUNTNO_FDESC	6		/* /dev/fd filesystem */
#define MOUNTNO_KERNFS	7		/* kernel variable filesystem */ 
#define MOUNTNO_DEVFS	8		/* device node filesystem */
#define MOUNTNO_AFS	9		/* AFS 3.x */
static const struct {
	const char *name;
	const int value;
} nv[] = {
	{ MOUNT_UFS, MOUNTNO_UFS },
	{ MOUNT_NFS, MOUNTNO_NFS },
	{ MOUNT_MFS, MOUNTNO_MFS },
	{ MOUNT_MSDOS, MOUNTNO_MSDOS },
	{ MOUNT_CD9660, MOUNTNO_CD9660 },
	{ MOUNT_FDESC, MOUNTNO_FDESC },
	{ MOUNT_KERNFS, MOUNTNO_KERNFS },
	{ MOUNT_AFS, MOUNTNO_AFS },
};

static void
vfs2fs(struct statfs12 *bfs, const struct statvfs *fs) 
{
	int i = 0;
	bfs->f_type = 0;
	bfs->f_oflags = (short)fs->f_flag;

	for (i = 0; i < sizeof(nv) / sizeof(nv[0]); i++) {
		if (strcmp(nv[i].name, fs->f_fstypename) == 0) {
			bfs->f_type = nv[i].value;
			break;
		}
	}
#define CLAMP(a)	(long)(((a) & ~LONG_MAX) ? LONG_MAX : (a))
	bfs->f_bsize = CLAMP(fs->f_frsize);
	bfs->f_iosize = CLAMP(fs->f_iosize);
	bfs->f_blocks = CLAMP(fs->f_blocks);
	bfs->f_bfree = CLAMP(fs->f_bfree);
	if (fs->f_bfree > fs->f_bresvd)
		bfs->f_bavail = CLAMP(fs->f_bfree - fs->f_bresvd);
	else
		bfs->f_bavail = -CLAMP(fs->f_bresvd - fs->f_bfree);
	bfs->f_files = CLAMP(fs->f_files);
	bfs->f_ffree = CLAMP(fs->f_ffree);
	bfs->f_fsid = fs->f_fsidx;
	bfs->f_owner = fs->f_owner;
	bfs->f_flags = (long)fs->f_flag;
	bfs->f_syncwrites = CLAMP(fs->f_syncwrites);
	bfs->f_asyncwrites = CLAMP(fs->f_asyncwrites);
	(void)strncpy(bfs->f_fstypename, fs->f_fstypename,
	    sizeof(bfs->f_fstypename));
	(void)strncpy(bfs->f_mntonname, fs->f_mntonname,
	    sizeof(bfs->f_mntonname));
	(void)strncpy(bfs->f_mntfromname, fs->f_mntfromname,
	    sizeof(bfs->f_mntfromname));
}

int
statfs(const char *file, struct statfs12 *ost)
{
	struct statvfs nst;
	int ret;

	if ((ret = statvfs(file, &nst)) == -1)
		return ret;
	vfs2fs(ost, &nst);
	return ret;
}

int
fstatfs(int f, struct statfs12 *ost)
{
	struct statvfs nst;
	int ret;

	if ((ret = fstatvfs(f, &nst)) == -1)
		return ret;
	vfs2fs(ost, &nst);
	return ret;
}

int
fhstatfs(const fhandle_t *fh, struct statfs12 *ost)
{
	struct statvfs nst;
	int ret;

	if ((ret = fhstatvfs(fh, &nst)) == -1)
		return ret;
	vfs2fs(ost, &nst);
	return ret;
}

int
_getfsstat(struct statfs12 *ost, long size, int flags)
{
	struct statvfs *nst;
	int ret, i;
	size_t bsize = (size_t)(size / sizeof(*ost)) * sizeof(*nst);

	if (ost != NULL) {
		if ((nst = malloc(bsize)) == NULL)
			return -1;
	} else
		nst = NULL;

	if ((ret = getvfsstat(nst, bsize, flags)) == -1)
		goto done;
	if (nst)
		for (i = 0; i < ret; i++)
			vfs2fs(&ost[i], &nst[i]);
done:
	if (nst)
		free(nst);
	return ret;
}

int
getfsstat(struct statfs12 *ost, long size, int flags)
{
	return _getfsstat(ost, size, flags);
}
