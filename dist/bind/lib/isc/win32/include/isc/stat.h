/*	$NetBSD: stat.h,v 1.1.1.2 2005/12/21 19:59:17 christos Exp $	*/

/*
 * Copyright (C) 2000, 2001, 2003  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* Id: stat.h,v 1.3.2.2 2003/07/22 04:03:52 marka Exp */

#ifndef ISC_STAT_H
#define ISC_STAT_H 1

#include <sys/stat.h>

/* open() under unix allows setting of read/write permissions
 * at the owner, group and other levels.  These don't exist in NT
 * We'll just map them all to the NT equivalent 
 */

#define S_IREAD	_S_IREAD	/* read permission, owner */
#define S_IWRITE _S_IWRITE	/* write permission, owner */
#define S_IRUSR _S_IREAD	/* Owner read permission */
#define S_IWUSR _S_IWRITE	/* Owner write permission */
#define S_IRGRP _S_IREAD	/* Group read permission */
#define S_IWGRP _S_IWRITE	/* Group write permission */
#define S_IROTH _S_IREAD	/* Other read permission */
#define S_IWOTH _S_IWRITE	/* Other write permission */

#ifndef S_ISDIR
# define S_ISDIR(m)	(((m) & S_IFMT) == S_IFDIR)
#endif
#ifndef S_ISREG
# define S_ISREG(m)	(((m) & S_IFMT) == S_IFREG)
#endif

#endif /* ISC_STAT_H */
