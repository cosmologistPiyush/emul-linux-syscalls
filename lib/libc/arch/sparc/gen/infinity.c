/*	$NetBSD: infinity.c,v 1.3 1998/07/26 14:14:16 mycroft Exp $	*/

#include <sys/cdefs.h>
#ifndef lint
__RCSID("$NetBSD: infinity.c,v 1.3 1998/07/26 14:14:16 mycroft Exp $");
#endif /* not lint */

/* infinity.c */

#include <math.h>

/* bytes for +Infinity on a sparc */
const char __infinity[] = { 0x7f, 0xf0, 0, 0, 0, 0, 0, 0 };
