/*	$NetBSD: infinity.c,v 1.4 1998/07/26 14:14:16 mycroft Exp $	*/

#include <sys/cdefs.h>
#ifndef lint
__RCSID("$NetBSD: infinity.c,v 1.4 1998/07/26 14:14:16 mycroft Exp $");
#endif /* not lint */
/*
 * XXX - THIS IS (probably) COMPLETELY WRONG ON VAX!!!
 */

/* infinity.c */

#include <math.h>

/* bytes for +Infinity on a 387 */
const char __infinity[] = { 0, 0, 0, 0, 0, 0, 0xf0, 0x7f };
