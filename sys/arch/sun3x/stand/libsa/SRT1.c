/*	$NetBSD: SRT1.c,v 1.1.1.1 1997/03/13 16:27:28 gwr Exp $	*/

/*
 * Copyright (c) 1995 Gordon W. Ross
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 * 4. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Gordon Ross
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* SRT1.c - Stand-alone Run-time startup code, part 1 */

#include <stdarg.h>
#include <sys/types.h>
#include <machine/mon.h>

extern int edata[], end[];
extern void ** getvbr();
extern __dead void abort();
extern void main();

__dead void
exit()
{
	mon_exit_to_mon();
	abort();
}

/*
 * This is called by SRT0.S
 * to do final prep for main
 */
__dead void
_start()
{
	register int *ip;
	register void **vbr;

	/* Clear BSS */
	ip = edata;
	do *ip++ = 0;
	while (ip < end);

	/* Set the vector for trap 0 used by abort. */
	vbr = getvbr();
	vbr[32] = romVectorPtr->abortEntry;

	main(0);
	exit();
}

/*
 * Boot programs in C++ ?  Not likely!
 */
void
__main() {}
