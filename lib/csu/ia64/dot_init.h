/* $NetBSD: dot_init.h,v 1.1 2006/07/02 17:15:22 cherry Exp $ */

/*-
 * Copyright (c) 2001 Ross Harvey
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the NetBSD
 *	Foundation, Inc. and its contributors.
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

#include <sys/cdefs.h>			/* RCS ID & Copyright macro defns */
#include <machine/asm.h>


#define	INIT_FALLTHRU_DECL void init_fallthru(void)
#define	FINI_FALLTHRU_DECL void fini_fallthru(void)

#define	INIT_FALLTHRU()	init_fallthru()
#define	FINI_FALLTHRU()	fini_fallthru()

/*-
 * $FreeBSD: src/lib/csu/ia64/crti.S,v 1.3 2001/11/03 06:31:27 peter Exp $
 */

#define	MD_SECTION_PROLOGUE(sect, entry_pt)			\
		__asm (						\
		".section "#sect",\"ax\",@progbits	\n"	\
		".proc "#entry_pt"			\n"	\
		#entry_pt":				\n"	\
		".regstk	0,2,0,0			\n"	\
		".prologue 12,loc0			\n"	\
		".save	ar.pfs,loc1			\n"	\
		"alloc	loc1=ar.pfs,0,2,0,0		\n"	\
		"mov	loc0=b0	/* Save return addr */	\n"	\
		".previous")

/*-
 * $FreeBSD: src/lib/csu/ia64/crtn.S,v 1.2 2001/10/29 10:18:58 peter Exp $
 */

#define	MD_SECTION_EPILOGUE(sect)				\
		__asm (						\
		".section "#sect",\"ax\",@progbits	\n"	\
		".regstk 0,2,0,0			\n"	\
		"mov	b0=loc0	/*Recover return addr*/ \n"	\
		"mov	ar.pfs=loc1			\n"	\
		"br.ret.sptk.many b0			\n"	\
		".previous")

#define	MD_INIT_SECTION_PROLOGUE MD_SECTION_PROLOGUE(.init, init_fallthru)
#define	MD_FINI_SECTION_PROLOGUE MD_SECTION_PROLOGUE(.fini, fini_fallthru)

#define	MD_INIT_SECTION_EPILOGUE MD_SECTION_EPILOGUE(.init)
#define	MD_FINI_SECTION_EPILOGUE MD_SECTION_EPILOGUE(.fini)

#define MD_DO_NOT_NEED_FALLTHRU
