/*	$NetBSD: scsireg.h,v 1.4 2007/03/05 18:06:09 he Exp $	*/
/*
 * Copyright (c) 1994, 1997 Rolf Grossmann
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
 *      This product includes software developed by Rolf Grossmann.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
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

/* from next/cpu.h */
#define	SLOT_ID		0x0
#ifdef	MC68030
#define	SLOT_ID_BMAP	0x0
#endif
#ifdef	MC68040
#define	SLOT_ID_BMAP	0x00100000
#endif

#define	P_SCSI_CSR	((void *)(SLOT_ID+0x02000010))
#define	P_SCSI		((void *)(SLOT_ID_BMAP+0x02014000))
#define	P_FLOPPY	((uint8_t *)(SLOT_ID_BMAP+0x02014100))

#define	SCSI_INTR	(1<<12)	/* I_BIT(I_SCSI) */

/* XXX floppy register (will get it's own header file some time) */
#define	FLP_CTRL	8
#define  FLC_82077_SEL		0x40	/* set = 82077, clear = 53C90A */
