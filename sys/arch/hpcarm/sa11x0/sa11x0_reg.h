/*	$NetBSD: sa11x0_reg.h,v 1.2 2001/02/23 04:31:19 ichiro Exp $	*/

/*-
 * Copyright (c) 2001 The NetBSD Foundation, Inc.  All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by IWAMOTO Toshihiro.
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

#ifndef _HPCARM_SA11X0_REG_H_
#define _HPCARM_SA11X0_REG_H_

/* Physical register base addresses */
#define SAOST_HW_BASE		0x90000000	/* OS Timer */
#define SARTC_HW_BASE		0x90010000	/* Real-Time Clock */
#define SAPMR_HW_BASE		0x90020000	/* Power Manager */
#define SARCR_HW_BASE		0x90030000	/* Reset Controller */
#define SAGPIO_HW_BASE		0x90040000	/* GPIO */
#define SAIPIC_HW_BASE		0x90050000	/* Interrupt Controller */
#define SACOM3_HW_BASE		0x80050000	/* UART 3  */

#define SADMAC_HW_BASE		0xB0000000	/* DMA Controller */
#define SALCD_HW_BASE		0xB0100000	/* LCD */

/* Register base virtual addresses mapped by initarm() */
#define SAOST_BASE		0xd0000000
#define SARTC_BASE		0xd0001000
#define SAPMR_BASE		0xd0002000
#define SARCR_BASE		0xd0003000
#define SAGPIO_BASE		0xd0004000
#define SAIPIC_BASE		0xd0005000
#define SAIPIC_BASE_0		0xd0000000 /* == IO_BASE XXX */
#define SAIPIC_BASE_1		0x5000
#define SADMAC_BASE		0xd0006000

#define SACOM3_BASE		0xd000d000	/* UART 3  */

#define SALCD_BASE		0xd0010000	/* LCD */

/* Interrupt controller registers */
#define SAIPIC_NPORTS		6
#define SAIPIC_IP		0		/* IRQ pending register */
#define SAIPIC_MR		1		/* Mask register */
#define SAIPIC_LR		2		/* Level register */
#define SAIPIC_FP		3		/* FIQ pending register */
#define SAIPIC_PR		4		/* Pending register */
#define SAIPIC_CR		5		/* Control register */

/* width of interrupt controller */
#define ICU_LEN			32
#endif /* _HPCARM_SA11X0_REG_H_ */
