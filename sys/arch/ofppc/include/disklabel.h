/*	$NetBSD: disklabel.h,v 1.4 1998/07/07 04:36:15 thorpej Exp $	*/

/*-
 * Copyright (C) 1995, 1996 Wolfgang Solfrank.
 * Copyright (C) 1995, 1996 TooLs GmbH.
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
 *	This product includes software developed by TooLs GmbH.
 * 4. The name of TooLs GmbH may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY TOOLS GMBH ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL TOOLS GMBH BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef	_MACHINE_DISKLABEL_H_
#define	_MACHINE_DISKLABEL_H_

#define	LABELSECTOR	1		/* sector containing label */
#define	LABELOFFSET	0		/* offset of label in sector */
#define	MAXPARTITIONS	16		/* number of partitions */
#define	RAW_PART	2		/* raw partition: XX?c */

/* MBR partition table */
#define	MBRSECTOR	0		/* MBR sector number */
#define	MBRPARTOFF	446		/* Offset of MBR partition table */
#define	NMBRPART	4		/* # of partitions in MBR */
#define	MBRMAGICOFF	510		/* Offset of magic number */
#define	MBRMAGIC	0xaa55		/* Actual magic number */

struct mbr_partition {
	u_int8_t	mbr_flag;	/* default boot flag */
	u_int8_t	mbr_shd;	/* start head, IsN't Always Meaningful */
	u_int8_t	mbr_ssect;	/* start sector, INAM */
	u_int8_t	mbr_scyl;	/* start cylinder, INAM */
	u_int8_t	mbr_type;	/* partition type */
	u_int8_t	mbr_ehd;	/* end head, INAM */
	u_int8_t	mbr_esect;	/* end sector, INAM */
	u_int8_t	mbr_ecyl;	/* end cylinder, INAM */
	u_int32_t	mbr_start;	/* absolute start sector number */
	u_int32_t	mbr_size;	/* partition size in sectors */
};

/* Known partition types: */
#define	MBR_EXTENDED	0x05		/* Extended partition */
#define	MBR_NETBSD	0xa9		/* NetBSD partition */
#define	MBR_386BSD	0xa5		/* 386BSD partition */

/* For compatibility reasons (mainly for fdisk): */
#define	dos_partition	mbr_partition
#define	dp_flag		mbr_flag
#define	dp_shd		mbr_shd
#define	dp_ssect	mbr_ssect
#define	dp_scyl		mbr_scyl
#define	dp_typ		mbr_type
#define	dp_ehd		mbr_ehd
#define	dp_esect	mbr_esect
#define	dp_ecyl		mbr_ecyl
#define	dp_start	mbr_start
#define	dp_size		mbr_size

#define	DOSPARTOFF	MBRPARTOFF
#define	NDOSPART	NMBRPART

#define	DOSPTYP_NETBSD	MBR_NETBSD

struct cpu_disklabel {
	int cd_start;		/* Offset to NetBSD partition in blocks */
};

/* Isolate the relevant bits to get sector and cylinder. */
#define	DPSECT(s)	((s) & 0x3f)
#define	DPCYL(c, s)	((c) + (((s) & 0xc0) << 2))

#ifdef	_KERNEL
struct disklabel;
int bounds_check_with_label __P((struct buf *bp, struct disklabel *lp, int wlabel));
#endif	/* _KERNEL */

#endif	/* _MACHINE_DISKLABEL_H_ */
