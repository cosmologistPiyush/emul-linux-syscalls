/*	$NetBSD: md.h,v 1.13 2003/06/11 21:35:51 dsl Exp $	*/

/*
 * Copyright 1997 Piermont Information Systems Inc.
 * All rights reserved.
 *
 * Based on code written by Philip A. Nelson for Piermont Information
 * Systems Inc.
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
 *      This product includes software developed for the NetBSD Project by
 *      Piermont Information Systems Inc.
 * 4. The name of Piermont Information Systems Inc. may not be used to endorse
 *    or promote products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY PIERMONT INFORMATION SYSTEMS INC. ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL PIERMONT INFORMATION SYSTEMS INC. BE 
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF 
 * THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/* md.h -- Machine specific definitions for the vax */

/* Constants and defines */

/*
 * Symbolic names for disk partitions.
 */
#define PART_ROOT	A
#define PART_SWAP	B
#define PART_RAW	C
#define PART_USR	D	/* Can be after PART_FIRST_FREE */
#define PART_FIRST_FREE	E

#define DEFSWAPRAM	16	/* Assume at least this RAM for swap calc */
#define DEFROOTSIZE	32	/* Default root size */
#define DEFVARSIZE	32	/* Default /var size, if created */
#define DEFUSRSIZE	70	/* Default /usr size, if /home */
#define STDNEEDMB	80	/* Min space for non X install */
#define XNEEDMB		35	/* Extra megs for full X installation */

/*
 * Default filesets to fetch and install during installation
 * or upgrade.
 */
#define SET_KERNEL_1_NAME	"kern-GENERIC"

/*
 * Disk names accepted as valid targets for a from-scratch installation.
 */
#define DISK_NAMES "sd", "ra", "rd", "hp"

/*
 * Machine-specific command to write a new label to a disk.
 * If not defined, we assume the port does not support disklabels and
 * the hand-edited disklabel will NOT be written by MI code.
 */
#define	DISKLABEL_CMD	"disklabel -w -r"

/*
 * Default file system type for floppies.
 */
EXTERN char *fdtype INIT("ffs");

#define	LIB_COUNT	0
#define	LIB_MOVE	1

