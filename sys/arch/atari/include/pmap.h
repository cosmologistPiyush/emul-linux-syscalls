/*	$NetBSD: pmap.h,v 1.7 1996/04/18 08:52:19 leo Exp $	*/

/* 
 * Copyright (c) 1987 Carnegie-Mellon University
 * Copyright (c) 1991 Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * the Systems Programming Group of the University of Utah Computer
 * Science Department.
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
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)pmap.h	7.6 (Berkeley) 5/10/91
 */

#ifndef	_MACHINE_PMAP_H_
#define	_MACHINE_PMAP_H_

/*
 * Pmap stuff (in anticipation of '40 support)
 */
struct pmap {
	u_int 	*pm_ptab;	/* KVA of page table */
	u_int	*pm_stab;	/* KVA of segment table */
	u_int	*pm_rtab;	/* KVA of 68040 root table */
	int	pm_stchanged;	/* ST changed */
	short	pm_sref;	/* segment table ref count */
	short	pm_count;	/* pmap reference count */
	long	pm_ptpages;	/* more stats: PT pages */
	simple_lock_data_t	pm_lock;	/* lock on pmap */
	struct pmap_statistics	pm_stats;	/* pmap statistics */
};

typedef struct pmap *pmap_t;

/*
 * Macros for speed
 */
#define PMAP_ACTIVATE(pmapp, pcbp, iscurproc) \
	if ((pmapp) != NULL && (pmapp)->pm_stchanged) { \
		(pcbp)->pcb_ustp = \
		    atari_btop(pmap_extract(pmap_kernel(), \
		    cpu040 ? (vm_offset_t)(pmapp)->pm_rtab : \
		    (vm_offset_t)(pmapp)->pm_stab)); \
		if (iscurproc) \
			loadustp((pcbp)->pcb_ustp); \
		(pmapp)->pm_stchanged = FALSE; \
	}
#define PMAP_DEACTIVATE(pmapp, pcbp)

/*
 * Description of the memory segments. Build in atari_init/start_c().
 * This gives a better separation between machine dependent stuff and
 * the pmap-module.
 */
#define	NPHYS_SEGS	8
struct physeg {
	vm_offset_t	start;		/* PA of first page in segment	*/
	vm_offset_t	end;		/* PA of last  page in segment	*/
	int		first_page;	/* relative page# of 'start'	*/
};

/*
 * For each vm_page_t, there is a list of all currently valid virtual
 * mappings of that page.  An entry is a pv_entry_t, the list is pv_table.
 */
typedef struct pv_entry {
	struct pv_entry	*pv_next;	/* next pv_entry */
	struct pmap	*pv_pmap;	/* pmap where mapping lies */
	vm_offset_t	pv_va;		/* virtual address for mapping */
	u_int		*pv_ptste;	/* non-zero if VA maps a PT page */
	struct pmap	*pv_ptpmap;	/* if pv_ptste, pmap for PT page */
	int		pv_flags;	/* flags */
} *pv_entry_t;

#define	PV_CI		0x01	/* all entries must be cache inhibited */
#define PV_PTPAGE	0x02	/* entry maps a page table page */

#ifdef	_KERNEL
struct physeg	phys_segs[NPHYS_SEGS];
pv_entry_t	pv_table;	/* array of entries, one per page */
u_int		*Sysmap;
char		*vmmap;		/* map for mem, dumps, etc. */
struct pmap	kernel_pmap_store;

#ifdef MACHINE_NONCONTIG
#define	pa_index(pa)			pmap_page_index(pa)
#else
#define pa_index(pa)			atop(pa - vm_first_phys)
#endif /* MACHINE_NONCONTIG */

#define pa_to_pvh(pa)			(&pv_table[pa_index(pa)])
#define	pmap_kernel()			(&kernel_pmap_store)
#define	pmap_resident_count(pmap)	((pmap)->pm_stats.resident_count)

void	pmap_bootstrap __P((vm_offset_t));
#endif	/* _KERNEL */

#endif	/* !_MACHINE_PMAP_H_ */
