/*	$NetBSD: kvm_i386.c,v 1.32 2022/01/10 19:51:30 christos Exp $	*/

/*-
 * Copyright (c) 1989, 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software developed by the Computer Systems
 * Engineering group at Lawrence Berkeley Laboratory under DARPA contract
 * BG 91-66 and contributed to Berkeley.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
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
 */

#include <sys/cdefs.h>
#if defined(LIBC_SCCS) && !defined(lint)
#if 0
static char sccsid[] = "@(#)kvm_hp300.c	8.1 (Berkeley) 6/4/93";
#else
__RCSID("$NetBSD: kvm_i386.c,v 1.32 2022/01/10 19:51:30 christos Exp $");
#endif
#endif /* LIBC_SCCS and not lint */

/*
 * i386 machine dependent routines for kvm.
 */

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/kcore.h>
#include <sys/types.h>

#include <stdlib.h>
#include <unistd.h>
#include <nlist.h>
#include <kvm.h>

#include <uvm/uvm_extern.h>

#include <limits.h>
#include <db.h>

#include "kvm_private.h"

#include <i386/kcore.h>
#include <i386/pmap.h>
#include <i386/pte.h>
#include <i386/vmparam.h>

#ifndef btop
#define	btop(x)		(((unsigned)(x)) >> PGSHIFT)	/* XXX */
#define	ptob(x)		((caddr_t)((x) << PGSHIFT))	/* XXX */
#endif

/*
 * Indicates whether PAE is in use for the kernel image
 * 0: native i386 memory mappings
 * 1: i386 PAE mappings
 */
static int i386_use_pae;

int _kvm_kvatop_i386(kvm_t *, vaddr_t, paddr_t *);
int _kvm_kvatop_i386pae(kvm_t *, vaddr_t, paddr_t *);

void
_kvm_freevtop(kvm_t *kd)
{

	/* Not actually used for anything right now, but safe. */
	if (kd->vmst != 0)
		free(kd->vmst);
}

/*ARGSUSED*/
int
_kvm_initvtop(kvm_t *kd)
{
	cpu_kcore_hdr_t *cpu_kh = kd->cpu_data;

	i386_use_pae = 0; /* default: non PAE mode */
	if ((cpu_kh->pdppaddr & I386_KCORE_PAE) == I386_KCORE_PAE)
		i386_use_pae = 1;

	return 0;
}

/*
 * Translate a kernel virtual address to a physical address.
 */
int
_kvm_kvatop(kvm_t *kd, vaddr_t va, paddr_t *pa)
{

	if (ISALIVE(kd)) {
		_kvm_err(kd, 0, "vatop called in live kernel!");
		return 0;
	}

	switch (i386_use_pae) {
	default:
	case 0:
		return _kvm_kvatop_i386(kd, va, pa);
	case 1:
		return _kvm_kvatop_i386pae(kd, va, pa);
	}
	
}

/*
 * Used to translate a virtual address to a physical address for systems
 * with PAE mode disabled. Only two levels of virtual memory pages are
 * dereferenced (L2 PDEs, then L1 PTEs).
 */
int
_kvm_kvatop_i386(kvm_t *kd, vaddr_t va, paddr_t *pa)
{
	cpu_kcore_hdr_t *cpu_kh;
	u_long page_off;
	pd_entry_t pde;
	pt_entry_t pte;
	paddr_t pde_pa, pte_pa;

	cpu_kh = kd->cpu_data;
	page_off = va & PGOFSET;

	/*
	 * Find and read the page directory entry.
	 * pdppaddr being PAGE_SIZE aligned, we mask the option bits.
	 */
	pde_pa = (cpu_kh->pdppaddr & PTE_FRAME) + (pl2_pi(va) * sizeof(pde));
	if (_kvm_pread(kd, kd->pmfd, (void *)&pde, sizeof(pde),
	    _kvm_pa2off(kd, pde_pa)) != sizeof(pde)) {
		_kvm_syserr(kd, 0, "could not read PDE");
		goto lose;
	}

	/*
	 * Find and read the page table entry.
	 */
	if ((pde & PTE_P) == 0) {
		_kvm_err(kd, 0, "invalid translation (invalid PDE)");
		goto lose;
	}
	if ((pde & PTE_PS) != 0) {
		/*
		 * This is a 4MB page.
		 */
		page_off = va & ~PTE_LGFRAME;
		*pa = (pde & PTE_LGFRAME) + page_off;
		return (int)(NBPD_L2 - page_off);
	}
	pte_pa = (pde & PTE_FRAME) + (pl1_pi(va) * sizeof(pt_entry_t));
	if (_kvm_pread(kd, kd->pmfd, (void *) &pte, sizeof(pte),
	    _kvm_pa2off(kd, pte_pa)) != sizeof(pte)) {
		_kvm_syserr(kd, 0, "could not read PTE");
		goto lose;
	}

	/*
	 * Validate the PTE and return the physical address.
	 */
	if ((pte & PTE_P) == 0) {
		_kvm_err(kd, 0, "invalid translation (invalid PTE)");
		goto lose;
	}
	*pa = (pte & PTE_FRAME) + page_off;
	return (int)(NBPG - page_off);

 lose:
	*pa = (paddr_t)~0L;
	return 0;
}

/*
 * Translate a physical address to a file-offset in the crash dump.
 */
off_t
_kvm_pa2off(kvm_t *kd, paddr_t pa)
{
	cpu_kcore_hdr_t *cpu_kh;
	phys_ram_seg_t *ramsegs;
	off_t off;
	int i;

	cpu_kh = kd->cpu_data;
	ramsegs = (void *)((char *)(void *)cpu_kh + ALIGN(sizeof *cpu_kh));

	off = 0;
	for (i = 0; i < cpu_kh->nmemsegs; i++) {
		if (pa >= ramsegs[i].start &&
		    (pa - ramsegs[i].start) < ramsegs[i].size) {
			off += (pa - ramsegs[i].start);
			break;
		}
		off += ramsegs[i].size;
	}

	return (kd->dump_off + off);
}

/*
 * Machine-dependent initialization for ALL open kvm descriptors,
 * not just those for a kernel crash dump.  Some architectures
 * have to deal with these NOT being constants!  (i.e. m68k)
 */
int
_kvm_mdopen(kvm_t *kd)
{

	kd->min_uva = VM_MIN_ADDRESS;
	kd->max_uva = VM_MAXUSER_ADDRESS;

	return 0;
}
