/*	$NetBSD: arm32_kvminit.c,v 1.69 2022/04/02 11:16:07 skrll Exp $	*/

/*
 * Copyright (c) 2002, 2003, 2005  Genetec Corporation.  All rights reserved.
 * Written by Hiroyuki Bessho for Genetec Corporation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of Genetec Corporation may not be used to endorse or
 *    promote products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY GENETEC CORPORATION ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL GENETEC CORPORATION
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Copyright (c) 2001 Wasabi Systems, Inc.
 * All rights reserved.
 *
 * Written by Jason R. Thorpe for Wasabi Systems, Inc.
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
 *	This product includes software developed for the NetBSD Project by
 *	Wasabi Systems, Inc.
 * 4. The name of Wasabi Systems, Inc. may not be used to endorse
 *    or promote products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY WASABI SYSTEMS, INC. ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL WASABI SYSTEMS, INC
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Copyright (c) 1997,1998 Mark Brinicombe.
 * Copyright (c) 1997,1998 Causality Limited.
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
 *	This product includes software developed by Mark Brinicombe
 *	for the NetBSD Project.
 * 4. The name of the company nor the name of the author may be used to
 *    endorse or promote products derived from this software without specific
 *    prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Copyright (c) 2007 Microsoft
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
 *	This product includes software developed by Microsoft
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTERS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "opt_arm_debug.h"
#include "opt_arm_start.h"
#include "opt_efi.h"
#include "opt_fdt.h"
#include "opt_multiprocessor.h"

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: arm32_kvminit.c,v 1.69 2022/04/02 11:16:07 skrll Exp $");

#include <sys/param.h>

#include <sys/asan.h>
#include <sys/bus.h>
#include <sys/device.h>
#include <sys/kernel.h>
#include <sys/reboot.h>

#include <dev/cons.h>

#include <uvm/uvm_extern.h>

#include <arm/arm32/machdep.h>
#include <arm/bootconfig.h>
#include <arm/db_machdep.h>
#include <arm/locore.h>
#include <arm/undefined.h>

#if defined(FDT)
#include <arch/evbarm/fdt/platform.h>
#include <arm/fdt/arm_fdtvar.h>
#include <dev/fdt/fdt_memory.h>
#endif

#ifdef MULTIPROCESSOR
#ifndef __HAVE_CPU_UAREA_ALLOC_IDLELWP
#error __HAVE_CPU_UAREA_ALLOC_IDLELWP required to not waste pages for idlestack
#endif
#endif

#ifdef VERBOSE_INIT_ARM
#define VPRINTF(...)	printf(__VA_ARGS__)
#else
#define VPRINTF(...)	__nothing
#endif

#if defined(__HAVE_GENERIC_START)
#if defined(KERNEL_BASE_VOFFSET)
#error KERNEL_BASE_VOFFSET should not be defined with __HAVE_GENERIC_START
#endif
#endif

#if defined(EFI_RUNTIME)
#if !defined(ARM_MMU_EXTENDED)
#error EFI_RUNTIME is only supported with ARM_MMU_EXTENDED
#endif
#endif

struct bootmem_info bootmem_info;

extern void *msgbufaddr;
paddr_t msgbufphys;
paddr_t physical_start;
paddr_t physical_end;

extern char etext[];
extern char __data_start[], _edata[];
extern char __bss_start[], __bss_end__[];
extern char _end[];

/* Page tables for mapping kernel VM */
#define KERNEL_L2PT_VMDATA_NUM	8	/* start with 32MB of KVM */

#ifdef KASAN
vaddr_t kasan_kernelstart;
vaddr_t kasan_kernelsize;

#define	KERNEL_L2PT_KASAN_NUM	howmany(VM_KERNEL_KASAN_SIZE, L2_S_SEGSIZE)
bool kasan_l2pts_created  __attribute__((__section__(".data"))) = false;
pv_addr_t kasan_l2pt[KERNEL_L2PT_KASAN_NUM];
#else
#define KERNEL_L2PT_KASAN_NUM	0
#endif

u_long kern_vtopdiff __attribute__((__section__(".data")));

void
arm32_bootmem_init(paddr_t memstart, psize_t memsize, vsize_t kernelstart)
{
	struct bootmem_info * const bmi = &bootmem_info;
	pv_addr_t *pv = bmi->bmi_freeblocks;

	/*
	 * FDT/generic start fills in kern_vtopdiff early
	 */
#if defined(__HAVE_GENERIC_START)
	extern char KERNEL_BASE_virt[];
	extern char const __stop__init_memory[];

	VPRINTF("%s: kern_vtopdiff=%#lx\n", __func__, kern_vtopdiff);

	vaddr_t kstartva = trunc_page((vaddr_t)KERNEL_BASE_virt);
	vaddr_t kendva = round_page((vaddr_t)__stop__init_memory);

	kernelstart = KERN_VTOPHYS(kstartva);

	VPRINTF("%s: kstartva=%#lx, kernelstart=%#lx\n", __func__, kstartva, kernelstart);
#else
	vaddr_t kendva = round_page((vaddr_t)_end);

#if defined(KERNEL_BASE_VOFFSET)
	kern_vtopdiff = KERNEL_BASE_VOFFSET;
#else
	KASSERT(memstart == kernelstart);
	kern_vtopdiff = KERNEL_BASE + memstart;
#endif
#endif
	paddr_t kernelend = KERN_VTOPHYS(kendva);

	VPRINTF("%s: memstart=%#lx, memsize=%#lx\n", __func__,
	    memstart, memsize);
	VPRINTF("%s: kernelstart=%#lx, kernelend=%#lx\n", __func__,
	    kernelstart, kernelend);

	physical_start = bmi->bmi_start = memstart;
	physical_end = bmi->bmi_end = memstart + memsize;
#ifndef ARM_HAS_LPAE
	if (physical_end == 0) {
		physical_end = -PAGE_SIZE;
		memsize -= PAGE_SIZE;
		bmi->bmi_end -= PAGE_SIZE;
		VPRINTF("%s: memsize shrunk by a page to avoid ending at 4GB\n",
		    __func__);
	}
#endif
	physmem = memsize / PAGE_SIZE;

	/*
	 * Let's record where the kernel lives.
	 */

	bmi->bmi_kernelstart = kernelstart;
	bmi->bmi_kernelend = kernelend;

#if defined(FDT)
	fdt_memory_remove_range(bmi->bmi_kernelstart,
	    bmi->bmi_kernelend - bmi->bmi_kernelstart);
#endif

	VPRINTF("%s: kernel phys start %#lx end %#lx\n", __func__, kernelstart,
	    kernelend);

#if 0
	// XXX Makes RPI abort
	KASSERT((kernelstart & (L2_S_SEGSIZE - 1)) == 0);
#endif
	/*
	 * Now the rest of the free memory must be after the kernel.
	 */
	pv->pv_pa = bmi->bmi_kernelend;
	pv->pv_va = KERN_PHYSTOV(pv->pv_pa);
	pv->pv_size = bmi->bmi_end - bmi->bmi_kernelend;
	bmi->bmi_freepages += pv->pv_size / PAGE_SIZE;
	VPRINTF("%s: adding %lu free pages: [%#lx..%#lx] (VA %#lx)\n",
	    __func__, pv->pv_size / PAGE_SIZE, pv->pv_pa,
	    pv->pv_pa + pv->pv_size - 1, pv->pv_va);
	pv++;

	/*
	 * Add a free block for any memory before the kernel.
	 */
	if (bmi->bmi_start < bmi->bmi_kernelstart) {
		pv->pv_pa = bmi->bmi_start;
		pv->pv_va = KERN_PHYSTOV(pv->pv_pa);
		pv->pv_size = bmi->bmi_kernelstart - pv->pv_pa;
		bmi->bmi_freepages += pv->pv_size / PAGE_SIZE;
		VPRINTF("%s: adding %lu free pages: [%#lx..%#lx] (VA %#lx)\n",
		    __func__, pv->pv_size / PAGE_SIZE, pv->pv_pa,
		    pv->pv_pa + pv->pv_size - 1, pv->pv_va);
		pv++;
	}

	bmi->bmi_nfreeblocks = pv - bmi->bmi_freeblocks;

	SLIST_INIT(&bmi->bmi_freechunks);
	SLIST_INIT(&bmi->bmi_chunks);
}

static bool
concat_pvaddr(pv_addr_t *acc_pv, pv_addr_t *pv)
{
	if (acc_pv->pv_pa + acc_pv->pv_size == pv->pv_pa
	    && acc_pv->pv_va + acc_pv->pv_size == pv->pv_va
	    && acc_pv->pv_prot == pv->pv_prot
	    && acc_pv->pv_cache == pv->pv_cache) {
#if 0
		VPRINTF("%s: appending pv %p (%#lx..%#lx) to %#lx..%#lx\n",
		    __func__, pv, pv->pv_pa, pv->pv_pa + pv->pv_size,
		    acc_pv->pv_pa, acc_pv->pv_pa + acc_pv->pv_size);
#endif
		acc_pv->pv_size += pv->pv_size;
		return true;
	}

	return false;
}

static void
add_pages(struct bootmem_info *bmi, pv_addr_t *pv)
{
	pv_addr_t **pvp = &SLIST_FIRST(&bmi->bmi_chunks);
	while ((*pvp) != NULL && (*pvp)->pv_va <= pv->pv_va) {
		pv_addr_t * const pv0 = (*pvp);
		KASSERT(SLIST_NEXT(pv0, pv_list) == NULL || pv0->pv_pa < SLIST_NEXT(pv0, pv_list)->pv_pa);
		if (concat_pvaddr(pv0, pv)) {
			VPRINTF("%s: %s pv %p (%#lx..%#lx) to %#lx..%#lx\n",
			    __func__, "appending", pv,
			    pv->pv_pa, pv->pv_pa + pv->pv_size - 1,
			    pv0->pv_pa, pv0->pv_pa + pv0->pv_size - pv->pv_size - 1);
			pv = SLIST_NEXT(pv0, pv_list);
			if (pv != NULL && concat_pvaddr(pv0, pv)) {
				VPRINTF("%s: %s pv %p (%#lx..%#lx) to %#lx..%#lx\n",
				    __func__, "merging", pv,
				    pv->pv_pa, pv->pv_pa + pv->pv_size - 1,
				    pv0->pv_pa,
				    pv0->pv_pa + pv0->pv_size - pv->pv_size - 1);
				SLIST_REMOVE_AFTER(pv0, pv_list);
				SLIST_INSERT_HEAD(&bmi->bmi_freechunks, pv, pv_list);
			}
			return;
		}
		KASSERT(pv->pv_va != (*pvp)->pv_va);
		pvp = &SLIST_NEXT(*pvp, pv_list);
	}
	KASSERT((*pvp) == NULL || pv->pv_va < (*pvp)->pv_va);
	pv_addr_t * const new_pv = SLIST_FIRST(&bmi->bmi_freechunks);
	KASSERT(new_pv != NULL);
	SLIST_REMOVE_HEAD(&bmi->bmi_freechunks, pv_list);
	*new_pv = *pv;
	SLIST_NEXT(new_pv, pv_list) = *pvp;
	(*pvp) = new_pv;

	VPRINTF("%s: adding pv %p (pa %#lx, va %#lx, %lu pages) ",
	    __func__, new_pv, new_pv->pv_pa, new_pv->pv_va,
	    new_pv->pv_size / PAGE_SIZE);
	if (SLIST_NEXT(new_pv, pv_list)) {
		VPRINTF("before pa %#lx\n", SLIST_NEXT(new_pv, pv_list)->pv_pa);
	} else {
		VPRINTF("at tail\n");
	}
}

static void
valloc_pages(struct bootmem_info *bmi, pv_addr_t *pv, size_t npages,
    int prot, int cache, bool zero_p)
{
	size_t nbytes = npages * PAGE_SIZE;
	pv_addr_t *free_pv = bmi->bmi_freeblocks;
	size_t free_idx = 0;
	static bool l1pt_found;

	KASSERT(npages > 0);

	/*
	 * If we haven't allocated the kernel L1 page table and we are aligned
	 * at a L1 table boundary, alloc the memory for it.
	 */
	if (!l1pt_found
	    && (free_pv->pv_pa & (L1_TABLE_SIZE - 1)) == 0
	    && free_pv->pv_size >= L1_TABLE_SIZE) {
		l1pt_found = true;
		VPRINTF(" l1pt");

		valloc_pages(bmi, &kernel_l1pt, L1_TABLE_SIZE / PAGE_SIZE,
		    VM_PROT_READ | VM_PROT_WRITE, PTE_PAGETABLE, true);
		add_pages(bmi, &kernel_l1pt);
#if defined(EFI_RUNTIME)
		valloc_pages(bmi, &efirt_l1pt, L1_TABLE_SIZE / PAGE_SIZE,
		    VM_PROT_READ | VM_PROT_WRITE, PTE_PAGETABLE, true);
		add_pages(bmi, &efirt_l1pt);
#endif
	}

	while (nbytes > free_pv->pv_size) {
		free_pv++;
		free_idx++;
		if (free_idx == bmi->bmi_nfreeblocks) {
			panic("%s: could not allocate %zu bytes",
			    __func__, nbytes);
		}
	}

	/*
	 * As we allocate the memory, make sure that we don't walk over
	 * our current first level translation table.
	 */
	KASSERT((armreg_ttbr_read() & ~(L1_TABLE_SIZE - 1)) != free_pv->pv_pa);

#if defined(FDT)
	fdt_memory_remove_range(free_pv->pv_pa, nbytes);
#endif
	pv->pv_pa = free_pv->pv_pa;
	pv->pv_va = free_pv->pv_va;
	pv->pv_size = nbytes;
	pv->pv_prot = prot;
	pv->pv_cache = cache;

	/*
	 * If PTE_PAGETABLE uses the same cache modes as PTE_CACHE
	 * just use PTE_CACHE.
	 */
	if (cache == PTE_PAGETABLE
	    && pte_l1_s_cache_mode == pte_l1_s_cache_mode_pt
	    && pte_l2_l_cache_mode == pte_l2_l_cache_mode_pt
	    && pte_l2_s_cache_mode == pte_l2_s_cache_mode_pt)
		pv->pv_cache = PTE_CACHE;

	free_pv->pv_pa += nbytes;
	free_pv->pv_va += nbytes;
	free_pv->pv_size -= nbytes;
	if (free_pv->pv_size == 0) {
		--bmi->bmi_nfreeblocks;
		for (; free_idx < bmi->bmi_nfreeblocks; free_idx++) {
			free_pv[0] = free_pv[1];
		}
	}

	bmi->bmi_freepages -= npages;

	if (zero_p)
		memset((void *)pv->pv_va, 0, nbytes);
}

void
arm32_kernel_vm_init(vaddr_t kernel_vm_base, vaddr_t vectors, vaddr_t iovbase,
    const struct pmap_devmap *devmap, bool mapallmem_p)
{
	struct bootmem_info * const bmi = &bootmem_info;
#ifdef MULTIPROCESSOR
	const size_t cpu_num = arm_cpu_max;
#else
	const size_t cpu_num = 1;
#endif

#ifdef ARM_HAS_VBAR
	const bool map_vectors_p = false;
#elif defined(CPU_ARMV7) || defined(CPU_ARM11)
	const bool map_vectors_p = vectors == ARM_VECTORS_HIGH
	    || (armreg_pfr1_read() & ARM_PFR1_SEC_MASK) == 0;
#else
	const bool map_vectors_p = true;
#endif

#ifdef __HAVE_MM_MD_DIRECT_MAPPED_PHYS
	KASSERT(mapallmem_p);
#ifdef ARM_MMU_EXTENDED
	/*
	 * The direct map VA space ends at the start of the kernel VM space.
	 */
	pmap_directlimit = kernel_vm_base;
#else
	KASSERT(kernel_vm_base - KERNEL_BASE >= physical_end - physical_start);
#endif /* ARM_MMU_EXTENDED */
#endif /* __HAVE_MM_MD_DIRECT_MAPPED_PHYS */

	/*
	 * Calculate the number of L2 pages needed for mapping the
	 * kernel + data + stuff.  Assume 2 L2 pages for kernel, 1 for vectors,
	 * and 1 for IO
	 */
	size_t kernel_size = bmi->bmi_kernelend;
	kernel_size -= (bmi->bmi_kernelstart & -L2_S_SEGSIZE);
	kernel_size += L1_TABLE_SIZE;
	kernel_size += PAGE_SIZE * KERNEL_L2PT_VMDATA_NUM;
	kernel_size += PAGE_SIZE * KERNEL_L2PT_KASAN_NUM;
	if (map_vectors_p) {
		kernel_size += PAGE_SIZE;	/* L2PT for VECTORS */
	}
	if (iovbase) {
		kernel_size += PAGE_SIZE;	/* L2PT for IO */
	}
	kernel_size +=
	    cpu_num * (ABT_STACK_SIZE + FIQ_STACK_SIZE + IRQ_STACK_SIZE
	    + UND_STACK_SIZE + UPAGES) * PAGE_SIZE;
	kernel_size += round_page(MSGBUFSIZE);
	kernel_size += 0x10000;	/* slop */
	if (!mapallmem_p) {
		kernel_size += PAGE_SIZE
		    * howmany(kernel_size, L2_S_SEGSIZE);
	}
	kernel_size = round_page(kernel_size);

	/*
	 * Now we know how many L2 pages it will take.
	 */
	const size_t KERNEL_L2PT_KERNEL_NUM =
	    howmany(kernel_size, L2_S_SEGSIZE);

	VPRINTF("%s: %zu L2 pages are needed to map %#zx kernel bytes\n",
	    __func__, KERNEL_L2PT_KERNEL_NUM, kernel_size);

	KASSERT(KERNEL_L2PT_KERNEL_NUM + KERNEL_L2PT_VMDATA_NUM < __arraycount(bmi->bmi_l2pts));
	pv_addr_t * const kernel_l2pt = bmi->bmi_l2pts;
	pv_addr_t * const vmdata_l2pt = kernel_l2pt + KERNEL_L2PT_KERNEL_NUM;
	pv_addr_t msgbuf;
	pv_addr_t text;
	pv_addr_t data;
	pv_addr_t chunks[__arraycount(bmi->bmi_l2pts) + 11];
#if ARM_MMU_XSCALE == 1
	pv_addr_t minidataclean;
#endif

	/*
	 * We need to allocate some fixed page tables to get the kernel going.
	 *
	 * We are going to allocate our bootstrap pages from the beginning of
	 * the free space that we just calculated.  We allocate one page
	 * directory and a number of page tables and store the physical
	 * addresses in the bmi_l2pts array in bootmem_info.
	 *
	 * The kernel page directory must be on a 16K boundary.  The page
	 * tables must be on 4K boundaries.  What we do is allocate the
	 * page directory on the first 16K boundary that we encounter, and
	 * the page tables on 4K boundaries otherwise.  Since we allocate
	 * at least 3 L2 page tables, we are guaranteed to encounter at
	 * least one 16K aligned region.
	 */

	VPRINTF("%s: allocating page tables for", __func__);
	for (size_t i = 0; i < __arraycount(chunks); i++) {
		SLIST_INSERT_HEAD(&bmi->bmi_freechunks, &chunks[i], pv_list);
	}

	kernel_l1pt.pv_pa = 0;
	kernel_l1pt.pv_va = 0;

#if defined(EFI_RUNTIME)
	efirt_l1pt.pv_pa = 0;
	efirt_l1pt.pv_va = 0;
#endif
	/*
	 * Allocate the L2 pages, but if we get to a page that is aligned for
	 * an L1 page table, we will allocate the pages for it first and then
	 * allocate the L2 page.
	 */

	if (map_vectors_p) {
		/*
		 * First allocate L2 page for the vectors.
		 */
		VPRINTF(" vector");
		valloc_pages(bmi, &bmi->bmi_vector_l2pt, 1,
		    VM_PROT_READ | VM_PROT_WRITE, PTE_PAGETABLE, true);
		add_pages(bmi, &bmi->bmi_vector_l2pt);
	}

	/*
	 * Now allocate L2 pages for the kernel
	 */
	VPRINTF(" kernel");
	for (size_t idx = 0; idx < KERNEL_L2PT_KERNEL_NUM; ++idx) {
		valloc_pages(bmi, &kernel_l2pt[idx], 1,
		    VM_PROT_READ | VM_PROT_WRITE, PTE_PAGETABLE, true);
		add_pages(bmi, &kernel_l2pt[idx]);
	}

	/*
	 * Now allocate L2 pages for the initial kernel VA space.
	 */
	VPRINTF(" vm");
	for (size_t idx = 0; idx < KERNEL_L2PT_VMDATA_NUM; ++idx) {
		valloc_pages(bmi, &vmdata_l2pt[idx], 1,
		    VM_PROT_READ | VM_PROT_WRITE, PTE_PAGETABLE, true);
		add_pages(bmi, &vmdata_l2pt[idx]);
	}

#ifdef KASAN
	/*
	 * Now allocate L2 pages for the KASAN shadow map l2pt VA space.
	 */
	VPRINTF(" kasan");
	for (size_t idx = 0; idx < KERNEL_L2PT_KASAN_NUM; ++idx) {
		valloc_pages(bmi, &kasan_l2pt[idx], 1,
		    VM_PROT_READ | VM_PROT_WRITE, PTE_PAGETABLE, true);
		add_pages(bmi, &kasan_l2pt[idx]);
	}

#endif
	/*
	 * If someone wanted a L2 page for I/O, allocate it now.
	 */
	if (iovbase) {
		VPRINTF(" io");
		valloc_pages(bmi, &bmi->bmi_io_l2pt, 1,
		    VM_PROT_READ | VM_PROT_WRITE, PTE_PAGETABLE, true);
		add_pages(bmi, &bmi->bmi_io_l2pt);
	}

	VPRINTF("%s: allocating stacks\n", __func__);

	/* Allocate stacks for all modes and CPUs */
	valloc_pages(bmi, &abtstack, ABT_STACK_SIZE * cpu_num,
	    VM_PROT_READ | VM_PROT_WRITE, PTE_CACHE, true);
	add_pages(bmi, &abtstack);
	valloc_pages(bmi, &fiqstack, FIQ_STACK_SIZE * cpu_num,
	    VM_PROT_READ | VM_PROT_WRITE, PTE_CACHE, true);
	add_pages(bmi, &fiqstack);
	valloc_pages(bmi, &irqstack, IRQ_STACK_SIZE * cpu_num,
	    VM_PROT_READ | VM_PROT_WRITE, PTE_CACHE, true);
	add_pages(bmi, &irqstack);
	valloc_pages(bmi, &undstack, UND_STACK_SIZE * cpu_num,
	    VM_PROT_READ | VM_PROT_WRITE, PTE_CACHE, true);
	add_pages(bmi, &undstack);
	valloc_pages(bmi, &idlestack, UPAGES * cpu_num,		/* SVC32 */
	    VM_PROT_READ | VM_PROT_WRITE, PTE_CACHE, true);
	add_pages(bmi, &idlestack);
	valloc_pages(bmi, &kernelstack, UPAGES,			/* SVC32 */
	    VM_PROT_READ | VM_PROT_WRITE, PTE_CACHE, true);
	add_pages(bmi, &kernelstack);

	/* Allocate the message buffer from the end of memory. */
	const size_t msgbuf_pgs = round_page(MSGBUFSIZE) / PAGE_SIZE;
	valloc_pages(bmi, &msgbuf, msgbuf_pgs,
	    VM_PROT_READ | VM_PROT_WRITE, PTE_CACHE, false);
	add_pages(bmi, &msgbuf);
	msgbufphys = msgbuf.pv_pa;
	msgbufaddr = (void *)msgbuf.pv_va;

#ifdef KASAN
	kasan_kernelstart = KERNEL_BASE;
	kasan_kernelsize = (msgbuf.pv_va + round_page(MSGBUFSIZE)) - KERNEL_BASE;
#endif

	if (map_vectors_p) {
		/*
		 * Allocate a page for the system vector page.
		 * This page will just contain the system vectors and can be
		 * shared by all processes.
		 */
		VPRINTF(" vector");

		valloc_pages(bmi, &systempage, 1,
		    VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,
		    PTE_CACHE, true);
	}
	systempage.pv_va = vectors;

	/*
	 * If the caller needed a few extra pages for some reason, allocate
	 * them now.
	 */
#if ARM_MMU_XSCALE == 1
#if (ARM_NMMUS > 1)
	if (xscale_use_minidata)
#endif
		valloc_pages(bmi, &minidataclean, 1,
		    VM_PROT_READ | VM_PROT_WRITE, 0, true);
#endif

	/*
	 * Ok we have allocated physical pages for the primary kernel
	 * page tables and stacks.  Let's just confirm that.
	 */
	if (kernel_l1pt.pv_va == 0
	    && (!kernel_l1pt.pv_pa || (kernel_l1pt.pv_pa & (L1_TABLE_SIZE - 1)) != 0))
		panic("%s: Failed to allocate or align the kernel "
		    "page directory", __func__);

	VPRINTF("Creating L1 page table at 0x%08lx/0x%08lx\n",
	    kernel_l1pt.pv_va, kernel_l1pt.pv_pa);

	/*
	 * Now we start construction of the L1 page table
	 * We start by mapping the L2 page tables into the L1.
	 * This means that we can replace L1 mappings later on if necessary
	 */
	vaddr_t l1pt_va = kernel_l1pt.pv_va;
	paddr_t l1pt_pa = kernel_l1pt.pv_pa;

	if (map_vectors_p) {
		/* Map the L2 pages tables in the L1 page table */
		const vaddr_t va = systempage.pv_va & -L2_S_SEGSIZE;

		pmap_link_l2pt(l1pt_va, va,  &bmi->bmi_vector_l2pt);

		VPRINTF("%s: adding L2 pt (VA %#lx, PA %#lx) for VA %#lx %s\n",
		    __func__, bmi->bmi_vector_l2pt.pv_va,
		    bmi->bmi_vector_l2pt.pv_pa, systempage.pv_va, "(vectors)");
	}

	/*
	 * This enforces an alignment requirement of L2_S_SEGSIZE for kernel
	 * start PA
	 */
	const vaddr_t kernel_base =
	    KERN_PHYSTOV(bmi->bmi_kernelstart & -L2_S_SEGSIZE);

	VPRINTF("%s: kernel_base %lx KERNEL_L2PT_KERNEL_NUM %zu\n", __func__,
	    kernel_base, KERNEL_L2PT_KERNEL_NUM);

	for (size_t idx = 0; idx < KERNEL_L2PT_KERNEL_NUM; idx++) {
		const vaddr_t va = kernel_base + idx * L2_S_SEGSIZE;

		pmap_link_l2pt(l1pt_va, va, &kernel_l2pt[idx]);

		VPRINTF("%s: adding L2 pt (VA %#lx, PA %#lx) for VA %#lx %s\n",
		    __func__, kernel_l2pt[idx].pv_va, kernel_l2pt[idx].pv_pa,
		    va, "(kernel)");
	}

	VPRINTF("%s: kernel_vm_base %lx KERNEL_L2PT_VMDATA_NUM %d\n", __func__,
	    kernel_vm_base, KERNEL_L2PT_VMDATA_NUM);

	for (size_t idx = 0; idx < KERNEL_L2PT_VMDATA_NUM; idx++) {
		const vaddr_t va = kernel_vm_base + idx * L2_S_SEGSIZE;

		pmap_link_l2pt(l1pt_va, va, &vmdata_l2pt[idx]);

		VPRINTF("%s: adding L2 pt (VA %#lx, PA %#lx) for VA %#lx %s\n",
		    __func__, vmdata_l2pt[idx].pv_va, vmdata_l2pt[idx].pv_pa,
		    va, "(vm)");
	}
	if (iovbase) {
		const vaddr_t va = iovbase & -L2_S_SEGSIZE;

		pmap_link_l2pt(l1pt_va, va, &bmi->bmi_io_l2pt);

		VPRINTF("%s: adding L2 pt (VA %#lx, PA %#lx) for VA %#lx %s\n",
		    __func__, bmi->bmi_io_l2pt.pv_va, bmi->bmi_io_l2pt.pv_pa,
		    va, "(io)");
	}

#ifdef KASAN
	VPRINTF("%s: kasan_shadow_base %x KERNEL_L2PT_KASAN_NUM %d\n", __func__,
	    VM_KERNEL_KASAN_BASE, KERNEL_L2PT_KASAN_NUM);

	for (size_t idx = 0; idx < KERNEL_L2PT_KASAN_NUM; idx++) {
		const vaddr_t va = VM_KERNEL_KASAN_BASE  + idx * L2_S_SEGSIZE;

		pmap_link_l2pt(l1pt_va, va, &kasan_l2pt[idx]);

		VPRINTF("%s: adding L2 pt (VA %#lx, PA %#lx) for VA %#lx %s\n",
		    __func__, kasan_l2pt[idx].pv_va, kasan_l2pt[idx].pv_pa,
		    va, "(kasan)");
	}
	kasan_l2pts_created = true;
#endif

	/* update the top of the kernel VM */
	pmap_curmaxkvaddr =
	    kernel_vm_base + (KERNEL_L2PT_VMDATA_NUM * L2_S_SEGSIZE);

	// This could be done earlier and then the kernel data and pages
	// allocated above would get merged (concatentated)

	VPRINTF("Mapping kernel\n");

	extern char etext[];
	size_t totalsize = bmi->bmi_kernelend - bmi->bmi_kernelstart;
	size_t textsize = KERN_VTOPHYS((uintptr_t)etext) - bmi->bmi_kernelstart;

	textsize = (textsize + PGOFSET) & ~PGOFSET;

	/* start at offset of kernel in RAM */

	text.pv_pa = bmi->bmi_kernelstart;
	text.pv_va = KERN_PHYSTOV(bmi->bmi_kernelstart);
	text.pv_size = textsize;
	text.pv_prot = VM_PROT_READ | VM_PROT_EXECUTE;
	text.pv_cache = PTE_CACHE;

	VPRINTF("%s: adding chunk for kernel text %#lx..%#lx (VA %#lx)\n",
	    __func__, text.pv_pa, text.pv_pa + text.pv_size - 1, text.pv_va);

	add_pages(bmi, &text);

	data.pv_pa = text.pv_pa + textsize;
	data.pv_va = text.pv_va + textsize;
	data.pv_size = totalsize - textsize;
	data.pv_prot = VM_PROT_READ | VM_PROT_WRITE;
	data.pv_cache = PTE_CACHE;

	VPRINTF("%s: adding chunk for kernel data/bss %#lx..%#lx (VA %#lx)\n",
	    __func__, data.pv_pa, data.pv_pa + data.pv_size - 1, data.pv_va);

	add_pages(bmi, &data);

	VPRINTF("Listing Chunks\n");

	pv_addr_t *lpv;
	SLIST_FOREACH(lpv, &bmi->bmi_chunks, pv_list) {
		VPRINTF("%s: pv %p: chunk VA %#lx..%#lx "
		    "(PA %#lx, prot %d, cache %d)\n",
		    __func__, lpv, lpv->pv_va, lpv->pv_va + lpv->pv_size - 1,
		    lpv->pv_pa, lpv->pv_prot, lpv->pv_cache);
	}
	VPRINTF("\nMapping Chunks\n");

	pv_addr_t cur_pv;
	pv_addr_t *pv = SLIST_FIRST(&bmi->bmi_chunks);
	if (!mapallmem_p || pv->pv_pa == bmi->bmi_start) {
		cur_pv = *pv;
		KASSERTMSG(cur_pv.pv_va >= KERNEL_BASE, "%#lx", cur_pv.pv_va);
		pv = SLIST_NEXT(pv, pv_list);
	} else {
		cur_pv.pv_va = KERNEL_BASE;
		cur_pv.pv_pa = KERN_VTOPHYS(cur_pv.pv_va);
		cur_pv.pv_size = pv->pv_pa - cur_pv.pv_pa;
		cur_pv.pv_prot = VM_PROT_READ | VM_PROT_WRITE;
		cur_pv.pv_cache = PTE_CACHE;
	}
	while (pv != NULL) {
		if (mapallmem_p) {
			if (concat_pvaddr(&cur_pv, pv)) {
				pv = SLIST_NEXT(pv, pv_list);
				continue;
			}
			if (cur_pv.pv_pa + cur_pv.pv_size < pv->pv_pa) {
				/*
				 * See if we can extend the current pv to emcompass the
				 * hole, and if so do it and retry the concatenation.
				 */
				if (cur_pv.pv_prot == (VM_PROT_READ | VM_PROT_WRITE)
				    && cur_pv.pv_cache == PTE_CACHE) {
					cur_pv.pv_size = pv->pv_pa - cur_pv.pv_va;
					continue;
				}

				/*
				 * We couldn't so emit the current chunk and then
				 */
				VPRINTF("%s: mapping chunk VA %#lx..%#lx "
				    "(PA %#lx, prot %d, cache %d)\n",
				    __func__,
				    cur_pv.pv_va, cur_pv.pv_va + cur_pv.pv_size - 1,
				    cur_pv.pv_pa, cur_pv.pv_prot, cur_pv.pv_cache);
				pmap_map_chunk(l1pt_va, cur_pv.pv_va, cur_pv.pv_pa,
				    cur_pv.pv_size, cur_pv.pv_prot, cur_pv.pv_cache);

				/*
				 * set the current chunk to the hole and try again.
				 */
				cur_pv.pv_pa += cur_pv.pv_size;
				cur_pv.pv_va += cur_pv.pv_size;
				cur_pv.pv_size = pv->pv_pa - cur_pv.pv_va;
				cur_pv.pv_prot = VM_PROT_READ | VM_PROT_WRITE;
				cur_pv.pv_cache = PTE_CACHE;
				continue;
			}
		}

		/*
		 * The new pv didn't concatenate so emit the current one
		 * and use the new pv as the current pv.
		 */
		VPRINTF("%s: mapping chunk VA %#lx..%#lx "
		    "(PA %#lx, prot %d, cache %d)\n",
		    __func__, cur_pv.pv_va, cur_pv.pv_va + cur_pv.pv_size - 1,
		    cur_pv.pv_pa, cur_pv.pv_prot, cur_pv.pv_cache);
		pmap_map_chunk(l1pt_va, cur_pv.pv_va, cur_pv.pv_pa,
		    cur_pv.pv_size, cur_pv.pv_prot, cur_pv.pv_cache);
		cur_pv = *pv;
		pv = SLIST_NEXT(pv, pv_list);
	}

	/*
	 * If we are mapping all of memory, let's map the rest of memory.
	 */
	if (mapallmem_p && cur_pv.pv_pa + cur_pv.pv_size < bmi->bmi_end) {
		if (cur_pv.pv_prot == (VM_PROT_READ | VM_PROT_WRITE)
		    && cur_pv.pv_cache == PTE_CACHE) {
			cur_pv.pv_size = bmi->bmi_end - cur_pv.pv_pa;
		} else {
			KASSERTMSG(cur_pv.pv_va + cur_pv.pv_size <= kernel_vm_base,
			    "%#lx >= %#lx", cur_pv.pv_va + cur_pv.pv_size,
			    kernel_vm_base);
			VPRINTF("%s: mapping chunk VA %#lx..%#lx "
			    "(PA %#lx, prot %d, cache %d)\n",
			    __func__, cur_pv.pv_va, cur_pv.pv_va + cur_pv.pv_size - 1,
			    cur_pv.pv_pa, cur_pv.pv_prot, cur_pv.pv_cache);
			pmap_map_chunk(l1pt_va, cur_pv.pv_va, cur_pv.pv_pa,
			    cur_pv.pv_size, cur_pv.pv_prot, cur_pv.pv_cache);
			cur_pv.pv_pa += cur_pv.pv_size;
			cur_pv.pv_va += cur_pv.pv_size;
			cur_pv.pv_size = bmi->bmi_end - cur_pv.pv_pa;
			cur_pv.pv_prot = VM_PROT_READ | VM_PROT_WRITE;
			cur_pv.pv_cache = PTE_CACHE;
		}
	}

	/*
	 * The amount we can direct map is limited by the start of the
	 * virtual part of the kernel address space.  Don't overrun
	 * into it.
	 */
	if (mapallmem_p && cur_pv.pv_va + cur_pv.pv_size > kernel_vm_base) {
		cur_pv.pv_size = kernel_vm_base - cur_pv.pv_va;
	}

	/*
	 * Now we map the final chunk.
	 */
	VPRINTF("%s: mapping last chunk VA %#lx..%#lx (PA %#lx, prot %d, cache %d)\n",
	    __func__, cur_pv.pv_va, cur_pv.pv_va + cur_pv.pv_size - 1,
	    cur_pv.pv_pa, cur_pv.pv_prot, cur_pv.pv_cache);
	pmap_map_chunk(l1pt_va, cur_pv.pv_va, cur_pv.pv_pa,
	    cur_pv.pv_size, cur_pv.pv_prot, cur_pv.pv_cache);

	/*
	 * Now we map the stuff that isn't directly after the kernel
	 */
	if (map_vectors_p) {
		/* Map the vector page. */
		pmap_map_entry(l1pt_va, systempage.pv_va, systempage.pv_pa,
		    VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE, PTE_CACHE);
	}

	/* Map the Mini-Data cache clean area. */
#if ARM_MMU_XSCALE == 1
#if (ARM_NMMUS > 1)
	if (xscale_use_minidata)
#endif
		xscale_setup_minidata(l1pt_va, minidataclean.pv_va,
		    minidataclean.pv_pa);
#endif

	/*
	 * Map integrated peripherals at same address in first level page
	 * table so that we can continue to use console.
	 */
	if (devmap)
		pmap_devmap_bootstrap(l1pt_va, devmap);

	/* Tell the user about where all the bits and pieces live. */
	VPRINTF("%22s       Physical              Virtual        Num\n", " ");
	VPRINTF("%22s Starting    Ending    Starting    Ending   Pages\n", " ");

#ifdef VERBOSE_INIT_ARM
	static const char mem_fmt[] =
	    "%20s: 0x%08lx 0x%08lx 0x%08lx 0x%08lx %u\n";
	static const char mem_fmt_nov[] =
	    "%20s: 0x%08lx 0x%08lx                       %zu\n";
#endif

#if 0
	// XXX Doesn't make sense if kernel not at bottom of RAM
	VPRINTF(mem_fmt, "SDRAM", bmi->bmi_start, bmi->bmi_end - 1,
	    KERN_PHYSTOV(bmi->bmi_start), KERN_PHYSTOV(bmi->bmi_end - 1),
	    (int)physmem);
#endif
	VPRINTF(mem_fmt, "text section",
	       text.pv_pa, text.pv_pa + text.pv_size - 1,
	       text.pv_va, text.pv_va + text.pv_size - 1,
	       (int)(text.pv_size / PAGE_SIZE));
	VPRINTF(mem_fmt, "data section",
	       KERN_VTOPHYS((vaddr_t)__data_start), KERN_VTOPHYS((vaddr_t)_edata),
	       (vaddr_t)__data_start, (vaddr_t)_edata,
	       (int)((round_page((vaddr_t)_edata)
		      - trunc_page((vaddr_t)__data_start)) / PAGE_SIZE));
	VPRINTF(mem_fmt, "bss section",
	       KERN_VTOPHYS((vaddr_t)__bss_start), KERN_VTOPHYS((vaddr_t)__bss_end__),
	       (vaddr_t)__bss_start, (vaddr_t)__bss_end__,
	       (int)((round_page((vaddr_t)__bss_end__)
		      - trunc_page((vaddr_t)__bss_start)) / PAGE_SIZE));
	VPRINTF(mem_fmt, "L1 page directory",
	    kernel_l1pt.pv_pa, kernel_l1pt.pv_pa + L1_TABLE_SIZE - 1,
	    kernel_l1pt.pv_va, kernel_l1pt.pv_va + L1_TABLE_SIZE - 1,
	    L1_TABLE_SIZE / PAGE_SIZE);
#if defined(EFI_RUNTIME)
	VPRINTF(mem_fmt, "EFI L1 page directory",
	    efirt_l1pt.pv_pa, efirt_l1pt.pv_pa + L1_TABLE_SIZE - 1,
	    efirt_l1pt.pv_va, efirt_l1pt.pv_va + L1_TABLE_SIZE - 1,
	    L1_TABLE_SIZE / PAGE_SIZE);
#endif
	VPRINTF(mem_fmt, "ABT stack (CPU 0)",
	    abtstack.pv_pa, abtstack.pv_pa + (ABT_STACK_SIZE * PAGE_SIZE) - 1,
	    abtstack.pv_va, abtstack.pv_va + (ABT_STACK_SIZE * PAGE_SIZE) - 1,
	    ABT_STACK_SIZE);
	VPRINTF(mem_fmt, "FIQ stack (CPU 0)",
	    fiqstack.pv_pa, fiqstack.pv_pa + (FIQ_STACK_SIZE * PAGE_SIZE) - 1,
	    fiqstack.pv_va, fiqstack.pv_va + (FIQ_STACK_SIZE * PAGE_SIZE) - 1,
	    FIQ_STACK_SIZE);
	VPRINTF(mem_fmt, "IRQ stack (CPU 0)",
	    irqstack.pv_pa, irqstack.pv_pa + (IRQ_STACK_SIZE * PAGE_SIZE) - 1,
	    irqstack.pv_va, irqstack.pv_va + (IRQ_STACK_SIZE * PAGE_SIZE) - 1,
	    IRQ_STACK_SIZE);
	VPRINTF(mem_fmt, "UND stack (CPU 0)",
	    undstack.pv_pa, undstack.pv_pa + (UND_STACK_SIZE * PAGE_SIZE) - 1,
	    undstack.pv_va, undstack.pv_va + (UND_STACK_SIZE * PAGE_SIZE) - 1,
	    UND_STACK_SIZE);
	VPRINTF(mem_fmt, "IDLE stack (CPU 0)",
	    idlestack.pv_pa, idlestack.pv_pa + (UPAGES * PAGE_SIZE) - 1,
	    idlestack.pv_va, idlestack.pv_va + (UPAGES * PAGE_SIZE) - 1,
	    UPAGES);
	VPRINTF(mem_fmt, "SVC stack",
	    kernelstack.pv_pa, kernelstack.pv_pa + (UPAGES * PAGE_SIZE) - 1,
	    kernelstack.pv_va, kernelstack.pv_va + (UPAGES * PAGE_SIZE) - 1,
	    UPAGES);
	VPRINTF(mem_fmt, "Message Buffer",
	    msgbuf.pv_pa, msgbuf.pv_pa + (msgbuf_pgs * PAGE_SIZE) - 1,
	    msgbuf.pv_va, msgbuf.pv_va + (msgbuf_pgs * PAGE_SIZE) - 1,
	    (int)msgbuf_pgs);
	if (map_vectors_p) {
		VPRINTF(mem_fmt, "Exception Vectors",
		    systempage.pv_pa, systempage.pv_pa + PAGE_SIZE - 1,
		    systempage.pv_va, systempage.pv_va + PAGE_SIZE - 1,
		    1);
	}
	for (size_t i = 0; i < bmi->bmi_nfreeblocks; i++) {
		pv = &bmi->bmi_freeblocks[i];

		VPRINTF(mem_fmt_nov, "Free Memory",
		    pv->pv_pa, pv->pv_pa + pv->pv_size - 1,
		    pv->pv_size / PAGE_SIZE);
	}
	/*
	 * Now we have the real page tables in place so we can switch to them.
	 * Once this is done we will be running with the REAL kernel page
	 * tables.
	 */

	VPRINTF("TTBR0=%#x", armreg_ttbr_read());
#ifdef _ARM_ARCH_6
	VPRINTF(" TTBR1=%#x TTBCR=%#x CONTEXTIDR=%#x",
	    armreg_ttbr1_read(), armreg_ttbcr_read(),
	    armreg_contextidr_read());
#endif
	VPRINTF("\n");

	/* Switch tables */
	VPRINTF("switching to new L1 page table @%#lx...\n", l1pt_pa);

	cpu_ttb = l1pt_pa;

	cpu_domains(DOMAIN_DEFAULT);

	cpu_idcache_wbinv_all();

#ifdef __HAVE_GENERIC_START

	/*
	 * Turn on caches and set SCTLR/ACTLR
	 */
	cpu_setup(boot_args);
#endif

	VPRINTF(" ttb");

#ifdef ARM_MMU_EXTENDED
	/*
	 * TTBCR should have been initialized by the MD start code.
	 */
	KASSERT((armreg_contextidr_read() & 0xff) == 0);
	KASSERT(armreg_ttbcr_read() == __SHIFTIN(1, TTBCR_S_N));
	/*
	 * Disable lookups via TTBR0 until there is an activated pmap.
	 */
	armreg_ttbcr_write(armreg_ttbcr_read() | TTBCR_S_PD0);
	cpu_setttb(l1pt_pa, KERNEL_PID);
	isb();
#else
	cpu_setttb(l1pt_pa, true);
#endif

	cpu_tlb_flushID();

#ifdef KASAN
	extern uint8_t start_stacks_bottom[];
	kasan_early_init((void *)start_stacks_bottom);
#endif

#ifdef ARM_MMU_EXTENDED
	VPRINTF("\nsctlr=%#x actlr=%#x\n",
	    armreg_sctlr_read(), armreg_auxctl_read());
#else
	VPRINTF(" (TTBR0=%#x)", armreg_ttbr_read());
#endif

#ifdef MULTIPROCESSOR
#ifndef __HAVE_GENERIC_START
	/*
	 * Kick the secondaries to load the TTB.  After which they'll go
	 * back to sleep to wait for the final kick so they will hatch.
	 */
	VPRINTF(" hatchlings");
	cpu_boot_secondary_processors();
#endif
#endif

	VPRINTF(" OK\n");
}
