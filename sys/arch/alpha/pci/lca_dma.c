/* $NetBSD: lca_dma.c,v 1.2 1997/06/06 23:59:26 thorpej Exp $ */

/*-
 * Copyright (c) 1997 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Jason R. Thorpe of the Numerical Aerospace Simulation Facility,
 * NASA Ames Research Center.
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

#include <machine/options.h>		/* Config options headers */
#include <sys/cdefs.h>			/* RCS ID & Copyright macro defns */

__KERNEL_RCSID(0, "$NetBSD: lca_dma.c,v 1.2 1997/06/06 23:59:26 thorpej Exp $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/device.h>
#include <sys/malloc.h>
#include <vm/vm.h>

#define _ALPHA_BUS_DMA_PRIVATE
#include <machine/bus.h>

#include <dev/pci/pcireg.h>
#include <dev/pci/pcivar.h>
#include <alpha/pci/lcareg.h>
#include <alpha/pci/lcavar.h>

bus_dma_tag_t lca_dma_get_tag __P((bus_dma_tag_t, alpha_bus_t));

int	lca_bus_dmamap_create_sgmap __P((bus_dma_tag_t, bus_size_t, int,
	    bus_size_t, bus_size_t, int, bus_dmamap_t *));

void	lca_bus_dmamap_destroy_sgmap __P((bus_dma_tag_t, bus_dmamap_t));

int	lca_bus_dmamap_load_direct __P((bus_dma_tag_t, bus_dmamap_t, void *,
	    bus_size_t, struct proc *, int));
int	lca_bus_dmamap_load_sgmap __P((bus_dma_tag_t, bus_dmamap_t, void *,
	    bus_size_t, struct proc *, int));

int	lca_bus_dmamap_load_mbuf_direct __P((bus_dma_tag_t, bus_dmamap_t,
	    struct mbuf *, int));
int	lca_bus_dmamap_load_mbuf_sgmap __P((bus_dma_tag_t, bus_dmamap_t,
	    struct mbuf *, int));

int	lca_bus_dmamap_load_uio_direct __P((bus_dma_tag_t, bus_dmamap_t,
	    struct uio *, int));
int	lca_bus_dmamap_load_uio_sgmap __P((bus_dma_tag_t, bus_dmamap_t,
	    struct uio *, int));

int	lca_bus_dmamap_load_raw_direct __P((bus_dma_tag_t, bus_dmamap_t,
	    bus_dma_segment_t *, int, bus_size_t, int));
int	lca_bus_dmamap_load_raw_sgmap __P((bus_dma_tag_t, bus_dmamap_t,
	    bus_dma_segment_t *, int, bus_size_t, int));

void	lca_bus_dmamap_unload_sgmap __P((bus_dma_tag_t, bus_dmamap_t));

/*
 * The 1G direct-mapped DMA window begins at this PCI address.
 */
#define	LCA_DIRECT_MAPPED_BASE	0x40000000

/*
 * The 8M SGMAP-mapped DMA window begins at this PCI address.
 */
#define	LCA_SGMAP_MAPPED_BASE	(8*1024*1024)

/*
 * Macro to flush LCA scatter/gather TLB.
 */
#define	LCA_TLB_INVALIDATE() \
do { \
	alpha_mb(); \
	REGVAL64(LCA_IOC_TBIA) = 0; \
	alpha_mb(); \
} while (0)

void
lca_dma_init(lcp)
	struct lca_config *lcp;
{
	bus_dma_tag_t t;

	/*
	 * Initialize the DMA tag used for direct-mapped DMA.
	 */
	t = &lcp->lc_dmat_direct;
	t->_cookie = lcp;
	t->_get_tag = lca_dma_get_tag;
	t->_dmamap_create = _bus_dmamap_create;
	t->_dmamap_destroy = _bus_dmamap_destroy;
	t->_dmamap_load = lca_bus_dmamap_load_direct;
	t->_dmamap_load_mbuf = lca_bus_dmamap_load_mbuf_direct;
	t->_dmamap_load_uio = lca_bus_dmamap_load_uio_direct;
	t->_dmamap_load_raw = lca_bus_dmamap_load_raw_direct;
	t->_dmamap_unload = _bus_dmamap_unload;
	t->_dmamap_sync = NULL;		/* Nothing to do. */

	t->_dmamem_alloc = _bus_dmamem_alloc;
	t->_dmamem_free = _bus_dmamem_free;
	t->_dmamem_map = _bus_dmamem_map;
	t->_dmamem_unmap = _bus_dmamem_unmap;
	t->_dmamem_mmap = _bus_dmamem_mmap;

	/*
	 * Initialize the DMA tag used for sgmap-mapped DMA.
	 */
	t = &lcp->lc_dmat_sgmap;
	t->_cookie = lcp;
	t->_get_tag = lca_dma_get_tag;
	t->_dmamap_create = lca_bus_dmamap_create_sgmap;
	t->_dmamap_destroy = lca_bus_dmamap_destroy_sgmap;
	t->_dmamap_load = lca_bus_dmamap_load_sgmap;
	t->_dmamap_load_mbuf = lca_bus_dmamap_load_mbuf_sgmap;
	t->_dmamap_load_uio = lca_bus_dmamap_load_uio_sgmap;
	t->_dmamap_load_raw = lca_bus_dmamap_load_raw_sgmap;
	t->_dmamap_unload = lca_bus_dmamap_unload_sgmap;
	t->_dmamap_sync = NULL;		/* Nothing to do. */

	t->_dmamem_alloc = _bus_dmamem_alloc;
	t->_dmamem_free = _bus_dmamem_free;
	t->_dmamem_map = _bus_dmamem_map;
	t->_dmamem_unmap = _bus_dmamem_unmap;
	t->_dmamem_mmap = _bus_dmamem_mmap;

	/*
	 * The firmware has set up window 1 as a 1G direct-mapped DMA
	 * window beginning at 1G.  We leave it alone.  Disable
	 * window 0.
	 */
	REGVAL64(LCA_IOC_W_BASE0) = 0;
	alpha_mb();

	/*
	 * Initialize the SGMAP if safe to do so.
	 */
	if (lcp->lc_mallocsafe) {
		alpha_sgmap_init(t, &lcp->lc_sgmap, "lca_sgmap",
		    LCA_SGMAP_MAPPED_BASE, 0, (8*1024*1024),
		    sizeof(u_int64_t), NULL);

		/*
		 * Set up window 0 as an 8MB SGMAP-mapped window
		 * starting at 8MB.
		 */
		if ((lcp->lc_sgmap.aps_ptpa & IOC_W_T_BASE) !=
		    lcp->lc_sgmap.aps_ptpa)
			panic("lca_dma_init: bad page table address");
		REGVAL64(LCA_IOC_W_T_BASE0) = lcp->lc_sgmap.aps_ptpa;
		REGVAL64(LCA_IOC_W_MASK0) = IOC_W_MASK_8M;
		alpha_mb();

		/* Enble the scatter/gather TLB. */
		REGVAL64(LCA_IOC_TB_ENA) = IOC_TB_ENA_TEN;
		alpha_mb();

		REGVAL64(LCA_IOC_W_BASE0) = LCA_SGMAP_MAPPED_BASE |
		    IOC_W_BASE_SG | IOC_W_BASE_WEN;
		alpha_mb();

		LCA_TLB_INVALIDATE();
	}

	/* XXX XXX BEGIN XXX XXX */
	{							/* XXX */
		extern vm_offset_t alpha_XXX_dmamap_or;		/* XXX */
		alpha_XXX_dmamap_or = LCA_DIRECT_MAPPED_BASE;	/* XXX */
	}							/* XXX */
	/* XXX XXX END XXX XXX */
}

/*
 * Return the bus dma tag to be used for the specified bus type.
 * INTERNAL USE ONLY!
 */
bus_dma_tag_t
lca_dma_get_tag(t, bustype)
	bus_dma_tag_t t;
	alpha_bus_t bustype;
{
	struct lca_config *lcp = t->_cookie;

	switch (bustype) {
	case ALPHA_BUS_PCI:
	case ALPHA_BUS_EISA:
		/*
		 * Systems with an LCA can only support 1G
		 * of memory, so we use the direct-mapped window
		 * on busses that have 32-bit DMA.
		 */
		return (&lcp->lc_dmat_direct);

	case ALPHA_BUS_ISA:
		/*
		 * ISA doesn't have enough address bits to use
		 * the direct-mapped DMA window, so we must use
		 * SGMAPs.
		 */
		return (&lcp->lc_dmat_sgmap);

	default:
		panic("lca_dma_get_tag: shouldn't be here, really...");
	}
}

/*
 * Create an LCA SGMAP-mapped DMA map.
 */
int
lca_bus_dmamap_create_sgmap(t, size, nsegments, maxsegsz, boundary,
    flags, dmamp)
	bus_dma_tag_t t;
	bus_size_t size;
	int nsegments;
	bus_size_t maxsegsz;
	bus_size_t boundary;
	int flags;
	bus_dmamap_t *dmamp;
{
	struct lca_config *lcp = t->_cookie;
	struct alpha_sgmap_cookie *a;
	bus_dmamap_t map;
	int error;

	error = _bus_dmamap_create(t, size, nsegments, maxsegsz,
	    boundary, flags, dmamp);
	if (error)
		return (error);

	map = *dmamp;

	a = malloc(sizeof(struct alpha_sgmap_cookie), M_DEVBUF,
	    (flags & BUS_DMA_NOWAIT) ? M_NOWAIT : M_WAITOK);
	if (a == NULL) {
		_bus_dmamap_destroy(t, map);
		return (ENOMEM);
	}
	bzero(a, sizeof(struct alpha_sgmap_cookie));
	map->_dm_sgcookie = a;

	if (flags & BUS_DMA_ALLOCNOW) {
		error = alpha_sgmap_alloc(map, round_page(size),
		    &lcp->lc_sgmap, flags);
		if (error)
			lca_bus_dmamap_destroy_sgmap(t, map);
	}

	return (error);
}

/*
 * Destroy an LCA SGMAP-mapped DMA map.
 */
void
lca_bus_dmamap_destroy_sgmap(t, map)
	bus_dma_tag_t t;
	bus_dmamap_t map;
{
	struct lca_config *lcp = t->_cookie;
	struct alpha_sgmap_cookie *a = map->_dm_sgcookie;

	if (a->apdc_flags & APDC_HAS_SGMAP)
		alpha_sgmap_free(&lcp->lc_sgmap, a);

	free(a, M_DEVBUF);
	_bus_dmamap_destroy(t, map);
}

/*
 * Load an LCA direct-mapped DMA map with a linear buffer.
 */
int
lca_bus_dmamap_load_direct(t, map, buf, buflen, p, flags)
	bus_dma_tag_t t;
	bus_dmamap_t map;
	void *buf;
	bus_size_t buflen;
	struct proc *p;
	int flags;
{

	return (_bus_dmamap_load_direct_common(t, map, buf, buflen, p,
	    flags, LCA_DIRECT_MAPPED_BASE));
}

/*
 * Load an LCA SGMAP-mapped DMA map with a linear buffer.
 */
int
lca_bus_dmamap_load_sgmap(t, map, buf, buflen, p, flags)
	bus_dma_tag_t t;
	bus_dmamap_t map;
	void *buf;
	bus_size_t buflen;
	struct proc *p;
	int flags;
{
	struct lca_config *lcp = t->_cookie;
	int error;

	error = pci_sgmap_pte64_load(t, map, buf, buflen, p, flags,
	    &lcp->lc_sgmap);
	if (error == 0)
		LCA_TLB_INVALIDATE();

	return (error);
}

/*
 * Load an LCA direct-mapped DMA map with an mbuf chain.
 */
int
lca_bus_dmamap_load_mbuf_direct(t, map, m, flags)
	bus_dma_tag_t t;
	bus_dmamap_t map;
	struct mbuf *m;
	int flags;
{

	return (_bus_dmamap_load_mbuf_direct_common(t, map, m,
	    flags, LCA_DIRECT_MAPPED_BASE));
}

/*
 * Load an LCA SGMAP-mapped DMA map with an mbuf chain.
 */
int
lca_bus_dmamap_load_mbuf_sgmap(t, map, m, flags)
	bus_dma_tag_t t;
	bus_dmamap_t map;
	struct mbuf *m;
	int flags;
{
	struct lca_config *lcp = t->_cookie;
	int error;

	error = pci_sgmap_pte64_load_mbuf(t, map, m, flags, &lcp->lc_sgmap);
	if (error == 0)
		LCA_TLB_INVALIDATE();

	return (error);
}

/*
 * Load an LCA direct-mapped DMA map with a uio.
 */
int
lca_bus_dmamap_load_uio_direct(t, map, uio, flags)
	bus_dma_tag_t t;
	bus_dmamap_t map;
	struct uio *uio;
	int flags;
{

	return (_bus_dmamap_load_uio_direct_common(t, map, uio,
	    flags, LCA_DIRECT_MAPPED_BASE));
}

/*
 * Load an LCA SGMAP-mapped DMA map with a uio.
 */
int
lca_bus_dmamap_load_uio_sgmap(t, map, uio, flags)
	bus_dma_tag_t t;
	bus_dmamap_t map;
	struct uio *uio;
	int flags;
{
	struct lca_config *lcp = t->_cookie;
	int error;

	error = pci_sgmap_pte64_load_uio(t, map, uio, flags, &lcp->lc_sgmap);
	if (error == 0)
		LCA_TLB_INVALIDATE();

	return (error);
}

/*
 * Load an LCA direct-mapped DMA map with raw memory.
 */
int
lca_bus_dmamap_load_raw_direct(t, map, segs, nsegs, size, flags)
	bus_dma_tag_t t;
	bus_dmamap_t map;
	bus_dma_segment_t *segs;
	int nsegs;
	bus_size_t size;
	int flags;
{

	return (_bus_dmamap_load_raw_direct_common(t, map, segs, nsegs,
	    size, flags, LCA_DIRECT_MAPPED_BASE));
}

/*
 * Load an LCA SGMAP-mapped DMA map with raw memory.
 */
int
lca_bus_dmamap_load_raw_sgmap(t, map, segs, nsegs, size, flags)
	bus_dma_tag_t t;
	bus_dmamap_t map;
	bus_dma_segment_t *segs;
	int nsegs;
	bus_size_t size;
	int flags;
{
	struct lca_config *lcp = t->_cookie;
	int error;

	error = pci_sgmap_pte64_load_raw(t, map, segs, nsegs, size, flags,
	    &lcp->lc_sgmap);
	if (error == 0)
		LCA_TLB_INVALIDATE();

	return (error);
}

/*
 * Unload an LCA DMA map.
 */
void
lca_bus_dmamap_unload_sgmap(t, map)
	bus_dma_tag_t t;
	bus_dmamap_t map;
{
	struct lca_config *lcp = t->_cookie;

	/*
	 * Invalidate any SGMAP page table entries used by this
	 * mapping.
	 */
	pci_sgmap_pte64_unload(t, map, &lcp->lc_sgmap);
	LCA_TLB_INVALIDATE();

	/*
	 * Do the generic bits of the unload.
	 */
	_bus_dmamap_unload(t, map);
}
