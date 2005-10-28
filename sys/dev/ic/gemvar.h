/*	$NetBSD: gemvar.h,v 1.13 2005/10/28 14:36:15 christos Exp $ */

/*
 *
 * Copyright (C) 2001 Eduardo Horvath.
 * All rights reserved.
 *
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR  ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR  BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifndef	_IF_GEMVAR_H
#define	_IF_GEMVAR_H


#include "rnd.h"

#include <sys/queue.h>
#include <sys/callout.h>

#if NRND > 0
#include <sys/rnd.h>
#endif

/*
 * Misc. definitions for the Sun ``Gem'' Ethernet controller family driver.
 */

/*
 * Transmit descriptor list size.  This is arbitrary, but allocate
 * enough descriptors for 64 pending transmissions and 16 segments
 * per packet.
 */
#define	GEM_NTXSEGS		16

#define	GEM_TXQUEUELEN		64
#define	GEM_NTXDESC		(GEM_TXQUEUELEN * GEM_NTXSEGS)
#define	GEM_NTXDESC_MASK	(GEM_NTXDESC - 1)
#define	GEM_NEXTTX(x)		((x + 1) & GEM_NTXDESC_MASK)

/*
 * Receive descriptor list size.  We have one Rx buffer per incoming
 * packet, so this logic is a little simpler.
 */
#define	GEM_NRXDESC		128
#define	GEM_NRXDESC_MASK	(GEM_NRXDESC - 1)
#define	GEM_PREVRX(x)		((x - 1) & GEM_NRXDESC_MASK)
#define	GEM_NEXTRX(x)		((x + 1) & GEM_NRXDESC_MASK)

/*
 * Control structures are DMA'd to the GEM chip.  We allocate them in
 * a single clump that maps to a single DMA segment to make several things
 * easier.
 */
struct gem_control_data {
	/*
	 * The transmit descriptors.
	 */
	struct gem_desc gcd_txdescs[GEM_NTXDESC];

	/*
	 * The receive descriptors.
	 */
	struct gem_desc gcd_rxdescs[GEM_NRXDESC];
};

#define	GEM_CDOFF(x)		offsetof(struct gem_control_data, x)
#define	GEM_CDTXOFF(x)		GEM_CDOFF(gcd_txdescs[(x)])
#define	GEM_CDRXOFF(x)		GEM_CDOFF(gcd_rxdescs[(x)])

/*
 * Software state for transmit jobs.
 */
struct gem_txsoft {
	struct mbuf *txs_mbuf;		/* head of our mbuf chain */
	bus_dmamap_t txs_dmamap;	/* our DMA map */
	int txs_firstdesc;		/* first descriptor in packet */
	int txs_lastdesc;		/* last descriptor in packet */
	int txs_ndescs;			/* number of descriptors */
	SIMPLEQ_ENTRY(gem_txsoft) txs_q;
};

SIMPLEQ_HEAD(gem_txsq, gem_txsoft);

/*
 * Software state for receive jobs.
 */
struct gem_rxsoft {
	struct mbuf *rxs_mbuf;		/* head of our mbuf chain */
	bus_dmamap_t rxs_dmamap;	/* our DMA map */
};

/*
 * Software state per device.
 */
struct gem_softc {
	struct device	sc_dev;		/* generic device information */
	struct ethercom sc_ethercom;	/* ethernet common data */
	struct mii_data	sc_mii;		/* MII media control */
#define sc_media	sc_mii.mii_media/* shorthand */
	struct callout	sc_tick_ch;	/* tick callout */

	/* The following bus handles are to be provided by the bus front-end */
	bus_space_tag_t	sc_bustag;	/* bus tag */
	bus_dma_tag_t	sc_dmatag;	/* bus dma tag */
	bus_dmamap_t	sc_dmamap;	/* bus dma handle */
	bus_space_handle_t sc_h;	/* bus space handle for all regs */

	int		sc_phys[2];	/* MII instance -> PHY map */

	int		sc_mif_config;	/* Selected MII reg setting */

	int		sc_pci;		/* XXXXX -- PCI buses are LE. */
	u_int		sc_variant;	/* which GEM are we dealing with? */
#define	GEM_UNKNOWN		0	/* don't know */
#define	GEM_SUN_GEM		1	/* Sun GEM variant */
#define	GEM_APPLE_GMAC		2	/* Apple GMAC variant */

	u_int		sc_flags;	/* */
	short		sc_if_flags;	/* copy of ifp->if_flags */
#define	GEM_GIGABIT		0x0001	/* has a gigabit PHY */

	void *sc_sdhook;		/* shutdown hook */
	void *sc_powerhook;		/* power management hook */

	/*
	 * Ring buffer DMA stuff.
	 */
	bus_dma_segment_t sc_cdseg;	/* control data memory */
	int		sc_cdnseg;	/* number of segments */
	bus_dmamap_t sc_cddmamap;	/* control data DMA map */
#define	sc_cddma	sc_cddmamap->dm_segs[0].ds_addr

	bus_dmamap_t sc_nulldmamap;	/* for small packets padding */

	/*
	 * Software state for transmit and receive descriptors.
	 */
	struct gem_txsoft sc_txsoft[GEM_TXQUEUELEN];
	struct gem_rxsoft sc_rxsoft[GEM_NRXDESC];

	/*
	 * Control data structures.
	 */
	struct gem_control_data *sc_control_data;
#define	sc_txdescs	sc_control_data->gcd_txdescs
#define	sc_rxdescs	sc_control_data->gcd_rxdescs

	int		sc_txfree;	/* number of free Tx descriptors */
	int		sc_txnext;	/* next ready Tx descriptor */
	int		sc_txwin;	/* Tx descriptors since last Tx int */

	struct gem_txsq	sc_txfreeq;	/* free Tx descsofts */
	struct gem_txsq	sc_txdirtyq;	/* dirty Tx descsofts */

	int		sc_rxptr;	/* next ready RX descriptor/descsoft */
	int		sc_rxfifosize;	/* Rx FIFO size (bytes) */

	/* ========== */
	int		sc_inited;
	int		sc_debug;
	void		*sc_sh;		/* shutdownhook cookie */

	/* Special hardware hooks */
	void	(*sc_hwreset)(struct gem_softc *);
	void	(*sc_hwinit)(struct gem_softc *);

#if NRND > 0
	rndsource_element_t	rnd_source;
#endif

	struct evcnt sc_ev_intr;
#ifdef GEM_COUNTERS
	struct evcnt sc_ev_txint;
	struct evcnt sc_ev_rxint;
	struct evcnt sc_ev_rxnobuf;
	struct evcnt sc_ev_rxfull;
	struct evcnt sc_ev_rxhist[9];
#endif
};

#ifdef GEM_COUNTERS
#define	GEM_COUNTER_INCR(sc, ctr)	((void) (sc->ctr.ev_count++))
#else
#define	GEM_COUNTER_INCR(sc, ctr)	((void) sc)
#endif


#define	GEM_DMA_READ(sc, v)	(((sc)->sc_pci) ? le64toh(v) : be64toh(v))
#define	GEM_DMA_WRITE(sc, v)	(((sc)->sc_pci) ? htole64(v) : htobe64(v))

#define	GEM_CDTXADDR(sc, x)	((sc)->sc_cddma + GEM_CDTXOFF((x)))
#define	GEM_CDRXADDR(sc, x)	((sc)->sc_cddma + GEM_CDRXOFF((x)))

#define	GEM_CDSPADDR(sc)	((sc)->sc_cddma + GEM_CDSPOFF)

#define	GEM_CDTXSYNC(sc, x, n, ops)					\
do {									\
	int __x, __n;							\
									\
	__x = (x);							\
	__n = (n);							\
									\
	/* If it will wrap around, sync to the end of the ring. */	\
	if ((__x + __n) > GEM_NTXDESC) {				\
		bus_dmamap_sync((sc)->sc_dmatag, (sc)->sc_cddmamap,	\
		    GEM_CDTXOFF(__x), sizeof(struct gem_desc) *		\
		    (GEM_NTXDESC - __x), (ops));			\
		__n -= (GEM_NTXDESC - __x);				\
		__x = 0;						\
	}								\
									\
	/* Now sync whatever is left. */				\
	bus_dmamap_sync((sc)->sc_dmatag, (sc)->sc_cddmamap,		\
	    GEM_CDTXOFF(__x), sizeof(struct gem_desc) * __n, (ops));	\
} while (0)

#define	GEM_CDRXSYNC(sc, x, ops)					\
	bus_dmamap_sync((sc)->sc_dmatag, (sc)->sc_cddmamap,		\
	    GEM_CDRXOFF((x)), sizeof(struct gem_desc), (ops))

#define	GEM_CDSPSYNC(sc, ops)						\
	bus_dmamap_sync((sc)->sc_dmatag, (sc)->sc_cddmamap,		\
	    GEM_CDSPOFF, GEM_SETUP_PACKET_LEN, (ops))

#define	GEM_INIT_RXDESC(sc, x)						\
do {									\
	struct gem_rxsoft *__rxs = &sc->sc_rxsoft[(x)];			\
	struct gem_desc *__rxd = &sc->sc_rxdescs[(x)];			\
	struct mbuf *__m = __rxs->rxs_mbuf;				\
									\
	__m->m_data = __m->m_ext.ext_buf;				\
	__rxd->gd_addr =						\
	    GEM_DMA_WRITE((sc), __rxs->rxs_dmamap->dm_segs[0].ds_addr);	\
	__rxd->gd_flags =						\
	    GEM_DMA_WRITE((sc),						\
			(((__m->m_ext.ext_size)<<GEM_RD_BUFSHIFT)	\
				& GEM_RD_BUFSIZE) | GEM_RD_OWN);	\
	GEM_CDRXSYNC((sc), (x), BUS_DMASYNC_PREREAD|BUS_DMASYNC_PREWRITE); \
} while (0)

#ifdef _KERNEL
void	gem_attach(struct gem_softc *, const uint8_t *);
int	gem_intr(void *);

void	gem_reset(struct gem_softc *);
#endif /* _KERNEL */


#endif
