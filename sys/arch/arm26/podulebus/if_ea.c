/* $NetBSD: if_ea.c,v 1.16 2000/08/12 17:03:44 bjh21 Exp $ */

/*
 * Copyright (c) 1995 Mark Brinicombe
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
 *	This product includes software developed by Mark Brinicombe.
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
 */
/*
 * if_ea.c - Ether3 device driver
 */

/*
 * SEEQ 8005 device driver
 */

/*
 * Bugs/possible improvements:
 *	- Does not currently support DMA
 *	- Does not currently support multicasts
 *	- Does not transmit multiple packets in one go
 *	- Does not support big-endian hosts
 *	- Does not support 8-bit busses
 */

#include "opt_inet.h"
#include "opt_ns.h"

#include <sys/types.h>
#include <sys/param.h>

__RCSID("$NetBSD: if_ea.c,v 1.16 2000/08/12 17:03:44 bjh21 Exp $");

#include <sys/systm.h>
#include <sys/endian.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/device.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_ether.h>

#ifdef INET
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/if_inarp.h>
#endif

#ifdef NS
#include <netns/ns.h>
#include <netns/ns_if.h>
#endif

#include "bpfilter.h"
#if NBPFILTER > 0
#include <net/bpf.h>
#include <net/bpfdesc.h>
#endif

#include <machine/bus.h>
#include <machine/cpu.h>
#include <machine/irq.h>

#include <arm26/podulebus/if_eareg.h>
#include <arm26/podulebus/podulebus.h>
#include <arm32/podulebus/podules.h>

#ifndef EA_TIMEOUT
#define EA_TIMEOUT	60
#endif

#define EA_TX_BUFFER_SIZE	0x4000
#define EA_RX_BUFFER_SIZE	0xC000

/*#define EA_TX_DEBUG*/
/*#define EA_RX_DEBUG*/
/*#define EA_DEBUG*/
/*#define EA_PACKET_DEBUG*/

/* for debugging convenience */
#ifdef EA_DEBUG
#define dprintf(x) printf x
#else
#define dprintf(x)
#endif

/*
 * per-line info and status
 */

struct ea_softc {
	struct device sc_dev;
	struct irq_handler *sc_ih;
	bus_space_tag_t sc_iot;		/* I/O base addr */
	bus_space_handle_t sc_ioh;
	struct ethercom sc_ethercom;	/* Ethernet common */
	int sc_config1;			/* Current config1 bits */
	int sc_config2;			/* Current config2 bits */
	int sc_command;			/* Current command bits */
	int sc_irqclaimed;		/* Whether we have an IRQ claimed */
	u_int sc_rx_ptr;		/* Receive buffer pointer */
	u_int sc_tx_ptr;		/* Transmit buffer pointer */
};

/*
 * prototypes
 */

int eaintr(void *);
static int ea_init(struct ea_softc *);
static int ea_ioctl(struct ifnet *, u_long, caddr_t);
static void ea_start(struct ifnet *);
static void ea_watchdog(struct ifnet *);
static void ea_reinit(struct ea_softc *);
static void ea_chipreset(struct ea_softc *);
static void ea_ramtest(struct ea_softc *);
static int ea_stoptx(struct ea_softc *);
static int ea_stoprx(struct ea_softc *);
static void ea_stop(struct ea_softc *);
static void ea_writebuf(struct ea_softc *, u_char *, u_int, size_t);
static void ea_readbuf(struct ea_softc *, u_char *, u_int, size_t);
static void earead(struct ea_softc *, int, int);
static struct mbuf *eaget(struct ea_softc *, int, int, struct ifnet *);
static void ea_hardreset(struct ea_softc *);
static void eagetpackets(struct ea_softc *);
static void eatxpacket(struct ea_softc *);

int eaprobe(struct device *, struct cfdata *, void *);
void eaattach(struct device *, struct device *, void *);

#ifdef EA_PACKET_DEBUG
void ea_dump_buffer(struct ea_softc *, int);
#endif
void ea_claimirq(struct ea_softc *);
void ea_releaseirq(struct ea_softc *);

/* driver structure for autoconf */

struct cfattach ea_ca = {
	sizeof(struct ea_softc), eaprobe, eaattach
};

#ifdef EA_PACKET_DEBUG
/*
 * Dump the interface buffer
 */

void
ea_dump_buffer(struct ea_softc *sc, u_int offset)
{
	bus_space_tag_t iot = sc->sc_iot;
	bus_space_handle_t ioh = sc->sc_ioh;
	u_int addr;
	int loop;
	size_t size;
	int ctrl;
	int ptr;
	
	addr = offset;

	do {
		bus_space_write_2(iot, ioh, EA_8005_COMMAND,
				 sc->sc_command | EA_CMD_FIFO_READ);
		bus_space_write_2(iot, ioh, EA_8005_CONFIG1,
				  sc->sc_config1 | EA_BUFCODE_LOCAL_MEM);
		bus_space_write_2(iot, ioh, EA_8005_DMA_ADDR, addr);

		ptr = bus_space_read_2(iot, ioh, EA_8005_BUFWIN);
		ctrl = bus_space_read_2(iot, ioh, EA_8005_BUFWIN);
		ptr = ((ptr & 0xff) << 8) | ((ptr >> 8) & 0xff);

		if (ptr == 0) break;
		size = ptr - addr;

		printf("addr=%04x size=%04x ", addr, size);
		printf("cmd=%02x st=%02x\n", ctrl & 0xff, ctrl >> 8);

		for (loop = 0; loop < size - 4; loop += 2)
			printf("%04x ",
			       bus_space_read_2(iot, ioh, EA_8005_BUFWIN));
		printf("\n");
		addr = ptr;
	} while (size != 0);
}
#endif

/*
 * Probe routine.
 */

/*
 * Probe for the ether3 podule.
 */

int
eaprobe(struct device *parent, struct cfdata *cf, void *aux)
{
	struct podulebus_attach_args *pa = aux;
	
	if ((matchpodule(pa, MANUFACTURER_ATOMWIDE,
			 PODULE_ATOMWIDE_ETHER3, -1) == 0)
	    && (matchpodule(pa, MANUFACTURER_ACORN,
			    PODULE_ACORN_ETHER3XXX, -1) == 0)
	    && (matchpodule(pa, MANUFACTURER_ANT, PODULE_ANT_ETHER3, -1) == 0))
		return 0;

	return 1;
}


/*
 * Attach podule.
 */

void
eaattach(struct device *parent, struct device *self, void *aux)
{
	struct ea_softc *sc = (void *)self;
	struct podulebus_attach_args *pa = aux;
	struct ifnet *ifp = &sc->sc_ethercom.ec_if;
	u_int8_t myaddr[ETHER_ADDR_LEN];
	char *ptr;
	int i;
	
/*	dprintf(("Attaching %s...\n", sc->sc_dev.dv_xname));*/

	/* Set the address of the controller for easy access */
	bus_space_shift(pa->pa_memc_t, pa->pa_memc_h, EA_8005_SHIFT,
			&sc->sc_iot, &sc->sc_ioh);

	/* Get the Ethernet address from the device description string. */
	if (pa->pa_descr == NULL) {
		printf(": No description for Ethernet address\n");
		return;
	}
	ptr = strchr(pa->pa_descr, '(');
	if (ptr == NULL) {
		printf(": Ethernet address not found in description\n");
		return;
	}
	ptr++;
	for (i = 0; i < ETHER_ADDR_LEN; i++) {
		myaddr[i] = strtoul(ptr, &ptr, 16);
		if (*ptr++ != (i == ETHER_ADDR_LEN - 1 ? ')' : ':')) {
			printf(": Bad Ethernet address found in "
			       "description\n");
			return;
		}
	}

	/* Print out some information for the user. */

	printf(": address %s", ether_sprintf(myaddr));

	sc->sc_irqclaimed = 0;

	/* Claim a podule interrupt */

	sc->sc_ih = podulebus_irq_establish(sc->sc_dev.dv_parent,
	    pa->pa_slotnum, IPL_NET, eaintr, sc);

	/* Stop the board. */

	ea_chipreset(sc);
	ea_stoptx(sc);
	ea_stoprx(sc);

	/* Initialise ifnet structure. */

	bcopy(sc->sc_dev.dv_xname, ifp->if_xname, IFNAMSIZ);
	ifp->if_softc = sc;
	ifp->if_start = ea_start;
	ifp->if_ioctl = ea_ioctl;
	ifp->if_watchdog = ea_watchdog;
	ifp->if_flags = IFF_BROADCAST | IFF_NOTRAILERS;

	/* Now we can attach the interface. */

/*	dprintf(("Attaching interface...\n"));*/
	if_attach(ifp);
	ether_ifattach(ifp, myaddr);

	/* Finally, attach to bpf filter if it is present. */

#if NBPFILTER > 0
/*	dprintf(("Attaching to BPF...\n"));*/
	bpfattach(&ifp->if_bpf, ifp, DLT_EN10MB, sizeof(struct ether_header));
#endif

	/* Should test the RAM */

	ea_ramtest(sc);

	printf("\n");
/*	dprintf(("eaattach() finished.\n"));*/
}


/*
 * Test the RAM on the ethernet card.
 */

void
ea_ramtest(struct ea_softc *sc)
{
	bus_space_tag_t iot = sc->sc_iot;
	bus_space_handle_t ioh = sc->sc_ioh;
	int loop;
	u_int sum = 0;
	char pbuf[9];

/*	dprintf(("ea_ramtest()\n"));*/

	/*
	 * Test the buffer memory on the board.
	 * Write simple pattens to it and read them back.
	 */

	/* Set up the whole buffer RAM for writing */

	bus_space_write_2(iot, ioh, EA_8005_CONFIG1, EA_BUFCODE_TX_EAP);
	bus_space_write_2(iot, ioh, EA_8005_BUFWIN, (EA_BUFFER_SIZE >> 8) - 1);
	bus_space_write_2(iot, ioh, EA_8005_TX_PTR, 0x0000);
	bus_space_write_2(iot, ioh, EA_8005_RX_PTR, EA_BUFFER_SIZE - 2);

	/* Set the write start address and write a pattern */

	ea_writebuf(sc, NULL, 0x0000, 0);

	for (loop = 0; loop < EA_BUFFER_SIZE; loop += 2)
		bus_space_write_2(iot, ioh, EA_8005_BUFWIN, loop);

	/* Set the read start address and verify the pattern */
	
	ea_readbuf(sc, NULL, 0x0000, 0);

	for (loop = 0; loop < EA_BUFFER_SIZE; loop += 2)
		if (bus_space_read_2(iot, ioh, EA_8005_BUFWIN) != loop)
			++sum;

	if (sum != 0)
		dprintf(("sum=%d\n", sum));

	/* Set the write start address and write a pattern */

	ea_writebuf(sc, NULL, 0x0000, 0);

	for (loop = 0; loop < EA_BUFFER_SIZE; loop += 2)
		bus_space_write_2(iot, ioh, EA_8005_BUFWIN,
			   loop ^ (EA_BUFFER_SIZE - 1));

	/* Set the read start address and verify the pattern */

	ea_readbuf(sc, NULL, 0x0000, 0);

	for (loop = 0; loop < EA_BUFFER_SIZE; loop += 2)
		if (bus_space_read_2(iot, ioh, EA_8005_BUFWIN) !=
		    (loop ^ (EA_BUFFER_SIZE - 1)))
			++sum;

	if (sum != 0)
		dprintf(("sum=%d\n", sum));

	/* Set the write start address and write a pattern */

	ea_writebuf(sc, NULL, 0x0000, 0);

	for (loop = 0; loop < EA_BUFFER_SIZE; loop += 2)
		bus_space_write_2(iot, ioh, EA_8005_BUFWIN, 0xaa55);

	/* Set the read start address and verify the pattern */

	ea_readbuf(sc, NULL, 0x0000, 0);

	for (loop = 0; loop < EA_BUFFER_SIZE; loop += 2)
		if (bus_space_read_2(iot, ioh, EA_8005_BUFWIN) != 0xaa55)
			++sum;

	if (sum != 0)
		dprintf(("sum=%d\n", sum));

	/* Set the write start address and write a pattern */

	ea_writebuf(sc, NULL, 0x0000, 0);

	for (loop = 0; loop < EA_BUFFER_SIZE; loop += 2)
		bus_space_write_2(iot, ioh, EA_8005_BUFWIN, 0x55aa);

	/* Set the read start address and verify the pattern */

	ea_readbuf(sc, NULL, 0x0000, 0);

	for (loop = 0; loop < EA_BUFFER_SIZE; loop += 2)
		if (bus_space_read_2(iot, ioh, EA_8005_BUFWIN) != 0x55aa)
			++sum;

	if (sum != 0)
		dprintf(("sum=%d\n", sum));

	/* Report */

	if (sum == 0) {
		format_bytes(pbuf, sizeof(pbuf), EA_BUFFER_SIZE);
		printf(", %s buffer RAM", pbuf);
	} else
		printf(", buffer RAM failed self test, %d faults", sum);
}


/* Claim an irq for the board */

void
ea_claimirq(struct ea_softc *sc)
{

	/* Have we claimed one already ? */
	if (sc->sc_irqclaimed) return;

	/* Claim it */
	irq_enable(sc->sc_ih);

	sc->sc_irqclaimed = 1;
}


/* Release an irq */

void
ea_releaseirq(struct ea_softc *sc)
{

	/* Have we claimed one ? */
	if (!sc->sc_irqclaimed) return;

	irq_disable(sc->sc_ih);

	sc->sc_irqclaimed = 0;
}


/*
 * Stop and reinitialise the interface.
 */

static void
ea_reinit(struct ea_softc *sc)
{
	int s;

	dprintf(("eareinit()\n"));

	/* Stop and reinitialise the interface */

	s = splnet();
	ea_stop(sc);
	ea_init(sc);
	splx(s);
}


/*
 * Stop the tx interface.
 *
 * Returns 0 if the tx was already stopped or 1 if it was active
 */

static int
ea_stoptx(struct ea_softc *sc)
{
	bus_space_tag_t iot = sc->sc_iot;
	bus_space_handle_t ioh = sc->sc_ioh;
	int timeout;
	int status;

	dprintf(("ea_stoptx()\n"));

	status = bus_space_read_2(iot, ioh, EA_8005_STATUS);
	if (!(status & EA_STATUS_TX_ON))
		return 0;

	/* Stop any tx and wait for confirmation */
	bus_space_write_2(iot, ioh, EA_8005_COMMAND,
			  sc->sc_command | EA_CMD_TX_OFF);

	timeout = 20000;
	do {
		status = bus_space_read_2(iot, ioh, EA_8005_STATUS);
	} while ((status & EA_STATUS_TX_ON) && --timeout > 0);
	if (timeout == 0)
		dprintf(("ea_stoptx: timeout waiting for tx termination\n"));

	/* Clear any pending tx interrupt */
	bus_space_write_2(iot, ioh, EA_8005_COMMAND,
		   sc->sc_command | EA_CMD_TX_INTACK);
	return 1;
}


/*
 * Stop the rx interface.
 *
 * Returns 0 if the tx was already stopped or 1 if it was active
 */

static int
ea_stoprx(struct ea_softc *sc)
{
	bus_space_tag_t iot = sc->sc_iot;
	bus_space_handle_t ioh = sc->sc_ioh;
	int timeout;
	int status;

	dprintf(("ea_stoprx()\n"));

	status = bus_space_read_2(iot, ioh, EA_8005_STATUS);
	if (!(status & EA_STATUS_RX_ON))
		return 0;

	/* Stop any rx and wait for confirmation */

	bus_space_write_2(iot, ioh, EA_8005_COMMAND,
			  sc->sc_command | EA_CMD_RX_OFF);

	timeout = 20000;
	do {
		status = bus_space_read_2(iot, ioh, EA_8005_STATUS);
	} while ((status & EA_STATUS_RX_ON) && --timeout > 0);
	if (timeout == 0)
		dprintf(("ea_stoprx: timeout waiting for rx termination\n"));

	/* Clear any pending rx interrupt */

	bus_space_write_2(iot, ioh, EA_8005_COMMAND,
		   sc->sc_command | EA_CMD_RX_INTACK);
	return 1;
}


/*
 * Stop interface.
 * Stop all IO and shut the interface down
 */

static void
ea_stop(struct ea_softc *sc)
{
	bus_space_tag_t iot = sc->sc_iot;
	bus_space_handle_t ioh = sc->sc_ioh;
	
	dprintf(("ea_stop()\n"));

	/* Stop all IO */
	ea_stoptx(sc);
	ea_stoprx(sc);

	/* Disable rx and tx interrupts */
	sc->sc_command &= (EA_CMD_RX_INTEN | EA_CMD_TX_INTEN);

	/* Clear any pending interrupts */
	bus_space_write_2(iot, ioh, EA_8005_COMMAND,
			  sc->sc_command | EA_CMD_RX_INTACK |
			  EA_CMD_TX_INTACK | EA_CMD_DMA_INTACK |
			  EA_CMD_BW_INTACK);
	dprintf(("st=%08x", bus_space_read_2(iot, ioh, EA_8005_STATUS)));

	/* Release the irq */
	ea_releaseirq(sc);

	/* Cancel any watchdog timer */
       	sc->sc_ethercom.ec_if.if_timer = 0;
}


/*
 * Reset the chip
 * Following this the software registers are reset
 */

static void
ea_chipreset(struct ea_softc *sc)
{
	bus_space_tag_t iot = sc->sc_iot;
	bus_space_handle_t ioh = sc->sc_ioh;

	dprintf(("ea_chipreset()\n"));

	/* Reset the controller. Min of 4us delay here */

	bus_space_write_2(iot, ioh, EA_8005_CONFIG2, EA_CFG2_RESET);
	delay(100);

	sc->sc_command = 0;
	sc->sc_config1 = 0;
	sc->sc_config2 = 0;
}


/*
 * Do a hardware reset of the board, and upload the ethernet address again in
 * case the board forgets.
 */

static void
ea_hardreset(struct ea_softc *sc)
{
	bus_space_tag_t iot = sc->sc_iot;
	bus_space_handle_t ioh = sc->sc_ioh;
	struct ifnet *ifp = &sc->sc_ethercom.ec_if;
	int loop;

	dprintf(("ea_hardreset()\n"));

	/* Stop any activity */
	ea_stoptx(sc);
	ea_stoprx(sc);

	ea_chipreset(sc);

	/* Set up defaults for the registers */

	/* Set the byte order for transfers to/from board RAM. */
#if BYTE_ORDER == BIG_ENDIAN
	sc->sc_config2 = EA_CFG2_BYTESWAP
#else
	sc->sc_config2 = 0;
#endif
	bus_space_write_2(iot, ioh, EA_8005_CONFIG2, sc->sc_config2);
	sc->sc_command = 0x00;
	sc->sc_config1 = EA_CFG1_STATION_ADDR0 | EA_CFG1_DMA_BSIZE_1 |
	    EA_CFG1_DMA_BURST_CONT;
	bus_space_write_2(iot, ioh, EA_8005_CONFIG1, sc->sc_config1);
	bus_space_write_2(iot, ioh, EA_8005_COMMAND, sc->sc_command);

	bus_space_write_2(iot, ioh, EA_8005_CONFIG1, EA_BUFCODE_TX_EAP);
	bus_space_write_2(iot, ioh, EA_8005_BUFWIN,
			  (EA_TX_BUFFER_SIZE >> 8) - 1);

	/* Write the station address - the receiver must be off */
	bus_space_write_2(iot, ioh, EA_8005_CONFIG1,
			  sc->sc_config1 | EA_BUFCODE_STATION_ADDR0);
	for (loop = 0; loop < ETHER_ADDR_LEN; ++loop)
		bus_space_write_2(iot, ioh, EA_8005_BUFWIN,
				  LLADDR(ifp->if_sadl)[loop]);
}


/*
 * write to the buffer memory on the interface
 *
 * If addr is within range for the interface buffer then the buffer
 * address is set to addr.
 * If len != 0 then data is copied from the address starting at buf
 * to the interface buffer.
 * BUF must be usable as a u_int16_t *.
 * If LEN is odd, it must be safe to overwrite one extra byte.
 */

static void
ea_writebuf(struct ea_softc *sc, u_char *buf, u_int addr, size_t len)
{
	bus_space_tag_t iot = sc->sc_iot;
	bus_space_handle_t ioh = sc->sc_ioh;
	int timeout;

	dprintf(("writebuf: st=%04x\n",
		 bus_space_read_2(iot, ioh, EA_8005_STATUS)));

#ifdef DIAGNOSTIC*/
	if (!ALIGNED_POINTER(buf, u_int16_t))
		panic("%s: unaligned writebuf", sc->sc_dev.dv_xname);
#endif
	/* Assume that copying too much is safe. */
	if (len % 2 != 0)
		len++;

	/*
	 * If we have a valid buffer address set the buffer pointer and
	 * direction.
	 */
	if (addr < EA_BUFFER_SIZE) {
		bus_space_write_2(iot, ioh, EA_8005_CONFIG1,
				  sc->sc_config1 | EA_BUFCODE_LOCAL_MEM);
		bus_space_write_2(iot, ioh, EA_8005_COMMAND,
				  sc->sc_command | EA_CMD_FIFO_WRITE);

		/* Should wait here of FIFO empty flag */

		timeout = 20000;
		while ((bus_space_read_2(iot, ioh, EA_8005_STATUS) &
			EA_STATUS_FIFO_EMPTY) == 0 &&
		       --timeout > 0)
			continue;

		bus_space_write_2(iot, ioh, EA_8005_DMA_ADDR, addr);
	}

	if (len > 0)
		bus_space_write_multi_2(iot, ioh, EA_8005_BUFWIN,
					(u_int16_t *)buf, len / 2);
}


/*
 * read from the buffer memory on the interface
 *
 * If addr is within range for the interface buffer then the buffer
 * address is set to addr.
 * If len != 0 then data is copied from the interface buffer to the
 * address starting at buf.
 * BUF must be usable as a u_int16_t *.
 * If LEN is odd, it must be safe to overwrite one extra byte.
 */

static void
ea_readbuf(struct ea_softc *sc, u_char *buf, u_int addr, size_t len)
{

	bus_space_tag_t iot = sc->sc_iot;
	bus_space_handle_t ioh = sc->sc_ioh;
	int timeout;

	dprintf(("readbuf: st=%04x addr=%04x len=%d\n",
		 bus_space_read_2(iot, ioh, EA_8005_STATUS), addr, len));

#ifdef DIAGNOSTIC*/
	if (!ALIGNED_POINTER(buf, u_int16_t))
		panic("%s: unaligned readbuf", sc->sc_dev.dv_xname);
#endif
	/* Assume that copying too much is safe. */
	if (len % 2 != 0)
		len++;

	/*
	 * If we have a valid buffer address set the buffer pointer and
	 * direction.
	 */
	if (addr < EA_BUFFER_SIZE) {
		if ((bus_space_read_2(iot, ioh, EA_8005_STATUS) &
		     EA_STATUS_FIFO_DIR) == 0) {
			/* Should wait here of FIFO empty flag */

			timeout = 20000;
			while ((bus_space_read_2(iot, ioh, EA_8005_STATUS) &
				EA_STATUS_FIFO_EMPTY) == 0 &&
			       --timeout > 0)
				continue;
		}
		bus_space_write_2(iot, ioh, EA_8005_CONFIG1,
				  sc->sc_config1 | EA_BUFCODE_LOCAL_MEM);
		bus_space_write_2(iot, ioh, EA_8005_COMMAND,
				  sc->sc_command | EA_CMD_FIFO_WRITE);

		/* Should wait here of FIFO empty flag */

		timeout = 20000;
		while ((bus_space_read_2(iot, ioh, EA_8005_STATUS) &
			EA_STATUS_FIFO_EMPTY) == 0 &&
		       --timeout > 0)
			continue;

		bus_space_write_2(iot, ioh, EA_8005_DMA_ADDR, addr);
		bus_space_write_2(iot, ioh, EA_8005_COMMAND,
				  sc->sc_command | EA_CMD_FIFO_READ);

		/* Should wait here of FIFO full flag */

		timeout = 20000;
		while ((bus_space_read_2(iot, ioh, + EA_8005_STATUS) &
			EA_STATUS_FIFO_FULL) == 0 && --timeout > 0)
			continue;
	}

	if (len > 0)
		bus_space_read_multi_2(iot, ioh, EA_8005_BUFWIN,
				       (u_int16_t *)buf, len / 2);
}


/*
 * Initialize interface.
 *
 * This should leave the interface in a state for packet reception and
 * transmission.
 */

static int
ea_init(struct ea_softc *sc)
{
	struct ifnet *ifp = &sc->sc_ethercom.ec_if;
	bus_space_tag_t iot = sc->sc_iot;
	bus_space_handle_t ioh = sc->sc_ioh;
	int s;

	dprintf(("ea_init()\n"));

	s = splnet();

	/* Grab an irq */

	ea_claimirq(sc);

	/* First, reset the board. */

	ea_hardreset(sc);


	/* Configure rx. */
	dprintf(("Configuring rx...\n"));
	if (ifp->if_flags & IFF_PROMISC)
		sc->sc_config1 = EA_CFG1_PROMISCUOUS;
	else
		sc->sc_config1 = EA_CFG1_BROADCAST;

	sc->sc_config1 |= EA_CFG1_DMA_BSIZE_8 | EA_CFG1_STATION_ADDR0 |
		EA_CFG1_DMA_BURST_CONT;
	bus_space_write_2(iot, ioh, EA_8005_CONFIG1, sc->sc_config1);


	/* Configure TX. */
	dprintf(("Configuring tx...\n"));

	bus_space_write_2(iot, ioh, EA_8005_CONFIG1,
			  sc->sc_config1 | EA_BUFCODE_TX_EAP);
	bus_space_write_2(iot, ioh, EA_8005_BUFWIN,
			  (EA_TX_BUFFER_SIZE >> 8) - 1);
	bus_space_write_2(iot, ioh, EA_8005_TX_PTR, 0x0000);

	sc->sc_config2 |= EA_CFG2_OUTPUT;
	bus_space_write_2(iot, ioh, EA_8005_CONFIG2, sc->sc_config2);


	/* Place a NULL header at the beginning of the transmit area */
	ea_writebuf(sc, NULL, 0x0000, 0);
		
	bus_space_write_2(iot, ioh, EA_8005_BUFWIN, 0x0000);
	bus_space_write_2(iot, ioh, EA_8005_BUFWIN, 0x0000);

	sc->sc_command |= EA_CMD_TX_INTEN;
	bus_space_write_2(iot, ioh, EA_8005_COMMAND, sc->sc_command);


	/* Setup the Rx pointers */
	sc->sc_rx_ptr = EA_TX_BUFFER_SIZE;

	bus_space_write_2(iot, ioh, EA_8005_RX_PTR, sc->sc_rx_ptr);
	bus_space_write_2(iot, ioh, EA_8005_RX_END, sc->sc_rx_ptr >> 8);


	/* Place a NULL header at the beginning of the receive area */
	ea_writebuf(sc, NULL, sc->sc_rx_ptr, 0);
		
	bus_space_write_2(iot, ioh, EA_8005_BUFWIN, 0x0000);
	bus_space_write_2(iot, ioh, EA_8005_BUFWIN, 0x0000);


	/* Turn on Rx */
	sc->sc_command |= EA_CMD_RX_INTEN;
	bus_space_write_2(iot, ioh, EA_8005_COMMAND,
			  sc->sc_command | EA_CMD_RX_ON);


	/* Set flags appropriately. */
	ifp->if_flags |= IFF_RUNNING;
	ifp->if_flags &= ~IFF_OACTIVE;

	dprintf(("init: st=%04x\n",
		 bus_space_read_2(iot, ioh, EA_8005_STATUS)));


	/* And start output. */
	ea_start(ifp);

	splx(s);
	return 0;
}


/*
 * Start output on interface. Get datagrams from the queue and output them,
 * giving the receiver a chance between datagrams. Call only from splnet or
 * interrupt level!
 */

static void
ea_start(struct ifnet *ifp)
{
	struct ea_softc *sc = ifp->if_softc;
	int s;

	s = splnet();
#ifdef EA_TX_DEBUG
	dprintf(("ea_start()...\n"));
#endif

	/* Don't do anything if output is active. */

	if (ifp->if_flags & IFF_OACTIVE)
		return;

	/* Mark interface as output active */
	
	ifp->if_flags |= IFF_OACTIVE;

	/* tx packets */

	eatxpacket(sc);
	splx(s);
}


/*
 * Transfer a packet to the interface buffer and start transmission
 *
 * Called at splnet()
 */
 
void
eatxpacket(struct ea_softc *sc)
{
	bus_space_tag_t iot = sc->sc_iot;
	bus_space_handle_t ioh = sc->sc_ioh;
	struct mbuf *m, *m0;
	struct ifnet *ifp;
	int len, nextpacket;
	u_int8_t hdr[4];

	ifp = &sc->sc_ethercom.ec_if;

	/* Dequeue the next packet. */
	IF_DEQUEUE(&ifp->if_snd, m0);

	/* If there's nothing to send, return. */
	if (!m0) {
		ifp->if_flags &= ~IFF_OACTIVE;
		sc->sc_config2 |= EA_CFG2_OUTPUT;
		bus_space_write_2(iot, ioh, EA_8005_CONFIG2, sc->sc_config2);
#ifdef EA_TX_DEBUG
		dprintf(("tx finished\n"));
#endif
		return;
	}

#if NBPFILTER > 0
	/* Give the packet to the bpf, if any. */
	if (ifp->if_bpf)
		bpf_mtap(ifp->if_bpf, m0);
#endif

#ifdef EA_TX_DEBUG
	dprintf(("Tx new packet\n"));
#endif

	sc->sc_config2 &= ~EA_CFG2_OUTPUT;
	bus_space_write_2(iot, ioh, EA_8005_CONFIG2, sc->sc_config2);

	/*
	 * Copy the frame to the start of the transmit area on the card,
	 * leaving four bytes for the transmit header.
	 */
	len = 0;
	for (m = m0; m; m = m->m_next) {
		if (m->m_len == 0)
			continue;
		ea_writebuf(sc, mtod(m, caddr_t), 4 + len, m->m_len);
		len += m->m_len;
	}
	m_freem(m0);


	/* If packet size is odd round up to the next 16 bit boundry */
	if (len % 2)
		++len;

	len = max(len, ETHER_MIN_LEN);
	
	if (len > (ETHER_MAX_LEN - ETHER_CRC_LEN))
		log(LOG_WARNING, "%s: oversize packet = %d bytes\n",
		    sc->sc_dev.dv_xname, len);

#if 0 /*def EA_TX_DEBUG*/
	dprintf(("ea: xfr pkt length=%d...\n", len));

	dprintf(("%s-->", ether_sprintf(sc->sc_pktbuf+6)));
	dprintf(("%s\n", ether_sprintf(sc->sc_pktbuf)));
#endif

/*	dprintf(("st=%04x\n", bus_space_read_2(iot, ioh, EA_8005_STATUS)));*/

	/* Follow it with a NULL packet header */
	bus_space_write_2(iot, ioh, EA_8005_BUFWIN, 0x0000);
	bus_space_write_2(iot, ioh, EA_8005_BUFWIN, 0x0000);


	/* Write the packet header */

	nextpacket = len + 4;
	hdr[0] = (nextpacket >> 8) & 0xff;
	hdr[1] = nextpacket & 0xff;
	hdr[2] = EA_PKTHDR_TX | EA_PKTHDR_DATA_FOLLOWS |
		EA_TXHDR_XMIT_SUCCESS_INT | EA_TXHDR_COLLISION_INT;
	hdr[3] = 0; /* Status byte -- will be update by hardware. */
	ea_writebuf(sc, hdr, 0x0000, 4);

	bus_space_write_2(iot, ioh, EA_8005_TX_PTR, 0x0000);

/*	dprintf(("st=%04x\n", bus_space_read_2(iot, ioh, EA_8005_STATUS)));*/

#ifdef EA_PACKET_DEBUG
	ea_dump_buffer(sc, 0);
#endif


	/* Now transmit the datagram. */
/*	dprintf(("st=%04x\n", bus_space_read_2(iot, ioh, EA_8005_STATUS)));*/
	bus_space_write_2(iot, ioh, EA_8005_COMMAND,
			  sc->sc_command | EA_CMD_TX_ON);
#ifdef EA_TX_DEBUG
	dprintf(("st=%04x\n", bus_space_read_2(iot, ioh, EA_8005_STATUS)));
	dprintf(("tx: queued\n"));
#endif
}


/*
 * Ethernet controller interrupt.
 */

int
eaintr(void *arg)
{
	struct ea_softc *sc = arg;
	bus_space_tag_t iot = sc->sc_iot;
	bus_space_handle_t ioh = sc->sc_ioh;
	struct ifnet *ifp = &sc->sc_ethercom.ec_if;
	int status, s, handled;
	u_int8_t txhdr[4];
	u_int txstatus;

	handled = 0;
	dprintf(("eaintr: "));


	/* Get the controller status */
	status = bus_space_read_2(iot, ioh, EA_8005_STATUS);
        dprintf(("st=%04x ", status));	


	/* Tx interrupt ? */
	if (status & EA_STATUS_TX_INT) {
		dprintf(("txint "));
		handled = 1;

		/* Acknowledge the interrupt */
		bus_space_write_2(iot, ioh, EA_8005_COMMAND,
				  sc->sc_command | EA_CMD_TX_INTACK);

		ea_readbuf(sc, txhdr, 0x0000, 4);

#ifdef EA_TX_DEBUG		
		dprintf(("txstatus=%02x %02x %02x %02x\n",
			 txhdr[0], txhdr[1], txhdr[2], txhdr[3]));
#endif
		txstatus = txhdr[3];

		/*
		 * Did it succeed ? Did we collide ?
		 *
		 * The exact proceedure here is not clear. We should get
		 * an interrupt on a sucessfull tx or on a collision.
		 * The done flag is set after successfull tx or 16 collisions
		 * We should thus get a interrupt for each of collision
		 * and the done bit should not be set. However it does appear
		 * to be set at the same time as the collision bit ...
		 *
		 * So we will count collisions and output errors and will
		 * assume that if the done bit is set the packet was
		 * transmitted. Stats may be wrong if 16 collisions occur on
		 * a packet as the done flag should be set but the packet
		 * may not have been transmitted. so the output count might
		 * not require incrementing if the 16 collisions flags is
		 * set. I don;t know abou this until it happens.
		 */

		if (txstatus & EA_TXHDR_COLLISION)
			ifp->if_collisions++;
		else if (txstatus & EA_TXHDR_ERROR_MASK)
			ifp->if_oerrors++;

#if 0
		if (txstatus & EA_TXHDR_ERROR_MASK)
			log(LOG_WARNING, "tx packet error =%02x\n", txstatus);
#endif

		if (txstatus & EA_PKTHDR_DONE) {
			ifp->if_opackets++;

			/* Tx next packet */

			s = splnet();
			eatxpacket(sc);
			splx(s);
		}
	}


	/* Rx interrupt ? */
	if (status & EA_STATUS_RX_INT) {
		dprintf(("rxint "));
		handled = 1;

		/* Acknowledge the interrupt */
		bus_space_write_2(iot, ioh, EA_8005_COMMAND,
				  sc->sc_command | EA_CMD_RX_INTACK);

		/* Install a watchdog timer needed atm to fixed rx lockups */
		ifp->if_timer = EA_TIMEOUT;

		/* Processes the received packets */
		eagetpackets(sc);


#if 0
		/* Make sure the receiver is on */
		if ((status & EA_STATUS_RX_ON) == 0) {
			bus_space_write_2(iot, ioh, EA_8005_COMMAND,
					  sc->sc_command | EA_CMD_RX_ON);
			printf("rxintr: rx is off st=%04x\n",status);
		}
#endif
	}

#ifdef EA_DEBUG
	status = bus_space_read_2(iot, ioh, EA_8005_STATUS);
        dprintf(("st=%04x\n", status));
#endif

	return handled;
}


void
eagetpackets(struct ea_softc *sc)
{
	bus_space_tag_t iot = sc->sc_iot;
	bus_space_handle_t ioh = sc->sc_ioh;
	u_int addr;
	int len;
	int ctrl;
	int ptr;
	int pack;
	int status;
	u_int8_t rxhdr[4];
	struct ifnet *ifp;

	ifp = &sc->sc_ethercom.ec_if;


	/* We start from the last rx pointer position */
	addr = sc->sc_rx_ptr;
	sc->sc_config2 &= ~EA_CFG2_OUTPUT;
	bus_space_write_2(iot, ioh, EA_8005_CONFIG2, sc->sc_config2);

	do {
		/* Read rx header */
		ea_readbuf(sc, rxhdr, addr, 4);
		
		/* Split the packet header */
		ptr = (rxhdr[0] << 8) | rxhdr[1];
		ctrl = rxhdr[2];
		status = rxhdr[3];

#ifdef EA_RX_DEBUG
		dprintf(("addr=%04x ptr=%04x ctrl=%02x status=%02x\n",
			 addr, ptr, ctrl, status));
#endif


		/* Zero packet ptr ? then must be null header so exit */
		if (ptr == 0) break;


		/* Get packet length */
       		len = (ptr - addr) - 4;

		if (len < 0)
			len += EA_RX_BUFFER_SIZE;

#ifdef EA_RX_DEBUG
		dprintf(("len=%04x\n", len));
#endif


		/* Has the packet rx completed ? if not then exit */
		if ((status & EA_PKTHDR_DONE) == 0)
			break;

		/*
		 * Did we have any errors? then note error and go to
		 * next packet
		 */
		if (__predict_false(status & 0x0f)) {
			++ifp->if_ierrors;
			log(LOG_WARNING,
			    "%s: rx packet error (%02x) - dropping packet\n",
			    sc->sc_dev.dv_xname, status & 0x0f);
			sc->sc_config2 |= EA_CFG2_OUTPUT;
			bus_space_write_2(iot, ioh, EA_8005_CONFIG2,
					  sc->sc_config2);
			ea_reinit(sc);
			return;
		}

		/*
		 * Is the packet too big ? - this will probably be trapped
		 * above as a receive error
		 */
		if (__predict_false(len > (ETHER_MAX_LEN - ETHER_CRC_LEN))) {
			++ifp->if_ierrors;
			log(LOG_WARNING, "%s: rx packet size error len=%d\n",
			    sc->sc_dev.dv_xname, len);
			sc->sc_config2 |= EA_CFG2_OUTPUT;
			bus_space_write_2(iot, ioh, EA_8005_CONFIG2,
					  sc->sc_config2);
			ea_reinit(sc);
			return;
		}

		ifp->if_ipackets++;
		/* Pass data up to upper levels. */
		earead(sc, addr + 4, len);

		addr = ptr;
		++pack;
	} while (len != 0);

	sc->sc_config2 |= EA_CFG2_OUTPUT;
	bus_space_write_2(iot, ioh, EA_8005_CONFIG2, sc->sc_config2);

#ifdef EA_RX_DEBUG
	dprintf(("new rx ptr=%04x\n", addr));
#endif


	/* Store new rx pointer */
	sc->sc_rx_ptr = addr;
	bus_space_write_2(iot, ioh, EA_8005_RX_END, sc->sc_rx_ptr >> 8);

	/* Make sure the receiver is on */
	bus_space_write_2(iot, ioh, EA_8005_COMMAND,
			  sc->sc_command | EA_CMD_RX_ON);

}


/*
 * Pass a packet up to the higher levels.
 */

static void
earead(struct ea_softc *sc, int addr, int len)
{
	register struct ether_header *eh;
	struct mbuf *m;
	struct ifnet *ifp;

	ifp = &sc->sc_ethercom.ec_if;

	/* Pull packet off interface. */
	m = eaget(sc, addr, len, ifp);
	if (m == 0)
		return;
	eh = mtod(m, struct ether_header *);

#ifdef EA_RX_DEBUG
	dprintf(("%s-->", ether_sprintf(eh->ether_shost)));
	dprintf(("%s\n", ether_sprintf(eh->ether_dhost)));
#endif

#if NBPFILTER > 0
	/*
	 * Check if there's a BPF listener on this interface.
	 * If so, hand off the raw packet to bpf.
	 */
	if (ifp->if_bpf) {
		bpf_mtap(ifp->if_bpf, m);

		/*
		 * Note that the interface cannot be in promiscuous mode if
		 * there are no BPF listeners.  And if we are in promiscuous
		 * mode, we have to check if this packet is really ours.
		 */
		if ((ifp->if_flags & IFF_PROMISC) &&
		    !ETHER_IS_MULTICAST(eh->ether_dhost) &&
		    bcmp(eh->ether_dhost, LLADDR(ifp->if_sadl),
			    sizeof(eh->ether_dhost)) != 0) {
			m_freem(m);
			return;
		}
	}
#endif

	(*ifp->if_input)(ifp, m);
}

/*
 * Pull read data off a interface.  Len is length of data, with local net
 * header stripped.  We copy the data into mbufs.  When full cluster sized
 * units are present we copy into clusters.
 */

struct mbuf *
eaget(struct ea_softc *sc, int addr, int totlen, struct ifnet *ifp)
{
        struct mbuf *top, **mp, *m;
        int len;
        u_int cp, epkt;

        cp = addr;
        epkt = cp + totlen;

        MGETHDR(m, M_DONTWAIT, MT_DATA);
        if (m == 0)
                return 0;
        m->m_pkthdr.rcvif = ifp;
        m->m_pkthdr.len = totlen;
        m->m_len = MHLEN;
        top = 0;
        mp = &top;

        while (totlen > 0) {
                if (top) {
                        MGET(m, M_DONTWAIT, MT_DATA);
                        if (m == 0) {
                                m_freem(top);
                                return 0;
                        }
                        m->m_len = MLEN;
                }
                len = min(totlen, epkt - cp);
                if (len >= MINCLSIZE) {
                        MCLGET(m, M_DONTWAIT);
                        if (m->m_flags & M_EXT)
                                m->m_len = len = min(len, MCLBYTES);
                        else
                                len = m->m_len;
                } else {
                        /*
                         * Place initial small packet/header at end of mbuf.
                         */
                        if (len < m->m_len) {
                                if (top == 0 && len + max_linkhdr <= m->m_len)
                                        m->m_data += max_linkhdr;
                                m->m_len = len;
                        } else
                                len = m->m_len;
                }
		if (top == 0) {
			/* Make sure the payload is aligned */
			caddr_t newdata = (caddr_t)
			    ALIGN(m->m_data + sizeof(struct ether_header)) -
			    sizeof(struct ether_header);
			len -= newdata - m->m_data;
			m->m_len = len;
			m->m_data = newdata;
		}
                ea_readbuf(sc, mtod(m, u_char *),
			   cp < EA_BUFFER_SIZE ? cp : cp - EA_RX_BUFFER_SIZE,
			   len);
                cp += len;
                *mp = m;
                mp = &m->m_next;
                totlen -= len;
                if (cp == epkt)
                        cp = addr;
        }

        return top;
}

/*
 * Process an ioctl request. This code needs some work - it looks pretty ugly.
 */
static int
ea_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct ea_softc *sc = ifp->if_softc;
	struct ifaddr *ifa = (struct ifaddr *)data;
/*	struct ifreq *ifr = (struct ifreq *)data;*/
	int s, error = 0;

	s = splnet();

	switch (cmd) {

	case SIOCSIFADDR:
		ifp->if_flags |= IFF_UP;
		dprintf(("if_flags=%08x\n", ifp->if_flags));

		switch (ifa->ifa_addr->sa_family) {
#ifdef INET
		case AF_INET:
			arp_ifinit(ifp, ifa);
			dprintf(("Interface ea is coming up (AF_INET)\n"));
			ea_init(sc);
			break;
#endif
#ifdef NS
		/* XXX - This code is probably wrong. */
		case AF_NS:
		    {
			register struct ns_addr *ina = &IA_SNS(ifa)->sns_addr;

			if (ns_nullhost(*ina))
				ina->x_host =
				    *(union ns_host *)LLADDR(ifp->if_sadl);
			else
				bcopy(ina->x_host.c_host,
				    LLADDR(ifp->if_sadl), ETHER_ADDR_LEN);
			/* Set new address. */
			dprintf(("Interface ea is coming up (AF_NS)\n"));
			ea_init(sc);
			break;
		    }
#endif
		default:
			dprintf(("Interface ea is coming up (default)\n"));
			ea_init(sc);
			break;
		}
		break;

	case SIOCSIFFLAGS:
		dprintf(("if_flags=%08x\n", ifp->if_flags));
		if ((ifp->if_flags & IFF_UP) == 0 &&
		    (ifp->if_flags & IFF_RUNNING) != 0) {
			/*
			 * If interface is marked down and it is running, then
			 * stop it.
			 */
			dprintf(("Interface ea is stopping\n"));
			ea_stop(sc);
			ifp->if_flags &= ~IFF_RUNNING;
		} else if ((ifp->if_flags & IFF_UP) != 0 &&
		    	   (ifp->if_flags & IFF_RUNNING) == 0) {
			/*
			 * If interface is marked up and it is stopped, then
			 * start it.
			 */
			dprintf(("Interface ea is restarting(1)\n"));
			ea_init(sc);
		} else {
			/*
			 * Some other important flag might have changed, so
			 * reset.
			 */
			dprintf(("Interface ea is reinitialising\n"));
			ea_reinit(sc);
		}
		break;

	default:
		error = EINVAL;
		break;
	}

	splx(s);
	return error;
}

/*
 * Device timeout routine.
 *
 * Ok I am not sure exactly how the device timeout should work....
 * Currently what will happens is that that the device timeout is only
 * set when a packet it received. This indicates we are on an active
 * network and thus we should expect more packets. If non arrive in
 * in the timeout period then we reinitialise as we may have jammed.
 * We zero the timeout at this point so that we don't end up with
 * an endless stream of timeouts if the network goes down.
 */

static void
ea_watchdog(struct ifnet *ifp)
{
	struct ea_softc *sc = ifp->if_softc;

	log(LOG_ERR, "%s: device timeout\n", sc->sc_dev.dv_xname);
	ifp->if_oerrors++;
	dprintf(("ea_watchdog: "));
	dprintf(("st=%04x\n",
		 bus_space_read_2(sc->sc_iot, sc->sc_ioh, EA_8005_STATUS)));

	/* Kick the interface */

	ea_reinit(sc);

/*	ifp->if_timer = EA_TIMEOUT;*/
	ifp->if_timer = 0;
}

/* End of if_ea.c */
