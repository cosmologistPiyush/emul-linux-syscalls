/*	$NetBSD: sbc_obio.c,v 1.8 1998/05/02 16:45:31 scottr Exp $	*/

/*
 * Copyright (C) 1996,1997 Scott Reynolds.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/errno.h>
#include <sys/device.h>
#include <sys/buf.h>
#include <sys/proc.h>
#include <sys/user.h>

#include <dev/scsipi/scsi_all.h>
#include <dev/scsipi/scsipi_all.h>
#include <dev/scsipi/scsipi_debug.h>
#include <dev/scsipi/scsiconf.h>

#include <dev/ic/ncr5380reg.h>
#include <dev/ic/ncr5380var.h>

#include <machine/cpu.h>
#include <machine/viareg.h>

#include <mac68k/dev/sbcreg.h>
#include <mac68k/dev/sbcvar.h>

/*
 * From Guide to the Macintosh Family Hardware, pp. 137-143
 * These are offsets from SCSIBase (see pmap_bootstrap.c)
 */
#define	SBC_REG_OFS		0x10000
#define	SBC_DMA_OFS		0x12000
#define	SBC_HSK_OFS		0x06000

#define	SBC_DMA_OFS_PB500	0x06000

#define	SBC_REG_OFS_IIFX	0x08000		/* Just guessing... */
#define	SBC_DMA_OFS_IIFX	0x0c000
#define	SBC_HSK_OFS_IIFX	0x0e000

#define	SBC_REG_OFS_DUO2	0x00000
#define	SBC_DMA_OFS_DUO2	0x02000
#define	SBC_HSK_OFS_DUO2	0x04000

static int	sbc_obio_match __P((struct device *, struct cfdata *, void *));
static void	sbc_obio_attach __P((struct device *, struct device *, void *));

void	sbc_intr_enable __P((struct ncr5380_softc *));
void	sbc_intr_disable __P((struct ncr5380_softc *));
void	sbc_obio_clrintr __P((struct ncr5380_softc *));

struct cfattach sbc_obio_ca = {
	sizeof(struct sbc_softc), sbc_obio_match, sbc_obio_attach
};

static int
sbc_obio_match(parent, cf, args)
	struct device *parent;
	struct cfdata *cf;
	void *args;
{
	switch (current_mac_model->machineid) {
	case MACH_MACIIFX:	/* Note: the IIfx isn't (yet) supported. */
/*
		if (cf->cf_unit == 0)
			return 1;
*/
		break;
	case MACH_MACPB210:
	case MACH_MACPB230:
	case MACH_MACPB250:
	case MACH_MACPB270:
	case MACH_MACPB280:
	case MACH_MACPB280C:
		if (cf->cf_unit == 1)
			return 1;
		/*FALLTHROUGH*/
	default:
		if (cf->cf_unit == 0 && mac68k_machine.scsi80)
			return 1;
	}
	return 0;
}

static void
sbc_obio_attach(parent, self, args)
	struct device *parent, *self;
	void *args;
{
	struct sbc_softc *sc = (struct sbc_softc *) self;
	struct ncr5380_softc *ncr_sc = (struct ncr5380_softc *) sc;
	char bits[64];
	extern vm_offset_t SCSIBase;

	/* Pull in the options flags. */ 
	sc->sc_options = ((ncr_sc->sc_dev.dv_cfdata->cf_flags | sbc_options)
	    & SBC_OPTIONS_MASK);

	/*
	 * Set up offsets to 5380 registers and GLUE I/O space, and turn
	 * off options we know we can't support on certain models.
	 */
	switch (current_mac_model->machineid) {
	case MACH_MACIIFX:	/* Note: the IIfx isn't (yet) supported. */
		sc->sc_regs = (struct sbc_regs *)(SCSIBase + SBC_REG_OFS_IIFX);
		sc->sc_drq_addr = (vm_offset_t)(SCSIBase + SBC_HSK_OFS_IIFX);
		sc->sc_nodrq_addr = (vm_offset_t)(SCSIBase + SBC_DMA_OFS_IIFX);
		sc->sc_options &= ~(SBC_INTR | SBC_RESELECT);
		break;
	case MACH_MACPB500:
		sc->sc_regs = (struct sbc_regs *)(SCSIBase + SBC_REG_OFS);
		sc->sc_drq_addr = (vm_offset_t)(SCSIBase + SBC_HSK_OFS); /*??*/
		sc->sc_nodrq_addr = (vm_offset_t)(SCSIBase + SBC_DMA_OFS_PB500);
		sc->sc_options &= ~(SBC_INTR | SBC_RESELECT);
		break;
	case MACH_MACPB210:
	case MACH_MACPB230:
	case MACH_MACPB250:
	case MACH_MACPB270:
	case MACH_MACPB280:
	case MACH_MACPB280C:
		if (ncr_sc->sc_dev.dv_unit == 1) {
			sc->sc_regs = (struct sbc_regs *)(0xfee00000 + SBC_REG_OFS_DUO2);
			sc->sc_drq_addr = (vm_offset_t)(0xfee00000 + SBC_HSK_OFS_DUO2);
			sc->sc_nodrq_addr = (vm_offset_t)(0xfee00000 + SBC_DMA_OFS_DUO2);
			break;
		}
		/*FALLTHROUGH*/
	default:
		sc->sc_regs = (struct sbc_regs *)(SCSIBase + SBC_REG_OFS);
		sc->sc_drq_addr = (vm_offset_t)(SCSIBase + SBC_HSK_OFS);
		sc->sc_nodrq_addr = (vm_offset_t)(SCSIBase + SBC_DMA_OFS);
		break;
	}

	/*
	 * Fill in the prototype scsi_link.
	 */
	ncr_sc->sc_link.scsipi_scsi.channel = SCSI_CHANNEL_ONLY_ONE;
	ncr_sc->sc_link.adapter_softc = sc;
	ncr_sc->sc_link.scsipi_scsi.adapter_target = 7;
	ncr_sc->sc_link.adapter = &sbc_ops;
	ncr_sc->sc_link.device = &sbc_dev;
	ncr_sc->sc_link.type = BUS_SCSI;

	/*
	 * Initialize fields used by the MI code
	 */
	ncr_sc->sci_r0 = &sc->sc_regs->sci_pr0.sci_reg;
	ncr_sc->sci_r1 = &sc->sc_regs->sci_pr1.sci_reg;
	ncr_sc->sci_r2 = &sc->sc_regs->sci_pr2.sci_reg;
	ncr_sc->sci_r3 = &sc->sc_regs->sci_pr3.sci_reg;
	ncr_sc->sci_r4 = &sc->sc_regs->sci_pr4.sci_reg;
	ncr_sc->sci_r5 = &sc->sc_regs->sci_pr5.sci_reg;
	ncr_sc->sci_r6 = &sc->sc_regs->sci_pr6.sci_reg;
	ncr_sc->sci_r7 = &sc->sc_regs->sci_pr7.sci_reg;

	/*
	 * MD function pointers used by the MI code.
	 */
	if (sc->sc_options & SBC_PDMA) {
		ncr_sc->sc_pio_out   = sbc_pdma_out;
		ncr_sc->sc_pio_in    = sbc_pdma_in;
	} else {
		ncr_sc->sc_pio_out   = ncr5380_pio_out;
		ncr_sc->sc_pio_in    = ncr5380_pio_in;
	}
	ncr_sc->sc_dma_alloc = NULL;
	ncr_sc->sc_dma_free  = NULL;
	ncr_sc->sc_dma_poll  = NULL;
	ncr_sc->sc_intr_on   = NULL;
	ncr_sc->sc_intr_off  = NULL;
	ncr_sc->sc_dma_setup = NULL;
	ncr_sc->sc_dma_start = NULL;
	ncr_sc->sc_dma_eop   = NULL;
	ncr_sc->sc_dma_stop  = NULL;
	ncr_sc->sc_flags = 0;
	ncr_sc->sc_min_dma_len = MIN_DMA_LEN;

	if (sc->sc_options & SBC_INTR) {
		ncr_sc->sc_dma_alloc = sbc_dma_alloc;
		ncr_sc->sc_dma_free  = sbc_dma_free;
		ncr_sc->sc_dma_poll  = sbc_dma_poll;
		ncr_sc->sc_dma_setup = sbc_dma_setup;
		ncr_sc->sc_dma_start = sbc_dma_start;
		ncr_sc->sc_dma_eop   = sbc_dma_eop;
		ncr_sc->sc_dma_stop  = sbc_dma_stop;
		via2_register_irq(VIA2_SCSIDRQ, sbc_drq_intr, ncr_sc);
	}

	via2_register_irq(VIA2_SCSIIRQ, sbc_irq_intr, ncr_sc);
	sc->sc_clrintr = sbc_obio_clrintr;

	if ((sc->sc_options & SBC_RESELECT) == 0)
		ncr_sc->sc_no_disconnect = 0xff;

	if (sc->sc_options)
		printf(": options=%s", bitmask_snprintf(sc->sc_options,
		    SBC_OPTIONS_BITS, bits, sizeof(bits)));
	printf("\n");

	if (sc->sc_options & (SBC_INTR|SBC_RESELECT)) {
		/* Enable SCSI interrupts through VIA2 */
		sbc_intr_enable(ncr_sc);
	}

#ifdef SBC_DEBUG
	if (sbc_debug)
		printf("%s: softc=%p regs=%p\n", ncr_sc->sc_dev.dv_xname,
		    sc, sc->sc_regs);
	ncr_sc->sc_link.flags |= sbc_link_flags;
#endif

	/*
	 *  Initialize the SCSI controller itself.
	 */
	ncr5380_init(ncr_sc);
	ncr5380_reset_scsibus(ncr_sc);
	config_found(self, &(ncr_sc->sc_link), scsiprint);
}

/*
 * Interrupt support routines.
 */
void
sbc_intr_enable(ncr_sc)
	struct ncr5380_softc *ncr_sc;
{
	struct sbc_softc *sc = (struct sbc_softc *)ncr_sc;
	int s, flags;

	flags = V2IF_SCSIIRQ;
	if (sc->sc_options & SBC_INTR)
		flags |= V2IF_SCSIDRQ;

	s = splhigh();
	if (VIA2 == VIA2OFF)
		via2_reg(vIER) = 0x80 | flags;
	else
		via2_reg(rIER) = 0x80 | flags;
	splx(s);
}

void
sbc_intr_disable(ncr_sc)
	struct ncr5380_softc *ncr_sc;
{
	struct sbc_softc *sc = (struct sbc_softc *)ncr_sc;
	int s, flags;

	flags = V2IF_SCSIIRQ;
	if (sc->sc_options & SBC_INTR)
		flags |= V2IF_SCSIDRQ;

	s = splhigh();
	if (VIA2 == VIA2OFF)
		via2_reg(vIER) = flags;
	else
		via2_reg(rIER) = flags;
	splx(s);
}

void
sbc_obio_clrintr(ncr_sc)
	struct ncr5380_softc *ncr_sc;
{
	struct sbc_softc *sc = (struct sbc_softc *)ncr_sc;
	int flags;

	flags = V2IF_SCSIIRQ;
	if (sc->sc_options & SBC_INTR)
		flags |= V2IF_SCSIDRQ;

	if (VIA2 == VIA2OFF)
		via2_reg(vIFR) = 0x80 | flags;
	else
		via2_reg(rIFR) = 0x80 | flags;
}
