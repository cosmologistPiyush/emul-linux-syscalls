/*	$NetBSD: cs4281.c,v 1.14 2002/12/23 02:58:36 tsutsui Exp $	*/

/*
 * Copyright (c) 2000 Tatoku Ogaito.  All rights reserved.
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
 *      This product includes software developed by Tatoku Ogaito
 *	for the NetBSD Project.
 * 4. The name of the author may not be used to endorse or promote products
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

/*
 * Cirrus Logic CS4281 driver.
 * Data sheets can be found
 * http://www.cirrus.com/ftp/pub/4281.pdf
 * ftp://ftp.alsa-project.org/pub/manuals/cirrus/cs4281tm.pdf
 *
 * TODO:
 *   1: midi and FM support
 *   2: ...
 *
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: cs4281.c,v 1.14 2002/12/23 02:58:36 tsutsui Exp $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/fcntl.h>
#include <sys/device.h>
#include <sys/systm.h>

#include <dev/pci/pcidevs.h>
#include <dev/pci/pcivar.h>
#include <dev/pci/cs4281reg.h>
#include <dev/pci/cs428xreg.h>

#include <sys/audioio.h>
#include <dev/audio_if.h>
#include <dev/midi_if.h>
#include <dev/mulaw.h>
#include <dev/auconv.h>

#include <dev/ic/ac97reg.h>
#include <dev/ic/ac97var.h>

#include <dev/pci/cs428x.h>

#include <machine/bus.h>

#if defined(ENABLE_SECONDARY_CODEC)
#define MAX_CHANNELS  (4)
#define MAX_FIFO_SIZE 32 /* 128/4channels */
#else
#define MAX_CHANNELS  (2)
#define MAX_FIFO_SIZE 64 /* 128/2channels */
#endif

/* IF functions for audio driver */
int	cs4281_match(struct device *, struct cfdata *, void *);
void	cs4281_attach(struct device *, struct device *, void *);
int	cs4281_intr(void *);
int	cs4281_query_encoding(void *, struct audio_encoding *);
int	cs4281_set_params(void *, int, int, struct audio_params *, struct audio_params *);
int	cs4281_halt_output(void *);
int	cs4281_halt_input(void *);
int	cs4281_getdev(void *, struct audio_device *);
int	cs4281_trigger_output(void *, void *, void *, int, void (*)(void *),
			      void *, struct audio_params *);
int	cs4281_trigger_input(void *, void *, void *, int, void (*)(void *),
			     void *, struct audio_params *);

void    cs4281_reset_codec(void *);

/* Internal functions */
u_int8_t cs4281_sr2regval(int);
void	 cs4281_set_dac_rate(struct cs428x_softc *, int);
void	 cs4281_set_adc_rate(struct cs428x_softc *, int);
int      cs4281_init(struct cs428x_softc *, int);

/* Power Management */
void cs4281_power(int, void *);

struct audio_hw_if cs4281_hw_if = {
	cs428x_open,
	cs428x_close,
	NULL,
	cs4281_query_encoding,
	cs4281_set_params,
	cs428x_round_blocksize,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	cs4281_halt_output,
	cs4281_halt_input,
	NULL,
	cs4281_getdev,
	NULL,
	cs428x_mixer_set_port,
	cs428x_mixer_get_port,
	cs428x_query_devinfo,
	cs428x_malloc,
	cs428x_free,
	cs428x_round_buffersize,
	cs428x_mappage,
	cs428x_get_props,
	cs4281_trigger_output,
	cs4281_trigger_input,
	NULL,
};

#if NMIDI > 0 && 0
/* Midi Interface */
void	cs4281_midi_close(void*);
void	cs4281_midi_getinfo(void *, struct midi_info *);
int	cs4281_midi_open(void *, int, void (*)(void *, int),
			      void (*)(void *), void *);
int	cs4281_midi_output(void *, int);

struct midi_hw_if cs4281_midi_hw_if = {
	cs4281_midi_open,
	cs4281_midi_close,
	cs4281_midi_output,
	cs4281_midi_getinfo,
	0,
};
#endif

CFATTACH_DECL(clct, sizeof(struct cs428x_softc),
    cs4281_match, cs4281_attach, NULL, NULL);

struct audio_device cs4281_device = {
	"CS4281",
	"",
	"cs4281"
};


int
cs4281_match(parent, match, aux) 
	struct device *parent;
	struct cfdata *match;
	void *aux;
{
	struct pci_attach_args *pa = (struct pci_attach_args *)aux;
	
	if (PCI_VENDOR(pa->pa_id) != PCI_VENDOR_CIRRUS)
		return 0;
	if (PCI_PRODUCT(pa->pa_id) == PCI_PRODUCT_CIRRUS_CS4281)
		return 1;
	return 0;
}

void
cs4281_attach(parent, self, aux)
	struct device *parent;
	struct device *self;
	void *aux;
{
	struct cs428x_softc *sc = (struct cs428x_softc *)self;
	struct pci_attach_args *pa = (struct pci_attach_args *)aux;
	pci_chipset_tag_t pc = pa->pa_pc;
	char const *intrstr;
	pci_intr_handle_t ih;
	pcireg_t reg;
	char devinfo[256];
	int pci_pwrmgmt_cap_reg, pci_pwrmgmt_csr_reg;

	pci_devinfo(pa->pa_id, pa->pa_class, 0, devinfo);
	printf(": %s (rev. 0x%02x)\n", devinfo, PCI_REVISION(pa->pa_class));

	/* Map I/O register */
	if (pci_mapreg_map(pa, PCI_BA0,
	    PCI_MAPREG_TYPE_MEM|PCI_MAPREG_MEM_TYPE_32BIT, 0,
	    &sc->ba0t, &sc->ba0h, NULL, NULL)) {
		printf("%s: can't map BA0 space\n", sc->sc_dev.dv_xname);
		return;
	}
	if (pci_mapreg_map(pa, PCI_BA1,
	    PCI_MAPREG_TYPE_MEM|PCI_MAPREG_MEM_TYPE_32BIT, 0,
	    &sc->ba1t, &sc->ba1h, NULL, NULL)) {
		printf("%s: can't map BA1 space\n", sc->sc_dev.dv_xname);
		return;
	}

	sc->sc_dmatag = pa->pa_dmat;

	/*
	 * Set Power State D0.
	 * Without do this, 0xffffffff is read from all registers after
	 * using Windows.
	 * On my IBM Thinkpad X20, it is set to D3 after using Windows2000.
	 */
	if (pci_get_capability(pa->pa_pc, pa->pa_tag, PCI_CAP_PWRMGMT,
			       &pci_pwrmgmt_cap_reg, 0)) {

		pci_pwrmgmt_csr_reg = pci_pwrmgmt_cap_reg + PCI_PMCSR;
		reg = pci_conf_read(pa->pa_pc, pa->pa_tag,
				    pci_pwrmgmt_csr_reg);
		if ((reg & PCI_PMCSR_STATE_MASK) != PCI_PMCSR_STATE_D0) {
			pci_conf_write(pc, pa->pa_tag, pci_pwrmgmt_csr_reg,
				       (reg & ~PCI_PMCSR_STATE_MASK) |
				       PCI_PMCSR_STATE_D0);
		}
	}

	/* Enable the device (set bus master flag) */
	reg = pci_conf_read(pa->pa_pc, pa->pa_tag, PCI_COMMAND_STATUS_REG);
	pci_conf_write(pa->pa_pc, pa->pa_tag, PCI_COMMAND_STATUS_REG,
	    reg | PCI_COMMAND_MASTER_ENABLE);

#if 0
	/* LATENCY_TIMER setting */
	temp1 = pci_conf_read(pa->pa_pc, pa->pa_tag, PCI_BHLC_REG);
	if (PCI_LATTIMER(temp1) < 32) {
		temp1 &= 0xffff00ff;
		temp1 |= 0x00002000;
		pci_conf_write(pa->pa_pc, pa->pa_tag, PCI_BHLC_REG, temp1);
	}
#endif
	
	/* Map and establish the interrupt. */
	if (pci_intr_map(pa, &ih)) { 
		printf("%s: couldn't map interrupt\n", sc->sc_dev.dv_xname);
		return;
	}
	intrstr = pci_intr_string(pc, ih);

	sc->sc_ih = pci_intr_establish(pc, ih, IPL_AUDIO, cs4281_intr, sc);
	if (sc->sc_ih == NULL) {
		printf("%s: couldn't establish interrupt", sc->sc_dev.dv_xname);
		if (intrstr != NULL)
			printf(" at %s", intrstr);
		printf("\n");
		return;
	}
	printf("%s: interrupting at %s\n", sc->sc_dev.dv_xname, intrstr);

	/*
	 * Sound System start-up
	 */
	if (cs4281_init(sc, 1) != 0)
		return;

	sc->type = TYPE_CS4281;
	sc->halt_input  = cs4281_halt_input;
	sc->halt_output = cs4281_halt_output;

	sc->dma_size     = CS4281_BUFFER_SIZE / MAX_CHANNELS;
	sc->dma_align    = 0x10;
	sc->hw_blocksize = sc->dma_size / 2;
	
	/* AC 97 attachment */
	sc->host_if.arg = sc;
	sc->host_if.attach = cs428x_attach_codec;
	sc->host_if.read   = cs428x_read_codec;
	sc->host_if.write  = cs428x_write_codec;
	sc->host_if.reset  = cs4281_reset_codec;
	if (ac97_attach(&sc->host_if) != 0) {
		printf("%s: ac97_attach failed\n", sc->sc_dev.dv_xname);
		return;
	}
	audio_attach_mi(&cs4281_hw_if, sc, &sc->sc_dev);

#if NMIDI > 0 && 0
	midi_attach_mi(&cs4281_midi_hw_if, sc, &sc->sc_dev);
#endif

	sc->sc_suspend = PWR_RESUME;
	sc->sc_powerhook = powerhook_establish(cs4281_power, sc);
}

int
cs4281_intr(p)
	void *p;
{
	struct cs428x_softc *sc = p;
	u_int32_t intr, hdsr0, hdsr1;
	char *empty_dma;
	int handled = 0;

	hdsr0 = 0;
	hdsr1 = 0;
	
	/* grab interrupt register */
	intr = BA0READ4(sc, CS4281_HISR);

	DPRINTF(("cs4281_intr:"));
	/* not for me */
	if ((intr & HISR_INTENA) == 0) {
		/* clear the interrupt register */
		BA0WRITE4(sc, CS4281_HICR, HICR_CHGM | HICR_IEV);
		return 0;
	}

	if (intr & HISR_DMA0)
		hdsr0 = BA0READ4(sc, CS4281_HDSR0); /* clear intr condition */
	if (intr & HISR_DMA1)
		hdsr1 = BA0READ4(sc, CS4281_HDSR1); /* clear intr condition */
	/* clear the interrupt register */
	BA0WRITE4(sc, CS4281_HICR, HICR_CHGM | HICR_IEV);
	
	DPRINTF(("intr = 0x%08x, hdsr0 = 0x%08x hdsr1 = 0x%08x\n",
		 intr, hdsr0, hdsr1));
	
	/* Playback Interrupt */
	if (intr & HISR_DMA0) {
		handled = 1;
		DPRINTF((" PB DMA 0x%x(%d)", (int)BA0READ4(sc, CS4281_DCA0),
			 (int)BA0READ4(sc, CS4281_DCC0)));
		if (sc->sc_pintr) {
			if ((sc->sc_pi%sc->sc_pcount) == 0)
				sc->sc_pintr(sc->sc_parg);
		} else {
			printf("unexpected play intr\n");
		}
		/* copy buffer */
		++sc->sc_pi;
		empty_dma = sc->sc_pdma->addr;
		if (sc->sc_pi&1)
			empty_dma += sc->hw_blocksize;
		memcpy(empty_dma, sc->sc_pn, sc->hw_blocksize);
		sc->sc_pn += sc->hw_blocksize;
		if (sc->sc_pn >= sc->sc_pe)
			sc->sc_pn = sc->sc_ps;
	}
	if (intr & HISR_DMA1) {
		handled = 1;
		/* copy from dma */
		DPRINTF((" CP DMA 0x%x(%d)", (int)BA0READ4(sc, CS4281_DCA1),
			 (int)BA0READ4(sc, CS4281_DCC1)));
		++sc->sc_ri;
		empty_dma = sc->sc_rdma->addr;
		if ((sc->sc_ri & 1) == 0)
			empty_dma += sc->hw_blocksize;
		memcpy(sc->sc_rn, empty_dma, sc->hw_blocksize);
		if (sc->sc_rn >= sc->sc_re)
			sc->sc_rn = sc->sc_rs;
		if (sc->sc_rintr) {
			if ((sc->sc_ri % sc->sc_rcount) == 0)
				sc->sc_rintr(sc->sc_rarg);
		} else {
			printf("unexpected record intr\n");
		}
	}
	DPRINTF(("\n"));

	return handled;
}

int
cs4281_query_encoding(addr, fp)
	void *addr;
	struct audio_encoding *fp;
{

	switch (fp->index) {
	case 0:
		strcpy(fp->name, AudioEulinear);
		fp->encoding = AUDIO_ENCODING_ULINEAR;
		fp->precision = 8;
		fp->flags = 0;
		break;
	case 1:
		strcpy(fp->name, AudioEmulaw);
		fp->encoding = AUDIO_ENCODING_ULAW;
		fp->precision = 8;
		fp->flags = AUDIO_ENCODINGFLAG_EMULATED;
		break;
	case 2:
		strcpy(fp->name, AudioEalaw);
		fp->encoding = AUDIO_ENCODING_ALAW;
		fp->precision = 8;
		fp->flags = AUDIO_ENCODINGFLAG_EMULATED;
		break;
	case 3:
		strcpy(fp->name, AudioEslinear);
		fp->encoding = AUDIO_ENCODING_SLINEAR;
		fp->precision = 8;
		fp->flags = 0;
		break;
	case 4:
		strcpy(fp->name, AudioEslinear_le);
		fp->encoding = AUDIO_ENCODING_SLINEAR_LE;
		fp->precision = 16;
		fp->flags = 0;
		break;
	case 5:
		strcpy(fp->name, AudioEulinear_le);
		fp->encoding = AUDIO_ENCODING_ULINEAR_LE;
		fp->precision = 16;
		fp->flags = 0;
		break;
	case 6:
		strcpy(fp->name, AudioEslinear_be);
		fp->encoding = AUDIO_ENCODING_SLINEAR_BE;
		fp->precision = 16;
		fp->flags = 0;
		break;
	case 7:
		strcpy(fp->name, AudioEulinear_be);
		fp->encoding = AUDIO_ENCODING_ULINEAR_BE;
		fp->precision = 16;
		fp->flags = 0;
		break;
	default:
		return EINVAL;
	}
	return 0;
}

int
cs4281_set_params(addr, setmode, usemode, play, rec)
	void *addr;
	int setmode, usemode;
	struct audio_params *play, *rec;
{
	struct cs428x_softc *sc = addr;
	struct audio_params *p;
	int mode;

	for (mode = AUMODE_RECORD; mode != -1;
	    mode = mode == AUMODE_RECORD ? AUMODE_PLAY : -1) {
		if ((setmode & mode) == 0)
			continue;
		
		p = mode == AUMODE_PLAY ? play : rec;
		
		if (p == play) {
			DPRINTFN(5, ("play: sample=%ld precision=%d channels=%d\n",
				p->sample_rate, p->precision, p->channels));
			if (p->sample_rate < 6023 || p->sample_rate > 48000 ||
			    (p->precision != 8 && p->precision != 16) ||
			    (p->channels != 1  && p->channels != 2)) {
				return (EINVAL);
			}
		} else {
			DPRINTFN(5, ("rec: sample=%ld precision=%d channels=%d\n",
				p->sample_rate, p->precision, p->channels));
			if (p->sample_rate < 6023 || p->sample_rate > 48000 ||
			    (p->precision != 8 && p->precision != 16) ||
			    (p->channels != 1 && p->channels != 2)) {
				return (EINVAL);
			}
		}
		p->factor  = 1;
		p->sw_code = 0;

		switch (p->encoding) {
		case AUDIO_ENCODING_SLINEAR_BE:
			break;
		case AUDIO_ENCODING_SLINEAR_LE:
			break;
		case AUDIO_ENCODING_ULINEAR_BE:
			break;
		case AUDIO_ENCODING_ULINEAR_LE:
			break;
		case AUDIO_ENCODING_ULAW:
			if (mode == AUMODE_PLAY) {
				p->sw_code = mulaw_to_slinear8;
			} else {
				p->sw_code = slinear8_to_mulaw;
			}
			break;
		case AUDIO_ENCODING_ALAW:
			if (mode == AUMODE_PLAY) {
				p->sw_code = alaw_to_slinear8;
			} else {
				p->sw_code = slinear8_to_alaw;
			}
			break;
		default:
			return (EINVAL);
		}
	}

	/* set sample rate */
	cs4281_set_dac_rate(sc, play->sample_rate);
	cs4281_set_adc_rate(sc, rec->sample_rate);
	return 0;
}

int
cs4281_halt_output(addr)
	void *addr;
{
	struct cs428x_softc *sc = addr;
	
	BA0WRITE4(sc, CS4281_DCR0, BA0READ4(sc, CS4281_DCR0) | DCRn_MSK);
	sc->sc_prun = 0;
	return 0;
}

int
cs4281_halt_input(addr)
	void *addr;
{
	struct cs428x_softc *sc = addr;

	BA0WRITE4(sc, CS4281_DCR1, BA0READ4(sc, CS4281_DCR1) | DCRn_MSK);
	sc->sc_rrun = 0;
	return 0;
}

int
cs4281_getdev(addr, retp)
     void *addr;
     struct audio_device *retp;
{

	*retp = cs4281_device;
	return 0;
}

int
cs4281_trigger_output(addr, start, end, blksize, intr, arg, param)
	void *addr;
	void *start, *end;
	int blksize;
	void (*intr) __P((void *));
	void *arg;
	struct audio_params *param;
{
	struct cs428x_softc *sc = addr;
	u_int32_t fmt=0;
	struct cs428x_dma *p;
	int dma_count;

#ifdef DIAGNOSTIC
	if (sc->sc_prun)
		printf("cs4281_trigger_output: already running\n");
#endif
	sc->sc_prun = 1;

	DPRINTF(("cs4281_trigger_output: sc=%p start=%p end=%p "
		 "blksize=%d intr=%p(%p)\n", addr, start, end, blksize, intr, arg));
	sc->sc_pintr = intr;
	sc->sc_parg  = arg;

	/* stop playback DMA */
	BA0WRITE4(sc, CS4281_DCR0, BA0READ4(sc, CS4281_DCR0) | DCRn_MSK);

	DPRINTF(("param: precision=%d  factor=%d channels=%d encoding=%d\n",
	       param->precision, param->factor, param->channels,
	       param->encoding));
	for (p = sc->sc_dmas; p != NULL && BUFADDR(p) != start; p = p->next)
		;
	if (p == NULL) {
		printf("cs4281_trigger_output: bad addr %p\n", start);
		return (EINVAL);
	}

	sc->sc_pcount = blksize / sc->hw_blocksize;
	sc->sc_ps = (char *)start;
	sc->sc_pe = (char *)end;
	sc->sc_pdma = p;
	sc->sc_pbuf = KERNADDR(p);
	sc->sc_pi = 0;
	sc->sc_pn = sc->sc_ps;
	if (blksize >= sc->dma_size) {
		sc->sc_pn = sc->sc_ps + sc->dma_size;
		memcpy(sc->sc_pbuf, start, sc->dma_size);
		++sc->sc_pi;
	} else {
		sc->sc_pn = sc->sc_ps + sc->hw_blocksize;
		memcpy(sc->sc_pbuf, start, sc->hw_blocksize);
	}

	dma_count = sc->dma_size;
	if (param->precision * param->factor != 8)
		dma_count /= 2;   /* 16 bit */
	if (param->channels > 1)
		dma_count /= 2;   /* Stereo */

	DPRINTF(("cs4281_trigger_output: DMAADDR(p)=0x%x count=%d\n",
		 (int)DMAADDR(p), dma_count));
	BA0WRITE4(sc, CS4281_DBA0, DMAADDR(p));
	BA0WRITE4(sc, CS4281_DBC0, dma_count-1);

	/* set playback format */
	fmt = BA0READ4(sc, CS4281_DMR0) & ~DMRn_FMTMSK;
	if (param->precision * param->factor == 8)
		fmt |= DMRn_SIZE8;
	if (param->channels == 1)
		fmt |= DMRn_MONO;
	if (param->encoding == AUDIO_ENCODING_ULINEAR_BE ||
	    param->encoding == AUDIO_ENCODING_SLINEAR_BE)
		fmt |= DMRn_BEND;
	if (param->encoding == AUDIO_ENCODING_ULINEAR_BE ||
	    param->encoding == AUDIO_ENCODING_ULINEAR_LE)
		fmt |= DMRn_USIGN;
	BA0WRITE4(sc, CS4281_DMR0, fmt);

	/* set sample rate */
	sc->sc_prate = param->sample_rate;
	cs4281_set_dac_rate(sc, param->sample_rate);

	/* start DMA */
	BA0WRITE4(sc, CS4281_DCR0, BA0READ4(sc, CS4281_DCR0) & ~DCRn_MSK);
	/* Enable interrupts */
	BA0WRITE4(sc, CS4281_HICR, HICR_IEV | HICR_CHGM);

	DPRINTF(("HICR =0x%08x(expected 0x00000001)\n", BA0READ4(sc, CS4281_HICR)));
	DPRINTF(("HIMR =0x%08x(expected 0x00f0fc3f)\n", BA0READ4(sc, CS4281_HIMR)));
	DPRINTF(("DMR0 =0x%08x(expected 0x2???0018)\n", BA0READ4(sc, CS4281_DMR0)));
	DPRINTF(("DCR0 =0x%08x(expected 0x00030000)\n", BA0READ4(sc, CS4281_DCR0)));
	DPRINTF(("FCR0 =0x%08x(expected 0x81000f00)\n", BA0READ4(sc, CS4281_FCR0)));
	DPRINTF(("DACSR=0x%08x(expected 1 for 44kHz 5 for 8kHz)\n",
		 BA0READ4(sc, CS4281_DACSR)));
	DPRINTF(("SRCSA=0x%08x(expected 0x0b0a0100)\n", BA0READ4(sc, CS4281_SRCSA)));
	DPRINTF(("SSPM&SSPM_PSRCEN =0x%08x(expected 0x00000010)\n",
		 BA0READ4(sc, CS4281_SSPM) & SSPM_PSRCEN));

	return 0;
}

int
cs4281_trigger_input(addr, start, end, blksize, intr, arg, param)
	void *addr;
	void *start, *end;
	int blksize;
	void (*intr) __P((void *));
	void *arg;
	struct audio_params *param;
{
	struct cs428x_softc *sc = addr;
	struct cs428x_dma *p;
	u_int32_t fmt=0;
	int dma_count;

#ifdef DIAGNOSTIC
	if (sc->sc_rrun)
		printf("cs4281_trigger_input: already running\n");
#endif
	sc->sc_rrun = 1;
	DPRINTF(("cs4281_trigger_input: sc=%p start=%p end=%p "
	    "blksize=%d intr=%p(%p)\n", addr, start, end, blksize, intr, arg));
	sc->sc_rintr = intr;
	sc->sc_rarg  = arg;

	/* stop recording DMA */
	BA0WRITE4(sc, CS4281_DCR1, BA0READ4(sc, CS4281_DCR1) | DCRn_MSK);

	for (p = sc->sc_dmas; p && BUFADDR(p) != start; p = p->next)
		;
	if (!p) {
		printf("cs4281_trigger_input: bad addr %p\n", start);
		return (EINVAL);
	}

	sc->sc_rcount = blksize / sc->hw_blocksize;
	sc->sc_rs = (char *)start;
	sc->sc_re = (char *)end;
	sc->sc_rdma = p;
	sc->sc_rbuf = KERNADDR(p);
	sc->sc_ri = 0;
	sc->sc_rn = sc->sc_rs;

	dma_count = sc->dma_size;
	if (param->precision * param->factor == 8)
		dma_count /= 2;
	if (param->channels > 1)
		dma_count /= 2;

	DPRINTF(("cs4281_trigger_input: DMAADDR(p)=0x%x count=%d\n",
		 (int)DMAADDR(p), dma_count));
	BA0WRITE4(sc, CS4281_DBA1, DMAADDR(p));
	BA0WRITE4(sc, CS4281_DBC1, dma_count-1);

	/* set recording format */
	fmt = BA0READ4(sc, CS4281_DMR1) & ~DMRn_FMTMSK;
	if (param->precision * param->factor == 8)
		fmt |= DMRn_SIZE8;
	if (param->channels == 1)
		fmt |= DMRn_MONO;
	if (param->encoding == AUDIO_ENCODING_ULINEAR_BE ||
	    param->encoding == AUDIO_ENCODING_SLINEAR_BE)
		fmt |= DMRn_BEND;
	if (param->encoding == AUDIO_ENCODING_ULINEAR_BE ||
	    param->encoding == AUDIO_ENCODING_ULINEAR_LE)
		fmt |= DMRn_USIGN;
	BA0WRITE4(sc, CS4281_DMR1, fmt);

	/* set sample rate */
	sc->sc_rrate = param->sample_rate;
	cs4281_set_adc_rate(sc, param->sample_rate);

	/* Start DMA */
	BA0WRITE4(sc, CS4281_DCR1, BA0READ4(sc, CS4281_DCR1) & ~DCRn_MSK);
	/* Enable interrupts */
	BA0WRITE4(sc, CS4281_HICR, HICR_IEV | HICR_CHGM);

	DPRINTF(("HICR=0x%08x\n", BA0READ4(sc, CS4281_HICR)));
	DPRINTF(("HIMR=0x%08x\n", BA0READ4(sc, CS4281_HIMR)));
	DPRINTF(("DMR1=0x%08x\n", BA0READ4(sc, CS4281_DMR1)));
	DPRINTF(("DCR1=0x%08x\n", BA0READ4(sc, CS4281_DCR1)));

	return 0;
}

/* Power Hook */
void
cs4281_power(why, v)
	int why;
	void *v;
{
	struct cs428x_softc *sc = (struct cs428x_softc *)v;
	static u_int32_t dba0 = 0, dbc0 = 0, dmr0 = 0, dcr0 = 0;
	static u_int32_t dba1 = 0, dbc1 = 0, dmr1 = 0, dcr1 = 0;

	DPRINTF(("%s: cs4281_power why=%d\n", sc->sc_dev.dv_xname, why));
	switch (why) {
	case PWR_SUSPEND:
	case PWR_STANDBY:
		sc->sc_suspend = why;

		/* save current playback status */
		if (sc->sc_prun) {
			dcr0 = BA0READ4(sc, CS4281_DCR0);
			dmr0 = BA0READ4(sc, CS4281_DMR0);
			dbc0 = BA0READ4(sc, CS4281_DBC0);
			dba0 = BA0READ4(sc, CS4281_DBA0);
		}

		/* save current capture status */
		if (sc->sc_rrun) {
			dcr1 = BA0READ4(sc, CS4281_DCR1);
			dmr1 = BA0READ4(sc, CS4281_DMR1);
			dbc1 = BA0READ4(sc, CS4281_DBC1);
			dba1 = BA0READ4(sc, CS4281_DBA1);
		}
		/* Stop DMA */
		BA0WRITE4(sc, CS4281_DCR0, BA0READ4(sc, CS4281_DCR0) | DCRn_MSK);
		BA0WRITE4(sc, CS4281_DCR1, BA0READ4(sc, CS4281_DCR1) | DCRn_MSK);
		break;
	case PWR_RESUME:
		if (sc->sc_suspend == PWR_RESUME) {
			printf("cs4281_power: odd, resume without suspend.\n");
			sc->sc_suspend = why;
			return;
		}
		sc->sc_suspend = why;
		cs4281_init(sc, 0);
		cs4281_reset_codec(sc);

		/* restore ac97 registers */
		(*sc->codec_if->vtbl->restore_ports)(sc->codec_if);

		/* restore DMA related status */
		if (sc->sc_prun) {
			cs4281_set_dac_rate(sc, sc->sc_prate);
			BA0WRITE4(sc, CS4281_DBA0, dba0);
			BA0WRITE4(sc, CS4281_DBC0, dbc0);
			BA0WRITE4(sc, CS4281_DMR0, dmr0);
			BA0WRITE4(sc, CS4281_DCR0, dcr0);
		}
		if (sc->sc_rrun) {
			cs4281_set_adc_rate(sc, sc->sc_rrate);
			BA0WRITE4(sc, CS4281_DBA1, dba1);
			BA0WRITE4(sc, CS4281_DBC1, dbc1);
			BA0WRITE4(sc, CS4281_DMR1, dmr1);
			BA0WRITE4(sc, CS4281_DCR1, dcr1);
		}
		/* enable intterupts */
		if (sc->sc_prun || sc->sc_rrun)
			BA0WRITE4(sc, CS4281_HICR, HICR_IEV | HICR_CHGM);
		break;
	case PWR_SOFTSUSPEND:
	case PWR_SOFTSTANDBY:
	case PWR_SOFTRESUME:
		break;
	}
}

/* control AC97 codec */
void
cs4281_reset_codec(void *addr)
{
	struct cs428x_softc *sc;
	u_int16_t data;
	u_int32_t dat32;
	int n;

	sc = addr;

	DPRINTFN(3, ("cs4281_reset_codec\n"));

	/* Reset codec */
	BA0WRITE4(sc, CS428X_ACCTL, 0);
	delay(50);    /* delay 50us */

	BA0WRITE4(sc, CS4281_SPMC, 0);
	delay(100);	/* delay 100us */
	BA0WRITE4(sc, CS4281_SPMC, SPMC_RSTN);
#if defined(ENABLE_SECONDARY_CODEC)
	BA0WRITE4(sc, CS4281_SPMC, SPMC_RSTN | SPCM_ASDIN2E);
	BA0WRITE4(sc, CS4281_SERMC, SERMC_TCID);
#endif
	delay(50000);   /* XXX: delay 50ms */

	/* Enable ASYNC generation */
	BA0WRITE4(sc, CS428X_ACCTL, ACCTL_ESYN);

	/* Wait for codec ready. Linux driver waits 50ms here */
	n = 0;
	while ((BA0READ4(sc, CS428X_ACSTS) & ACSTS_CRDY) == 0) {
		delay(100);
		if (++n > 1000) {
			printf("reset_codec: AC97 codec ready timeout\n");
			return;
		}
	}
#if defined(ENABLE_SECONDARY_CODEC)
	/* secondary codec ready*/
	n = 0;
	while ((BA0READ4(sc, CS4281_ACSTS2) & ACSTS2_CRDY2) == 0) {
		delay(100);
		if (++n > 1000)
			return;
	}
#endif
	/* Set the serial timing configuration */
	/* XXX: undocumented but the Linux driver do this */
	BA0WRITE4(sc, CS4281_SERMC, SERMC_PTCAC97);
	
	/* Wait for codec ready signal */
	n = 0;
	do {
		delay(1000);
		if (++n > 1000) {
			printf("%s: timeout waiting for codec ready\n",
			       sc->sc_dev.dv_xname);
			return;
		}
		dat32 = BA0READ4(sc, CS428X_ACSTS) & ACSTS_CRDY;
	} while (dat32 == 0);

	/* Enable Valid Frame output on ASDOUT */
	BA0WRITE4(sc, CS428X_ACCTL, ACCTL_ESYN | ACCTL_VFRM);
	
	/* Wait until codec calibration is finished. Codec register 26h */
	n = 0;
	do {
		delay(1);
		if (++n > 1000) {
			printf("%s: timeout waiting for codec calibration\n",
			       sc->sc_dev.dv_xname);
			return ;
		}
		cs428x_read_codec(sc, AC97_REG_POWER, &data);
	} while ((data & 0x0f) != 0x0f);

	/* Set the serial timing configuration again */
	/* XXX: undocumented but the Linux driver do this */
	BA0WRITE4(sc, CS4281_SERMC, SERMC_PTCAC97);

	/* Wait until we've sampled input slots 3 & 4 as valid */
	n = 0;
	do {
		delay(1000);
		if (++n > 1000) {
			printf("%s: timeout waiting for sampled input slots as valid\n",
			       sc->sc_dev.dv_xname);
			return;
		}
		dat32 = BA0READ4(sc, CS428X_ACISV) & (ACISV_ISV3 | ACISV_ISV4) ;
	} while (dat32 != (ACISV_ISV3 | ACISV_ISV4));
	
	/* Start digital data transfer of audio data to the codec */
	BA0WRITE4(sc, CS428X_ACOSV, (ACOSV_SLV3 | ACOSV_SLV4));
}


/* Internal functions */

/* convert sample rate to register value */
u_int8_t
cs4281_sr2regval(rate)
     int rate;
{
	u_int8_t retval;

	/* We don't have to change here. but anyway ... */
	if (rate > 48000)
		rate = 48000;
	if (rate < 6023)
		rate = 6023;

	switch (rate) {
	case 8000:
		retval = 5;
		break;
	case 11025:
		retval = 4;
		break;
	case 16000:
		retval = 3;
		break;
	case 22050:
		retval = 2;
		break;
	case 44100:
		retval = 1;
		break;
	case 48000:
		retval = 0;
		break;
	default:
		retval = 1536000/rate; /* == 24576000/(rate*16) */
	}
	return retval;
}

void
cs4281_set_adc_rate(sc, rate)
	struct cs428x_softc *sc;
	int rate;
{

	BA0WRITE4(sc, CS4281_ADCSR, cs4281_sr2regval(rate));
}

void
cs4281_set_dac_rate(sc, rate)
	struct cs428x_softc *sc;
	int rate;
{

	BA0WRITE4(sc, CS4281_DACSR, cs4281_sr2regval(rate));
}

int
cs4281_init(sc, init)
     struct cs428x_softc *sc;
     int init;
{
	int n;
	u_int16_t data;
	u_int32_t dat32;

	/* set "Configuration Write Protect" register to
	 * 0x4281 to allow to write */
	BA0WRITE4(sc, CS4281_CWPR, 0x4281);

	/*
	 * Unset "Full Power-Down bit of Extended PCI Power Management
	 * Control" register to release the reset state.
	 */
	dat32 = BA0READ4(sc, CS4281_EPPMC);
	if (dat32 & EPPMC_FPDN) {
		BA0WRITE4(sc, CS4281_EPPMC, dat32 & ~EPPMC_FPDN);
	}

	/* Start PLL out in known state */
	BA0WRITE4(sc, CS4281_CLKCR1, 0);
	/* Start serial ports out in known state */
	BA0WRITE4(sc, CS4281_SERMC, 0);
	
	/* Reset codec */
	BA0WRITE4(sc, CS428X_ACCTL, 0);
	delay(50);	/* delay 50us */

	BA0WRITE4(sc, CS4281_SPMC, 0);
	delay(100);	/* delay 100us */
	BA0WRITE4(sc, CS4281_SPMC, SPMC_RSTN);
#if defined(ENABLE_SECONDARY_CODEC)
	BA0WRITE4(sc, CS4281_SPMC, SPMC_RSTN | SPCM_ASDIN2E);
	BA0WRITE4(sc, CS4281_SERMC, SERMC_TCID);
#endif
	delay(50000);   /* XXX: delay 50ms */

	/* Turn on Sound System clocks based on ABITCLK */
	BA0WRITE4(sc, CS4281_CLKCR1, CLKCR1_DLLP);
	delay(50000);   /* XXX: delay 50ms */
	BA0WRITE4(sc, CS4281_CLKCR1, CLKCR1_SWCE | CLKCR1_DLLP);

	/* Set enables for sections that are needed in the SSPM registers */
	BA0WRITE4(sc, CS4281_SSPM,
		  SSPM_MIXEN |		/* Mixer */
		  SSPM_CSRCEN |		/* Capture SRC */
		  SSPM_PSRCEN |		/* Playback SRC */
		  SSPM_JSEN |		/* Joystick */
		  SSPM_ACLEN |		/* AC LINK */
		  SSPM_FMEN		/* FM */
		  );

	/* Wait for clock stabilization */
	n = 0;
#if 1
	/* what document says */
	while ((BA0READ4(sc, CS4281_CLKCR1)& (CLKCR1_DLLRDY | CLKCR1_CLKON))
		 != (CLKCR1_DLLRDY | CLKCR1_CLKON)) {
		delay(100);
		if (++n > 1000) {
			printf("%s: timeout waiting for clock stabilization\n",
			       sc->sc_dev.dv_xname);
			return -1;
		}
	}
#else
	/* Cirrus driver for Linux does */
	while (!(BA0READ4(sc, CS4281_CLKCR1) & CLKCR1_DLLRDY)) {
		delay(1000);
		if (++n > 1000) {
			printf("%s: timeout waiting for clock stabilization\n",
			       sc->sc_dev.dv_xname);
			return -1;
		}
	}
#endif

	/* Enable ASYNC generation */
	BA0WRITE4(sc, CS428X_ACCTL, ACCTL_ESYN);

	/* Wait for codec ready. Linux driver waits 50ms here */
	n = 0;
	while ((BA0READ4(sc, CS428X_ACSTS) & ACSTS_CRDY) == 0) {
		delay(100);
		if (++n > 1000) {
			printf("%s: timeout waiting for codec ready\n",
			       sc->sc_dev.dv_xname);
			return -1;
		}
	}

#if defined(ENABLE_SECONDARY_CODEC)
	/* secondary codec ready*/
	n = 0;
	while ((BA0READ4(sc, CS4281_ACSTS2) & ACSTS2_CRDY2) == 0) {
		delay(100);
		if (++n > 1000) {
			printf("%s: timeout waiting for secondary codec ready\n",
			       sc->sc_dev.dv_xname);
			return -1;
		}
	}
#endif

	/* Set the serial timing configuration */
	/* XXX: undocumented but the Linux driver do this */
	BA0WRITE4(sc, CS4281_SERMC, SERMC_PTCAC97);
	
	/* Wait for codec ready signal */
	n = 0;
	do {
		delay(1000);
		if (++n > 1000) {
			printf("%s: timeout waiting for codec ready\n",
			       sc->sc_dev.dv_xname);
			return -1;
		}
		dat32 = BA0READ4(sc, CS428X_ACSTS) & ACSTS_CRDY;
	} while (dat32 == 0);

	/* Enable Valid Frame output on ASDOUT */
	BA0WRITE4(sc, CS428X_ACCTL, ACCTL_ESYN | ACCTL_VFRM);
	
	/* Wait until codec calibration is finished. codec register 26h */
	n = 0;
	do {
		delay(1);
		if (++n > 1000) {
			printf("%s: timeout waiting for codec calibration\n",
			       sc->sc_dev.dv_xname);
			return -1;
		}
		cs428x_read_codec(sc, AC97_REG_POWER, &data);
	} while ((data & 0x0f) != 0x0f);

	/* Set the serial timing configuration again */
	/* XXX: undocumented but the Linux driver do this */
	BA0WRITE4(sc, CS4281_SERMC, SERMC_PTCAC97);

	/* Wait until we've sampled input slots 3 & 4 as valid */
	n = 0;
	do {
		delay(1000);
		if (++n > 1000) {
			printf("%s: timeout waiting for sampled input slots as valid\n",
			       sc->sc_dev.dv_xname);
			return -1;
		}
		dat32 = BA0READ4(sc, CS428X_ACISV) & (ACISV_ISV3 | ACISV_ISV4);
	} while (dat32 != (ACISV_ISV3 | ACISV_ISV4));
	
	/* Start digital data transfer of audio data to the codec */
	BA0WRITE4(sc, CS428X_ACOSV, (ACOSV_SLV3 | ACOSV_SLV4));
	
	cs428x_write_codec(sc, AC97_REG_HEADPHONE_VOLUME, 0);
	cs428x_write_codec(sc, AC97_REG_MASTER_VOLUME, 0);
	
	/* Power on the DAC */
	cs428x_read_codec(sc, AC97_REG_POWER, &data);
	cs428x_write_codec(sc, AC97_REG_POWER, data & 0xfdff);

	/* Wait until we sample a DAC ready state.
	 * Not documented, but Linux driver does.
	 */
	for (n = 0; n < 32; ++n) {
		delay(1000);
		cs428x_read_codec(sc, AC97_REG_POWER, &data);
		if (data & 0x02)
			break;
	}
	
	/* Power on the ADC */
	cs428x_read_codec(sc, AC97_REG_POWER, &data);
	cs428x_write_codec(sc, AC97_REG_POWER, data & 0xfeff);

	/* Wait until we sample ADC ready state.
	 * Not documented, but Linux driver does.
	 */
	for (n = 0; n < 32; ++n) {
		delay(1000);
		cs428x_read_codec(sc, AC97_REG_POWER, &data);
		if (data & 0x01)
			break;
	}
	
#if 0
	/* Initialize AC-Link features */
	/* variable sample-rate support */
	mem = BA0READ4(sc, CS4281_SERMC);
	mem |=  (SERMC_ODSEN1 | SERMC_ODSEN2);
	BA0WRITE4(sc, CS4281_SERMC, mem);
	/* XXX: more... */
	
	/* Initialize SSCR register features */
	/* XXX: hardware volume setting */
	BA0WRITE4(sc, CS4281_SSCR, ~SSCR_HVC); /* disable HW volume setting */
#endif

	/* disable Sound Blaster Pro emulation */
	/* XXX: 
	 * Cannot set since the documents does not describe which bit is
	 * correspond to SSCR_SB. Since the reset value of SSCR is 0,
	 * we can ignore it.*/
#if 0
	BA0WRITE4(sc, CS4281_SSCR, SSCR_SB);
#endif

	/* map AC97 PCM playback to DMA Channel 0 */
	/* Reset FEN bit to setup first */
	BA0WRITE4(sc, CS4281_FCR0, (BA0READ4(sc, CS4281_FCR0) & ~FCRn_FEN));
	/*
	 *| RS[4:0]/|        |
	 *| LS[4:0] |  AC97  | Slot Function
	 *|---------+--------+--------------------
	 *|     0   |    3   | Left PCM Playback
	 *|     1   |    4   | Right PCM Playback
	 *|     2   |    5   | Phone Line 1 DAC
	 *|     3   |    6   | Center PCM Playback
	 *....
	 *  quoted from Table 29(p109)
	 */
	dat32 = 0x01 << 24 |   /* RS[4:0] =  1 see above */
		0x00 << 16 |   /* LS[4:0] =  0 see above */
		0x0f <<  8 |   /* SZ[6:0] = 15 size of buffer */
		0x00 <<  0 ;   /* OF[6:0] =  0 offset */
	BA0WRITE4(sc, CS4281_FCR0, dat32);
	BA0WRITE4(sc, CS4281_FCR0, dat32 | FCRn_FEN);

	/* map AC97 PCM record to DMA Channel 1 */
	/* Reset FEN bit to setup first */
	BA0WRITE4(sc, CS4281_FCR1, (BA0READ4(sc, CS4281_FCR1) & ~FCRn_FEN));
	/*
	 *| RS[4:0]/|
	 *| LS[4:0] | AC97 | Slot Function
	 *|---------+------+-------------------
	 *|   10    |   3  | Left PCM Record
	 *|   11    |   4  | Right PCM Record
	 *|   12    |   5  | Phone Line 1 ADC
	 *|   13    |   6  | Mic ADC
	 *....
	 * quoted from Table 30(p109)
	 */
	dat32 = 0x0b << 24 |    /* RS[4:0] = 11 See above */
		0x0a << 16 |    /* LS[4:0] = 10 See above */
		0x0f <<  8 |    /* SZ[6:0] = 15 Size of buffer */
		0x10 <<  0 ;    /* OF[6:0] = 16 offset */

	/* XXX: I cannot understand why FCRn_PSH is needed here. */
	BA0WRITE4(sc, CS4281_FCR1, dat32 | FCRn_PSH);
	BA0WRITE4(sc, CS4281_FCR1, dat32 | FCRn_FEN);

#if 0
	/* Disable DMA Channel 2, 3 */
	BA0WRITE4(sc, CS4281_FCR2, (BA0READ4(sc, CS4281_FCR2) & ~FCRn_FEN));
	BA0WRITE4(sc, CS4281_FCR3, (BA0READ4(sc, CS4281_FCR3) & ~FCRn_FEN));
#endif

	/* Set the SRC Slot Assignment accordingly */
	/*| PLSS[4:0]/
	 *| PRSS[4:0] | AC97 | Slot Function
	 *|-----------+------+----------------
	 *|     0     |  3   | Left PCM Playback
	 *|     1     |  4   | Right PCM Playback
	 *|     2     |  5   | phone line 1 DAC
	 *|     3     |  6   | Center PCM Playback
	 *|     4     |  7   | Left Surround PCM Playback
	 *|     5     |  8   | Right Surround PCM Playback
	 *......
	 *
	 *| CLSS[4:0]/
	 *| CRSS[4:0] | AC97 | Codec |Slot Function
	 *|-----------+------+-------+-----------------
	 *|    10     |   3  |Primary| Left PCM Record
	 *|    11     |   4  |Primary| Right PCM Record
	 *|    12     |   5  |Primary| Phone Line 1 ADC
	 *|    13     |   6  |Primary| Mic ADC
	 *|.....
	 *|    20     |   3  |  Sec. | Left PCM Record
	 *|    21     |   4  |  Sec. | Right PCM Record
	 *|    22     |   5  |  Sec. | Phone Line 1 ADC
	 *|    23     |   6  |  Sec. | Mic ADC
	 */
	dat32 = 0x0b << 24 |   /* CRSS[4:0] Right PCM Record(primary) */
		0x0a << 16 |   /* CLSS[4:0] Left  PCM Record(primary) */
		0x01 <<  8 |   /* PRSS[4:0] Right PCM Playback */
		0x00 <<  0;    /* PLSS[4:0] Left  PCM Playback */
	BA0WRITE4(sc, CS4281_SRCSA, dat32);
	
	/* Set interrupt to occurred at Half and Full terminal
	 * count interrupt enable for DMA channel 0 and 1.
	 * To keep DMA stop, set MSK.
	 */
	dat32 = DCRn_HTCIE | DCRn_TCIE | DCRn_MSK;
	BA0WRITE4(sc, CS4281_DCR0, dat32);
	BA0WRITE4(sc, CS4281_DCR1, dat32);
	
	/* Set Auto-Initialize Contorl enable */
	BA0WRITE4(sc, CS4281_DMR0,
		  DMRn_DMA | DMRn_AUTO | DMRn_TR_READ);
	BA0WRITE4(sc, CS4281_DMR1,
		  DMRn_DMA | DMRn_AUTO | DMRn_TR_WRITE);

	/* Clear DMA Mask in HIMR */
	dat32 = ~HIMR_DMAIM & ~HIMR_D1IM & ~HIMR_D0IM;
	BA0WRITE4(sc, CS4281_HIMR,
		  BA0READ4(sc, CS4281_HIMR) & dat32);

	/* set current status */
	if (init != 0) {
		sc->sc_prun = 0;
		sc->sc_rrun = 0;
	}

	/* setup playback volume */
	BA0WRITE4(sc, CS4281_PPRVC, 7);
	BA0WRITE4(sc, CS4281_PPLVC, 7);

	return 0;
}
