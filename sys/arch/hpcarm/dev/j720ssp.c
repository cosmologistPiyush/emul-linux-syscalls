/* $NetBSD: j720ssp.c,v 1.7 2002/07/19 19:15:49 ichiro Exp $ */

/*-
 * Copyright (c) 1998, 2001 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Charles M. Hannum.
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
 *        This product includes software developed by the NetBSD
 *        Foundation, Inc. and its contributors.
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

/*-
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * William Jolitz and Don Ahn.
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
 *	@(#)pccons.c	5.11 (Berkeley) 5/21/91
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/device.h>
#include <sys/callout.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/ioctl.h>

#include <machine/bus.h>
#include <machine/config_hook.h>
#include <machine/bootinfo.h>

#include <hpcarm/dev/sed1356var.h>

#include <arm/sa11x0/sa11x0_var.h>
#include <arm/sa11x0/sa11x0_gpioreg.h>
#include <arm/sa11x0/sa11x0_ppcreg.h>
#include <arm/sa11x0/sa11x0_sspreg.h>

#include <dev/wscons/wsconsio.h>
#include <dev/wscons/wskbdvar.h>
#include <dev/wscons/wsksymdef.h>
#include <dev/wscons/wsksymvar.h>
#include <dev/wscons/wsmousevar.h>
#include <dev/hpc/tpcalibvar.h>

extern const struct wscons_keydesc j720kbd_keydesctab[];

struct j720ssp_softc {
        struct device sc_dev;

	bus_space_tag_t sc_iot;
	bus_space_handle_t sc_gpioh;
	bus_space_handle_t sc_ssph;

	struct device *sc_wskbddev;
	struct device *sc_wsmousedev;
	struct tpcalib_softc sc_tpcalib;

	void *sc_kbdsi;
	void *sc_tpsi;
	struct callout sc_tptimeout;
	int sc_enabled;
};

int j720kbd_intr(void *);
int j720tp_intr(void *);
void j720kbdsoft(void *);
void j720tpsoft(void *);
void j720tp_timeout(void *);
int j720lcdparam(void *, int, long, void *);
static void j720kbd_read(struct j720ssp_softc *, char *);
static int j720ssp_readwrite(struct j720ssp_softc *, int, int, int *);

int j720sspprobe(struct device *, struct cfdata *, void *);
void j720sspattach(struct device *, struct device *, void *);

int j720kbd_submatch(struct device *, struct cfdata *, void *);
int j720tp_submatch(struct device *, struct cfdata *, void *);

int j720kbd_enable(void *, int);
void j720kbd_set_leds(void *, int);
int j720kbd_ioctl(void *, u_long, caddr_t, int, struct proc *);

struct cfattach j720ssp_ca = {
	sizeof(struct j720ssp_softc), j720sspprobe, j720sspattach,
};

const struct wskbd_accessops j720kbd_accessops = {
	j720kbd_enable,
	j720kbd_set_leds,
	j720kbd_ioctl,
};

void j720kbd_cngetc(void *, u_int *, int *);
void j720kbd_cnpollc(void *, int);
void j720kbd_cnbell(void *, u_int, u_int, u_int);

const struct wskbd_consops j720kbd_consops = {
	j720kbd_cngetc,
	j720kbd_cnpollc,
	j720kbd_cnbell,
};

const struct wskbd_mapdata j720kbd_keymapdata = {
	j720kbd_keydesctab,
#ifdef J720KBD_LAYOUT
	J720KBD_LAYOUT,
#else
	KB_US,
#endif
};

static int j720tp_enable(void *);
static int j720tp_ioctl(void *, u_long, caddr_t, int, struct proc *);
static void j720tp_disable(void *);

const struct wsmouse_accessops j720tp_accessops = {
	j720tp_enable,
	j720tp_ioctl,
	j720tp_disable,
};

static int j720ssp_powerstate = 1;

static struct j720ssp_softc j720kbdcons_sc;
static int j720kbdcons_initstate = 0;

#define DEBUG
#ifdef DEBUG
int j720sspwaitcnt;
int j720sspwaittime;
extern int gettick();
#endif

#define BIT_INVERT(x)	do {					\
	(x) = ((((x) & 0xf0) >> 4) | (((x) & 0x0f) << 4));	\
	(x) = ((((x) & 0xcc) >> 2) | (((x) & 0x33) << 2));	\
	(x) = ((((x) & 0xaa) >> 1) | (((x) & 0x55) << 1));	\
	} while(0)

int
j720sspprobe(struct device *parent, struct cfdata *cf, void *aux)
{
	return (1);
}

void
j720sspattach(struct device *parent, struct device *self, void *aux)
{
	struct j720ssp_softc *sc = (void *)self;
	struct sa11x0_softc *psc = (void *)parent;
	struct sa11x0_attach_args *sa = aux;
	struct wskbddev_attach_args a;
	struct wsmousedev_attach_args ma;

	printf("\n");

	sc->sc_iot = psc->sc_iot;
	sc->sc_gpioh = psc->sc_gpioh;
	if (bus_space_map(sc->sc_iot, sa->sa_addr, sa->sa_size, 0,
			  &sc->sc_ssph)) {
		printf("%s: unable to map SSP registers\n",
		       sc->sc_dev.dv_xname);
		return;
	}

	sc->sc_kbdsi = softintr_establish(IPL_SOFTCLOCK, j720kbdsoft, sc);

	sc->sc_enabled = 0;

	a.console = 0;

	a.keymap = &j720kbd_keymapdata;

	a.accessops = &j720kbd_accessops;
	a.accesscookie = sc;

	/* Do console initialization */
	if (! (bootinfo->bi_cnuse & BI_CNUSE_SERIAL)) {
		j720kbdcons_sc = *sc;
		a.console = 1;

		wskbd_cnattach(&j720kbd_consops, NULL, &j720kbd_keymapdata);
		j720kbdcons_initstate = 1;
	}

	/*
	 * Attach the wskbd, saving a handle to it.
	 * XXX XXX XXX
	 */
	sc->sc_wskbddev = config_found_sm(self, &a, wskbddevprint,
	    j720kbd_submatch);

#ifdef DEBUG
	/* Zero the stat counters */
	j720sspwaitcnt = 0;
	j720sspwaittime = 0;
#endif

	if (j720kbdcons_initstate == 1)
		j720kbd_enable(sc, 1);

	ma.accessops = &j720tp_accessops;
	ma.accesscookie = sc;

	sc->sc_wsmousedev = config_found_sm(self, &ma, wsmousedevprint,
	    j720tp_submatch);
	tpcalib_init(&sc->sc_tpcalib);

	/* XXX fill in "default" calibrate param */
	{
		static const struct wsmouse_calibcoords j720_default_calib = {
			0, 0, 639, 239,
			4,
			{ { 988,  80,   0,   0 },
			  {  88,  84, 639,   0 },
			  { 988, 927,   0, 239 },
			  {  88, 940, 639, 239 } } };
		tpcalib_ioctl(&sc->sc_tpcalib, WSMOUSEIO_SCALIBCOORDS,
		    (caddr_t)&j720_default_calib, 0, 0);
	}

	j720tp_disable(sc);
	callout_init(&sc->sc_tptimeout);

	/* Setup touchpad interrupt */
	sc->sc_tpsi = softintr_establish(IPL_SOFTCLOCK, j720tpsoft, sc);
	sa11x0_intr_establish(0, 9, 1, IPL_BIO, j720tp_intr, sc);

	/* LCD control is on the same bus */
	config_hook(CONFIG_HOOK_SET, CONFIG_HOOK_BRIGHTNESS,
		    CONFIG_HOOK_SHARE, j720lcdparam, sc);
	config_hook(CONFIG_HOOK_GET, CONFIG_HOOK_BRIGHTNESS,
		    CONFIG_HOOK_SHARE, j720lcdparam, sc);
	config_hook(CONFIG_HOOK_GET, CONFIG_HOOK_BRIGHTNESS_MAX,
		    CONFIG_HOOK_SHARE, j720lcdparam, sc);

	config_hook(CONFIG_HOOK_SET, CONFIG_HOOK_CONTRAST,
		    CONFIG_HOOK_SHARE, j720lcdparam, sc);
	config_hook(CONFIG_HOOK_GET, CONFIG_HOOK_CONTRAST,
		    CONFIG_HOOK_SHARE, j720lcdparam, sc);
	config_hook(CONFIG_HOOK_GET, CONFIG_HOOK_CONTRAST_MAX,
		    CONFIG_HOOK_SHARE, j720lcdparam, sc);
}

int
j720kbd_submatch(struct device *parant, struct cfdata *cf, void *aux) {

	if (strcmp(cf->cf_driver->cd_name, "wskbd") == 0)
		return (1);
	return (0);
}

int
j720tp_submatch(struct device *parant, struct cfdata *cf, void *aux) {

	if (strcmp(cf->cf_driver->cd_name, "wsmouse") == 0)
		return (1);
	return (0);
}

int
j720kbd_enable(void *v, int on)
{
	struct j720ssp_softc *sc = v;

	if (! sc->sc_enabled) {
		sc->sc_enabled = 1;

		sa11x0_intr_establish(0, 0, 1, IPL_BIO, j720kbd_intr, sc);
	}
	/* XXX */
	return (0);
}

void
j720kbd_set_leds(void *v, int on)
{
	/* XXX */
	return;
}

int
j720kbd_ioctl(void *v, u_long cmd, caddr_t data, int flag, struct proc *p)
{
	return (EPASSTHROUGH);
}

int
j720kbd_intr(void *arg)
{
	struct j720ssp_softc *sc = arg;

	bus_space_write_4(sc->sc_iot, sc->sc_gpioh, SAGPIO_EDR, 1);

	/*
	 * Schedule a soft interrupt to process at lower priority,
	 * as reading keycodes takes time.
	 *
	 * Interrupts are generated every 25-33ms as long as there
	 * are unprocessed key events.  So it is not a good idea to
	 * use callout to call j720kbdsoft after some delay in hope
	 * of reducing interrupts.
	 */
	softintr_schedule(sc->sc_kbdsi);

	return (1);
}

int
j720tp_intr(void *arg)
{
	struct j720ssp_softc *sc = arg;

	bus_space_write_4(sc->sc_iot, sc->sc_gpioh, SAGPIO_EDR, 1 << 9);

	softintr_schedule(sc->sc_tpsi);

	return (1);
}

void
j720kbdsoft(void *arg)
{
	struct j720ssp_softc *sc = arg;
	int s, type, value;
	char buf[9], *p;

	j720kbd_read(sc, buf);

	for(p = buf; *p; p++) {
		type = *p & 0x80 ? WSCONS_EVENT_KEY_UP :
		    WSCONS_EVENT_KEY_DOWN;
		value = *p & 0x7f;
		s = spltty();
		wskbd_input(sc->sc_wskbddev, type, value);
		splx(s);
		if (type == WSCONS_EVENT_KEY_DOWN &&
		    value == 0x7f) {
			j720ssp_powerstate = ! j720ssp_powerstate;
			config_hook_call(CONFIG_HOOK_POWERCONTROL,
					 CONFIG_HOOK_POWERCONTROL_LCDLIGHT,
					 (void *)j720ssp_powerstate);
		}
	}

	return;
}

void
j720kbd_read(struct j720ssp_softc *sc, char *buf)
{
	int data, count;
#ifdef DEBUG
	u_int32_t oscr;

	oscr = gettick();
#endif
	bus_space_write_4(sc->sc_iot, sc->sc_gpioh, SAGPIO_PCR, 0x2000000);

	/* send scan keycode command */
	if (j720ssp_readwrite(sc, 1, 0x900, &data) < 0 ||
	    data != 0x88)
		goto out;

	/* read numbers of scancode available */
	if (j720ssp_readwrite(sc, 0, 0x8800, &data) < 0)
		goto out;
	BIT_INVERT(data);
	count = data;

	for(; count; count--) {
		if (j720ssp_readwrite(sc, 0, 0x8800, &data) < 0)
			goto out;
		BIT_INVERT(data);
		*buf++ = data;
	}
	*buf = 0;
	bus_space_write_4(sc->sc_iot, sc->sc_gpioh, SAGPIO_PSR, 0x2000000);

#ifdef DEBUG
	oscr = (u_int32_t)gettick() - oscr;
	j720sspwaitcnt++;
	j720sspwaittime += oscr;
#endif

	return;

out:
	*buf = 0;
	bus_space_write_4(sc->sc_iot, sc->sc_gpioh, SAGPIO_PSR, 0x2000000);

	/* reset SSP */
	bus_space_write_4(sc->sc_iot, sc->sc_ssph, SASSP_CR0, 0x307);
	delay(100);
	bus_space_write_4(sc->sc_iot, sc->sc_ssph, SASSP_CR0, 0x387);
printf("j720kbd_read: error %x\n", data);
}

void
j720tpsoft(void *arg)
{
	struct j720ssp_softc *sc = arg;
	int buf[8], data, i, x, y;

	bus_space_write_4(sc->sc_iot, sc->sc_gpioh, SAGPIO_PCR, 0x2000000);

	/* send read touchpanel command */
	if (j720ssp_readwrite(sc, 1, 0x500, &data) < 0 ||
	    data != 0x88)
		goto out;

	for(i = 0; i < 8; i++) {
		if (j720ssp_readwrite(sc, 0, 0x8800, &data) < 0)
			goto out;
		BIT_INVERT(data);
		buf[i] = data;
	}

	bus_space_write_4(sc->sc_iot, sc->sc_gpioh, SAGPIO_PSR, 0x2000000);

	buf[6] <<= 8;
	buf[7] <<= 8;
	for(i = 0; i < 3; i++) {
		buf[i] |= buf[6] & 0x300;
		buf[6] >>= 2;
		buf[i + 3] |= buf[7] & 0x300;
		buf[7] >>= 2;
	}
#if 0
	printf("j720tpsoft: %d %d %d  %d %d %d\n", buf[0], buf[1], buf[2],
	    buf[3], buf[4], buf[5]);
#endif

	/* XXX buf[1], buf[2], ... should also be used */
	tpcalib_trans(&sc->sc_tpcalib, buf[1], buf[4], &x, &y);
	wsmouse_input(sc->sc_wsmousedev, 1, x, y, 0,
	    WSMOUSE_INPUT_ABSOLUTE_X | WSMOUSE_INPUT_ABSOLUTE_Y);

	callout_reset(&sc->sc_tptimeout, hz / 10, j720tp_timeout, sc);

	return;

out:
	*buf = 0;
	bus_space_write_4(sc->sc_iot, sc->sc_gpioh, SAGPIO_PSR, 0x2000000);

	/* reset SSP */
	bus_space_write_4(sc->sc_iot, sc->sc_ssph, SASSP_CR0, 0x307);
	delay(100);
	bus_space_write_4(sc->sc_iot, sc->sc_ssph, SASSP_CR0, 0x387);
	printf("j720tpsoft: error %x\n", data);
}

void
j720tp_timeout(void *arg)
{
	struct j720ssp_softc *sc = arg;

#if 0
	/* XXX I don't this this is necessary (untested) */
	if (bus_space_read_4(sc->sc_iot, sc->sc_gpioh, SAGPIO_PLR) &
	    (1 << 9)) {
		/* Touchpad is still pressed */
		callout_reset(&sc->sc_tptimeout, hz / 10, j720tp_timeout, sc);
		return;
	}
#endif

	wsmouse_input(sc->sc_wsmousedev, 0, 0, 0, 0, 0);
}

static int
j720tp_enable(void *arg) {
	struct j720ssp_softc *sc = arg;
	int er, s;

	s = splhigh();
	er = bus_space_read_4(sc->sc_iot, sc->sc_gpioh, SAGPIO_FER);
	er |= 1 << 9;
	bus_space_write_4(sc->sc_iot, sc->sc_gpioh, SAGPIO_FER, er);
	splx(s);

	return (0);
}
	
static void
j720tp_disable(void *arg) {
	struct j720ssp_softc *sc = arg;
	int er, s;

	s = splhigh();
	er = bus_space_read_4(sc->sc_iot, sc->sc_gpioh, SAGPIO_FER);
	er &= ~(1 << 9);
	bus_space_write_4(sc->sc_iot, sc->sc_gpioh, SAGPIO_FER, er);
	splx(s);
}

static int
j720tp_ioctl(void *arg, u_long cmd, caddr_t data, int flag, struct proc *p) {
	struct j720ssp_softc *sc = arg;

	switch (cmd) {
	case WSMOUSEIO_GTYPE:
		*(u_int *)data = WSMOUSE_TYPE_TPANEL;
		return (0);

	case WSMOUSEIO_SCALIBCOORDS:
	case WSMOUSEIO_GCALIBCOORDS:
		return tpcalib_ioctl(&sc->sc_tpcalib, cmd, data, flag, p);

	default:
		return (EPASSTHROUGH);
	}
}

int
j720lcdparam(void *ctx, int type, long id, void *msg)
{
	struct j720ssp_softc *sc = ctx;
	int i, s;
	u_int32_t data[2], len;

	switch (type) {
	case CONFIG_HOOK_GET:
		switch (id) {
		case CONFIG_HOOK_BRIGHTNESS_MAX:
		case CONFIG_HOOK_CONTRAST_MAX:
			*(int *)msg = 255;
			return 1;
		case CONFIG_HOOK_BRIGHTNESS:
			data[0] = 0x6b00;
			data[1] = 0x8800;
			len = 2;
			break;
		case CONFIG_HOOK_CONTRAST:
			data[0] = 0x2b00;
			data[1] = 0x8800;
			len = 2;
			break;
		default:
			return 0;
		}
		break;

	case CONFIG_HOOK_SET:
		switch (id) {
		case CONFIG_HOOK_BRIGHTNESS:
			if (*(int *)msg >= 0) {
				data[0] = 0xcb00;
				data[1] = *(int *)msg;
				BIT_INVERT(data[1]);
				data[1] <<= 8;
				len = 2;
			} else {
				/* XXX hack */
				data[0] = 0xfb00;
				len = 1;
			}
			break;
		case CONFIG_HOOK_CONTRAST:
			data[0] = 0x8b00;
			data[1] = *(int *)msg;
			BIT_INVERT(data[1]);
			data[1] <<= 8;
			len = 2;
			break;
		default:
			return 0;
		}
	}

	s = splbio();
	bus_space_write_4(sc->sc_iot, sc->sc_gpioh, SAGPIO_PCR, 0x2000000);

	for (i = 0; i < len; i++) {
		if (j720ssp_readwrite(sc, 1, data[i], &data[i]) < 0)
			goto out;
	}
	bus_space_write_4(sc->sc_iot, sc->sc_gpioh, SAGPIO_PSR, 0x2000000);
	splx(s);

	if (type == CONFIG_HOOK_SET)
		return 1;

	BIT_INVERT(data[1]);
	*(int *)msg = data[1];

	return 1;

out:
	bus_space_write_4(sc->sc_iot, sc->sc_gpioh, SAGPIO_PSR, 0x2000000);

	/* reset SSP */
	bus_space_write_4(sc->sc_iot, sc->sc_ssph, SASSP_CR0, 0x307);
	delay(100);
	bus_space_write_4(sc->sc_iot, sc->sc_ssph, SASSP_CR0, 0x387);
	splx(s);
	return 0;
}

static int
j720ssp_readwrite(struct j720ssp_softc *sc, int drainfifo, int in, int *out)
{
	int timo;

	timo = 100000;
	while(bus_space_read_4(sc->sc_iot, sc->sc_gpioh, SAGPIO_PLR) & 0x400)
		if (--timo == 0) {
			printf("timo0\n");
			return -1;
		}
	if (drainfifo) {
		while(bus_space_read_4(sc->sc_iot, sc->sc_ssph, SASSP_SR) &
		      SR_RNE)
			bus_space_read_4(sc->sc_iot, sc->sc_ssph, SASSP_DR);
#if 1
		delay(5000);
#endif
	}

	bus_space_write_4(sc->sc_iot, sc->sc_ssph, SASSP_DR, in);

	delay(5000);
	timo = 100000;
	while(! (bus_space_read_4(sc->sc_iot, sc->sc_ssph, SASSP_SR) & SR_RNE))
		if (--timo == 0) {
			printf("timo1\n");
			return -1;
		}

	*out = bus_space_read_4(sc->sc_iot, sc->sc_ssph, SASSP_DR);

	return 0;
}

#if 0
int
j720kbd_cnattach()
{
	/* XXX defer initialization till j720sspattach */

	return (0);
}
#endif

/* ARGSUSED */
void
j720kbd_cngetc(void *v, u_int *type, int *data)
{
	char buf[9];

	if (j720kbdcons_initstate < 1)
		return;

	for (;;) {
		j720kbd_read(&j720kbdcons_sc, buf);

		if (buf[0] != 0) {
			/* XXX we are discarding buffer contents */
			*type = buf[0] & 0x80 ? WSCONS_EVENT_KEY_UP :
			    WSCONS_EVENT_KEY_DOWN;
			*data = buf[0] & 0x7f;
			return;
		}
	}
}

void
j720kbd_cnpollc(void *v, int on)
{
#if 0
	/* XXX */
	struct j720kbd_internal *t = v;

	pckbc_set_poll(t->t_kbctag, t->t_kbcslot, on);
#endif
}

void
j720kbd_cnbell(void *v, u_int pitch, u_int period, u_int volume)
{
}

int
j720lcdpower(void *ctx, int type, long id, void *msg)
{
	struct sed1356_softc *sc = ctx;
	struct sa11x0_softc *psc = sc->sc_parent;
	int val;
	u_int32_t reg;

	if (type != CONFIG_HOOK_POWERCONTROL ||
	    id != CONFIG_HOOK_POWERCONTROL_LCDLIGHT)
		return 0;

	sed1356_init_brightness(sc, 0);
	sed1356_init_contrast(sc, 0);

	if (msg) {
		bus_space_write_1(sc->sc_iot, sc->sc_regh, 0x1f0, 0);

		reg = bus_space_read_4(psc->sc_iot, psc->sc_ppch, SAPPC_PSR);
		reg |= 0x1;
		bus_space_write_4(psc->sc_iot, psc->sc_ppch, SAPPC_PSR, reg);
		delay(50000);

		val = sc->sc_contrast;
		config_hook_call(CONFIG_HOOK_SET, CONFIG_HOOK_CONTRAST, &val);
		delay(100000);

		reg = bus_space_read_4(psc->sc_iot, psc->sc_ppch, SAPPC_PSR);
		reg |= 0x4;
		bus_space_write_4(psc->sc_iot, psc->sc_ppch, SAPPC_PSR, reg);

		val = sc->sc_brightness;
		config_hook_call(CONFIG_HOOK_SET, CONFIG_HOOK_BRIGHTNESS, &val);

		reg = bus_space_read_4(psc->sc_iot, psc->sc_ppch, SAPPC_PSR);
		reg |= 0x2;
		bus_space_write_4(psc->sc_iot, psc->sc_ppch, SAPPC_PSR, reg);
	} else {
		reg = bus_space_read_4(psc->sc_iot, psc->sc_ppch, SAPPC_PSR);
		reg &= ~0x2;
		bus_space_write_4(psc->sc_iot, psc->sc_ppch, SAPPC_PSR, reg);
		reg &= ~0x4;
		bus_space_write_4(psc->sc_iot, psc->sc_ppch, SAPPC_PSR, reg);
		delay(100000);

		val = -2;
		config_hook_call(CONFIG_HOOK_SET, CONFIG_HOOK_BRIGHTNESS, &val);

		bus_space_write_1(sc->sc_iot, sc->sc_regh, 0x1f0, 1);

		delay(100000);
		reg = bus_space_read_4(psc->sc_iot, psc->sc_ppch, SAPPC_PSR);
		reg &= ~0x1;
		bus_space_write_4(psc->sc_iot, psc->sc_ppch, SAPPC_PSR, reg);
	}
	return 1;
}
