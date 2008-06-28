/*	$NetBSD: cmos.c,v 1.5 2008/06/28 15:03:27 ad Exp $	*/

/*
 * Copyright (C) 2003 JONE System Co., Inc.
 * All right reserved.
 *
 * Copyright (C) 1999, 2000, 2001, 2002 JEPRO Co., Ltd.
 * All right reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
/*
 * Copyright (c) 2007 David Young.  All right reserved.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 * 3. The name of David Young may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: cmos.c,v 1.5 2008/06/28 15:03:27 ad Exp $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/ioctl.h>
#include <sys/proc.h>
#include <sys/device.h>
#include <sys/conf.h>
#include <sys/kauth.h>

#include <machine/bus.h>
#include <machine/intr.h>

#include <dev/isa/isareg.h>
#include <dev/isa/isavar.h>
#include <dev/ic/mc146818reg.h>
#include <i386/isa/nvram.h>

#define	CMOS_SUM	32
#define	CMOS_BIOSSPEC	34	/* start of BIOS-specific configuration data */

#define	NVRAM_SUM	(MC_NVRAM_START + CMOS_SUM)
#define	NVRAM_BIOSSPEC	(MC_NVRAM_START + CMOS_BIOSSPEC)

#define	CMOS_SIZE	NVRAM_BIOSSPEC

struct cmos_softc {			/* driver status information */
	int	sc_open;
	uint8_t	sc_buf[CMOS_SIZE];
} cmos_softc;

int cmos_debug = 0;

void cmosattach(int);
dev_type_open(cmos_open);
dev_type_read(cmos_read);
dev_type_write(cmos_write);

static void cmos_sum(uint8_t *, int, int, int);

const struct cdevsw cmos_cdevsw = {
	.d_open = cmos_open, .d_close = nullclose, .d_read = cmos_read,
	.d_write = cmos_write, .d_ioctl = noioctl,
	.d_stop = nostop, .d_tty = notty, .d_poll = nopoll, .d_mmap = nommap,
	.d_kqfilter = nokqfilter, .d_flag = D_OTHER | D_MPSAFE
};

static kmutex_t cmos_lock;

void
cmosattach(int n)
{

	mutex_init(&cmos_lock, MUTEX_DEFAULT, IPL_NONE);
}

int
cmos_open(dev_t dev, int flags, int ifmt, struct lwp *l)
{

	return kauth_authorize_generic(kauth_cred_get(),
	    KAUTH_GENERIC_ISSUSER, NULL);
}

static void
cmos_fetch(struct cmos_softc *sc)
{
	int i, s;
	uint8_t *p;

	p = sc->sc_buf;

	s = splclock();
	for (i = 0; i < CMOS_SIZE; i++)
		*p++ = mc146818_read(sc, i);
	splx(s);
}

int
cmos_read(dev_t dev, struct uio *uio, int ioflag)
{
	struct cmos_softc *sc = &cmos_softc;
	int error;

	if (uio->uio_offset + uio->uio_resid > CMOS_SIZE)
		return EINVAL;

	mutex_enter(&cmos_lock);
	cmos_fetch(sc);
	error = uiomove(sc->sc_buf, CMOS_SIZE, uio);
	mutex_exit(&cmos_lock);

	return error;
}

int
cmos_write(dev_t dev, struct uio *uio, int ioflag)
{
	struct cmos_softc *sc = &cmos_softc;
	int error = 0, i, s;

	if (uio->uio_offset + uio->uio_resid > CMOS_SIZE)
		return EINVAL;

	mutex_enter(&cmos_lock);
	cmos_fetch(sc);
	error = uiomove(sc->sc_buf, CMOS_SIZE, uio);
	if (error == 0) {
		cmos_sum(sc->sc_buf, NVRAM_DISKETTE, NVRAM_SUM, NVRAM_SUM);
		s = splclock();
		for (i = NVRAM_DISKETTE; i < CMOS_SIZE; i++)
			mc146818_write(sc, i, sc->sc_buf[i]);
		splx(s);
	}
	mutex_exit(&cmos_lock);

	return error;
}

static void
cmos_sum(uint8_t *p, int from, int to, int offset)
{
	int i;
	uint16_t sum;

#ifdef CMOS_DEBUG
	printf("%s: from %d to %d and store %d\n", __func__, from, to, offset);
#endif

	sum = 0;
	for (i = from; i < to; i++)
		sum += p[i];
	p[offset] = sum >> 8;
	p[offset + 1] = sum & 0xff;
}
