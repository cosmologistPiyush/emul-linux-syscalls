/*	$NetBSD: pckbc_mace.c,v 1.2 2002/03/13 13:12:26 simonb Exp $	*/

/*
 * Copyright (c) 2000 Soren S. Jorvang
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
 *          This product includes software developed for the
 *          NetBSD Project.  See http://www.netbsd.org/ for
 *          information about NetBSD.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/tty.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/kernel.h>
#include <sys/syslog.h>
#include <sys/types.h>
#include <sys/device.h>

#include <machine/cpu.h>
#include <machine/locore.h>
#include <machine/autoconf.h>
#include <machine/bus.h>

#include <sgimips/dev/macevar.h>

#include <dev/ic/i8042reg.h>
#include <dev/ic/pckbcvar.h>

struct pckbc_mace_softc {
	struct pckbc_softc sc_pckbc;

	/* XXX intr cookie */
};

static int	pckbc_mace_match(struct device *, struct cfdata *, void *);
static void	pckbc_mace_attach(struct device *, struct device *, void *);

struct cfattach pckbc_mace_ca = {
	sizeof(struct pckbc_mace_softc), pckbc_mace_match, pckbc_mace_attach
};

static int
pckbc_mace_match(parent, match, aux)
	struct device *parent;
	struct cfdata *match;
	void *aux;
{
	return 1;
}

static void
pckbc_mace_attach(parent, self, aux)
	struct device *parent;
	struct device *self;
	void *aux;
{
#if 0
	struct pckbc_mace_softc *msc = (void *)self;
	struct pckbc_softc *sc = &msc->sc_pckbc;
	struct mace_attach_args *maa = aux;
#endif

	printf(": stub\n");

	return;
}

/* XXX */

/*
 * glue code to support old console code with the
 * mi keyboard controller driver
 */
int
pckbc_machdep_cnattach(kbctag, kbcslot)
	pckbc_tag_t kbctag;
	pckbc_slot_t kbcslot;
{
	return (ENXIO);
}
