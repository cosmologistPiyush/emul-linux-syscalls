/*	$NetBSD: grf_mv.c,v 1.8 1996/05/05 06:16:35 briggs Exp $	*/

/*
 * Copyright (c) 1995 Allen Briggs.  All rights reserved.
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
 *	This product includes software developed by Allen Briggs.
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
/*
 * Device-specific routines for handling Nubus-based video cards.
 */

#include <sys/param.h>

#include <sys/device.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/malloc.h>
#include <sys/mman.h>
#include <sys/proc.h>
#include <sys/systm.h>

#include <machine/cpu.h>
#include <machine/grfioctl.h>
#include <machine/viareg.h>

#include "nubus.h"
#include "grfvar.h"

static void	load_image_data __P((caddr_t data, struct image_data *image));
static void	grfmv_intr __P((void *vsc, int slot));
static int	get_vrsrcid __P((nubus_slot *slot));

static char zero = 0;

static int	grfmv_mode __P((struct grf_softc *gp, int cmd, void *arg));
static caddr_t	grfmv_phys __P((struct grf_softc *gp, vm_offset_t addr));
static int	grfmv_match __P((struct device *, void *, void *));
static void	grfmv_attach __P((struct device *, struct device *, void *));

struct cfattach grf_mv_ca = {
	sizeof(struct grf_softc), grfmv_match, grfmv_attach
};

static void
load_image_data(data, image)
	caddr_t	data;
	struct	image_data *image;
{
	bcopy(data     , &image->size,       4);
	bcopy(data +  4, &image->offset,     4);
	bcopy(data +  8, &image->rowbytes,   2);
	bcopy(data + 10, &image->top,        2);
	bcopy(data + 12, &image->left,       2);
	bcopy(data + 14, &image->bottom,     2);
	bcopy(data + 16, &image->right,      2);
	bcopy(data + 18, &image->version,    2);
	bcopy(data + 20, &image->packType,   2);
	bcopy(data + 22, &image->packSize,   4);
	bcopy(data + 26, &image->hRes,       4);
	bcopy(data + 30, &image->vRes,       4);
	bcopy(data + 34, &image->pixelType,  2);
	bcopy(data + 36, &image->pixelSize,  2);
	bcopy(data + 38, &image->cmpCount,   2);
	bcopy(data + 40, &image->cmpSize,    2);
	bcopy(data + 42, &image->planeBytes, 4);
}

/*ARGSUSED*/
static void
grfmv_intr(vsc, slot)
	void	*vsc;
	int	slot;
{
	caddr_t		 slotbase;

	slotbase = (caddr_t) NUBUS_SLOT_TO_BASE(slot);
	slotbase[0xa0000] = zero;
}

static int
get_vrsrcid(slot)
	nubus_slot	*slot;
{
extern	u_short	mac68k_vrsrc_vec[];
	int	i;

	for (i = 0 ; i < 6 ; i++)
		if ((mac68k_vrsrc_vec[i] & 0xff) == slot->slot)
			return ((mac68k_vrsrc_vec[i] >> 8) & 0xff);
	return 0x80;
}

static int
grfmv_match(pdp, match, aux)
	struct device *pdp;
	void *match, *aux;
{
	struct grf_softc	*sc;
	nubus_slot	*slot = (nubus_slot *) aux;
	nubus_dir	dir, *dirp, *dirp2;
	nubus_dirent	dirent, *direntp;
	nubus_type	slottype;
	int		vrsrc;

	sc = (struct grf_softc *) match;
	dirp = &dir;
	direntp = &dirent;
	nubus_get_main_dir(slot, dirp);

	vrsrc = get_vrsrcid(slot);
	if (nubus_find_rsrc(slot, dirp, vrsrc, direntp) <= 0) {
		if (   (vrsrc != 128)
		    || (nubus_find_rsrc(slot, dirp, 129, direntp) <= 0)) {
			return 0;
		}
	}

	dirp2 = (nubus_dir *) &sc->board_dir;
	nubus_get_dir_from_rsrc(slot, direntp, dirp2);

	if (nubus_find_rsrc(slot, dirp2, NUBUS_RSRC_TYPE, direntp) <= 0)
		/* Type is a required entry...  This should never happen. */
		return 0;

	if (nubus_get_ind_data(slot, direntp,
			(caddr_t) &slottype, sizeof(nubus_type)) <= 0)
		return 0;

	if (slottype.category != NUBUS_CATEGORY_DISPLAY)
		return 0;

	if (slottype.type != NUBUS_TYPE_VIDEO)
		return 0;

	if (slottype.drsw != NUBUS_DRSW_APPLE)
		return 0;

	/*
	 * If we've gotten this far, then we're dealing with a real-live
	 * Apple QuickDraw-compatible display card resource.  Now, how to
	 * determine that this is an active resource???  Dunno.  But we'll
	 * proceed like it is.
	 */

	sc->card_id = slottype.drhw;

	/* Need to load display info (and driver?), etc... */

	return 1;
}

static void
grfmv_attach(parent, self, aux)
	struct device *parent, *self;
	void *aux;
{
	struct grf_softc	*sc;
	struct image_data image_store, image;
	nubus_dirent	dirent;
	nubus_dir	mode_dir;
	int		mode;
	u_long		base;

	sc = (struct grf_softc *) self;

	sc->g_mode = grfmv_mode;
	sc->g_phys = grfmv_phys;

	mode = NUBUS_RSRC_FIRSTMODE;
	if (nubus_find_rsrc(&sc->sc_slot, &sc->board_dir, mode, &dirent) <= 0) {
		printf("grf probe failed to get board rsrc.\n");
		return;
	}

	nubus_get_dir_from_rsrc(&sc->sc_slot, &dirent, &mode_dir);

	if (nubus_find_rsrc(&sc->sc_slot, &mode_dir, VID_PARAMS, &dirent)
	    <= 0) {
		printf("grf probe failed to get mode dir.\n");
		return;
	}

	if (nubus_get_ind_data(&sc->sc_slot, &dirent, (caddr_t) &image_store,
				sizeof(struct image_data)) <= 0) {
		printf("grf probe failed to get indirect mode data.\n");
		return;
	}

	load_image_data((caddr_t) &image_store, &image);

	base = NUBUS_SLOT_TO_BASE(sc->sc_slot.slot);

	sc->curr_mode.mode_id = mode;
	sc->curr_mode.fbbase = (caddr_t) (base + image.offset);
	sc->curr_mode.fboff = image.offset;
	sc->curr_mode.rowbytes = image.rowbytes;
	sc->curr_mode.width = image.right - image.left;
	sc->curr_mode.height = image.bottom - image.top;
	sc->curr_mode.fbsize = sc->curr_mode.height * sc->curr_mode.rowbytes;
	sc->curr_mode.hres = image.hRes;
	sc->curr_mode.vres = image.vRes;
	sc->curr_mode.ptype = image.pixelType;
	sc->curr_mode.psize = image.pixelSize;

	strncpy(sc->card_name, nubus_get_card_name(&sc->sc_slot),
		CARD_NAME_LEN);

	sc->card_name[CARD_NAME_LEN-1] = '\0';

	add_nubus_intr(sc->sc_slot.slot, grfmv_intr, sc);

	sc->g_flags = GF_ALIVE;

	printf(": %d x %d ", sc->curr_mode.width, sc->curr_mode.height);

	if (sc->curr_mode.psize == 1)
		printf("monochrome");
	else
		printf("%d color", 1 << sc->curr_mode.psize);

	printf(" %s display\n", sc->card_name);
}

static int
grfmv_mode(gp, cmd, arg)
	struct grf_softc *gp;
	int cmd;
	void *arg;
{
	switch (cmd) {
	case GM_GRFON:
	case GM_GRFOFF:
		return 0;
	case GM_CURRMODE:
		break;
	case GM_NEWMODE:
		break;
	case GM_LISTMODES:
		break;
	}
	return EINVAL;
}

static caddr_t
grfmv_phys(gp, addr)
	struct grf_softc *gp;
	vm_offset_t addr;
{
	return (caddr_t) (NUBUS_SLOT_TO_PADDR(gp->sc_slot.slot) +
				(addr - gp->sc_slot.virtual_base));
}
