/*	$NetBSD: urlphy.c,v 1.21 2007/12/29 19:34:56 dyoung Exp $	*/
/*
 * Copyright (c) 2001, 2002
 *     Shingo WATANABE <nabe@nabechan.org>.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
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
 * driver for Realtek RL8150L internal phy
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: urlphy.c,v 1.21 2007/12/29 19:34:56 dyoung Exp $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/device.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/if_media.h>

#include <dev/mii/mii.h>
#include <dev/mii/miivar.h>
#include <dev/mii/miidevs.h>
#include <dev/mii/urlphyreg.h>

#ifdef URLPHY_DEBUG
#define DPRINTF(x)	if (urlphydebug) printf x
#define DPRINTFN(n,x)	if (urlphydebug>(n)) printf x
int urlphydebug = URLPHY_DEBUG;
#else
#define DPRINTF(x)
#define DPRINTFN(n,x)
#endif

static int	urlphy_match(struct device *, struct cfdata *, void *);
static void	urlphy_attach(struct device *, struct device *, void *);

CFATTACH_DECL(urlphy, sizeof(struct mii_softc),
    urlphy_match, urlphy_attach, mii_phy_detach, mii_phy_activate);

static int	urlphy_service(struct mii_softc *, struct mii_data *, int);
static void	urlphy_status(struct mii_softc *);

static const struct mii_phy_funcs urlphy_funcs = {
	urlphy_service, urlphy_status, mii_phy_reset,
};

static int
urlphy_match(struct device *parent, struct cfdata *match, void *aux)
{
	struct mii_attach_args *ma = aux;

	/*
	 * RTL8150 reports OUT == 0, MODEL == 0
	 */
	if (MII_OUI(ma->mii_id1, ma->mii_id2) != 0 &&
	    MII_MODEL(ma->mii_id2) != 0)
		return (0);

	/*
	 * Make sure the parent is an 'url' device.
	 */
	if (!device_is_a(parent, "url"))
		return(0);

	return (10);
}

static void
urlphy_attach(struct device *parent, struct device *self, void *aux)
{
	struct mii_softc *sc = device_private(self);
	struct mii_attach_args *ma = aux;
	struct mii_data *mii = ma->mii_data;

	aprint_naive(": Media interface\n");
	aprint_normal(": Realtek RTL8150L internal media interface\n");

	DPRINTF(("%s: %s: enter\n", sc->mii_dev.dv_xname, __func__));

	sc->mii_inst = mii->mii_instance;
	sc->mii_phy = ma->mii_phyno;
	sc->mii_funcs = &urlphy_funcs;
	sc->mii_pdata = mii;
	sc->mii_flags = mii->mii_flags;
	sc->mii_anegticks = MII_ANEGTICKS_GIGE;

	/* Don't do loopback on this PHY. */
	sc->mii_flags |= MIIF_NOLOOP;
	/* Don't do isolate on this PHY. */
	sc->mii_flags |= MIIF_NOISOLATE;

	if (mii->mii_instance != 0) {
		aprint_error("%s: ignoring this PHY, non-zero instance\n",
		       sc->mii_dev.dv_xname);
		return;
	}
	PHY_RESET(sc);

	sc->mii_capabilities = PHY_READ(sc, MII_BMSR) & ma->mii_capmask;
	aprint_normal("%s: ", sc->mii_dev.dv_xname);
	if ((sc->mii_capabilities & BMSR_MEDIAMASK) == 0)
		aprint_error("no media present");
	else
		mii_phy_add_media(sc);
	aprint_normal("\n");

	if (!pmf_device_register(self, NULL, mii_phy_resume))
		aprint_error_dev(self, "couldn't establish power handler\n");
}

static int
urlphy_service(struct mii_softc *sc, struct mii_data *mii, int cmd)
{
	struct ifmedia_entry *ife = mii->mii_media.ifm_cur;
	int reg;

	DPRINTF(("%s: %s: enter\n", sc->mii_dev.dv_xname, __func__));

	switch (cmd) {
	case MII_POLLSTAT:
		/*
		 * If we're not polling our PHY instance, just return.
		 */
		if (IFM_INST(ife->ifm_media) != sc->mii_inst)
			return (0);
		break;

	case MII_MEDIACHG:
		/*
		 * If we're not currently selected, just return.
		 */
		if (IFM_INST(ife->ifm_media) != sc->mii_inst)
			return (0);

		/* If the interface is not up, don't do anything. */
		if ((mii->mii_ifp->if_flags & IFF_UP) == 0)
			break;

		mii_phy_setmedia(sc);
		break;

	case MII_TICK:
		/*
		 * If we're not currently selected, just return.
		 */
		if (IFM_INST(ife->ifm_media) != sc->mii_inst)
			return (0);

		/* Just bail now if the interface is down. */
		if ((mii->mii_ifp->if_flags & IFF_UP) == 0)
			return (0);

		/*
		 * If we're not doing autonegotiation, we don't need to do
		 * any extra work here.  However, we need to check the link
		 * status so we can generate an announcement if the status
		 * changes.
		 */
		if (IFM_SUBTYPE(ife->ifm_media) != IFM_AUTO)
			return (0);

		/* Read the status register twice; MSR_LINK is latch-low. */
		reg = PHY_READ(sc, URLPHY_MSR) | PHY_READ(sc, URLPHY_MSR);
		if (reg & URLPHY_MSR_LINK)
			return (0);

		/*
		 * Only retry autonegotiation every N seconds.
		 */
		KASSERT(sc->mii_anegticks != 0);
		if (++sc->mii_ticks <= sc->mii_anegticks)
			return (0);

		sc->mii_ticks = 0;
		PHY_RESET(sc);

		if (mii_phy_auto(sc, 0) == EJUSTRETURN)
			return (0);

		break;

	case MII_DOWN:
		mii_phy_down(sc);
		return (0);
	}

	/* Update the media status. */
	mii_phy_status(sc);

	/* Callback if something changed. */
	mii_phy_update(sc, cmd);

	return (0);
}

static void
urlphy_status(struct mii_softc *sc)
{
	struct mii_data *mii = sc->mii_pdata;
	struct ifmedia_entry *ife = mii->mii_media.ifm_cur;
	int msr, bmsr, bmcr;

	DPRINTF(("%s: %s: enter\n", sc->mii_dev.dv_xname, __func__));

	mii->mii_media_status = IFM_AVALID;
	mii->mii_media_active = IFM_ETHER;

	/*
	 * The link status bit is not exist in the BMSR register,
	 * so we need to read the MSR register to get link status.
	 */
	msr = PHY_READ(sc, URLPHY_MSR) | PHY_READ(sc, URLPHY_MSR);
	if (msr & URLPHY_MSR_LINK)
		mii->mii_media_status |= IFM_ACTIVE;

	DPRINTF(("%s: %s: link %s\n", sc->mii_dev.dv_xname, __func__,
		 mii->mii_media_status & IFM_ACTIVE ? "up" : "down"));

	bmcr = PHY_READ(sc, MII_BMCR);
	if (bmcr & BMCR_AUTOEN) {
		bmsr = PHY_READ(sc, MII_BMSR) | PHY_READ(sc, MII_BMSR);
		if ((bmsr & BMSR_ACOMP) == 0) {
			/* Erg, still trying, I guess... */
			mii->mii_media_active |= IFM_NONE;
			return;
		}

		if (msr & URLPHY_MSR_SPEED_100)
			mii->mii_media_active |= IFM_100_TX;
		else
			mii->mii_media_active |= IFM_10_T;
		if (msr & URLPHY_MSR_DUPLEX)
			mii->mii_media_active |= IFM_FDX;
	} else
		mii->mii_media_active = ife->ifm_media;
}
