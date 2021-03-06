/* $NetBSD: rk_usb.c,v 1.13 2021/08/07 16:18:45 thorpej Exp $ */

/*-
 * Copyright (c) 2018 Jared McNeill <jmcneill@invisible.ca>
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

#include <sys/cdefs.h>

__KERNEL_RCSID(0, "$NetBSD: rk_usb.c,v 1.13 2021/08/07 16:18:45 thorpej Exp $");

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/device.h>
#include <sys/intr.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/kmem.h>

#include <dev/clk/clk_backend.h>

#include <dev/fdt/fdtvar.h>
#include <dev/fdt/syscon.h>

static int rk_usb_match(device_t, cfdata_t, void *);
static void rk_usb_attach(device_t, device_t, void *);

#define	RK3328_CON0_REG			0x100
#define	RK3328_CON1_REG			0x104
#define	RK3328_CON2_REG			0x108
#define	 RK3328_USBPHY_COMMONONN	__BIT(4)

#define	RK3399_GRF_USB20_PHY0_CON0_REG	0x0e450
#define	RK3399_GRF_USB20_PHY1_CON0_REG	0x0e460
#define	 RK3399_USBPHY_COMMONONN	__BIT(4)
#define	RK3399_GRF_USB20_PHY0_CON1_REG	0x0e454
#define	RK3399_GRF_USB20_PHY1_CON1_REG	0x0e464
#define	RK3399_GRF_USB20_PHY0_CON2_REG	0x0e458
#define	RK3399_GRF_USB20_PHY1_CON2_REG	0x0e468
#define	 RK3399_USBPHY_SUSPEND_N	__BIT(1)
#define	 RK3399_USBPHY_UTMI_SEL		__BIT(0)

#define	RK3399_PHY_NO(_sc)	((_sc)->sc_reg == 0xe450 ? 0 : 1)

enum rk_usb_type {
	USB_RK3328 = 1,
	USB_RK3399,
};

static const struct device_compatible_entry compat_data[] = {
	{ .compat = "rockchip,rk3328-usb2phy",	.value = USB_RK3328 },
	{ .compat = "rockchip,rk3399-usb2phy",	.value = USB_RK3399 },
	DEVICE_COMPAT_EOL
};

struct rk_usb_clk {
	struct clk		base;
};

struct rk_usb_softc {
	device_t		sc_dev;
	struct syscon		*sc_syscon;
	enum rk_usb_type	sc_type;

	struct clk_domain	sc_clkdom;
	struct rk_usb_clk	sc_usbclk;

	bus_addr_t		sc_reg;
};

CFATTACH_DECL_NEW(rk_usb, sizeof(struct rk_usb_softc),
	rk_usb_match, rk_usb_attach, NULL, NULL);

static struct clk *
rk_usb_clk_get(void *priv, const char *name)
{
	struct rk_usb_softc * const sc = priv;

	if (strcmp(name, sc->sc_usbclk.base.name) != 0)
		return NULL;

	return &sc->sc_usbclk.base;
}

static void
rk_usb_clk_put(void *priv, struct clk *clk)
{
}

static u_int
rk_usb_clk_get_rate(void *priv, struct clk *clk)
{
	return 480000000;
}

static int
rk_usb_clk_enable(void *priv, struct clk *clk)
{
	struct rk_usb_softc * const sc = priv;
	uint32_t reg, write_mask, write_val;

	switch (sc->sc_type) {
	case USB_RK3328:
		reg = RK3328_CON2_REG;
		write_mask = RK3328_USBPHY_COMMONONN << 16;
		write_val = 0;
		break;
	case USB_RK3399:
		reg = RK3399_PHY_NO(sc) == 0 ?
		    RK3399_GRF_USB20_PHY0_CON0_REG :
		    RK3399_GRF_USB20_PHY1_CON0_REG;
		write_mask = RK3399_USBPHY_COMMONONN << 16;
		write_val = 0;
		break;
	default:
		return ENXIO;
	}

	syscon_lock(sc->sc_syscon);
	syscon_write_4(sc->sc_syscon, reg, write_mask | write_val);
	syscon_unlock(sc->sc_syscon);

	return 0;
}

static int
rk_usb_clk_disable(void *priv, struct clk *clk)
{
	struct rk_usb_softc * const sc = priv;
	uint32_t reg, write_mask, write_val;

	switch (sc->sc_type) {
	case USB_RK3328:
		reg = RK3328_CON2_REG;
		write_mask = RK3328_USBPHY_COMMONONN << 16;
		write_val = RK3328_USBPHY_COMMONONN;
		break;
	case USB_RK3399:
		reg = RK3399_PHY_NO(sc) == 0 ?
		    RK3399_GRF_USB20_PHY0_CON0_REG :
		    RK3399_GRF_USB20_PHY1_CON0_REG;
		write_mask = RK3399_USBPHY_COMMONONN << 16;
		write_val = RK3399_USBPHY_COMMONONN;
		break;
	default:
		return ENXIO;
	}

	syscon_lock(sc->sc_syscon);
	syscon_write_4(sc->sc_syscon, reg, write_mask | write_val);
	syscon_unlock(sc->sc_syscon);

	return 0;
}

static const struct clk_funcs rk_usb_clk_funcs = {
	.get = rk_usb_clk_get,
	.put = rk_usb_clk_put,
	.get_rate = rk_usb_clk_get_rate,
	.enable = rk_usb_clk_enable,
	.disable = rk_usb_clk_disable,
};

static struct clk *
rk_usb_fdt_decode(device_t dev, int cc_phandle, const void *data, size_t len)
{
	struct rk_usb_softc * const sc = device_private(dev);

	if (len != 0)
		return NULL;

	return &sc->sc_usbclk.base;
}

static const struct fdtbus_clock_controller_func rk_usb_fdt_funcs = {
	.decode = rk_usb_fdt_decode
};

static int
rk_usb_match(device_t parent, cfdata_t cf, void *aux)
{
	struct fdt_attach_args * const faa = aux;

	return of_compatible_match(faa->faa_phandle, compat_data);
}

static void
rk_usb_attach(device_t parent, device_t self, void *aux)
{
	struct rk_usb_softc * const sc = device_private(self);
	struct fdt_attach_args * const faa = aux;
	const int phandle = faa->faa_phandle;
	struct clk *clk;
	int child;

	/* Cache the base address of this PHY so we know which instance we are */
	if (fdtbus_get_reg(phandle, 0, &sc->sc_reg, NULL) != 0) {
		aprint_error(": couldn't get registers\n");
		return;
	}

	clk = fdtbus_clock_get(phandle, "phyclk");
	if (clk && clk_enable(clk) != 0) {
		aprint_error(": couldn't enable phy clock\n");
		return;
	}

	sc->sc_dev = self;
	sc->sc_type = of_compatible_lookup(phandle, compat_data)->value;
	sc->sc_syscon = fdtbus_syscon_lookup(OF_parent(phandle));
	if (sc->sc_syscon == NULL) {
		aprint_error(": couldn't get grf syscon\n");
		return;
	}

	const char *clkname = fdtbus_get_string(phandle, "clock-output-names");
	if (clkname == NULL)
		clkname = faa->faa_name;

	sc->sc_clkdom.name = device_xname(self);
	sc->sc_clkdom.funcs = &rk_usb_clk_funcs;
	sc->sc_clkdom.priv = sc;
	sc->sc_usbclk.base.domain = &sc->sc_clkdom;
	sc->sc_usbclk.base.name = kmem_asprintf("%s", clkname);
	clk_attach(&sc->sc_usbclk.base);

	aprint_naive("\n");
	aprint_normal(": USB2 PHY\n");

	fdtbus_register_clock_controller(self, phandle, &rk_usb_fdt_funcs);

	for (child = OF_child(phandle); child; child = OF_peer(child)) {
		if (!fdtbus_status_okay(child))
			continue;

		struct fdt_attach_args cfaa = *faa;
		cfaa.faa_phandle = child;
		cfaa.faa_name = fdtbus_get_string(child, "name");
		cfaa.faa_quiet = false;

		config_found(self, &cfaa, NULL, CFARGS_NONE);
	}
}

/*
 * USB PHY
 */

static int rk_usbphy_match(device_t, cfdata_t, void *);
static void rk_usbphy_attach(device_t, device_t, void *);

struct rk_usbphy_softc {
	device_t	sc_dev;
	int		sc_phandle;
	struct fdtbus_regulator *sc_supply;
};

CFATTACH_DECL_NEW(rk_usbphy, sizeof(struct rk_usbphy_softc),
	rk_usbphy_match, rk_usbphy_attach, NULL, NULL);

static void *
rk_usbphy_acquire(device_t dev, const void *data, size_t len)
{
	struct rk_usbphy_softc * const sc = device_private(dev);

	if (len != 0)
		return NULL;

	return sc;
}

static void
rk_usbphy_release(device_t dev, void *priv)
{
}

static int
rk_usbphy_otg_enable(device_t dev, void *priv, bool enable)
{
	struct rk_usbphy_softc * const sc = device_private(dev);
	struct rk_usb_softc * const usb_sc = device_private(device_parent(dev));
	uint32_t reg, write_mask, write_val;
	int error;

	switch (usb_sc->sc_type) {
	case USB_RK3328:
		reg = RK3328_CON0_REG;
		write_mask = 0x1ffU << 16;
		write_val = enable ? 0 : 0x1d1;
		break;
	case USB_RK3399:
		reg = RK3399_PHY_NO(usb_sc) == 0 ?
		    RK3399_GRF_USB20_PHY0_CON1_REG :
		    RK3399_GRF_USB20_PHY1_CON1_REG;
		write_mask = (RK3399_USBPHY_SUSPEND_N|RK3399_USBPHY_UTMI_SEL) << 16;
		write_val = enable ? 0 : RK3399_USBPHY_UTMI_SEL;
		break;
	default:
		return ENXIO;
	}

	if (sc->sc_supply) {
		error = enable ? fdtbus_regulator_enable(sc->sc_supply) :
				 fdtbus_regulator_disable(sc->sc_supply);
		if (error != 0)
			return error;
	}

	syscon_lock(usb_sc->sc_syscon);
	syscon_write_4(usb_sc->sc_syscon, reg, write_mask | write_val);
	syscon_unlock(usb_sc->sc_syscon);

	return 0;
}

static int
rk_usbphy_host_enable(device_t dev, void *priv, bool enable)
{
	struct rk_usbphy_softc * const sc = device_private(dev);
	struct rk_usb_softc * const usb_sc = device_private(device_parent(dev));
	uint32_t reg, write_mask, write_val;
	int error;

	switch (usb_sc->sc_type) {
	case USB_RK3328:
		reg = RK3328_CON1_REG;
		write_mask = 0x1ffU << 16;
		write_val = enable ? 0 : 0x1d1;
		break;
	case USB_RK3399:
		reg = RK3399_PHY_NO(usb_sc) == 0 ?
		    RK3399_GRF_USB20_PHY0_CON2_REG :
		    RK3399_GRF_USB20_PHY1_CON2_REG;
		write_mask = (RK3399_USBPHY_SUSPEND_N|RK3399_USBPHY_UTMI_SEL) << 16;
		write_val = enable ? 0 : RK3399_USBPHY_UTMI_SEL;
		break;
	default:
		return ENXIO;
	}

	if (sc->sc_supply) {
		error = enable ? fdtbus_regulator_enable(sc->sc_supply) :
				 fdtbus_regulator_disable(sc->sc_supply);
		if (error != 0)
			return error;
	}

	syscon_lock(usb_sc->sc_syscon);
	syscon_write_4(usb_sc->sc_syscon, reg, write_mask | write_val);
	syscon_unlock(usb_sc->sc_syscon);

	return 0;
}

const struct fdtbus_phy_controller_func rk_usbphy_otg_funcs = {
	.acquire = rk_usbphy_acquire,
	.release = rk_usbphy_release,
	.enable = rk_usbphy_otg_enable,
};

const struct fdtbus_phy_controller_func rk_usbphy_host_funcs = {
	.acquire = rk_usbphy_acquire,
	.release = rk_usbphy_release,
	.enable = rk_usbphy_host_enable,
};

static int
rk_usbphy_match(device_t parent, cfdata_t cf, void *aux)
{
	struct fdt_attach_args * const faa = aux;
	const int phandle = faa->faa_phandle;
	const char *name = fdtbus_get_string(phandle, "name");

	if (strcmp(name, "otg-port") == 0 || strcmp(name, "host-port") == 0)
		return 1;

	return 0;
}

static void
rk_usbphy_attach(device_t parent, device_t self, void *aux)
{
	struct rk_usbphy_softc * const sc = device_private(self);
	struct fdt_attach_args * const faa = aux;
	const int phandle = faa->faa_phandle;
	const char *name = fdtbus_get_string(phandle, "name");

	sc->sc_dev = self;
	sc->sc_phandle = phandle;
	if (of_hasprop(phandle, "phy-supply")) {
		sc->sc_supply = fdtbus_regulator_acquire(phandle, "phy-supply");
		if (sc->sc_supply == NULL) {
			aprint_error(": couldn't acquire regulator\n");
			return;
		}
	}

	aprint_naive("\n");

	if (strcmp(name, "otg-port") == 0) {
		aprint_normal(": USB2 OTG port\n");
		fdtbus_register_phy_controller(self, phandle, &rk_usbphy_otg_funcs);
	} else if (strcmp(name, "host-port") == 0) {
		aprint_normal(": USB2 host port\n");
		fdtbus_register_phy_controller(self, phandle, &rk_usbphy_host_funcs);
	}
}
