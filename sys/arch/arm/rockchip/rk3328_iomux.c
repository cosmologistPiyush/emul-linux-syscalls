/* $NetBSD: rk3328_iomux.c,v 1.8 2021/08/07 16:18:45 thorpej Exp $ */

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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: rk3328_iomux.c,v 1.8 2021/08/07 16:18:45 thorpej Exp $");

#include <sys/param.h>
#include <sys/bus.h>
#include <sys/device.h>
#include <sys/intr.h>
#include <sys/systm.h>
#include <sys/mutex.h>
#include <sys/kmem.h>
#include <sys/lwp.h>

#include <dev/fdt/fdtvar.h>
#include <dev/fdt/syscon.h>

#define	GRF_GPIO_P_REG(_bank, _idx)	(0x0100 + (_bank) * 0x10 + ((_idx) >> 3) * 4)
#define	 GRF_GPIO_P_CTL(_idx)		(0x3 << (((_idx) & 7) * 2))
#define	  GRF_GPIO_P_CTL_Z		0
#define	  GRF_GPIO_P_CTL_PULLUP		1
#define	  GRF_GPIO_P_CTL_PULLDOWN	2
#define	  GRF_GPIO_P_CTL_REPEATER	3
#define	  GRF_GPIO_P_CTL_MASK		0x3
#define	 GRF_GPIO_P_WRITE_EN(_idx)	(0x3 << (((_idx) & 7) * 2 + 16))

#define	GRF_GPIO_E_REG(_bank, _idx)	(0x0200 + (_bank) * 0x10 + ((_idx) >> 3) * 4)
#define	 GRF_GPIO_E_CTL(_idx)		(0x3 << (((_idx) & 7) * 2))
#define	  GRF_GPIO_E_CTL_2MA		0
#define	  GRF_GPIO_E_CTL_4MA		1
#define	  GRF_GPIO_E_CTL_8MA		2
#define	  GRF_GPIO_E_CTL_12MA		3
#define	  GRF_GPIO_E_CTL_MASK		0x3
#define	 GRF_GPIO_E_WRITE_EN(_idx)	(0x3 << (((_idx) & 7) * 2 + 16))

struct rk3328_iomux {
	bus_size_t		base;
	u_int			type;
#define	RK3328_IOMUX_TYPE_3BIT	0x01
};

struct rk3328_iomux_bank {
	struct rk3328_iomux		iomux[4];
};

static const struct rk3328_iomux_bank rk3328_iomux_banks[] = {
	[0] = {
		.iomux = {
			[0] = { .base = 0x0000 },
			[1] = { .base = 0x0004 },
			[2] = { .base = 0x0008 },
			[3] = { .base = 0x000c },
		},
	},
	[1] = {
		.iomux = {
			[0] = { .base = 0x0010 },
			[1] = { .base = 0x0014 },
			[2] = { .base = 0x0018 },
			[3] = { .base = 0x001c },
		}
	},
	[2] = {
		.iomux = {
			[0] = { .base = 0x0020 },
			[1] = { .base = 0x0024, .type = RK3328_IOMUX_TYPE_3BIT },
			[2] = { .base = 0x002c, .type = RK3328_IOMUX_TYPE_3BIT },
			[3] = { .base = 0x0034 },
		},
	},
	[3] = {
		.iomux = {
			[0] = { .base = 0x0038, .type = RK3328_IOMUX_TYPE_3BIT },
			[1] = { .base = 0x0040, .type = RK3328_IOMUX_TYPE_3BIT },
			[2] = { .base = 0x0048 },
			[3] = { .base = 0x004c },
		},
	},
};

struct rk3328_iomux_conf {
	const struct rk3328_iomux_bank *banks;
	u_int nbanks;
};

static const struct rk3328_iomux_conf rk3328_iomux_conf = {
	.banks = rk3328_iomux_banks,
	.nbanks = __arraycount(rk3328_iomux_banks),
};

static const struct device_compatible_entry compat_data[] = {
	{ .compat = "rockchip,rk3328-pinctrl",	.data = &rk3328_iomux_conf },
	DEVICE_COMPAT_EOL
};

struct rk3328_iomux_softc {
	device_t sc_dev;
	struct syscon *sc_syscon;

	const struct rk3328_iomux_conf *sc_conf;
};

#define	LOCK(sc)		\
	syscon_lock((sc)->sc_syscon)
#define	UNLOCK(sc)		\
	syscon_unlock((sc)->sc_syscon)
#define	RD4(sc, reg) 		\
	syscon_read_4((sc)->sc_syscon, (reg))
#define	WR4(sc, reg, val) 	\
	syscon_write_4((sc)->sc_syscon, (reg), (val))

static int	rk3328_iomux_match(device_t, cfdata_t, void *);
static void	rk3328_iomux_attach(device_t, device_t, void *);

CFATTACH_DECL_NEW(rk3328_iomux, sizeof(struct rk3328_iomux_softc),
	rk3328_iomux_match, rk3328_iomux_attach, NULL, NULL);

static void
rk3328_iomux_calc_iomux_reg(struct rk3328_iomux_softc *sc, u_int bank, u_int pin, bus_size_t *reg, uint32_t *mask)
{
	const struct rk3328_iomux_bank *banks = sc->sc_conf->banks;

	KASSERT(bank < sc->sc_conf->nbanks);

	*reg = banks[bank].iomux[pin / 8].base;
	if (banks[bank].iomux[pin / 8].type & RK3328_IOMUX_TYPE_3BIT) {
		if ((pin % 8) >= 5)
			*reg += 0x04;
		const u_int bit = (pin % 8 % 5) * 3;
		*mask = 7 << bit;
	} else {
		const u_int bit = (pin % 8) * 2;
		*mask = 3 << bit;
	}
}

static void
rk3328_iomux_set_bias(struct rk3328_iomux_softc *sc, u_int bank, u_int idx, u_int bias)
{
	WR4(sc, GRF_GPIO_P_REG(bank, idx),
	    __SHIFTIN(GRF_GPIO_P_CTL_MASK, GRF_GPIO_P_WRITE_EN(idx)) |
	    __SHIFTIN(bias, GRF_GPIO_P_CTL(idx)));
}

static void
rk3328_iomux_set_drive_strength(struct rk3328_iomux_softc *sc, u_int bank, u_int idx, u_int drv)
{
	WR4(sc, GRF_GPIO_E_REG(bank, idx),
	    __SHIFTIN(GRF_GPIO_E_CTL_MASK, GRF_GPIO_E_WRITE_EN(idx)) |
	    __SHIFTIN(drv, GRF_GPIO_E_CTL(idx)));
}

static void
rk3328_iomux_set_mux(struct rk3328_iomux_softc *sc, u_int bank, u_int idx, u_int mux)
{
	bus_size_t reg;
	uint32_t mask;

	rk3328_iomux_calc_iomux_reg(sc, bank, idx, &reg, &mask);

	WR4(sc, reg, (mask << 16) | __SHIFTIN(mux, mask));
}

static int
rk3328_iomux_config(struct rk3328_iomux_softc *sc, const int phandle, u_int bank, u_int idx, u_int mux)
{

	const int bias = fdtbus_pinctrl_parse_bias(phandle, NULL);
	switch (bias) {
	case 0:
		rk3328_iomux_set_bias(sc, bank, idx, GRF_GPIO_P_CTL_Z);
		break;
	case GPIO_PIN_PULLUP:
		rk3328_iomux_set_bias(sc, bank, idx, GRF_GPIO_P_CTL_PULLUP);
		break;
	case GPIO_PIN_PULLDOWN:
		rk3328_iomux_set_bias(sc, bank, idx, GRF_GPIO_P_CTL_PULLDOWN);
		break;
	}

	const int drv = fdtbus_pinctrl_parse_drive_strength(phandle);
	switch (drv) {
	case -1:
		break;
	case 2:
		rk3328_iomux_set_drive_strength(sc, bank, idx, GRF_GPIO_E_CTL_2MA);
		break;
	case 4:
		rk3328_iomux_set_drive_strength(sc, bank, idx, GRF_GPIO_E_CTL_4MA);
		break;
	case 8:
		rk3328_iomux_set_drive_strength(sc, bank, idx, GRF_GPIO_E_CTL_8MA);
		break;
	case 12:
		rk3328_iomux_set_drive_strength(sc, bank, idx, GRF_GPIO_E_CTL_12MA);
		break;
	default:
		aprint_error_dev(sc->sc_dev, "unsupported drive-strength %u\n", drv);
		return EINVAL;
	}

#if notyet
	int output_value;
	const int direction =
	    fdtbus_pinctrl_parse_input_output(phandle, &output_value);
	if (direction != -1) {
		rk3328_iomux_set_direction(sc, bank, idx, direction,
		    output_value);
	}
#endif

	rk3328_iomux_set_mux(sc, bank, idx, mux);

	return 0;
}

static int
rk3328_iomux_pinctrl_set_config(device_t dev, const void *data, size_t len)
{
	struct rk3328_iomux_softc * const sc = device_private(dev);
	int pins_len;

	if (len != 4)
		return -1;

	const int phandle = fdtbus_get_phandle_from_native(be32dec(data));
	const u_int *pins = fdtbus_get_prop(phandle, "rockchip,pins", &pins_len);

	while (pins_len >= 16) {
		const u_int bank = be32toh(pins[0]);
		const u_int idx = be32toh(pins[1]);
		const u_int mux = be32toh(pins[2]);
		const int cfg = fdtbus_get_phandle_from_native(be32toh(pins[3]));

		LOCK(sc);
		rk3328_iomux_config(sc, cfg, bank, idx, mux);
		UNLOCK(sc);

		pins_len -= 16;
		pins += 4;
	}

	return 0;
}

static struct fdtbus_pinctrl_controller_func rk3328_iomux_pinctrl_funcs = {
	.set_config = rk3328_iomux_pinctrl_set_config,
};

static int
rk3328_iomux_match(device_t parent, cfdata_t cf, void *aux)
{
	struct fdt_attach_args * const faa = aux;

	return of_compatible_match(faa->faa_phandle, compat_data);
}

static void
rk3328_iomux_attach(device_t parent, device_t self, void *aux)
{
	struct rk3328_iomux_softc * const sc = device_private(self);
	struct fdt_attach_args * const faa = aux;
	const int phandle = faa->faa_phandle;
	int child, sub;

	sc->sc_dev = self;
	sc->sc_syscon = fdtbus_syscon_acquire(phandle, "rockchip,grf");
	if (sc->sc_syscon == NULL) {
		aprint_error(": couldn't acquire grf syscon\n");
		return;
	}
	sc->sc_conf = of_compatible_lookup(phandle, compat_data)->data;

	aprint_naive("\n");
	aprint_normal(": RK3328 IOMUX control\n");

	for (child = OF_child(phandle); child; child = OF_peer(child)) {
		for (sub = OF_child(child); sub; sub = OF_peer(sub)) {
			if (!of_hasprop(sub, "rockchip,pins"))
				continue;
			fdtbus_register_pinctrl_config(self, sub, &rk3328_iomux_pinctrl_funcs);
		}
	}

	for (child = OF_child(phandle); child; child = OF_peer(child)) {
		struct fdt_attach_args cfaa = *faa;
		cfaa.faa_phandle = child;
		cfaa.faa_name = fdtbus_get_string(child, "name");
		cfaa.faa_quiet = false;

		config_found(self, &cfaa, NULL, CFARGS_NONE);
	}
}
