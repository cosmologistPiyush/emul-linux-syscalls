/*	$NetBSD: sdmmcchip.h,v 1.1 2009/04/21 03:00:30 nonaka Exp $	*/
/*	$OpenBSD: sdmmcchip.h,v 1.3 2007/05/31 10:09:01 uwe Exp $	*/

/*
 * Copyright (c) 2006 Uwe Stuehler <uwe@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef	_SDMMC_CHIP_H_
#define	_SDMMC_CHIP_H_

#include <sys/device.h>

#include <machine/bus.h>

struct sdmmc_command;

typedef struct sdmmc_chip_functions *sdmmc_chipset_tag_t;
typedef void *sdmmc_chipset_handle_t;

struct sdmmc_chip_functions {
	/* host controller reset */
	int		(*host_reset)(sdmmc_chipset_handle_t);

	/* host capabilities */
	uint32_t	(*host_ocr)(sdmmc_chipset_handle_t);
	int		(*host_maxblklen)(sdmmc_chipset_handle_t);

	/* card detection */
	int		(*card_detect)(sdmmc_chipset_handle_t);

	/* write protect */
	int		(*write_protect)(sdmmc_chipset_handle_t);

	/* bus power, clock frequency and width */
	int		(*bus_power)(sdmmc_chipset_handle_t, uint32_t);
	int		(*bus_clock)(sdmmc_chipset_handle_t, int);
	int		(*bus_width)(sdmmc_chipset_handle_t, int);

	/* command execution */
	void		(*exec_command)(sdmmc_chipset_handle_t,
			    struct sdmmc_command *);

	/* card interrupt */
	void		(*card_enable_intr)(sdmmc_chipset_handle_t, int);
	void		(*card_intr_ack)(sdmmc_chipset_handle_t);
};

/* host controller reset */
#define sdmmc_chip_host_reset(tag, handle)				\
	((tag)->host_reset((handle)))
/* host capabilities */
#define sdmmc_chip_host_ocr(tag, handle)				\
	((tag)->host_ocr((handle)))
#define sdmmc_chip_host_maxblklen(tag, handle)				\
	((tag)->host_maxblklen((handle)))
/* card detection */
#define sdmmc_chip_card_detect(tag, handle)				\
	((tag)->card_detect((handle)))
/* write protect */
#define sdmmc_chip_write_protect(tag, handle)				\
	((tag)->write_protect((handle)))
/* bus power, clock frequency and width */
#define sdmmc_chip_bus_power(tag, handle, ocr)				\
	((tag)->bus_power((handle), (ocr)))
#define sdmmc_chip_bus_clock(tag, handle, freq)				\
	((tag)->bus_clock((handle), (freq)))
#define sdmmc_chip_bus_width(tag, handle, width)			\
	((tag)->bus_width((handle), (width)))
/* command execution */
#define sdmmc_chip_exec_command(tag, handle, cmdp)			\
	((tag)->exec_command((handle), (cmdp)))
/* card interrupt */
#define sdmmc_chip_card_enable_intr(tag, handle, enable)		\
	((tag)->card_enable_intr((handle), (enable)))
#define sdmmc_chip_card_intr_ack(tag, handle)				\
	((tag)->card_intr_ack((handle)))

/* clock frequencies for sdmmc_chip_bus_clock() */
#define SDMMC_SDCLK_OFF		0
#define SDMMC_SDCLK_400K	400

struct sdmmcbus_attach_args {
	const char		*saa_busname;
	sdmmc_chipset_tag_t	saa_sct;
	sdmmc_chipset_handle_t	saa_sch;
	bus_dma_tag_t		saa_dmat;
	u_int			saa_clkmin;
	u_int			saa_clkmax;
	uint32_t		saa_caps;	/* see sdmmc_softc.sc_caps */
};

void	sdmmc_needs_discover(device_t);
void	sdmmc_card_intr(device_t);
void	sdmmc_delay(u_int);

#endif	/* _SDMMC_CHIP_H_ */
