/*	$NetBSD: imxusb.c,v 1.1 2010/11/30 13:05:27 bsh Exp $	*/
/*
 * Copyright (c) 2009, 2010  Genetec Corporation.  All rights reserved.
 * Written by Hashimoto Kenichi and Hiroyuki Bessho for Genetec Corporation.
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
 * THIS SOFTWARE IS PROVIDED BY GENETEC CORPORATION ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL GENETEC CORPORATION
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: imxusb.c,v 1.1 2010/11/30 13:05:27 bsh Exp $");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/device.h>
#include <sys/intr.h>
#include <sys/bus.h>

#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>
#include <dev/usb/usbdivar.h>
#include <dev/usb/usb_mem.h>

#include <dev/usb/ehcireg.h>
#include <dev/usb/ehcivar.h>

#include <arm/imx/imxusbreg.h>
#include <arm/imx/imxusbvar.h>
#include <arm/imx/imxgpiovar.h>
#include "locators.h"

#include <dev/usb/ulpireg.h>	/* for test */

static int	imxehci_match(device_t, cfdata_t, void *);
static void	imxehci_attach(device_t, device_t, void *);
						     
uint8_t imxusb_ulpi_read(struct imxehci_softc *sc, int addr);
void imxusb_ulpi_write(struct imxehci_softc *sc, int addr, uint8_t data);
static void ulpi_reset(struct imxehci_softc *sc);



/* attach structures */
CFATTACH_DECL_NEW(imxehci, sizeof(struct imxehci_softc),
    imxehci_match, imxehci_attach, NULL, NULL);

static int
imxehci_match(device_t parent, cfdata_t cf, void *aux)
{
	struct imxusbc_attach_args *aa = aux;
	
	if (aa->aa_unit < 0 || 3 < aa->aa_unit) {
		return 0;
	}
		
	return 1;
}

static void
imxehci_attach(device_t parent, device_t self, void *aux)
{
	struct imxusbc_attach_args *aa = aux;
	struct imxusbc_softc *usbc = device_private(parent);
	struct imxehci_softc *sc = device_private(self);
	ehci_softc_t *hsc = &sc->sc_hsc;
	bus_space_tag_t iot;
	uint16_t hcirev;
	usbd_status r;
	uint32_t id, hwhost, hwdevice;
	const char *comma;
	
	sc->sc_hsc.sc_dev = self;
	iot = sc->sc_iot = sc->sc_hsc.iot = aa->aa_iot;
	sc->sc_unit = aa->aa_unit;
	sc->sc_usbc = usbc;
	hsc->sc_bus.hci_private = sc;

	aprint_normal("\n");

	/* per unit registers */
	if (bus_space_subregion(iot, aa->aa_ioh, 
		aa->aa_unit * IMXUSB_EHCI_SIZE, IMXUSB_EHCI_SIZE,
		&sc->sc_ioh) ||
	    bus_space_subregion(iot, aa->aa_ioh,
		aa->aa_unit * IMXUSB_EHCI_SIZE + IMXUSB_EHCIREGS,
		IMXUSB_EHCI_SIZE - IMXUSB_EHCIREGS,
		&sc->sc_hsc.ioh)) {

		aprint_error_dev(self, "can't subregion\n");
		return;
	}

	id = bus_space_read_4(iot, sc->sc_ioh, IMXUSB_ID);
	hcirev = bus_space_read_2(iot, sc->sc_hsc.ioh, EHCI_HCIVERSION);

	aprint_normal_dev(self,
	    "i.MX USB Controller id=%d revision=%d HCI revision=0x%x\n", 
	    id & (uint32_t)IMXUSB_ID_ID_MASK, 
	    (id & (uint32_t)IMXUSB_ID_REVISION_MASK) >>
	    	IMXUSB_ID_REVISION_SHIFT,
	    hcirev);
			  
	hwhost = bus_space_read_4(iot, sc->sc_ioh, IMXUSB_HWHOST);
	hwdevice = bus_space_read_4(iot, sc->sc_ioh, IMXUSB_HWDEVICE);

	aprint_normal_dev(self, "");

	comma = "";
	if (hwhost & HWHOST_HC) {
		int n_ports = 1 + ((hwhost & HWHOST_NPORT_MASK) >>
		    HWHOST_NPORT_SHIFT);
		aprint_normal("%d host port%s",
		    n_ports, n_ports > 1 ? "s" : "");
		comma = ", ";
	}

	if (hwdevice & HWDEVICE_DC) {
		int n_endpoints = (hwdevice & HWDEVICE_DEVEP_MASK) >>
		    HWDEVICE_DEVEP_SHIFT;
		aprint_normal("%sdevice capable, %d endpoint%s",
		    comma,
		    n_endpoints, n_endpoints > 1 ? "s" : "");
	}
	aprint_normal("\n");

	sc->sc_hsc.sc_bus.dmatag = aa->aa_dmat;

	sc->sc_hsc.sc_offs = bus_space_read_1(iot, sc->sc_hsc.ioh, 
	    EHCI_CAPLENGTH);

	/* Platform dependent setup */
	if (usbc->sc_init_md_hook)
		usbc->sc_init_md_hook(sc);

	
	imxehci_reset(sc);
	imxehci_select_interface(sc, sc->sc_iftype);

	if (sc->sc_iftype == IMXUSBC_IF_ULPI) {
		bus_space_write_4(sc->sc_iot, sc->sc_ioh, IMXUSB_ULPIVIEW, 0);

		aprint_normal_dev(hsc->sc_dev,
		    "ULPI phy VID 0x%04x PID 0x%04x\n",
		    (imxusb_ulpi_read(sc, ULPI_VENDOR_ID_LOW) |
			imxusb_ulpi_read(sc, ULPI_VENDOR_ID_HIGH) << 8),
		    (imxusb_ulpi_read(sc, ULPI_PRODUCT_ID_LOW) |
			imxusb_ulpi_read(sc, ULPI_PRODUCT_ID_HIGH) << 8));

		ulpi_reset(sc);

	}

	imxehci_host_mode(sc);
	
	if (usbc->sc_setup_md_hook)
		usbc->sc_setup_md_hook(sc, IMXUSB_HOST);
	else if (sc->sc_iftype == IMXUSBC_IF_ULPI) {
		imxusb_ulpi_write(sc, ULPI_FUNCTION_CONTROL + ULPI_REG_CLEAR,
		    OTG_CONTROL_IDPULLUP);

		imxusb_ulpi_write(sc, ULPI_OTG_CONTROL + ULPI_REG_SET,
		    OTG_CONTROL_USEEXTVBUSIND |
		    OTG_CONTROL_DRVVBUSEXT |
		    OTG_CONTROL_DRVVBUS |
		    OTG_CONTROL_CHRGVBUS
		    );
	}

	/* Disable interrupts, so we don't get any spurious ones. */
	EOWRITE2(hsc, EHCI_USBINTR, 0);

	intr_establish(aa->aa_irq, IPL_USB, IST_LEVEL, ehci_intr, hsc);

	/* Figure out vendor for root hub descriptor. */
	strlcpy(hsc->sc_vendor, "i.MX", sizeof(hsc->sc_vendor));

	r = ehci_init(hsc);
	if (r != USBD_NORMAL_COMPLETION) {
		aprint_error_dev(self, "init failed, error=%d\n", r);
		return;
	}

	/* Attach usb device. */
	hsc->sc_child = config_found(self, &hsc->sc_bus, usbctlprint);
}




void
imxehci_select_interface(struct imxehci_softc *sc, enum imx_usb_if interface)
{
	uint32_t reg;
	struct ehci_softc *hsc = &sc->sc_hsc;

	reg = EOREAD4(hsc, EHCI_PORTSC(1));
	reg = (reg & ~PORTSC_PTS_MASK) | (interface << PORTSC_PTS_SHIFT);
	EOWRITE4(hsc, EHCI_PORTSC(1), reg);
}


static uint32_t
ulpi_wakeup(struct imxehci_softc *sc, int tout)
{
	uint32_t ulpi_view;
	int i = 0;
	ulpi_view = bus_space_read_4(sc->sc_iot, sc->sc_ioh, IMXUSB_ULPIVIEW);

	if ( !(ulpi_view & ULPI_SS) ) {
		bus_space_write_4(sc->sc_iot, sc->sc_ioh,
		    IMXUSB_ULPIVIEW, ULPI_WU);
		for (i = 0; (tout < 0) || (i < tout); i++) {
			ulpi_view = bus_space_read_4(sc->sc_iot,
			    sc->sc_ioh, IMXUSB_ULPIVIEW);
			if ( !(ulpi_view & ULPI_WU) )
				break;
			delay(1);
		};
	}

	if ((tout > 0) && (i >= tout)) {
		aprint_error_dev(sc->sc_hsc.sc_dev, "%s: timeout\n", __func__);
	}

	return ulpi_view;
}

static uint32_t
ulpi_wait(struct imxehci_softc *sc, int tout)
{
	uint32_t ulpi_view;
	int i;
	ulpi_view = bus_space_read_4(sc->sc_iot, sc->sc_ioh, IMXUSB_ULPIVIEW);

	for (i = 0; (tout < 0) | (i < tout); i++) {
		ulpi_view = bus_space_read_4(sc->sc_iot, sc->sc_ioh,
		    IMXUSB_ULPIVIEW);
		if (!(ulpi_view & ULPI_RUN))
			break;
		delay(1);
	}

	if ((tout > 0) && (i >= tout)) {
		aprint_error_dev(sc->sc_hsc.sc_dev, "%s: timeout\n", __func__);
	}

	return ulpi_view;
}

#define	TIMEOUT	100000
						     
uint8_t
imxusb_ulpi_read(struct imxehci_softc *sc, int addr)
{
	uint32_t data;

	ulpi_wakeup(sc, TIMEOUT);

	data = ULPI_RUN | (addr << ULPI_ADDR_SHIFT);
	bus_space_write_4(sc->sc_iot, sc->sc_ioh, IMXUSB_ULPIVIEW, data);

	data = ulpi_wait(sc, TIMEOUT);

	return (data & ULPI_DATRD_MASK) >> ULPI_DATRD_SHIFT;
}

void
imxusb_ulpi_write(struct imxehci_softc *sc, int addr, uint8_t data)
{
	uint32_t reg;

	ulpi_wakeup(sc, TIMEOUT);

	reg = ULPI_RUN | ULPI_RW | ((addr) << ULPI_ADDR_SHIFT) | data;
	bus_space_write_4(sc->sc_iot, sc->sc_ioh, IMXUSB_ULPIVIEW, reg);

	ulpi_wait(sc, TIMEOUT);

	return;
}

#if 0
static int
ulpi_scratch_test(struct imxehci_softc *sc)
{
	uint32_t ulpi_view;

	ulpi_view = ulpi_wakeup(sc, 1000);
	if (ulpi_view & ULPI_WU) {
		return -1;
	}

	bus_space_write_4(sc->sc_iot, sc->sc_ioh, IMXUSB_ULPIVIEW,
		(ULPI_RUN | ULPI_RW |
		 (ULPI_SCRATCH << ULPI_ADDR_SHIFT) | 0xAA));

	ulpi_view = ulpi_wait(sc, 1000);

	if (ulpi_view & ULPI_RUN) {
		return -1;
	}

	return 0;
}
#endif

static void
ulpi_reset(struct imxehci_softc *sc)
{
	uint8_t data;
	int timo = 1000 * 1000;	/* XXXX: 1sec */

	imxusb_ulpi_write(sc, ULPI_FUNCTION_CONTROL + ULPI_REG_SET,
	    FUNCTION_CONTROL_RESET /*0x20*/);
	do {
		data = imxusb_ulpi_read(sc, ULPI_FUNCTION_CONTROL);
		if (!(data & FUNCTION_CONTROL_RESET))
			break;
		delay(100);
		timo -= 100;
	} while (timo > 0);
	if (timo <= 0) {
		aprint_error_dev(sc->sc_hsc.sc_dev, "%s: reset failed!!\n",
		    __func__);
		return;
	}

	return;
}

void
imxehci_reset(struct imxehci_softc *sc)
{
	u_int32_t reg;
	int i;
	struct ehci_softc *hsc = &sc->sc_hsc;
#define	RESET_TIMEOUT 100

	reg = EOREAD4(hsc, EHCI_USBCMD);
	reg &= ~EHCI_CMD_RS;
	EOWRITE4(hsc, EHCI_USBCMD, reg);

	for (i=0; i < RESET_TIMEOUT; ++i) {
		reg = EOREAD4(hsc, EHCI_USBCMD);
		if ((reg & EHCI_CMD_RS) == 0)
			break;
		usb_delay_ms(&hsc->sc_bus, 1);
	}

	EOWRITE4(hsc, EHCI_USBCMD, reg | EHCI_CMD_HCRESET);
	for (i = 0; i < RESET_TIMEOUT; i++) {
		reg = EOREAD4(hsc, EHCI_USBCMD);
		if ((reg &  EHCI_CMD_HCRESET) == 0)
			break;
		usb_delay_ms(&hsc->sc_bus, 1);
	}
	if (i >= RESET_TIMEOUT) {
		aprint_error_dev(hsc->sc_dev, "reset timeout (%x)\n", reg);
	}

	usb_delay_ms(&hsc->sc_bus, 100);
}

void
imxehci_host_mode(struct imxehci_softc *sc)
{
	struct ehci_softc *hsc = &sc->sc_hsc;
	uint32_t reg;

	reg = EOREAD4(hsc, EHCI_PORTSC(1));
	reg &= ~(EHCI_PS_CSC | EHCI_PS_PEC | EHCI_PS_OCC);
	reg |= EHCI_PS_PP | EHCI_PS_PE;
	EOWRITE4(hsc, EHCI_PORTSC(1), reg);

	reg = bus_space_read_4(sc->sc_iot, sc->sc_ioh, IMXUSB_OTGSC);
	reg |= OTGSC_IDPU;
	reg |= OTGSC_DPIE | OTGSC_IDIE;
	bus_space_write_4(sc->sc_iot, sc->sc_ioh, IMXUSB_OTGSC, reg);

	reg = bus_space_read_4(sc->sc_iot, sc->sc_ioh, IMXUSB_OTGMODE);
	reg |= USBMODE_HOST;
	bus_space_write_4(sc->sc_iot, sc->sc_ioh, IMXUSB_OTGMODE, reg);
}
