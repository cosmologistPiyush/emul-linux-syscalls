/*	$NetBSD: uipaq.c,v 1.30 2021/08/07 16:19:17 thorpej Exp $	*/
/*	$OpenBSD: uipaq.c,v 1.1 2005/06/17 23:50:33 deraadt Exp $	*/

/*
 * Copyright (c) 2000-2005 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Lennart Augustsson (lennart@augustsson.net) at
 * Carlstedt Research & Technology.
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

/*
 * iPAQ driver
 *
 * 19 July 2003:	Incorporated changes suggested by Sam Lawrance from
 * 			the uppc module
 *
 *
 * Contact isis@cs.umd.edu if you have any questions/comments about this driver
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: uipaq.c,v 1.30 2021/08/07 16:19:17 thorpej Exp $");

#ifdef _KERNEL_OPT
#include "opt_usb.h"
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/device.h>
#include <sys/conf.h>
#include <sys/tty.h>

#include <dev/usb/usb.h>

#include <dev/usb/usbcdc.h>	/*UCDC_* stuff */

#include <dev/usb/usbdi.h>
#include <dev/usb/usbdi_util.h>
#include <dev/usb/usbdevs.h>

#include <dev/usb/ucomvar.h>

#ifdef UIPAQ_DEBUG
#define DPRINTF(x)	if (uipaqdebug) printf x
#define DPRINTFN(n,x)	if (uipaqdebug>(n)) printf x
int uipaqdebug = 0;
#else
#define DPRINTF(x)
#define DPRINTFN(n,x)
#endif

#define UIPAQ_CONFIG_NO		1
#define UIPAQ_IFACE_INDEX	0

#define UIPAQIBUFSIZE 1024
#define UIPAQOBUFSIZE 1024

struct uipaq_softc {
	device_t		sc_dev;		/* base device */
	struct usbd_device *	sc_udev;	/* device */
	struct usbd_interface *	sc_iface;	/* interface */

	device_t		sc_subdev;	/* ucom uses that */
	uint16_t		sc_lcr;		/* state for DTR/RTS */

	uint16_t		sc_flags;

	bool			sc_dying;
};

/* Callback routines */
static void	uipaq_set(void *, int, int, int);
static int	uipaq_open(void *, int);


/* Support routines. */
/* based on uppc module by Sam Lawrance */
static void	uipaq_dtr(struct uipaq_softc *, int);
static void	uipaq_rts(struct uipaq_softc *, int);
static void	uipaq_break(struct uipaq_softc *, int);


static const struct ucom_methods uipaq_methods = {
	.ucom_set = uipaq_set,
	.ucom_open = uipaq_open,
};

struct uipaq_type {
	struct usb_devno	uv_dev;
	uint16_t		uv_flags;
};

static const struct uipaq_type uipaq_devs[] = {
	{{ USB_VENDOR_HP, USB_PRODUCT_HP_2215 }, 0 },
	{{ USB_VENDOR_HP, USB_PRODUCT_HP_568J }, 0},
	{{ USB_VENDOR_COMPAQ, USB_PRODUCT_COMPAQ_IPAQPOCKETPC} , 0},
	{{ USB_VENDOR_CASIO, USB_PRODUCT_CASIO_BE300} , 0},
	{{ USB_VENDOR_SHARP, USB_PRODUCT_SHARP_WS007SH} , 0},
	{{ USB_VENDOR_SHARP, USB_PRODUCT_SHARP_WS011SH} , 0}
};

#define uipaq_lookup(v, p) ((const struct uipaq_type *)usb_lookup(uipaq_devs, v, p))

static int uipaq_match(device_t, cfdata_t, void *);
static void uipaq_attach(device_t, device_t, void *);
static void uipaq_childdet(device_t, device_t);
static int uipaq_detach(device_t, int);

CFATTACH_DECL2_NEW(uipaq, sizeof(struct uipaq_softc), uipaq_match,
    uipaq_attach, uipaq_detach, NULL, NULL, uipaq_childdet);

static int
uipaq_match(device_t parent, cfdata_t match, void *aux)
{
	struct usb_attach_arg *uaa = aux;

	DPRINTFN(20,("uipaq: vendor=%#x, product=%#x\n",
	    uaa->uaa_vendor, uaa->uaa_product));

	return uipaq_lookup(uaa->uaa_vendor, uaa->uaa_product) != NULL ?
	    UMATCH_VENDOR_PRODUCT : UMATCH_NONE;
}

static void
uipaq_attach(device_t parent, device_t self, void *aux)
{
	struct uipaq_softc *sc = device_private(self);
	struct usb_attach_arg *uaa = aux;
	struct usbd_device *dev = uaa->uaa_device;
	struct usbd_interface *iface;
	usb_interface_descriptor_t *id;
	usb_endpoint_descriptor_t *ed;
	char *devinfop;
	const char *devname = device_xname(self);
	int i;
	usbd_status err;
	struct ucom_attach_args ucaa;

	DPRINTFN(10,("\nuipaq_attach: sc=%p\n", sc));

	sc->sc_dev = self;
	sc->sc_dying = false;

	aprint_naive("\n");
	aprint_normal("\n");

	devinfop = usbd_devinfo_alloc(dev, 0);
	aprint_normal_dev(self, "%s\n", devinfop);
	usbd_devinfo_free(devinfop);

	/* Move the device into the configured state. */
	err = usbd_set_config_no(dev, UIPAQ_CONFIG_NO, 1);
	if (err) {
		aprint_error_dev(self, "failed to set configuration, err=%s\n",
		    usbd_errstr(err));
		goto bad;
	}

	err = usbd_device2interface_handle(dev, UIPAQ_IFACE_INDEX, &iface);
	if (err) {
		aprint_error("\n%s: failed to get interface, err=%s\n",
		    devname, usbd_errstr(err));
		goto bad;
	}

	sc->sc_flags = uipaq_lookup(uaa->uaa_vendor, uaa->uaa_product)->uv_flags;

	id = usbd_get_interface_descriptor(iface);

	sc->sc_udev = dev;
	sc->sc_iface = iface;

	ucaa.ucaa_ibufsize = UIPAQIBUFSIZE;
	ucaa.ucaa_obufsize = UIPAQOBUFSIZE;
	ucaa.ucaa_ibufsizepad = UIPAQIBUFSIZE;
	ucaa.ucaa_opkthdrlen = 0;
	ucaa.ucaa_device = dev;
	ucaa.ucaa_iface = iface;
	ucaa.ucaa_methods = &uipaq_methods;
	ucaa.ucaa_arg = sc;
	ucaa.ucaa_portno = UCOM_UNK_PORTNO;
	ucaa.ucaa_info = "Generic";

/*	err = uipaq_init(sc);
	if (err) {
		printf("%s: init failed, %s\n", device_xname(sc->sc_dev),
		    usbd_errstr(err));
		goto bad;
	}*/

	usbd_add_drv_event(USB_EVENT_DRIVER_ATTACH, sc->sc_udev, sc->sc_dev);

	ucaa.ucaa_bulkin = ucaa.ucaa_bulkout = -1;
	for (i=0; i<id->bNumEndpoints; i++) {
		ed = usbd_interface2endpoint_descriptor(iface, i);
		if (ed == NULL) {
			aprint_error_dev(self,
			    "no endpoint descriptor for %d\n", i);
			goto bad;
		}
		if (UE_GET_DIR(ed->bEndpointAddress) == UE_DIR_IN &&
		    (ed->bmAttributes & UE_XFERTYPE) == UE_BULK) {
			ucaa.ucaa_bulkin = ed->bEndpointAddress;
		} else if (UE_GET_DIR(ed->bEndpointAddress) == UE_DIR_OUT &&
		    (ed->bmAttributes & UE_XFERTYPE) == UE_BULK) {
			ucaa.ucaa_bulkout = ed->bEndpointAddress;
		}
	}
	if (ucaa.ucaa_bulkin == -1 || ucaa.ucaa_bulkout == -1) {
		aprint_error_dev(self, "no proper endpoints found (%d,%d) \n",
		    ucaa.ucaa_bulkin, ucaa.ucaa_bulkout);
		return;
	}

	sc->sc_subdev = config_found(self, &ucaa, ucomprint,
	    CFARGS(.submatch = ucomsubmatch));

	return;

bad:
	DPRINTF(("uipaq_attach: ATTACH ERROR\n"));
	sc->sc_dying = true;
	return;
}


void
uipaq_dtr(struct uipaq_softc* sc, int onoff)
{
	usb_device_request_t req;
	usbd_status err;
	int retries = 3;

	DPRINTF(("%s: uipaq_dtr: onoff=%x\n", device_xname(sc->sc_dev), onoff));

	/* Avoid sending unnecessary requests */
	if (onoff && (sc->sc_lcr & UCDC_LINE_DTR))
		return;
	if (!onoff && !(sc->sc_lcr & UCDC_LINE_DTR))
		return;

	/* Other parameters depend on reg */
	req.bmRequestType = UT_WRITE_CLASS_INTERFACE;
	req.bRequest = UCDC_SET_CONTROL_LINE_STATE;
	sc->sc_lcr = onoff ? sc->sc_lcr | UCDC_LINE_DTR
	    : sc->sc_lcr & ~UCDC_LINE_DTR;
	USETW(req.wValue, sc->sc_lcr);
	USETW(req.wIndex, 0x0);
	USETW(req.wLength, 0);

	/* Fire off the request a few times if necessary */
	while (retries) {
		err = usbd_do_request(sc->sc_udev, &req, NULL);
		if (!err)
			break;
		retries--;
	}
}


void
uipaq_rts(struct uipaq_softc* sc, int onoff)
{
	usb_device_request_t req;
	usbd_status err;
	int retries = 3;

	DPRINTF(("%s: uipaq_rts: onoff=%x\n", device_xname(sc->sc_dev), onoff));

	/* Avoid sending unnecessary requests */
	if (onoff && (sc->sc_lcr & UCDC_LINE_RTS)) return;
	if (!onoff && !(sc->sc_lcr & UCDC_LINE_RTS)) return;

	req.bmRequestType = UT_WRITE_CLASS_INTERFACE;
	req.bRequest = UCDC_SET_CONTROL_LINE_STATE;
	sc->sc_lcr = onoff ? sc->sc_lcr | UCDC_LINE_RTS
	    : sc->sc_lcr & ~UCDC_LINE_RTS;
	USETW(req.wValue, sc->sc_lcr);
	USETW(req.wIndex, 0x0);
	USETW(req.wLength, 0);

	while (retries) {
		err = usbd_do_request(sc->sc_udev, &req, NULL);
		if (!err)
			break;
		retries--;
	}
}


void
uipaq_break(struct uipaq_softc* sc, int onoff)
{
	usb_device_request_t req;
	usbd_status err;
	int retries = 3;

	DPRINTF(("%s: uipaq_break: onoff=%x\n", device_xname(sc->sc_dev),
	    onoff));

	req.bmRequestType = UT_WRITE_CLASS_INTERFACE;
	req.bRequest = UCDC_SEND_BREAK;

	USETW(req.wValue, onoff ? UCDC_BREAK_ON : UCDC_BREAK_OFF);
	USETW(req.wIndex, 0x0);
	USETW(req.wLength, 0);

	while (retries) {
		err = usbd_do_request(sc->sc_udev, &req, NULL);
		if (!err)
			break;
		retries--;
	}
}


void
uipaq_set(void *addr, int portno, int reg, int onoff)
{
	struct uipaq_softc* sc = addr;

	if (sc->sc_dying)
		return;

	switch (reg) {
	case UCOM_SET_DTR:
		uipaq_dtr(addr, onoff);
		break;
	case UCOM_SET_RTS:
		uipaq_rts(addr, onoff);
		break;
	case UCOM_SET_BREAK:
		uipaq_break(addr, onoff);
		break;
	default:
		aprint_error_dev(sc->sc_dev,
		    "unhandled set request: reg=%x onoff=%x\n", reg, onoff);
		return;
	}
}

static int
uipaq_open(void *arg, int portno)
{
	struct uipaq_softc *sc = arg;

	if (sc->sc_dying)
		return EIO;

	return 0;
}

static void
uipaq_childdet(device_t self, device_t child)
{
	struct uipaq_softc *sc = device_private(self);

	KASSERT(sc->sc_subdev == child);
	sc->sc_subdev = NULL;
}

static int
uipaq_detach(device_t self, int flags)
{
	struct uipaq_softc *sc = device_private(self);
	int rv = 0;

	DPRINTF(("uipaq_detach: sc=%p flags=%d\n", sc, flags));

	sc->sc_dying = true;

	if (sc->sc_subdev != NULL) {
		rv |= config_detach(sc->sc_subdev, flags);
		sc->sc_subdev = NULL;
	}
	if (sc->sc_udev != NULL)
		usbd_add_drv_event(USB_EVENT_DRIVER_DETACH, sc->sc_udev,
		    sc->sc_dev);

	return rv;
}
