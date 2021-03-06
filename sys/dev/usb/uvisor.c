/*	$NetBSD: uvisor.c,v 1.57 2021/08/07 16:19:17 thorpej Exp $	*/

/*
 * Copyright (c) 2000 The NetBSD Foundation, Inc.
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
 * Handspring Visor (Palmpilot compatible PDA) driver
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: uvisor.c,v 1.57 2021/08/07 16:19:17 thorpej Exp $");

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

#include <dev/usb/usbdi.h>
#include <dev/usb/usbdi_util.h>
#include <dev/usb/usbdevs.h>

#include <dev/usb/ucomvar.h>

#ifdef UVISOR_DEBUG
#define DPRINTF(x)	if (uvisordebug) printf x
#define DPRINTFN(n,x)	if (uvisordebug>(n)) printf x
int uvisordebug = 0;
#else
#define DPRINTF(x)
#define DPRINTFN(n,x)
#endif

#define UVISOR_CONFIG_INDEX	0
#define UVISOR_IFACE_INDEX	0

/* From the Linux driver */
/*
 * UVISOR_REQUEST_BYTES_AVAILABLE asks the visor for the number of bytes that
 * are available to be transferred to the host for the specified endpoint.
 * Currently this is not used, and always returns 0x0001
 */
#define UVISOR_REQUEST_BYTES_AVAILABLE		0x01

/*
 * UVISOR_CLOSE_NOTIFICATION is set to the device to notify it that the host
 * is now closing the pipe. An empty packet is sent in response.
 */
#define UVISOR_CLOSE_NOTIFICATION		0x02

/*
 * UVISOR_GET_CONNECTION_INFORMATION is sent by the host during enumeration to
 * get the endpoints used by the connection.
 */
#define UVISOR_GET_CONNECTION_INFORMATION	0x03


/*
 * UVISOR_GET_CONNECTION_INFORMATION returns data in the following format
 */
#define UVISOR_MAX_CONN 8
struct uvisor_connection_info {
	uWord	num_ports;
	struct {
		uByte	port_function_id;
		uByte	port;
	} connections[UVISOR_MAX_CONN];
};
#define UVISOR_CONNECTION_INFO_SIZE 18

/* struct uvisor_connection_info.connection[x].port_function_id defines: */
#define UVISOR_FUNCTION_GENERIC		0x00
#define UVISOR_FUNCTION_DEBUGGER	0x01
#define UVISOR_FUNCTION_HOTSYNC		0x02
#define UVISOR_FUNCTION_CONSOLE		0x03
#define UVISOR_FUNCTION_REMOTE_FILE_SYS	0x04

/*
 * Unknown PalmOS stuff.
 */
#define UVISOR_GET_PALM_INFORMATION		0x04
#define UVISOR_GET_PALM_INFORMATION_LEN		0x44

struct uvisor_palm_connection_info {
	uByte	num_ports;
	uByte	endpoint_numbers_different;
	uWord	reserved1;
	struct {
		uDWord	port_function_id;
		uByte	port;
		uByte	end_point_info;
		uWord	reserved;
	} connections[UVISOR_MAX_CONN];
};



#define UVISORIBUFSIZE 64
#define UVISOROBUFSIZE 1024

struct uvisor_softc {
	device_t		sc_dev;		/* base device */
	struct usbd_device *	sc_udev;	/* device */
	struct usbd_interface *	sc_iface;	/* interface */

	device_t		sc_subdevs[UVISOR_MAX_CONN];
	int			sc_numcon;

	uint16_t		sc_flags;

	bool			sc_dying;
};

static usbd_status uvisor_init(struct uvisor_softc *,
			       struct uvisor_connection_info *,
			       struct uvisor_palm_connection_info *);

static int uvisor_open(void *, int);
static void uvisor_close(void *, int);

static const struct ucom_methods uvisor_methods = {
	.ucom_open = uvisor_open,
	.ucom_close = uvisor_close,
};

struct uvisor_type {
	struct usb_devno	uv_dev;
	uint16_t		uv_flags;
#define PALM4	0x0001
#define VISOR	0x0002

};
static const struct uvisor_type uvisor_devs[] = {
	{{ USB_VENDOR_HANDSPRING, USB_PRODUCT_HANDSPRING_VISOR }, VISOR },
	{{ USB_VENDOR_HANDSPRING, USB_PRODUCT_HANDSPRING_TREO }, PALM4 },
	{{ USB_VENDOR_HANDSPRING, USB_PRODUCT_HANDSPRING_TREO600 }, PALM4 },
	{{ USB_VENDOR_PALM, USB_PRODUCT_PALM_M500 }, PALM4 },
	{{ USB_VENDOR_PALM, USB_PRODUCT_PALM_M505 }, PALM4 },
	{{ USB_VENDOR_PALM, USB_PRODUCT_PALM_M515 }, PALM4 },
	{{ USB_VENDOR_PALM, USB_PRODUCT_PALM_I705 }, PALM4 },
	{{ USB_VENDOR_PALM, USB_PRODUCT_PALM_M125 }, PALM4 },
	{{ USB_VENDOR_PALM, USB_PRODUCT_PALM_M130 }, PALM4 },
	{{ USB_VENDOR_PALM, USB_PRODUCT_PALM_TUNGSTEN_Z }, PALM4 },
	{{ USB_VENDOR_PALM, USB_PRODUCT_PALM_TUNGSTEN_T }, PALM4 },
	{{ USB_VENDOR_PALM, USB_PRODUCT_PALM_ZIRE31 }, PALM4 },
	{{ USB_VENDOR_PALM, USB_PRODUCT_PALM_ZIRE }, PALM4 },
	{{ USB_VENDOR_SONY, USB_PRODUCT_SONY_CLIE_40 }, PALM4 },
	{{ USB_VENDOR_SONY, USB_PRODUCT_SONY_CLIE_41 }, PALM4 },
	{{ USB_VENDOR_SONY, USB_PRODUCT_SONY_CLIE_S360 }, PALM4 },
	{{ USB_VENDOR_SONY, USB_PRODUCT_SONY_CLIE_NX60 }, PALM4 },
	{{ USB_VENDOR_SONY, USB_PRODUCT_SONY_CLIE_35 }, 0 },
/*	{{ USB_VENDOR_SONY, USB_PRODUCT_SONY_CLIE_25 }, PALM4 },*/
};
#define uvisor_lookup(v, p) ((const struct uvisor_type *)usb_lookup(uvisor_devs, v, p))

static int	uvisor_match(device_t, cfdata_t, void *);
static void	uvisor_attach(device_t, device_t, void *);
static void	uvisor_childdet(device_t, device_t);
static int	uvisor_detach(device_t, int);

CFATTACH_DECL2_NEW(uvisor, sizeof(struct uvisor_softc), uvisor_match,
    uvisor_attach, uvisor_detach, NULL, NULL, uvisor_childdet);

static int
uvisor_match(device_t parent, cfdata_t match, void *aux)
{
	struct usb_attach_arg *uaa = aux;

	DPRINTFN(20,("uvisor: vendor=%#x, product=%#x\n",
		     uaa->uaa_vendor, uaa->uaa_product));

	return uvisor_lookup(uaa->uaa_vendor, uaa->uaa_product) != NULL ?
		UMATCH_VENDOR_PRODUCT : UMATCH_NONE;
}

static void
uvisor_attach(device_t parent, device_t self, void *aux)
{
	struct uvisor_softc *sc = device_private(self);
	struct usb_attach_arg *uaa = aux;
	struct usbd_device *dev = uaa->uaa_device;
	struct usbd_interface *iface;
	usb_interface_descriptor_t *id;
	struct uvisor_connection_info coninfo;
	struct uvisor_palm_connection_info palmconinfo;
	usb_endpoint_descriptor_t *ed;
	char *devinfop;
	const char *devname = device_xname(self);
	int i, j, hasin, hasout, port;
	usbd_status err;
	struct ucom_attach_args ucaa;

	DPRINTFN(10,("\nuvisor_attach: sc=%p\n", sc));

	sc->sc_dev = self;
	sc->sc_dying = false;

	aprint_naive("\n");
	aprint_normal("\n");

	devinfop = usbd_devinfo_alloc(dev, 0);
	aprint_normal_dev(self, "%s\n", devinfop);
	usbd_devinfo_free(devinfop);

	/* Move the device into the configured state. */
	err = usbd_set_config_index(dev, UVISOR_CONFIG_INDEX, 1);
	if (err) {
		aprint_error("\n%s: failed to set configuration, err=%s\n",
		       devname, usbd_errstr(err));
		goto bad;
	}

	err = usbd_device2interface_handle(dev, UVISOR_IFACE_INDEX, &iface);
	if (err) {
		aprint_error("\n%s: failed to get interface, err=%s\n",
		       devname, usbd_errstr(err));
		goto bad;
	}

	sc->sc_flags = uvisor_lookup(uaa->uaa_vendor, uaa->uaa_product)->uv_flags;

	if ((sc->sc_flags & (VISOR | PALM4)) == 0) {
		aprint_error_dev(self,
		    "init failed, device type is neither visor nor palm\n");
		goto bad;
	}

	id = usbd_get_interface_descriptor(iface);

	sc->sc_udev = dev;
	sc->sc_iface = iface;

	ucaa.ucaa_ibufsize = UVISORIBUFSIZE;
	ucaa.ucaa_obufsize = UVISOROBUFSIZE;
	ucaa.ucaa_ibufsizepad = UVISORIBUFSIZE;
	ucaa.ucaa_opkthdrlen = 0;
	ucaa.ucaa_device = dev;
	ucaa.ucaa_iface = iface;
	ucaa.ucaa_methods = &uvisor_methods;
	ucaa.ucaa_arg = sc;

	err = uvisor_init(sc, &coninfo, &palmconinfo);
	if (err) {
		aprint_error_dev(self, "init failed, %s\n", usbd_errstr(err));
		goto bad;
	}

	usbd_add_drv_event(USB_EVENT_DRIVER_ATTACH, sc->sc_udev, sc->sc_dev);

	if (sc->sc_flags & VISOR) {
		sc->sc_numcon = UGETW(coninfo.num_ports);
		if (sc->sc_numcon > UVISOR_MAX_CONN)
			sc->sc_numcon = UVISOR_MAX_CONN;

		/* Attach a ucom for each connection. */
		for (i = 0; i < sc->sc_numcon; ++i) {
			switch (coninfo.connections[i].port_function_id) {
			case UVISOR_FUNCTION_GENERIC:
				ucaa.ucaa_info = "Generic";
				break;
			case UVISOR_FUNCTION_DEBUGGER:
				ucaa.ucaa_info = "Debugger";
				break;
			case UVISOR_FUNCTION_HOTSYNC:
				ucaa.ucaa_info = "HotSync";
				break;
			case UVISOR_FUNCTION_REMOTE_FILE_SYS:
				ucaa.ucaa_info = "Remote File System";
				break;
			default:
				ucaa.ucaa_info = "unknown";
				break;
			}
			port = coninfo.connections[i].port;
			ucaa.ucaa_portno = port;
			ucaa.ucaa_bulkin = port | UE_DIR_IN;
			ucaa.ucaa_bulkout = port | UE_DIR_OUT;
			/* Verify that endpoints exist. */
			hasin = 0;
			hasout = 0;
			for (j = 0; j < id->bNumEndpoints; j++) {
				ed = usbd_interface2endpoint_descriptor(iface, j);
				if (ed == NULL)
					break;
				if (UE_GET_ADDR(ed->bEndpointAddress) == port &&
				    (ed->bmAttributes & UE_XFERTYPE) == UE_BULK) {
					if (UE_GET_DIR(ed->bEndpointAddress)
					    == UE_DIR_IN)
						hasin++;
					else
						hasout++;
				}
			}
			if (hasin == 1 && hasout == 1)
				sc->sc_subdevs[i] =
				    config_found(self, &ucaa, ucomprint,
						 CFARGS(.submatch =
						            ucomsubmatch));
			else
				aprint_error_dev(self,
				    "no proper endpoints for port %d (%d,%d)\n",
				    port, hasin, hasout);
		}

	} else {
		sc->sc_numcon = palmconinfo.num_ports;
		if (sc->sc_numcon > UVISOR_MAX_CONN)
			sc->sc_numcon = UVISOR_MAX_CONN;

		/* Attach a ucom for each connection. */
		for (i = 0; i < sc->sc_numcon; ++i) {
			/*
			 * XXX this should copy out 4-char string from the
			 * XXX port_function_id, but where would the string go?
			 * XXX ucaa.ucaa_info is a const char *, not an array.
			 */
			ucaa.ucaa_info = "sync";
			ucaa.ucaa_portno = i;
			if (palmconinfo.endpoint_numbers_different) {
				port = palmconinfo.connections[i].end_point_info;
				ucaa.ucaa_bulkin = (port >> 4) | UE_DIR_IN;
				ucaa.ucaa_bulkout = (port & 0xf) | UE_DIR_OUT;
			} else {
				port = palmconinfo.connections[i].port;
				ucaa.ucaa_bulkin = port | UE_DIR_IN;
				ucaa.ucaa_bulkout = port | UE_DIR_OUT;
			}
			sc->sc_subdevs[i] =
			    config_found(self, &ucaa, ucomprint,
					 CFARGS(.submatch = ucomsubmatch));
		}
	}

	return;

bad:
	DPRINTF(("uvisor_attach: ATTACH ERROR\n"));
	sc->sc_dying = true;
	return;
}

static void
uvisor_childdet(device_t self, device_t child)
{
	int i;
	struct uvisor_softc *sc = device_private(self);

	for (i = 0; i < sc->sc_numcon; i++) {
		if (sc->sc_subdevs[i] == child)
			break;
	}
	KASSERT(i < sc->sc_numcon);
	sc->sc_subdevs[i] = NULL;
}

static int
uvisor_detach(device_t self, int flags)
{
	struct uvisor_softc *sc = device_private(self);
	int rv = 0;
	int i;

	DPRINTF(("uvisor_detach: sc=%p flags=%d\n", sc, flags));

	sc->sc_dying = true;

	for (i = 0; i < sc->sc_numcon; i++) {
		if (sc->sc_subdevs[i] != NULL) {
			rv |= config_detach(sc->sc_subdevs[i], flags);
			sc->sc_subdevs[i] = NULL;
		}
	}
	if (sc->sc_udev != NULL)
		usbd_add_drv_event(USB_EVENT_DRIVER_DETACH, sc->sc_udev,
		    sc->sc_dev);

	return rv;
}

static usbd_status
uvisor_init(struct uvisor_softc *sc, struct uvisor_connection_info *ci,
    struct uvisor_palm_connection_info *cpi)
{
	usbd_status err;
	usb_device_request_t req;
	int actlen;
	uWord avail;

	if (sc->sc_flags & VISOR) {
		DPRINTF(("uvisor_init: getting Visor connection info\n"));
		req.bmRequestType = UT_READ_VENDOR_ENDPOINT;
		req.bRequest = UVISOR_GET_CONNECTION_INFORMATION;
		USETW(req.wValue, 0);
		USETW(req.wIndex, 0);
		USETW(req.wLength, UVISOR_CONNECTION_INFO_SIZE);
		err = usbd_do_request_flags(sc->sc_udev, &req, ci,
		    USBD_SHORT_XFER_OK, &actlen, USBD_DEFAULT_TIMEOUT);
		if (err)
			return err;
	}

	if (sc->sc_flags & PALM4) {
		DPRINTF(("uvisor_init: getting Palm connection info\n"));
		req.bmRequestType = UT_READ_VENDOR_ENDPOINT;
		req.bRequest = UVISOR_GET_PALM_INFORMATION;
		USETW(req.wValue, 0);
		USETW(req.wIndex, 0);
		USETW(req.wLength, UVISOR_GET_PALM_INFORMATION_LEN);
		err = usbd_do_request_flags(sc->sc_udev, &req, cpi,
		    USBD_SHORT_XFER_OK, &actlen, USBD_DEFAULT_TIMEOUT);
		if (err)
			return err;
	}

	DPRINTF(("uvisor_init: getting available bytes\n"));
	req.bmRequestType = UT_READ_VENDOR_ENDPOINT;
	req.bRequest = UVISOR_REQUEST_BYTES_AVAILABLE;
	USETW(req.wValue, 0);
	USETW(req.wIndex, 5);
	USETW(req.wLength, sizeof(avail));
	err = usbd_do_request(sc->sc_udev, &req, &avail);
	if (err)
		return err;
	DPRINTF(("uvisor_init: avail=%d\n", UGETW(avail)));

	DPRINTF(("uvisor_init: done\n"));
	return err;
}

static int
uvisor_open(void *arg, int portno)
{
	struct uvisor_softc *sc = arg;

	if (sc->sc_dying)
		return EIO;

	return 0;
}

void
uvisor_close(void *addr, int portno)
{
	struct uvisor_softc *sc = addr;
	usb_device_request_t req;
	struct uvisor_connection_info coninfo; /* XXX ? */
	int actlen;

	if (sc->sc_dying)
		return;

	req.bmRequestType = UT_READ_VENDOR_ENDPOINT; /* XXX read? */
	req.bRequest = UVISOR_CLOSE_NOTIFICATION;
	USETW(req.wValue, 0);
	USETW(req.wIndex, 0);
	USETW(req.wLength, UVISOR_CONNECTION_INFO_SIZE);
	(void)usbd_do_request_flags(sc->sc_udev, &req, &coninfo,
		  USBD_SHORT_XFER_OK, &actlen, USBD_DEFAULT_TIMEOUT);
}
