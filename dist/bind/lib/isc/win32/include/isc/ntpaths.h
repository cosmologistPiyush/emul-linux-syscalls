/*	$NetBSD: ntpaths.h,v 1.1.1.2 2005/12/21 19:59:17 christos Exp $	*/

/*
 * Copyright (C) 2000, 2001  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* Id: ntpaths.h,v 1.12.2.1 2001/09/04 19:36:33 gson Exp */

/*
 * Windows-specific path definitions
 * These routines are used to set up and return system-specific path
 * information about the files enumerated in NtPaths
 */

#ifndef ISC_NTPATHS_H
#define ISC_NTPATHS_H

#include <isc/lang.h>

/*
 * Index of paths needed
 */
enum NtPaths {
	NAMED_CONF_PATH,
	LWRES_CONF_PATH,
	RESOLV_CONF_PATH,
	RNDC_CONF_PATH,
	NAMED_PID_PATH,
	LWRESD_PID_PATH,
	LOCAL_STATE_DIR,
	SYS_CONF_DIR,
	RNDC_KEY_PATH
};

/*
 * Define macros to get the path of the config files
 */
#define NAMED_CONFFILE isc_ntpaths_get(NAMED_CONF_PATH)
#define RNDC_CONFFILE isc_ntpaths_get(RNDC_CONF_PATH)
#define RNDC_KEYFILE isc_ntpaths_get(RNDC_KEY_PATH)
#define RESOLV_CONF isc_ntpaths_get(RESOLV_CONF_PATH)


/*
 * Information about where the files are on disk
 */
#define NS_LOCALSTATEDIR	"/dns/bin"
#define NS_SYSCONFDIR		"/dns/etc"

ISC_LANG_BEGINDECLS

void
isc_ntpaths_init(void);

char *
isc_ntpaths_get(int);

ISC_LANG_ENDDECLS

#endif /* ISC_NTPATHS_H */
