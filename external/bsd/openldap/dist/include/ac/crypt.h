/* Generic crypt.h */
/* $OpenLDAP: pkg/ldap/include/ac/crypt.h,v 1.10.2.3 2008/02/11 23:26:40 kurt Exp $ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2008 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */

#ifndef _AC_CRYPT_H
#define _AC_CRYPT_H

#include <ac/unistd.h>

/* crypt() may be defined in a separate include file */
#ifdef HAVE_CRYPT_H
#	include <crypt.h>
#else
	extern char *(crypt)();
#endif

#endif /* _AC_CRYPT_H */
