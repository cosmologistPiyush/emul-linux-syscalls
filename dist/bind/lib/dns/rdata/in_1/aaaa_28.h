/*	$NetBSD: aaaa_28.h,v 1.1.1.2 2005/12/21 19:58:39 christos Exp $	*/

/*
 * Copyright (C) 1999-2001  Internet Software Consortium.
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

#ifndef IN_1_AAAA_28_H
#define IN_1_AAAA_28_H 1

/* Id: aaaa_28.h,v 1.16 2001/01/09 21:55:06 bwelling Exp */

/* RFC 1886 */

typedef struct dns_rdata_in_aaaa {
	dns_rdatacommon_t	common;
	struct in6_addr		in6_addr;
} dns_rdata_in_aaaa_t;

#endif /* IN_1_AAAA_28_H */
