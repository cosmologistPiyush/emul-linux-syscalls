/*	$NetBSD: main.h,v 1.1.1.2 2005/12/21 19:51:21 christos Exp $	*/

/*
 * Copyright (C) 1999-2002  Internet Software Consortium.
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

/* Id: main.h,v 1.8.2.2 2002/08/05 06:57:03 marka Exp */

#ifndef NAMED_MAIN_H
#define NAMED_MAIN_H 1

void
ns_main_earlyfatal(const char *format, ...) ISC_FORMAT_PRINTF(1, 2);

void
ns_main_earlywarning(const char *format, ...) ISC_FORMAT_PRINTF(1, 2);

#endif /* NAMED_MAIN_H */
