/*	$NetBSD: lcong48.c,v 1.4 1998/01/09 03:15:37 perry Exp $	*/

/*
 * Copyright (c) 1993 Martin Birgmeier
 * All rights reserved.
 *
 * You may redistribute unmodified or modified versions of this source
 * code provided that the above copyright notice and this and the
 * following conditions are retained.
 *
 * This software is provided ``as is'', and comes with no warranties
 * of any kind. I shall in no event be liable for anything that happens
 * to anyone/anything when using this software.
 */

#include "namespace.h"
#include "rand48.h"

#ifdef __weak_alias
__weak_alias(lcong48,_lcong48);
#endif

void
lcong48(unsigned short p[7])
{
	__rand48_seed[0] = p[0];
	__rand48_seed[1] = p[1];
	__rand48_seed[2] = p[2];
	__rand48_mult[0] = p[3];
	__rand48_mult[1] = p[4];
	__rand48_mult[2] = p[5];
	__rand48_add = p[6];
}
