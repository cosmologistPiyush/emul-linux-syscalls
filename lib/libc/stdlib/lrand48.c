/*	$NetBSD: lrand48.c,v 1.5 1998/01/09 03:15:38 perry Exp $	*/

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
__weak_alias(lrand48,_lrand48);
#endif

long
lrand48(void)
{
	__dorand48(__rand48_seed);
	return ((long) __rand48_seed[2] << 15) + ((long) __rand48_seed[1] >> 1);
}
