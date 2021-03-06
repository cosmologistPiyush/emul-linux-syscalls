/*	$NetBSD: bitmap.h,v 1.13 2021/12/19 12:21:30 riastradh Exp $	*/

/*-
 * Copyright (c) 2018 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Taylor R. Campbell.
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

#ifndef _LINUX_BITMAP_H_
#define _LINUX_BITMAP_H_

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>

#include <linux/slab.h>

/*
 * bitmap_zero(bitmap, nbits)
 *
 *	Zero a bitmap that was allocated to have nbits bits.  Yes, this
 *	zeros bits past nbits.
 */
static inline void
bitmap_zero(unsigned long *bitmap, size_t nbits)
{
	const size_t bpl = NBBY * sizeof(*bitmap);
	size_t n = howmany(nbits, bpl);

	memset(bitmap, 0, n * sizeof(*bitmap));
}

/*
 * bitmap_empty(bitmap, nbits)
 *
 *	Return true if all bits at 0, 1, 2, ..., nbits-2, nbits-1 are
 *	0, or false if any of them is 1.
 */
static inline bool
bitmap_empty(const unsigned long *bitmap, size_t nbits)
{
	const size_t bpl = NBBY * sizeof(*bitmap);

	for (; nbits >= bpl; nbits -= bpl) {
		if (*bitmap++)
			return false;
	}

	if (nbits) {
		if (*bitmap & ~(~0UL << nbits))
			return false;
	}

	return true;
}

/*
 * bitmap_weight(bitmap, nbits)
 *
 *	Compute the number of 1 bits at 0, 1, 2, ..., nbits-2, nbits-1.
 */
static inline int
bitmap_weight(const unsigned long *bitmap, size_t nbits)
{
	const size_t bpl = NBBY * sizeof(*bitmap);
	int weight = 0;

	for (; nbits >= bpl; nbits -= bpl)
		weight += popcountl(*bitmap++);
	if (nbits)
		weight += popcountl(*bitmap & ~(~0UL << nbits));

	return weight;
}

/*
 * bitmap_set(bitmap, startbit, nbits)
 *
 *	Set bits at startbit, startbit+1, ..., startbit+nbits-2,
 *	startbit+nbits-1 to 1.
 */
static inline void
bitmap_set(unsigned long *bitmap, size_t startbit, size_t nbits)
{
	const size_t bpl = NBBY * sizeof(*bitmap);
	unsigned long *p = bitmap + startbit/bpl;
	unsigned initial = startbit%bpl;

	/* Handle an initial odd word if any.  */
	if (initial) {
		/* Does the whole thing fit in a single word?  */
		if (nbits <= bpl - initial) {
			/* Yes: just set nbits starting at initial.  */
			*p |= ~(~0ULL << nbits) << initial;
			return;
		}
		/* Nope: set all bits above initial, and advance.  */
		*p++ |= ~0ULL << initial;
		nbits -= bpl - initial;
	}

	/* Set the middle part to all bits 1.  */
	for (; nbits >= bpl; nbits -= bpl)
		*p++ = ~0UL;

	/* Handle a final odd word if any by setting its low nbits.  */
	if (nbits)
		*p |= ~(~0ULL << nbits);
}

/*
 * bitmap_clear(bitmap, startbit, nbits)
 *
 *	Clear bits at startbit, startbit+1, ..., startbit+nbits-2,
 *	startbit+nbits-1, replacing them by 0.
 */
static inline void
bitmap_clear(unsigned long *bitmap, size_t startbit, size_t nbits)
{
	const size_t bpl = NBBY * sizeof(*bitmap);
	unsigned long *p = bitmap + startbit/bpl;
	unsigned initial = startbit%bpl;

	/* Handle an initial odd word if any.  */
	if (initial) {
		/* Does the whole thing fit in a single word?  */
		if (nbits <= bpl - initial) {
			/* Yes: just clear nbits starting at initial.  */
			*p &= ~(~(~0ULL << nbits) << initial);
			return;
		}
		/* Nope: clear all bits above initial, and advance.  */
		*p++ &= ~(~0ULL << initial);
		nbits -= bpl - initial;
	}

	/* Zero the middle part.  */
	for (; nbits >= bpl; nbits -= bpl)
		*p++ = 0UL;

	/* Handle a final odd word if any by clearing its low nbits.  */
	if (nbits)
		*p &= ~0ULL << nbits;
}

/*
 * bitmap_copy(dst, src, nbits)
 *
 *	Copy the bitmap from src to dst.  dst and src may alias (but
 *	why would you bother?).
 */
static inline void
bitmap_copy(unsigned long *dst, const unsigned long *src, size_t nbits)
{
	const size_t bpl = NBBY * sizeof(unsigned long);
	size_t n = howmany(nbits, bpl);

	while (n --> 0)
		*dst++ = *src++;
}

/*
 * bitmap_complement(dst, src, nbits)
 *
 *	Set dst to the the bitwise NOT of src.  dst and src may alias.
 */
static inline void
bitmap_complement(unsigned long *dst, const unsigned long *src, size_t nbits)
{
	const size_t bpl = NBBY * sizeof(unsigned long);
	size_t n = howmany(nbits, bpl);

	while (n --> 0)
		*dst++ = ~*src++;
}

/*
 * bitmap_and(dst, src1, src2, nbits)
 *
 *	Set dst to be the bitwise AND of src1 and src2, all bitmaps
 *	allocated to have nbits bits.  Yes, this modifies bits past
 *	nbits.  Any pair of {dst, src1, src2} may be aliases.
 */
static inline void
bitmap_and(unsigned long *dst, const unsigned long *src1,
    const unsigned long *src2, size_t nbits)
{
	const size_t bpl = NBBY * sizeof(unsigned long);
	size_t n = howmany(nbits, bpl);

	while (n --> 0)
		*dst++ = *src1++ & *src2++;
}

/*
 * bitmap_andnot(dst, src1, src2, nbits)
 *
 *	Set dst to be the bitwise AND of src1 and ~src2, all bitmaps
 *	allocated to have nbits bits.  Yes, this modifies bits past
 *	nbits.  Any pair of {dst, src1, src2} may be aliases.
 */
static inline void
bitmap_andnot(unsigned long *dst, const unsigned long *src1,
    const unsigned long *src2, size_t nbits)
{
	const size_t bpl = NBBY * sizeof(unsigned long);
	size_t n = howmany(nbits, bpl);

	while (n --> 0)
		*dst++ = *src1++ & ~*src2++;
}

/*
 * bitmap_or(dst, src1, src2, nbits)
 *
 *	Set dst to be the bitwise inclusive-OR of src1 and src2, all
 *	bitmaps allocated to have nbits bits.  Yes, this modifies bits
 *	past nbits.  Any pair of {dst, src1, src2} may be aliases.
 */
static inline void
bitmap_or(unsigned long *dst, const unsigned long *src1,
    const unsigned long *src2, size_t nbits)
{
	const size_t bpl = NBBY * sizeof(unsigned long);
	size_t n = howmany(nbits, bpl);

	while (n --> 0)
		*dst++ = *src1++ | *src2++;
}

static inline unsigned long *
bitmap_zalloc(size_t nbits, gfp_t gfp)
{
	const size_t bpl = NBBY * sizeof(unsigned long);
	size_t n = howmany(nbits, bpl);

	return kcalloc(n, sizeof(unsigned long), gfp);
}

static inline void
bitmap_free(unsigned long *bitmap)
{

	kfree(bitmap);
}

#endif  /* _LINUX_BITMAP_H_ */
