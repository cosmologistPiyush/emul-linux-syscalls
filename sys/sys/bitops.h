/*	$NetBSD: bitops.h,v 1.4 2010/03/20 12:54:42 joerg Exp $	*/

/*-
 * Copyright (c) 2007, 2010 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Christos Zoulas and Joerg Sonnenberger.
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
#ifndef _SYS_BITOPS_H_
#define _SYS_BITOPS_H_

#include <sys/stdint.h>

/*
 * Find First Set functions
 */
#ifndef ffs32
static __inline int __unused
ffs32(uint32_t _n)
{
	int _v;

	if (!_n)
		return 0;

	_v = 1;
	if ((_n & 0x0000FFFFU) == 0) {
		_n >>= 16;
		_v += 16;
	}
	if ((_n & 0x000000FFU) == 0) {
		_n >>= 8;
		_v += 8;
	}
	if ((_n & 0x0000000FU) == 0) {
		_n >>= 4;
		_v += 4;
	}
	if ((_n & 0x00000003U) == 0) {
		_n >>= 2;
		_v += 2;
	}
	if ((_n & 0x00000001U) == 0) {
		_n >>= 1;
		_v += 1;
	}
	return _v;
}
#endif

#ifndef ffs64
static __inline int __unused
ffs64(uint64_t _n)
{
	int _v;

	if (!_n)
		return 0;

	_v = 1;
	if ((_n & 0x00000000FFFFFFFFULL) == 0) {
		_n >>= 32;
		_v += 32;
	}
	if ((_n & 0x000000000000FFFFULL) == 0) {
		_n >>= 16;
		_v += 16;
	}
	if ((_n & 0x00000000000000FFULL) == 0) {
		_n >>= 8;
		_v += 8;
	}
	if ((_n & 0x000000000000000FULL) == 0) {
		_n >>= 4;
		_v += 4;
	}
	if ((_n & 0x0000000000000003ULL) == 0) {
		_n >>= 2;
		_v += 2;
	}
	if ((_n & 0x0000000000000001ULL) == 0) {
		_n >>= 1;
		_v += 1;
	}
	return _v;
}
#endif

/*
 * Find Last Set functions
 */
#ifndef fls32
static __inline int __unused
fls32(uint32_t _n)
{
	int _v;

	if (!_n)
		return 0;

	_v = 32;
	if ((_n & 0xFFFF0000U) == 0) {
		_n <<= 16;
		_v -= 16;
	}
	if ((_n & 0xFF000000U) == 0) {
		_n <<= 8;
		_v -= 8;
	}
	if ((_n & 0xF0000000U) == 0) {
		_n <<= 4;
		_v -= 4;
	}
	if ((_n & 0xC0000000U) == 0) {
		_n <<= 2;
		_v -= 2;
	}
	if ((_n & 0x80000000U) == 0) {
		_n <<= 1;
		_v -= 1;
	}
	return _v;
}
#endif

#ifndef fls64
static __inline int __unused
fls64(uint64_t _n)
{
	int _v;

	if (!_n)
		return 0;

	_v = 64;
	if ((_n & 0xFFFFFFFF00000000ULL) == 0) {
		_n <<= 32;
		_v -= 32;
	}
	if ((_n & 0xFFFF000000000000ULL) == 0) {
		_n <<= 16;
		_v -= 16;
	}
	if ((_n & 0xFF00000000000000ULL) == 0) {
		_n <<= 8;
		_v -= 8;
	}
	if ((_n & 0xF000000000000000ULL) == 0) {
		_n <<= 4;
		_v -= 4;
	}
	if ((_n & 0xC000000000000000ULL) == 0) {
		_n <<= 2;
		_v -= 2;
	}
	if ((_n & 0x8000000000000000ULL) == 0) {
		_n <<= 1;
		_v -= 1;
	}
	return _v;
}
#endif

/*
 * Integer logarithm, returns -1 on error. Inspired by the linux
 * version written by David Howells.
 */
#define _ilog2_helper(_n, _x)	((_n) & (1ULL << (_x))) ? _x :
#define ilog2(_n) \
( \
	__builtin_constant_p(_n) ? ( \
	_ilog2_helper(_n, 63) \
	_ilog2_helper(_n, 62) \
	_ilog2_helper(_n, 61) \
	_ilog2_helper(_n, 60) \
	_ilog2_helper(_n, 59) \
	_ilog2_helper(_n, 58) \
	_ilog2_helper(_n, 57) \
	_ilog2_helper(_n, 56) \
	_ilog2_helper(_n, 55) \
	_ilog2_helper(_n, 54) \
	_ilog2_helper(_n, 53) \
	_ilog2_helper(_n, 52) \
	_ilog2_helper(_n, 51) \
	_ilog2_helper(_n, 50) \
	_ilog2_helper(_n, 49) \
	_ilog2_helper(_n, 48) \
	_ilog2_helper(_n, 47) \
	_ilog2_helper(_n, 46) \
	_ilog2_helper(_n, 45) \
	_ilog2_helper(_n, 44) \
	_ilog2_helper(_n, 43) \
	_ilog2_helper(_n, 42) \
	_ilog2_helper(_n, 41) \
	_ilog2_helper(_n, 40) \
	_ilog2_helper(_n, 39) \
	_ilog2_helper(_n, 38) \
	_ilog2_helper(_n, 37) \
	_ilog2_helper(_n, 36) \
	_ilog2_helper(_n, 35) \
	_ilog2_helper(_n, 34) \
	_ilog2_helper(_n, 33) \
	_ilog2_helper(_n, 32) \
	_ilog2_helper(_n, 31) \
	_ilog2_helper(_n, 30) \
	_ilog2_helper(_n, 29) \
	_ilog2_helper(_n, 28) \
	_ilog2_helper(_n, 27) \
	_ilog2_helper(_n, 26) \
	_ilog2_helper(_n, 25) \
	_ilog2_helper(_n, 24) \
	_ilog2_helper(_n, 23) \
	_ilog2_helper(_n, 22) \
	_ilog2_helper(_n, 21) \
	_ilog2_helper(_n, 20) \
	_ilog2_helper(_n, 19) \
	_ilog2_helper(_n, 18) \
	_ilog2_helper(_n, 17) \
	_ilog2_helper(_n, 16) \
	_ilog2_helper(_n, 15) \
	_ilog2_helper(_n, 14) \
	_ilog2_helper(_n, 13) \
	_ilog2_helper(_n, 12) \
	_ilog2_helper(_n, 11) \
	_ilog2_helper(_n, 10) \
	_ilog2_helper(_n,  9) \
	_ilog2_helper(_n,  8) \
	_ilog2_helper(_n,  7) \
	_ilog2_helper(_n,  6) \
	_ilog2_helper(_n,  5) \
	_ilog2_helper(_n,  4) \
	_ilog2_helper(_n,  3) \
	_ilog2_helper(_n,  2) \
	_ilog2_helper(_n,  1) \
	_ilog2_helper(_n,  0) \
	-1) : ((sizeof(_n) >= 4 ? fls64(_n) : fls32(_n)) - 1) \
)

static __inline void
fast_divide32_prepare(uint32_t _div, uint32_t * __restrict _m,
    uint8_t *__restrict _s1, uint8_t *__restrict _s2)
{
	uint64_t _mt;
	int _l;

	_l = fls32(_div - 1);
	_mt = 0x100000000ULL * ((1ULL << _l) - _div);
	/* LINTED */
	*_m = _mt / _div + 1;
	*_s1 = (_l > 1) ? 1 : _l;
	*_s2 = (_l == 0) ? 0 : _l - 1;
}

/* ARGSUSED */
static __inline uint32_t
fast_divide32(uint32_t _v, uint32_t _div, uint32_t _m, uint8_t _s1,
    uint8_t _s2)
{
	uint32_t _t;

	/* LINTED */
	_t = ((uint64_t)_v * _m) >> 32;
	return (_t + ((_v - _t) >> _s1)) >> _s2;
}

static __inline uint32_t
fast_remainder32(uint32_t _v, uint32_t _div, uint32_t _m, uint8_t _s1,
    uint8_t _s2)
{

	return _v - _div * fast_divide32(_v, _div, _m, _s1, _s2);
}

#endif /* _SYS_BITOPS_H_ */
