/*	$NetBSD: atomic.h,v 1.42 2021/12/19 12:21:30 riastradh Exp $	*/

/*-
 * Copyright (c) 2013 The NetBSD Foundation, Inc.
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

#ifndef _LINUX_ATOMIC_H_
#define _LINUX_ATOMIC_H_

#include <sys/atomic.h>

#include <machine/limits.h>

#include <asm/barrier.h>

/* XXX Hope the GCC __sync builtins work everywhere we care about!  */
#define	xchg(P, V)		__sync_lock_test_and_set(P, V)
#define	cmpxchg(P, O, N)	__sync_val_compare_and_swap(P, O, N)
#define	try_cmpxchg(P, V, N)						      \
({									      \
	__typeof__(*(V)) *__tcx_v = (V), __tcx_expected = *__tcx_v;	      \
	(*__tcx_v = cmpxchg((P), __tcx_expected, (N))) == __tcx_expected;     \
})

/*
 * atomic (u)int operations
 *
 *	Atomics that return a value, other than atomic_read, imply a
 *	full memory_sync barrier.  Those that do not return a value
 *	imply no memory barrier.
 */

struct atomic {
	union {
		volatile int au_int;
		volatile unsigned int au_uint;
	} a_u;
};

#define	ATOMIC_INIT(i)	{ .a_u = { .au_int = (i) } }

typedef struct atomic atomic_t;

static inline int
atomic_read(const atomic_t *atomic)
{
	/* no membar */
	return atomic->a_u.au_int;
}

static inline void
atomic_set(atomic_t *atomic, int value)
{
	/* no membar */
	atomic->a_u.au_int = value;
}

static inline void
atomic_set_release(atomic_t *atomic, int value)
{
	atomic_store_release(&atomic->a_u.au_int, value);
}

static inline void
atomic_add(int addend, atomic_t *atomic)
{
	/* no membar */
	atomic_add_int(&atomic->a_u.au_uint, addend);
}

static inline void
atomic_sub(int subtrahend, atomic_t *atomic)
{
	/* no membar */
	atomic_add_int(&atomic->a_u.au_uint, -subtrahend);
}

static inline int
atomic_add_return(int addend, atomic_t *atomic)
{
	int v;

	smp_mb__before_atomic();
	v = (int)atomic_add_int_nv(&atomic->a_u.au_uint, addend);
	smp_mb__after_atomic();

	return v;
}

static inline int
atomic_sub_return(int subtrahend, atomic_t *atomic)
{
	int v;

	smp_mb__before_atomic();
	v = (int)atomic_add_int_nv(&atomic->a_u.au_uint, -subtrahend);
	smp_mb__after_atomic();

	return v;
}

static inline void
atomic_inc(atomic_t *atomic)
{
	/* no membar */
	atomic_inc_uint(&atomic->a_u.au_uint);
}

static inline void
atomic_dec(atomic_t *atomic)
{
	/* no membar */
	atomic_dec_uint(&atomic->a_u.au_uint);
}

static inline int
atomic_inc_return(atomic_t *atomic)
{
	int v;

	smp_mb__before_atomic();
	v = (int)atomic_inc_uint_nv(&atomic->a_u.au_uint);
	smp_mb__after_atomic();

	return v;
}

static inline int
atomic_dec_return(atomic_t *atomic)
{
	int v;

	smp_mb__before_atomic();
	v = (int)atomic_dec_uint_nv(&atomic->a_u.au_uint);
	smp_mb__after_atomic();

	return v;
}

static inline int
atomic_dec_and_test(atomic_t *atomic)
{
	/* membar implied by atomic_dec_return */
	return atomic_dec_return(atomic) == 0;
}

static inline int
atomic_dec_if_positive(atomic_t *atomic)
{
	int v;

	smp_mb__before_atomic();
	do {
		v = atomic->a_u.au_uint;
		if (v <= 0)
			break;
	} while (atomic_cas_uint(&atomic->a_u.au_uint, v, v - 1) != v);
	smp_mb__after_atomic();

	return v - 1;
}

static inline void
atomic_or(int value, atomic_t *atomic)
{
	/* no membar */
	atomic_or_uint(&atomic->a_u.au_uint, value);
}

static inline void
atomic_and(int value, atomic_t *atomic)
{
	/* no membar */
	atomic_and_uint(&atomic->a_u.au_uint, value);
}

static inline void
atomic_andnot(int value, atomic_t *atomic)
{
	/* no membar */
	atomic_and_uint(&atomic->a_u.au_uint, ~value);
}

static inline int
atomic_fetch_add(int value, atomic_t *atomic)
{
	unsigned old, new;

	smp_mb__before_atomic();
	do {
		old = atomic->a_u.au_uint;
		new = old + value;
	} while (atomic_cas_uint(&atomic->a_u.au_uint, old, new) != old);
	smp_mb__after_atomic();

	return old;
}

static inline int
atomic_fetch_inc(atomic_t *atomic)
{
	return atomic_fetch_add(1, atomic);
}

static inline int
atomic_fetch_xor(int value, atomic_t *atomic)
{
	unsigned old, new;

	smp_mb__before_atomic();
	do {
		old = atomic->a_u.au_uint;
		new = old ^ value;
	} while (atomic_cas_uint(&atomic->a_u.au_uint, old, new) != old);
	smp_mb__after_atomic();

	return old;
}

static inline void
atomic_set_mask(unsigned long mask, atomic_t *atomic)
{
	/* no membar */
	atomic_or_uint(&atomic->a_u.au_uint, mask);
}

static inline void
atomic_clear_mask(unsigned long mask, atomic_t *atomic)
{
	/* no membar */
	atomic_and_uint(&atomic->a_u.au_uint, ~mask);
}

static inline int
atomic_add_unless(atomic_t *atomic, int addend, int zero)
{
	int value;

	smp_mb__before_atomic();
	do {
		value = atomic->a_u.au_int;
		if (value == zero)
			break;
	} while (atomic_cas_uint(&atomic->a_u.au_uint, value, (value + addend))
	    != (unsigned)value);
	smp_mb__after_atomic();

	return value != zero;
}

static inline int
atomic_inc_not_zero(atomic_t *atomic)
{
	/* membar implied by atomic_add_unless */
	return atomic_add_unless(atomic, 1, 0);
}

static inline int
atomic_xchg(atomic_t *atomic, int new)
{
	int old;

	smp_mb__before_atomic();
	old = (int)atomic_swap_uint(&atomic->a_u.au_uint, (unsigned)new);
	smp_mb__after_atomic();

	return old;
}

static inline int
atomic_cmpxchg(atomic_t *atomic, int expect, int new)
{
	int old;

	/*
	 * XXX As an optimization, under Linux's semantics we are
	 * allowed to skip the memory barrier if the comparison fails,
	 * but taking advantage of that is not convenient here.
	 */
	smp_mb__before_atomic();
	old = (int)atomic_cas_uint(&atomic->a_u.au_uint, (unsigned)expect,
	    (unsigned)new);
	smp_mb__after_atomic();

	return old;
}

static inline bool
atomic_try_cmpxchg(atomic_t *atomic, int *valuep, int new)
{
	int expect = *valuep;

	*valuep = atomic_cmpxchg(atomic, expect, new);

	return *valuep == expect;
}

struct atomic64 {
	volatile uint64_t	a_v;
};

typedef struct atomic64 atomic64_t;

#define	ATOMIC64_INIT(v)	{ .a_v = (v) }

int		linux_atomic64_init(void);
void		linux_atomic64_fini(void);

#ifdef __HAVE_ATOMIC64_OPS

static inline uint64_t
atomic64_read(const struct atomic64 *a)
{
	/* no membar */
	return a->a_v;
}

static inline void
atomic64_set(struct atomic64 *a, uint64_t v)
{
	/* no membar */
	a->a_v = v;
}

static inline void
atomic64_add(int64_t d, struct atomic64 *a)
{
	/* no membar */
	atomic_add_64(&a->a_v, d);
}

static inline void
atomic64_sub(int64_t d, struct atomic64 *a)
{
	/* no membar */
	atomic_add_64(&a->a_v, -d);
}

static inline int64_t
atomic64_add_return(int64_t d, struct atomic64 *a)
{
	int64_t v;

	smp_mb__before_atomic();
	v = (int64_t)atomic_add_64_nv(&a->a_v, d);
	smp_mb__after_atomic();

	return v;
}

static inline uint64_t
atomic64_xchg(struct atomic64 *a, uint64_t new)
{
	uint64_t old;

	smp_mb__before_atomic();
	old = atomic_swap_64(&a->a_v, new);
	smp_mb__after_atomic();

	return old;
}

static inline uint64_t
atomic64_cmpxchg(struct atomic64 *atomic, uint64_t expect, uint64_t new)
{
	uint64_t old;

	/*
	 * XXX As an optimization, under Linux's semantics we are
	 * allowed to skip the memory barrier if the comparison fails,
	 * but taking advantage of that is not convenient here.
	 */
	smp_mb__before_atomic();
	old = atomic_cas_64(&atomic->a_v, expect, new);
	smp_mb__after_atomic();

	return old;
}

#else  /* !defined(__HAVE_ATOMIC64_OPS) */

#define	atomic64_add		linux_atomic64_add
#define	atomic64_add_return	linux_atomic64_add_return
#define	atomic64_cmpxchg	linux_atomic64_cmpxchg
#define	atomic64_read		linux_atomic64_read
#define	atomic64_set		linux_atomic64_set
#define	atomic64_sub		linux_atomic64_sub
#define	atomic64_xchg		linux_atomic64_xchg

uint64_t	atomic64_read(const struct atomic64 *);
void		atomic64_set(struct atomic64 *, uint64_t);
void		atomic64_add(int64_t, struct atomic64 *);
void		atomic64_sub(int64_t, struct atomic64 *);
int64_t		atomic64_add_return(int64_t, struct atomic64 *);
uint64_t	atomic64_xchg(struct atomic64 *, uint64_t);
uint64_t	atomic64_cmpxchg(struct atomic64 *, uint64_t, uint64_t);

#endif

static inline void
atomic64_inc(struct atomic64 *a)
{
	atomic64_add(1, a);
}

static inline int64_t
atomic64_inc_return(struct atomic64 *a)
{
	return atomic64_add_return(1, a);
}

struct atomic_long {
	volatile unsigned long	al_v;
};

typedef struct atomic_long atomic_long_t;

static inline long
atomic_long_read(struct atomic_long *a)
{
	/* no membar */
	return (unsigned long)a->al_v;
}

static inline void
atomic_long_set(struct atomic_long *a, long v)
{
	/* no membar */
	a->al_v = v;
}

static inline long
atomic_long_add_unless(struct atomic_long *a, long addend, long zero)
{
	long value;

	smp_mb__before_atomic();
	do {
		value = (long)a->al_v;
		if (value == zero)
			break;
	} while (atomic_cas_ulong(&a->al_v, (unsigned long)value,
		(unsigned long)(value + addend)) != (unsigned long)value);
	smp_mb__after_atomic();

	return value != zero;
}

static inline long
atomic_long_inc_not_zero(struct atomic_long *a)
{
	/* membar implied by atomic_long_add_unless */
	return atomic_long_add_unless(a, 1, 0);
}

static inline long
atomic_long_xchg(struct atomic_long *a, long new)
{
	long old;

	smp_mb__before_atomic();
	old = (long)atomic_swap_ulong(&a->al_v, (unsigned long)new);
	smp_mb__after_atomic();

	return old;
}

static inline long
atomic_long_cmpxchg(struct atomic_long *a, long expect, long new)
{
	long old;

	/*
	 * XXX As an optimization, under Linux's semantics we are
	 * allowed to skip the memory barrier if the comparison fails,
	 * but taking advantage of that is not convenient here.
	 */
	smp_mb__before_atomic();
	old = (long)atomic_cas_ulong(&a->al_v, (unsigned long)expect,
	    (unsigned long)new);
	smp_mb__after_atomic();

	return old;
}

#endif  /* _LINUX_ATOMIC_H_ */
