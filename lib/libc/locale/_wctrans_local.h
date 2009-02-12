/*	$NetBSD: _wctrans_local.h,v 1.8 2009/02/12 05:00:46 lukem Exp $	*/

/*-
 * Copyright (c)2003 Citrus Project,
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _WCTRANS_LOCAL_H_
#define _WCTRANS_LOCAL_H_

__BEGIN_DECLS
wint_t	_towctrans_ext(wint_t, _WCTransEntry *);
__END_DECLS

static __inline wint_t
_towctrans(wint_t c, _WCTransEntry *te)
{
	return (_RUNE_ISCACHED(c)
		? (wint_t)te->te_cached[(size_t)c]
		: _towctrans_ext(c, te));
}

static __inline struct _WCTransEntry *
_wctrans_lower(_RuneLocale *rl)
{
	_DIAGASSERT(rl->rl_wctrans[_WCTRANS_INDEX_LOWER].te_name != NULL);

	return (&rl->rl_wctrans[_WCTRANS_INDEX_LOWER]);
}

static __inline struct _WCTransEntry *
_wctrans_upper(_RuneLocale *rl)
{
	_DIAGASSERT(rl->rl_wctrans[_WCTRANS_INDEX_UPPER].te_name != NULL);

	return (&rl->rl_wctrans[_WCTRANS_INDEX_UPPER]);
}

#endif /*_WCTRANS_LOCAL_H_*/
